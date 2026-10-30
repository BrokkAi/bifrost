use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes;

use brokk_bifrost_analysis::analyzer::semantic_model::CatalogCoordinate;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyArtifactRole;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryOutcome;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyDiscoveryProfile;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnostic;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackDiagnosticSeverity;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::DependencyProvenance;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind;

use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependency;

use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependencyArtifact;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationEvidence;

use brokk_bifrost_analysis::analyzer::semantic_model::SuppressedDiagnostics;
use brokk_bifrost_analysis::analyzer::topology::DependencyScope;

use brokk_bifrost_core::analyzer::config::GoAnalyzerConfig;

use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryConfig;

use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::process::BoundedProcessRequest;

use brokk_bifrost_core::process::run_bounded_process;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_analysis::analyzer::store::go_package_context::GoOverlaySnapshot;

const MAX_GO_ENV_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_GO_LIST_STDOUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_GO_STDERR_BYTES: usize = 1024 * 1024;
const MAX_GO_METADATA_BYTES: u64 = 4 * 1024 * 1024;

pub use brokk_bifrost_go::package_discovery::{
    GoBuildConfiguration, GoEnvironment, GoModule, GoPackage, GoPackageDiscovery, GoPackageError,
    host_build_configuration, selected_build_configuration,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DiscoveredGoPackage {
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

/// All replacement bytes and the Go mapping die together on every return,
/// including cancellation during a bounded process. Nothing is written beside
/// a workspace source file, even when that source does not exist on disk yet.
struct GoOverlayDirectory {
    directory: tempfile::TempDir,
}

impl GoOverlayDirectory {
    fn write(root: &Path, overlays: &GoOverlaySnapshot) -> std::io::Result<Option<Self>> {
        if overlays.files.is_empty() {
            return Ok(None);
        }
        let directory = tempfile::Builder::new()
            .prefix("bifrost-go-overlay-")
            .tempdir()?;
        let mut replacements = BTreeMap::new();
        for (ordinal, file) in overlays.files.iter().enumerate() {
            let destination = directory.path().join(format!("{ordinal}.go"));
            std::fs::write(&destination, &file.bytes)?;
            // Paths are native absolute paths. Portable API renderers must not
            // normalize the path spelling consumed by the host Go tool.
            replacements.insert(root.join(&file.path), destination);
        }
        let mapping = serde_json::to_vec(&serde_json::json!({"Replace": replacements}))?;
        std::fs::write(directory.path().join("overlay.json"), mapping)?;
        Ok(Some(Self { directory }))
    }
}

/// Canonical source membership and the independently filtered semantic product.
/// None means discovery was disabled or failed before decoding primary records.
#[derive(Debug)]
pub struct GoDiscoveryOutcome {
    pub canonical: Option<GoPackageDiscovery>,
    pub semantic_packs: DependencyDiscoveryOutcome,
}

impl From<DependencyDiscoveryOutcome> for GoDiscoveryOutcome {
    fn from(semantic_packs: DependencyDiscoveryOutcome) -> Self {
        Self {
            canonical: None,
            semantic_packs,
        }
    }
}

pub fn resolve_go_semantic_pack_dependencies(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    discover_go_packages(config, project, limits, cancellation).semantic_packs
}

/// Run during reconciliation; never rerun against live files for an old revision.
pub fn discover_go_packages(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> GoDiscoveryOutcome {
    discover_with_runner(
        config,
        project,
        limits,
        cancellation,
        &SystemGoCommandRunner,
    )
}

#[cfg(test)]
fn resolve_with_runner(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    runner: &dyn GoCommandRunner,
) -> DependencyDiscoveryOutcome {
    discover_with_runner(config, project, limits, cancellation, runner).semantic_packs
}

fn discover_with_runner(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    runner: &dyn GoCommandRunner,
) -> GoDiscoveryOutcome {
    discover_domain_with_runner(
        config,
        project,
        limits,
        cancellation,
        runner,
        &Default::default(),
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn discover_domain_with_runner(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    runner: &dyn GoCommandRunner,
    domain: &brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
    environment: Option<GoEnvironment>,
    overlays: Option<&GoOverlaySnapshot>,
) -> GoDiscoveryOutcome {
    let root = project.root().join(&domain.directory);
    let discovery = &config.dependency_discovery;
    if discovery.mode == GoDependencyDiscoveryMode::Disabled {
        return DependencyDiscoveryOutcome::complete(Vec::new()).into();
    }
    if let Err(error) = validate_config(discovery) {
        return failed_outcome("go.config_invalid", error, cancellation, limits).into();
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_outcome().into();
    }
    let executable = discovery
        .go_executable
        .as_deref()
        .unwrap_or_else(|| Path::new("go"));
    let mut base_env = hardened_environment(discovery);
    let gowork = if domain.gowork_path.is_empty() {
        OsString::from("off")
    } else {
        project.root().join(&domain.gowork_path).into_os_string()
    };
    set_env(&mut base_env, "GOWORK", &gowork);
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
    let environment = if let Some(environment) = environment {
        environment
    } else {
        let env_bytes =
            match runner.run(executable, &root, discovery, &env_invocation, cancellation) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return failed_outcome("go.env_failed", error, cancellation, limits).into();
                }
            };
        let environment: GoEnvironment = match serde_json::from_slice(&env_bytes) {
            Ok(environment) => environment,
            Err(error) => {
                return failed_outcome(
                    "go.env_invalid_json",
                    format!("Go environment discovery returned invalid JSON: {error}"),
                    cancellation,
                    limits,
                )
                .into();
            }
        };
        environment
    };
    let build_configuration =
        selected_build_configuration(discovery, &environment.goos, &environment.goarch);
    if build_configuration.goos.is_empty() || build_configuration.goarch.is_empty() {
        return failed_outcome(
            "go.target_missing",
            "Go environment discovery did not return a target GOOS and GOARCH".to_owned(),
            cancellation,
            limits,
        )
        .into();
    }
    let captured;
    let overlays = if let Some(overlays) = overlays {
        overlays
    } else {
        captured = match GoOverlaySnapshot::capture(project) {
            Ok(overlays) => overlays,
            Err(error) => {
                return failed_outcome(
                    "go.overlay_capture_failed",
                    error.to_string(),
                    cancellation,
                    limits,
                )
                .into();
            }
        };
        &captured
    };
    // The environment query already supplies the toolchain identity; never
    // probe support by executing a failing list command on older toolchains.
    if !overlays.files.is_empty()
        && go_version(&environment.goversion)
            .is_some_and(|version| version < Version::new(1, 16, 0))
    {
        return failed_outcome(
            "go.overlay_unsupported_toolchain",
            format!(
                "Go {} does not support -overlay (requires Go 1.16 or newer)",
                environment.goversion
            ),
            cancellation,
            limits,
        )
        .into();
    }
    let overlay = match GoOverlayDirectory::write(project.root(), overlays) {
        Ok(overlay) => overlay,
        Err(error) => {
            return failed_outcome(
                "go.overlay_write_failed",
                error.to_string(),
                cancellation,
                limits,
            )
            .into();
        }
    };
    let vendor = root.join("vendor").join("modules.txt").is_file();
    let mut list_args = vec![
        OsString::from("list"),
        OsString::from("-deps"),
        OsString::from("-test"),
        OsString::from("-json"),
        OsString::from("-e"),
        OsString::from(if vendor {
            "-mod=vendor"
        } else {
            "-mod=readonly"
        }),
    ];
    if let Some(overlay) = &overlay {
        let mut argument = OsString::from("-overlay=");
        argument.push(overlay.directory.path().join("overlay.json"));
        list_args.push(argument);
    }
    if !build_configuration.tags.is_empty() {
        list_args.push(OsString::from(format!(
            "-tags={}",
            build_configuration.tags.join(",")
        )));
    }
    if domain.gowork_path.is_empty() {
        list_args.extend(discovery.workspace_patterns.iter().map(OsString::from));
    } else {
        list_args.extend(
            domain
                .modules
                .iter()
                .map(|(_, module)| OsString::from(format!("{module}/..."))),
        );
    }
    let list_invocation = GoInvocation {
        args: list_args,
        env: target_environment(
            discovery,
            &environment,
            &build_configuration.goos,
            &build_configuration.goarch,
        ),
        stdout_limit: MAX_GO_LIST_STDOUT_BYTES,
        description: "Go package discovery",
    };
    let package_bytes =
        match runner.run(executable, &root, discovery, &list_invocation, cancellation) {
            Ok(bytes) => bytes,
            Err(error) => {
                let semantic_packs =
                    failed_outcome("go.list_failed", error.clone(), cancellation, limits);
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return semantic_packs.into();
                }
                // An unsuccessful root invocation has no per-file selection
                // authority. Retain its structured failure alongside inventory
                // placements instead of erasing them with an empty tool profile.
                let packages = discovery
                    .workspace_patterns
                    .iter()
                    .map(|pattern| GoPackage {
                        import_path: pattern.clone(),
                        name: String::new(),
                        dir: root.clone(),
                        standard: false,
                        incomplete: true,
                        error: Some(GoPackageError {
                            err: error.clone(),
                            import_stack: Vec::new(),
                            pos: String::new(),
                        }),
                        module: None,
                        go_files: Vec::new(),
                        cgo_files: Vec::new(),
                        ignored_go_files: Vec::new(),
                        imports: Vec::new(),
                        import_map: BTreeMap::new(),
                        for_test: String::new(),
                        test_go_files: Vec::new(),
                        x_test_go_files: Vec::new(),
                        test_imports: Vec::new(),
                        x_test_imports: Vec::new(),
                        deps_errors: Vec::new(),
                    })
                    .collect();
                return GoDiscoveryOutcome {
                    canonical: Some(GoPackageDiscovery {
                        domain: domain.clone(),
                        input_digest: None,
                        failure: None,
                        packages,
                        environment: environment.clone(),
                        build_configuration: build_configuration.clone(),
                        workspace_patterns: discovery.workspace_patterns.clone(),
                        vendor,
                    }),
                    semantic_packs,
                };
            }
        };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return cancelled_outcome().into();
    }
    let mut packages = match parse_package_stream(&package_bytes) {
        Ok(packages) => packages,
        Err(error) => {
            return failed_outcome("go.list_invalid_json", error, cancellation, limits).into();
        }
    };
    let canonical = GoPackageDiscovery {
        domain: domain.clone(),
        input_digest: None,
        failure: None,
        packages: packages.clone(),
        environment: environment.clone(),
        build_configuration: build_configuration.clone(),
        workspace_patterns: discovery.workspace_patterns.clone(),
        vendor,
    };
    let finish = |semantic_packs| GoDiscoveryOutcome {
        canonical: Some(canonical),
        semantic_packs,
    };
    if !domain.directory.is_empty() {
        return finish(DependencyDiscoveryOutcome::complete(Vec::new()));
    }
    if discovery.mode == GoDependencyDiscoveryMode::CuratedPackEvidence {
        return finish(build_curated_pack_evidence_outcome(
            packages,
            &environment,
            &build_configuration.goos,
            &build_configuration.goarch,
            discovery,
            vendor,
            limits,
        ));
    }
    debug_assert_eq!(discovery.mode, GoDependencyDiscoveryMode::FullProduction);
    if packages.iter().any(|package| {
        package.cgo_files.is_empty()
            && package.ignored_go_files.iter().any(|path| {
                !path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.ends_with("_test.go"))
            })
    }) {
        let mut cgo_invocation = list_invocation;
        set_env(&mut cgo_invocation.env, "CGO_ENABLED", OsStr::new("1"));
        cgo_invocation.description = "Go cgo surface discovery";
        let cgo_bytes =
            match runner.run(executable, &root, discovery, &cgo_invocation, cancellation) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return finish(failed_outcome(
                        "go.cgo_probe_failed",
                        error,
                        cancellation,
                        limits,
                    ));
                }
            };
        let cgo_packages = match parse_package_stream(&cgo_bytes) {
            Ok(packages) => packages,
            Err(error) => {
                return finish(failed_outcome(
                    "go.cgo_probe_invalid_json",
                    error,
                    cancellation,
                    limits,
                ));
            }
        };
        let cgo_files = cgo_packages
            .into_iter()
            .filter(|package| !package.cgo_files.is_empty())
            .map(|package| (package.import_path, package.cgo_files))
            .collect::<BTreeMap<_, _>>();
        for package in &mut packages {
            if let Some(files) = cgo_files.get(&package.import_path) {
                package.cgo_files.clone_from(files);
            }
        }
    }
    finish(build_outcome(
        packages,
        &environment,
        &root,
        &build_configuration.goos,
        &build_configuration.goarch,
        discovery,
        vendor,
        limits,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_curated_pack_evidence_outcome(
    packages: Vec<GoPackage>,
    environment: &GoEnvironment,
    goos: &str,
    goarch: &str,
    config: &GoDependencyDiscoveryConfig,
    vendor: bool,
    limits: &DependencyPackLimits,
) -> DependencyDiscoveryOutcome {
    let mut modules = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for package in packages {
        push_package_incompleteness_diagnostic(&package, &mut diagnostics, limits);
        if package.module.as_ref().is_some_and(|module| module.main) {
            continue;
        }
        if package.standard {
            continue;
        }
        let Some(module) = package.module else {
            diagnostics.push(error_diagnostic(
                "go.module_missing",
                Some(package.import_path.clone()),
                format!("Go package {} has no module metadata", package.import_path),
                limits,
            ));
            continue;
        };
        modules.entry(module_id(&module)).or_insert(module);
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
    let mut dependencies = modules
        .into_iter()
        .map(|(module_id, module)| ResolvedDependency {
            id: format!("go:curated:{module_id}"),
            evidence: SemanticModelActivationEvidence {
                language: "go".to_owned(),
                ecosystem: "go-module".to_owned(),
                package: None,
                module: Some(CatalogCoordinate {
                    name: module.path.clone(),
                    version: module_version(&module.version),
                }),
                toolchain: Some(toolchain.clone()),
                target: Some(target.clone()),
                configuration: Some(configuration.clone()),
                artifact_sha256: None,
            },
            provenance: module_provenance(&module),
            artifacts: Vec::new(),
            scope: DependencyScope::Unknown,
            declared_by: None,
        })
        .collect::<Vec<_>>();

    let mut suppressed_diagnostics = SuppressedDiagnostics::default();
    if dependencies.len() > limits.max_dependencies {
        // Dropped dependencies are not diagnostics; the breach itself is
        // reported as the error diagnostic pushed here.
        suppressed_diagnostics.warnings = dependencies.len() - limits.max_dependencies;
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
        // Go discovery emits error-severity diagnostics only.
        suppressed_diagnostics.errors = diagnostics.len() - limits.max_diagnostics;
        diagnostics.truncate(limits.max_diagnostics);
    }
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered: 2,
            dependencies_resolved: dependencies.len(),
            informational_evidence: Vec::new(),
        },
        dependencies,
        complete: diagnostics.is_empty() && suppressed_diagnostics.total() == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn hardened_environment(config: &GoDependencyDiscoveryConfig) -> Vec<(OsString, OsString)> {
    let build_configuration = host_build_configuration(config);
    let mut env = reviewed_host_environment(|name| std::env::var_os(name));
    env.extend([
        // #7002: belt-and-braces against git credential prompts; downloads and VCS stamping are already disabled.
        os_env("GIT_TERMINAL_PROMPT", "0"),
        os_env("GOTOOLCHAIN", "local"),
        os_env("GOPROXY", "off"),
        os_env("GOSUMDB", "off"),
        os_env("GOENV", "off"),
        os_env("GOWORK", "off"),
        os_env("GOFLAGS", "-buildvcs=false"),
        os_env(
            "CGO_ENABLED",
            if build_configuration.cgo_enabled {
                "1"
            } else {
                "0"
            },
        ),
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
    set_env(&mut env, "GOWORK", OsStr::new(&environment.gowork));
    set_env(&mut env, "GOROOT", environment.goroot.as_os_str());
    set_env(&mut env, "GOPATH", environment.gopath.as_os_str());
    set_env(&mut env, "GOMODCACHE", environment.gomodcache.as_os_str());
    env
}

fn reviewed_host_environment(
    mut value: impl FnMut(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    [
        "PATH",
        "HOME",
        "USERPROFILE",
        "LOCALAPPDATA",
        "GOCACHE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
    ]
    .into_iter()
    .filter_map(|name| value(name).map(|value| (OsString::from(name), value)))
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

fn push_package_incompleteness_diagnostic(
    package: &GoPackage,
    diagnostics: &mut Vec<DependencyPackDiagnostic>,
    limits: &DependencyPackLimits,
) {
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
    let workspace_identity =
        match workspace_metadata_identity(&packages, &environment.gowork, project_root) {
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
        push_package_incompleteness_diagnostic(&package, &mut diagnostics, limits);
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
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    let mut suppressed_diagnostics = SuppressedDiagnostics::default();
    if dependencies.len() > limits.max_dependencies {
        // Dropped dependencies are not diagnostics; the breach itself is
        // reported as the error diagnostic pushed here.
        suppressed_diagnostics.warnings = dependencies.len() - limits.max_dependencies;
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
        // Go discovery emits error-severity diagnostics only.
        suppressed_diagnostics.errors = diagnostics.len() - limits.max_diagnostics;
        diagnostics.truncate(limits.max_diagnostics);
    }
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered: 2,
            dependencies_resolved: dependencies.len(),
            informational_evidence: Vec::new(),
        },
        dependencies,
        complete: diagnostics.is_empty() && suppressed_diagnostics.total() == 0,
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
    let version = raw.strip_prefix("go").unwrap_or(raw);
    // Initial Go releases before 1.21 omit the patch component (go1.15).
    if let Ok(version) =
        Version::parse(version).or_else(|_| Version::parse(&format!("{version}.0")))
    {
        return Some(version);
    }
    for marker in ["rc", "beta"] {
        let Some(marker_offset) = version.find(marker) else {
            continue;
        };
        let (release, prerelease) = version.split_at(marker_offset);
        let ordinal = prerelease.strip_prefix(marker)?;
        if ordinal.is_empty() || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let release = if release.bytes().filter(|byte| *byte == b'.').count() == 1 {
            format!("{release}.0")
        } else {
            release.to_owned()
        };
        return Version::parse(&format!("{release}-{marker}.{ordinal}")).ok();
    }
    None
}

fn workspace_metadata_identity(
    packages: &[GoPackage],
    gowork: &str,
    project_root: &Path,
) -> Result<String, String> {
    let mut metadata = BTreeMap::new();
    if !gowork.is_empty() && gowork != "off" {
        let path = Path::new(gowork);
        metadata.insert("go.work".to_owned(), file_identity(path)?);
        let sum = path.with_extension("work.sum");
        if sum.is_file() {
            metadata.insert("go.work.sum".to_owned(), file_identity(&sum)?);
        }
    }
    for module in packages
        .iter()
        .filter_map(|package| package.module.as_ref())
        .filter(|module| module.main && !module.go_mod.as_os_str().is_empty())
    {
        metadata.insert(
            format!("module:{}:go.mod", module.path),
            file_identity(&module.go_mod)?,
        );
        let sum = module.go_mod.with_file_name("go.sum");
        if sum.is_file() {
            metadata.insert(
                format!("module:{}:go.sum", module.path),
                file_identity(&sum)?,
            );
        }
    }
    if metadata.is_empty() {
        for name in ["go.mod", "go.sum"] {
            let path = project_root.join(name);
            if path.is_file() {
                metadata.insert(name.to_owned(), file_identity(&path)?);
            }
        }
    }
    if metadata.is_empty() {
        return Ok("off".to_owned());
    }
    let encoded =
        serde_json::to_vec(&metadata).expect("Go workspace metadata identity is JSON serializable");
    Ok(format!(
        "workspace:{}",
        lower_hex_string(&sha256_bytes(&encoded))
    ))
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
        suppressed_diagnostics: SuppressedDiagnostics::default(),
        complete: false,
        cancelled: false,
        profile: DependencyDiscoveryProfile::default(),
    }
}

fn cancelled_outcome() -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome::cancelled_with_message("Go dependency discovery was cancelled")
}

/// Environment observation precedes the reconciliation-only rerun decision.
pub(crate) fn domain_environment(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    domain: &brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
    cancellation: &CancellationToken,
) -> Result<GoEnvironment, String> {
    let config = &config.dependency_discovery;
    let mut env = hardened_environment(config);
    let gowork = if domain.gowork_path.is_empty() {
        OsString::from("off")
    } else {
        project.root().join(&domain.gowork_path).into_os_string()
    };
    set_env(&mut env, "GOWORK", &gowork);
    let bytes = SystemGoCommandRunner.run(
        config
            .go_executable
            .as_deref()
            .unwrap_or_else(|| Path::new("go")),
        &project.root().join(&domain.directory),
        config,
        &GoInvocation {
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
            env,
            stdout_limit: MAX_GO_ENV_STDOUT_BYTES,
            description: "Go domain environment discovery",
        },
        Some(cancellation),
    )?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid Go environment: {error}"))
}

pub(crate) fn discover_domain(
    config: &GoAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: &CancellationToken,
    domain: &brokk_bifrost_go::package_discovery::GoDiscoveryDomain,
    environment: GoEnvironment,
    overlays: &GoOverlaySnapshot,
) -> GoDiscoveryOutcome {
    discover_domain_with_runner(
        config,
        project,
        limits,
        Some(cancellation),
        &SystemGoCommandRunner,
        domain,
        Some(environment),
        Some(overlays),
    )
}

#[cfg(test)]
mod tests {

    use crate::analyzer::go::dependency_discovery::*;
    use brokk_bifrost_analysis::analyzer::semantic_model::ResolvedDependencyArtifactInput;

    use brokk_bifrost_core::analyzer::config::GoAnalyzerConfig;

    use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryConfig;

    use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_test_macros::hardwon;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::process::Command;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeRunner {
        outputs: RefCell<VecDeque<Result<Vec<u8>, String>>>,
        invocations: RefCell<Vec<GoInvocation>>,
        roots: RefCell<Vec<PathBuf>>,
    }

    impl FakeRunner {
        fn with_outputs(outputs: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                outputs: RefCell::new(outputs.into_iter().map(Ok).collect()),
                invocations: RefCell::new(Vec::new()),
                roots: RefCell::new(Vec::new()),
            }
        }
    }

    impl GoCommandRunner for FakeRunner {
        fn run(
            &self,
            _executable: &Path,
            root: &Path,
            _config: &GoDependencyDiscoveryConfig,
            invocation: &GoInvocation,
            _cancellation: Option<&CancellationToken>,
        ) -> Result<Vec<u8>, String> {
            self.roots.borrow_mut().push(root.to_path_buf());
            self.invocations.borrow_mut().push(invocation.clone());
            self.outputs.borrow_mut().pop_front().unwrap()
        }
    }

    fn config() -> GoAnalyzerConfig {
        GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
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
    fn go_overlay_discovery_cancellation_removes_only_request_files() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("main.go", "package main\nfunc main(){}\n")
            .build();
        let overlay =
            brokk_bifrost_core::analyzer::project::OverlayProject::new(fixture.project_dyn());
        overlay.set(
            fixture.file("main.go").abs_path(),
            "package main\nfunc main(){ println(1) }\n".into(),
        );
        overlay.set(fixture.file("new.go").abs_path(), "package main\n".into());
        struct CancelRunner {
            directory: RefCell<Option<PathBuf>>,
            runs: std::cell::Cell<usize>,
        }
        impl GoCommandRunner for CancelRunner {
            fn run(
                &self,
                _executable: &Path,
                root: &Path,
                _config: &GoDependencyDiscoveryConfig,
                invocation: &GoInvocation,
                cancellation: Option<&CancellationToken>,
            ) -> Result<Vec<u8>, String> {
                self.runs.set(self.runs.get() + 1);
                if invocation.args[0] == "env" {
                    return Ok(environment(root));
                }
                let argument = invocation
                    .args
                    .iter()
                    .find_map(|arg| arg.to_str().and_then(|arg| arg.strip_prefix("-overlay=")))
                    .unwrap();
                let mapping: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(argument).unwrap()).unwrap();
                let directory = Path::new(argument).parent().unwrap();
                assert!(!directory.starts_with(root));
                let replacements = mapping["Replace"].as_object().unwrap();
                assert_eq!(replacements.len(), 2);
                for (source, replacement) in replacements {
                    assert!(Path::new(source).is_absolute());
                    let replacement = Path::new(replacement.as_str().unwrap());
                    assert!(replacement.starts_with(directory));
                    assert!(replacement.is_file());
                }
                assert_eq!(
                    std::fs::read_to_string(root.join("main.go")).unwrap(),
                    "package main\nfunc main(){}\n"
                );
                assert!(!root.join("new.go").exists());
                *self.directory.borrow_mut() = Some(directory.to_path_buf());
                cancellation.unwrap().cancel();
                Err("cancelled during discovery".into())
            }
        }
        let runner = CancelRunner {
            directory: RefCell::new(None),
            runs: std::cell::Cell::new(0),
        };
        let cancellation = CancellationToken::new();
        let result = discover_with_runner(
            &config(),
            &overlay,
            &Default::default(),
            Some(&cancellation),
            &runner,
        );
        assert!(!result.semantic_packs.complete);
        assert_eq!(runner.runs.get(), 2, "overlay adds no tool invocations");
        let directory = runner.directory.borrow();
        assert!(
            !directory.as_ref().unwrap().exists(),
            "drop removes overlay after cancellation"
        );
    }

    #[test]
    fn go_overlay_rejects_old_toolchain_without_list() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("main.go", "package main\n")
            .build();
        let overlay =
            brokk_bifrost_core::analyzer::project::OverlayProject::new(fixture.project_dyn());
        overlay.set(
            fixture.file("main.go").abs_path(),
            "package main\nfunc main(){}\n".into(),
        );
        let mut env: serde_json::Value =
            serde_json::from_slice(&environment(fixture.root())).unwrap();
        for version in ["go1.15", "go1.15.15"] {
            env["GOVERSION"] = version.into();
            let runner = FakeRunner::with_outputs([serde_json::to_vec(&env).unwrap()]);
            let outcome =
                discover_with_runner(&config(), &overlay, &Default::default(), None, &runner);
            assert!(!outcome.semantic_packs.complete);
            assert!(
                outcome
                    .semantic_packs
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == "go.overlay_unsupported_toolchain"),
                "{outcome:?}"
            );
            assert_eq!(runner.invocations.borrow().len(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    #[hardwon(
        "#7154: unsaved import edits failed to publish while body-only overlays must reuse placement"
    )]
    fn installed_go_overlay_membership_discovery_and_unchanged_save_reuse() {
        use brokk_bifrost_analysis::analyzer::workspace::{
            DependencyPackEcosystem, WorkspaceAnalyzer,
        };
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use std::collections::BTreeSet;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        if !Command::new("go")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        let Some(go) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join("go"))
            .find(|path| path.is_file())
        else {
            return;
        };
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/overlay\n\ngo 1.22\n")
            .file("consumer.go", "package overlay\nfunc Run(){}\n")
            .file("new/new.go", "package new\nfunc New(){}\n")
            .build();
        let log = fixture.root().join("go-runs");
        let quote = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
        let wrapper = fixture.root().join("go-wrapper");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nif [ \"$1\" = list ]; then echo list >> {}; fi\nexec {} \"$@\"\n",
                quote(&log),
                quote(&go)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        let mut config = AnalyzerConfig::default();
        config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
        config.go.dependency_discovery.go_executable = Some(wrapper);
        let mut workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(overlay.clone(), config.clone()).unwrap();
        let outcome = workspace.resolve_dependency_discovery(
            DependencyPackEcosystem::Go,
            &config,
            &Default::default(),
            &CancellationToken::new(),
        );
        assert!(outcome.complete, "{outcome:?}");
        let runs = || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .count()
        };
        let context = |workspace: &WorkspaceAnalyzer| {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT p.context_id FROM go_context_publications p JOIN go_context_selections s USING(selection_id) WHERE s.profile_digest<>?1 AND p.valid_until IS NULL",[brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile()],|row|row.get::<_,i64>(0)).unwrap()
        };
        let publications = |workspace: &WorkspaceAnalyzer| {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT count(*) FROM go_context_publications p JOIN go_context_selections s USING(selection_id) WHERE s.profile_digest<>?1",[brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile()],|row|row.get::<_,i64>(0)).unwrap()
        };
        // Equal-output saves move the input key without moving valid_from.
        // A later body overlay must still compare the recorded membership.
        fixture
            .file("consumer.go")
            .write("package overlay\nfunc Run(){println(0)}\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([fixture.file("consumer.go")]));
        let original = context(&workspace);
        let before = runs();
        let before_publications = publications(&workspace);
        let consumer = fixture.file("consumer.go");
        overlay.set(
            consumer.abs_path(),
            "package overlay\nfunc Run(){println(1)}\n".into(),
        );
        workspace = workspace.update(&BTreeSet::from([consumer.clone()]));
        assert_eq!(runs(), before, "body-only overlay runs no discovery");
        assert_eq!(context(&workspace), original);
        assert_eq!(
            publications(&workspace),
            before_publications,
            "body-only overlay publishes nothing"
        );
        let edited =
            "package overlay\nimport \"example.test/overlay/new\"\nfunc Run(){new.New()}\n";
        overlay.set(consumer.abs_path(), edited.into());
        let provider = fixture.file("new/new.go");
        overlay.set(
            provider.abs_path(),
            "package new\nfunc New(){println(2)}\n".into(),
        );
        workspace = workspace.update(&BTreeSet::from([consumer.clone(), provider]));
        assert_eq!(
            runs(),
            before + 1,
            "one existing discovery invocation per changed domain"
        );
        assert_eq!(
            publications(&workspace),
            before_publications + 1,
            "one tool context published for import edit"
        );
        let imported = context(&workspace);
        assert_ne!(imported, original);
        overlay.set(
            consumer.abs_path(),
            edited.replace("new.New()", "new.New();println(3)"),
        );
        workspace = workspace.update(&BTreeSet::from([consumer.clone()]));
        assert_eq!(
            runs(),
            before + 1,
            "a body edit after an unsaved import also reuses placement"
        );
        assert_eq!(publications(&workspace), before_publications + 1);
        overlay.set(consumer.abs_path(), edited.into());
        workspace = workspace.update(&BTreeSet::from([consumer.clone()]));
        assert_eq!(runs(), before + 1);
        consumer.write(edited).unwrap();
        overlay.clear(&consumer.abs_path());
        workspace = workspace.update(&BTreeSet::from([consumer.clone()]));
        assert_eq!(runs(), before + 1, "unchanged save does no discovery");
        assert_eq!(context(&workspace), imported);
        let snapshot = {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT workspace_id,generation,revision FROM workspace_heads WHERE lang='go'",[],|row|Ok(brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId {
                workspace_id:brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(fixture.root()),lang:"go".into(),
                generation:brokk_bifrost_analysis::analyzer::store::GenerationId::from_persisted(row.get(1)?),revision:row.get(2)? })).unwrap()
        };
        let observe = |workspace: &WorkspaceAnalyzer| {
            workspace
                .store()
                .unwrap()
                .observe_go_context_inputs(
                    &snapshot,
                    workspace.analyzer().project(),
                    &CancellationToken::new(),
                )
                .unwrap()
        };
        let observed = observe(&workspace);
        std::fs::File::open(consumer.abs_path())
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() + Duration::from_secs(60)),
            )
            .unwrap();
        assert!(
            matches!((observed,observe(&workspace)),(brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::Ready(before),brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::Ready(after)) if before==after),
            "mtime does not participate in observation"
        );
        workspace = workspace.update(&BTreeSet::from([consumer]));
        assert_eq!(
            runs(),
            before + 1,
            "equal-byte mtime touch does no discovery"
        );
        assert_eq!(context(&workspace), imported);
        let added = fixture.file("added.go");
        overlay.set(
            added.abs_path(),
            "package overlay\nimport \"example.test/overlay/new\"\nfunc Added(){new.New()}\n"
                .into(),
        );
        workspace = workspace.update(&BTreeSet::from([added]));
        assert_eq!(runs(), before + 2, "missing predecessor triggers discovery");
        assert_eq!(publications(&workspace), before_publications + 2);
        let conn = workspace.store().unwrap().read_conn().unwrap();
        assert!(conn.query_row("SELECT EXISTS(SELECT 1 FROM go_package_files f JOIN go_package_instances p USING(package_id) WHERE f.rel_path='added.go' AND p.context_id=?1)",[context(&workspace)],|row|row.get::<_,bool>(0)).unwrap(),"Go must list the new unsaved file");
        drop(conn);
        let mut latest = snapshot.clone();
        latest.revision = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM workspace_heads WHERE lang='go'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let captured = GoOverlaySnapshot::capture(workspace.analyzer().project()).unwrap();
        let store = workspace.store().unwrap();
        assert!(matches!(store.observe_go_context_inputs_with_overlay(&latest,workspace.analyzer().project(),&CancellationToken::new(),&captured).unwrap(),brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::Ready(_)));
        overlay.set(
            fixture.file("added.go").abs_path(),
            "package overlay\nfunc Added(){}\n".into(),
        );
        assert!(matches!(store.observe_go_context_inputs_with_overlay(&latest,workspace.analyzer().project(),&CancellationToken::new(),&captured).unwrap(),brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::InputsChanged(_)),"a newer buffer cannot validate a captured discovery");
        assert!(overlay.clear(&fixture.file("added.go").abs_path()));
        assert!(!fixture.file("added.go").abs_path().exists());
        assert!(
            matches!(
                store.observe_go_context_inputs_with_overlay(
                    &latest,
                    workspace.analyzer().project(),
                    &CancellationToken::new(),
                    &captured,
                ).unwrap(),
                brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::InputsChanged(
                    brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputChange::Missing { path, .. }
                ) if path == "added.go"
            ),
            "closing a new unsaved file must refuse publication without an I/O error"
        );
    }

    #[test]
    fn canonical_discovery_preserves_main_packages_imports_and_test_variants() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::write(root.join("go.mod"), "module example.test/app\n").unwrap();
        let project = TestProject::new(root, Language::Go);
        let package = serde_json::json!({
            "ImportPath": "example.test/app [example.test/app.test]",
            "Name": "different_name",
            "Dir": root,
            "Module": { "Path": "example.test/app", "Main": true, "Dir": root,
                "GoMod": root.join("go.mod"),
                "Replace": { "Path": "../provider", "Dir": root.join("provider") } },
            "GoFiles": ["app.go", "app_test.go"],
            "IgnoredGoFiles": ["ignored_test.go"],
            "TestGoFiles": ["app_test.go"],
            "XTestGoFiles": ["external_test.go"],
            "Imports": ["example.test/provider [example.test/app.test]"],
            "ImportMap": {"example.test/provider": "example.test/provider [example.test/app.test]"},
            "ForTest": "example.test/app",
            "TestImports": ["testing"],
            "XTestImports": ["example.test/app"],
            "Incomplete": true,
            "Error": {"Err": "package failure", "Pos": "app.go:3:1", "ImportStack": ["example.test/app"]},
            "DepsErrors": [{"Err": "dependency failure", "ImportStack": ["example.test/app", "example.test/provider"]}]
        });
        for mode in [
            GoDependencyDiscoveryMode::FullProduction,
            GoDependencyDiscoveryMode::CuratedPackEvidence,
        ] {
            let mut config = config();
            config.dependency_discovery.mode = mode;
            let runner = FakeRunner::with_outputs([
                environment(root),
                serde_json::to_vec(&package).unwrap(),
            ]);
            let result = discover_with_runner(
                &config,
                &project,
                &DependencyPackLimits::default(),
                None,
                &runner,
            );
            let discovery = result.canonical.unwrap();
            assert_eq!(discovery.packages.len(), 1);
            let found = &discovery.packages[0];
            assert_eq!(
                found.import_path,
                "example.test/app [example.test/app.test]"
            );
            assert_eq!(found.name, "different_name");
            assert_eq!(found.for_test, "example.test/app");
            assert_eq!(found.import_map["example.test/provider"], found.imports[0]);
            assert_eq!(
                found.go_files,
                [PathBuf::from("app.go"), PathBuf::from("app_test.go")]
            );
            assert_eq!(found.test_go_files, [PathBuf::from("app_test.go")]);
            assert_eq!(found.x_test_go_files, [PathBuf::from("external_test.go")]);
            assert_eq!(found.test_imports, ["testing"]);
            assert_eq!(found.x_test_imports, ["example.test/app"]);
            assert!(found.module.as_ref().unwrap().main);
            assert_eq!(
                found.module.as_ref().unwrap().replace.as_ref().unwrap().dir,
                root.join("provider")
            );
            assert!(found.incomplete);
            assert_eq!(found.error.as_ref().unwrap().pos, "app.go:3:1");
            assert_eq!(
                found.error.as_ref().unwrap().import_stack,
                ["example.test/app"]
            );
            assert_eq!(found.deps_errors[0].err, "dependency failure");
            assert_eq!(discovery.build_configuration.goos, "linux");
            assert_eq!(discovery.build_configuration.goarch, "arm64");
            assert_eq!(discovery.environment.goversion, "go1.25.1");
            assert_eq!(discovery.build_configuration.tags, ["integration", "safe"]);
            assert_eq!(discovery.workspace_patterns, ["./cmd/..."]);
            assert!(!discovery.vendor);
            // Semantic pack filtering remains independent of native membership.
            assert!(result.semantic_packs.dependencies.is_empty());
            assert_eq!(runner.invocations.borrow().len(), 2);
        }
    }

    #[test]
    fn canonical_membership_survives_cgo_probe_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let package = serde_json::json!({
            "ImportPath": "example.test/app", "Name": "app", "Dir": temporary.path(),
            "GoFiles": ["app.go"], "IgnoredGoFiles": ["cgo.go"],
            "Module": {"Path": "example.test/app", "Main": true}
        });
        let runner = FakeRunner::with_outputs([
            environment(temporary.path()),
            serde_json::to_vec(&package).unwrap(),
        ]);
        runner
            .outputs
            .borrow_mut()
            .push_back(Err("probe unavailable".to_owned()));
        let result = discover_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        let canonical = result.canonical.unwrap();
        assert_eq!(canonical.packages[0].go_files, [PathBuf::from("app.go")]);
        assert!(canonical.packages[0].cgo_files.is_empty());
        assert_eq!(
            canonical.packages[0].ignored_go_files,
            [PathBuf::from("cgo.go")]
        );
        assert!(!result.semantic_packs.complete);
        assert_eq!(
            result.semantic_packs.diagnostics[0].code,
            "go.cgo_probe_failed"
        );
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
        assert!(invocations[1].args.iter().any(|arg| arg == "-deps"));
        assert!(invocations[1].args.iter().any(|arg| arg == "-test"));
        assert!(invocations[1].args.iter().any(|arg| arg == "-mod=readonly"));
        assert!(
            invocations[1]
                .args
                .iter()
                .any(|arg| arg == "-tags=integration,safe")
        );
        let env: BTreeMap<_, _> = invocations[1].env.iter().cloned().collect();
        assert_eq!(env.get(OsStr::new("GIT_TERMINAL_PROMPT")).unwrap(), "0");
        assert_eq!(env.get(OsStr::new("GOTOOLCHAIN")).unwrap(), "local");
        assert_eq!(env.get(OsStr::new("GOPROXY")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("GOSUMDB")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("GOENV")).unwrap(), "off");
        assert_eq!(env.get(OsStr::new("GOFLAGS")).unwrap(), "-buildvcs=false");
        assert_eq!(env.get(OsStr::new("CGO_ENABLED")).unwrap(), "0");
        assert_eq!(env.get(OsStr::new("GOOS")).unwrap(), "linux");
        assert_eq!(env.get(OsStr::new("GOARCH")).unwrap(), "arm64");
    }

    #[test]
    #[hardwon("c854959b2829: dropping LOCALAPPDATA or GOCACHE broke Go discovery")]
    fn hardened_environment_preserves_host_go_cache_locations() {
        let env = reviewed_host_environment(|name| match name {
            "LOCALAPPDATA" => Some(OsString::from(r"C:\Users\runner\AppData\Local")),
            "GOCACHE" => Some(OsString::from(r"D:\go-build")),
            "UNREVIEWED_SECRET" => Some(OsString::from("must-not-pass")),
            _ => None,
        })
        .into_iter()
        .collect::<BTreeMap<_, _>>();

        assert_eq!(
            env.get(OsStr::new("LOCALAPPDATA")),
            Some(&OsString::from(r"C:\Users\runner\AppData\Local"))
        );
        assert_eq!(
            env.get(OsStr::new("GOCACHE")),
            Some(&OsString::from(r"D:\go-build"))
        );
        assert!(!env.contains_key(OsStr::new("UNREVIEWED_SECRET")));
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
            "IgnoredGoFiles": ["cgo_unix.go"]
        })
        .to_string()
        .into_bytes();
        let cgo_packages = serde_json::json!({
            "ImportPath": "net",
            "Dir": temporary.path().join("goroot/src/net"),
            "Standard": true,
            "GoFiles": ["net.go"],
            "CgoFiles": ["cgo_unix.go"]
        })
        .to_string()
        .into_bytes();
        let runner =
            FakeRunner::with_outputs([environment(temporary.path()), packages, cgo_packages]);
        let project = TestProject::new(temporary.path(), Language::Go);
        let result = discover_with_runner(
            &config(),
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );
        let primary = result.canonical.unwrap();
        assert!(primary.packages[0].cgo_files.is_empty());
        assert_eq!(
            primary.packages[0].ignored_go_files,
            [PathBuf::from("cgo_unix.go")]
        );
        let outcome = result.semantic_packs;
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
        let invocations = runner.invocations.borrow();
        assert_eq!(invocations.len(), 3);
        assert!(
            invocations[2]
                .env
                .iter()
                .any(|(key, value)| key == "CGO_ENABLED" && value == "1")
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
    fn go_toolchain_versions_preserve_prerelease_identity() {
        assert_eq!(go_version("go1.26.1"), Some(Version::new(1, 26, 1)));
        assert_eq!(go_version("go1.27rc2").unwrap().to_string(), "1.27.0-rc.2");
        assert_eq!(
            go_version("go1.27beta1").unwrap().to_string(),
            "1.27.0-beta.1"
        );
        assert_eq!(go_version("devel go1.28-deadbeef"), None);
    }

    #[test]
    fn go_domains_use_structured_membership_and_isolated_invocations() {
        use brokk_bifrost_go::package_discovery::go_discovery_domains;
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/root\n")
            .file("go.work", "go 1.22\nuse ./shared\n")
            .file("shared/go.mod", "module example.test/shared\n")
            .file("nested/go.mod", "module example.test/nested\n")
            .file("team/go.work", "go 1.22\nuse (\n./a\n./b\n)\n")
            .file("team/a/go.mod", "module example.test/a\n")
            .file("team/b/go.mod", "module example.test/b\n")
            .file("vendor/ignored/go.mod", "module example.test/vendor\n")
            .file("testdata/ignored/go.mod", "module example.test/testdata\n")
            .file("_hidden/go.mod", "module example.test/hidden\n")
            .file(".hidden/go.mod", "module example.test/dot\n")
            .file("empty/go.mod", "")
            .build();
        let inputs = fixture
            .project_dyn()
            .all_files()
            .unwrap()
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .file_name()
                    .is_some_and(|name| name == "go.mod" || name == "go.work")
            })
            .map(|file| {
                (
                    file.rel_path().to_path_buf(),
                    fixture.project_dyn().read_source(&file).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let domains = go_discovery_domains(fixture.root(), &inputs).unwrap();
        assert_eq!(
            domains.len(),
            4,
            "root isolated, root workfile, nested, team workfile: {domains:?}"
        );
        let mut outcomes = Vec::new();
        for domain in &domains {
            let runner = FakeRunner::with_outputs([environment(fixture.root()), Vec::new()]);
            if domain.directory == "nested" {
                *runner.outputs.borrow_mut().back_mut().unwrap() = Err("offline domain".into());
            }
            let mut config = config();
            config.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
            let outcome = discover_domain_with_runner(
                &config,
                fixture.project_dyn().as_ref(),
                &DependencyPackLimits::default(),
                None,
                &runner,
                domain,
                None,
                None,
            );
            assert!(
                runner
                    .roots
                    .borrow()
                    .iter()
                    .all(|root| root == &fixture.root().join(&domain.directory))
            );
            let expected = if domain.gowork_path.is_empty() {
                OsString::from("off")
            } else {
                fixture.root().join(&domain.gowork_path).into_os_string()
            };
            assert!(
                runner.invocations.borrow()[0]
                    .env
                    .iter()
                    .any(|(key, value)| key == "GOWORK" && value == &expected)
            );
            if !domain.gowork_path.is_empty() {
                for (_, module) in &domain.modules {
                    assert!(
                        runner.invocations.borrow()[1]
                            .args
                            .contains(&OsString::from(format!("{module}/...")))
                    );
                }
            }
            outcomes.push((domain.directory.clone(), outcome.semantic_packs.complete));
        }
        assert!(
            outcomes
                .iter()
                .any(|(directory, complete)| directory == "nested" && !*complete)
        );
        assert_eq!(
            outcomes.iter().filter(|(_, complete)| *complete).count(),
            3,
            "a failed domain leaves sibling outcomes: {outcomes:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn installed_go_domain_lifecycle_reuses_placement_and_retries_incomplete_domains() {
        use crate::analyzer::go::dependency_packs::{
            GoReconciliationTrigger, reconcile_selected_go_domains,
        };
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::workspace::{
            DependencyPackEcosystem, WorkspaceAnalyzer,
        };
        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use std::collections::BTreeSet;
        use std::os::unix::fs::PermissionsExt;
        let Some(go) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join("go"))
            .find(|path| path.is_file())
        else {
            return;
        };
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/root\n\ngo 1.22\n")
            .file(
                "root.go",
                "package root\nfunc Value() int {return 1}\nfunc caller(){_ = Value()}\n",
            )
            .file("nested/go.mod", "module example.test/nested\n\ngo 1.22\n")
            .file(
                "nested/nested.go",
                "package nested\nfunc Value() int {return 1}\n",
            )
            .build();
        let log = fixture.root().join("go-invocations");
        let quote = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
        let wrapper = fixture.root().join("go-wrapper");
        std::fs::write(&wrapper,format!("#!/bin/sh\nif [ \"$1\" = list ]; then pwd >> {}; if [ -f \"$PWD/fail-list\" ]; then echo forced-offline >&2; exit 1; fi; fi\nexec {} \"$@\"\n",quote(&log),quote(&go))).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AnalyzerConfig::default();
        config.go.dependency_discovery.go_executable = Some(wrapper);
        config.go.dependency_discovery.timeout = Duration::from_secs(30);
        let database = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_persistent(
                &database.path().join("domains.db"),
            )
            .unwrap(),
        );
        let store_context =
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_shared_store(
                fixture.project_dyn().as_ref(),
                store,
                false,
            );
        let mut workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            config.clone(),
            store_context,
        )
        .unwrap();
        let activate = |workspace: &WorkspaceAnalyzer| {
            workspace.resolve_dependency_discovery(
                DependencyPackEcosystem::Go,
                &config,
                &DependencyPackLimits::default(),
                &CancellationToken::new(),
            )
        };
        let clear = || std::fs::write(&log, "").unwrap();
        let runs = || {
            std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        };
        assert!(activate(&workspace).complete);
        assert_eq!(runs().len(), 2, "each initial module invokes Go once");
        let context = |workspace: &WorkspaceAnalyzer, directory: &str| {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT p.context_id,s.profile_digest,p.complete FROM go_context_selections s JOIN go_context_publications p USING(selection_id) WHERE s.domain_dir=?1 AND p.valid_until IS NULL AND s.profile_digest<>?2",
                rusqlite::params![directory,brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile()],
                |row|Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,bool>(2)?))).unwrap()
        };
        let root = context(&workspace, "");
        let nested = context(&workspace, "nested");
        assert_ne!(root.1, nested.1, "module domains have distinct profiles");
        clear();
        fixture
            .file("nested/nested.go")
            .write("package nested\nfunc Value() int {return 2}\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([fixture.file("nested/nested.go")]));
        assert_eq!(
            runs(),
            vec![fixture.root().join("nested")],
            "body edit reruns only its domain"
        );
        assert_eq!(
            context(&workspace, "nested").0,
            nested.0,
            "body edit cuts off placement publication"
        );
        clear();
        fixture
            .file("nested/go.mod")
            .write("module example.test/nested2\n\ngo 1.22\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([fixture.file("nested/go.mod")]));
        assert_eq!(runs(), vec![fixture.root().join("nested")]);
        assert_ne!(
            context(&workspace, "nested").0,
            nested.0,
            "module identity change publishes placement"
        );
        clear();
        let summary = |workspace: &WorkspaceAnalyzer| {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT versions.valid_from FROM resolution_unit_summary_versions versions JOIN resolution_unit_summaries summary USING(summary_id) WHERE versions.lang='go' AND versions.valid_until IS NULL AND versions.profile_digest=?1 LIMIT 1",[&root.1],|row|row.get::<_,i64>(0)).unwrap()
        };
        let previous = summary(&workspace);
        let source =
            "package root\nfunc Value() string {return \"new\"}\nfunc caller(){_ = Value()}\n";
        fixture.file("root.go").write(source).unwrap();
        workspace = workspace.update(&BTreeSet::from([fixture.file("root.go")]));
        assert_eq!(
            context(&workspace, "").0,
            root.0,
            "signature edit leaves placement unchanged"
        );
        assert!(
            summary(&workspace) > previous,
            "changed member blob rolls the summary version despite cutoff"
        );
        let analyzer =
            resolve_analyzer::<crate::analyzer::GoAnalyzer>(workspace.analyzer()).unwrap();
        let value = analyzer
            .declarations(&fixture.file("root.go"))
            .into_iter()
            .find(|unit| unit.identifier() == "Value")
            .unwrap();
        assert!(
            analyzer
                .signature_metadata(&value)
                .iter()
                .any(|metadata| metadata.return_type_text() == Some("string")),
            "{:?}",
            analyzer.signature_metadata(&value)
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut pending = vec![tree.root_node()];
        let mut call = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression" {
                call = node.child_by_field_name("function");
                break;
            }
            pending.extend(node.named_children(&mut node.walk()));
        }
        let call = call.unwrap();
        let site = brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
            path: "root.go".into(),
            text: "Value".into(),
            range: brokk_bifrost_core::analyzer::model::Range {
                start_byte: call.start_byte(),
                end_byte: call.end_byte(),
                start_line: call.start_position().row,
                end_line: call.end_position().row,
            },
            focus_start_byte: call.start_byte(),
            focus_end_byte: call.end_byte(),
        };
        let file = fixture.file("root.go");
        let answer = crate::analyzer::go::native_points::resolve_go_definition_bounded(
            brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: Default::default(),
                cancellation: None,
            },
            || {},
        );
        let brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete {
            value: answer,
            ..
        } = answer
        else {
            panic!("definition request must complete");
        };
        assert_eq!(
            answer.definitions.len(),
            1,
            "usage must see the new definition: {answer:?}"
        );
        assert!(
            analyzer
                .signature_metadata(&answer.definitions[0])
                .iter()
                .any(|metadata| metadata.return_type_text() == Some("string")),
            "{:?}",
            analyzer.signature_metadata(&answer.definitions[0])
        );
        // A request bound before a same-revision replacement must not publish
        // its retained rows as a current or empty answer.
        let mut replacement = discover_go_packages(
            &config.go,
            fixture.project_dyn().as_ref(),
            &DependencyPackLimits::default(),
            None,
        )
        .canonical
        .unwrap();
        replacement.packages[0].incomplete = true;
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::go_package_context::profile_digest(
                &replacement
            )
            .as_slice(),
            root.1,
            "replacement must target the request's profile"
        );
        let store = workspace.store().unwrap();
        let snapshot = analyzer.selected_snapshot_for_test().unwrap();
        let cancellation = CancellationToken::new();
        let brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome::Ready(observation) = store.observe_go_context_inputs(&snapshot, fixture.project_dyn().as_ref(), &cancellation).unwrap() else { panic!("selected inputs") };
        let stale = crate::analyzer::go::native_points::resolve_go_definition_bounded(
            brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: Default::default(),
                cancellation: None,
            },
            || {
                let brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome::Published(replaced) = store.publish_go_package_context(snapshot, fixture.root().to_path_buf(), None, &observation, &observation, replacement, &cancellation).unwrap() else {panic!("replacement must publish")};
                assert_ne!(
                    replaced.context_id, root.0,
                    "replacement must supersede the request's context"
                );
            },
        );
        let brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete {
            value: stale,
            ..
        } = stale
        else {
            panic!("stale request completes with an honest status")
        };
        assert_eq!(stale.status, brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Unavailable, "{stale:?}");
        assert!(
            stale
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "native_stale"),
            "{stale:?}"
        );
        std::fs::write(fixture.root().join("nested/fail-list"), "").unwrap();
        reconcile_selected_go_domains(
            &workspace,
            &config,
            &DependencyPackLimits::default(),
            &CancellationToken::new(),
            GoReconciliationTrigger::ExplicitRefresh,
        )
        .unwrap();
        assert!(
            !context(&workspace, "nested").2,
            "failed domain is published with source inventory"
        );
        std::fs::remove_file(fixture.root().join("nested/fail-list")).unwrap();
        clear();
        assert!(activate(&workspace).complete);
        assert!(
            context(&workspace, "nested").2,
            "next activation retries incomplete output at the SAME revision"
        );
        assert_eq!(
            runs().len(),
            2,
            "root activation plus incomplete sibling retry"
        );
        // A shared receiver request can bind files from several domains.
        // Superseding any of them invalidates even a zero-row result.
        {
            use crate::analyzer::go::native_points::{
                GoNativePointRequest, GoNativePointRequestOpen,
            };
            let analyzer =
                resolve_analyzer::<crate::analyzer::go::GoAnalyzer>(workspace.analyzer()).unwrap();
            let token = CancellationToken::new();
            let GoNativePointRequestOpen::Ready(mut request) =
                GoNativePointRequest::open(analyzer, None, &token).unwrap()
            else {
                panic!("shared point request opens");
            };
            let root_id = request.oracle_for_test("root.go").1;
            let (operation, nested_id) = request.oracle_for_test("nested/nested.go");
            assert_ne!(root_id, nested_id);
            let snapshot = analyzer.selected_snapshot_for_test().unwrap();
            workspace.store().unwrap().conn.execute(move |conn| {
                assert_eq!(conn.execute("UPDATE go_context_publications SET valid_until=?2 WHERE context_id=?1 AND valid_until IS NULL", rusqlite::params![nested_id, snapshot.revision]).unwrap(), 1);
            });
            assert!(matches!(operation.finish_native(Vec::<()>::new(), &brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion::Complete, &token).unwrap(), brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome::Stale(_)), "all bound contexts must still certify the result");
        }
        std::fs::remove_file(fixture.file("go.mod").abs_path()).unwrap();
        workspace = workspace.update(&BTreeSet::from([fixture.file("go.mod")]));
        let no_root = activate(&workspace);
        assert!(
            !no_root.complete,
            "nested-only workspace has no semantic root domain"
        );
        assert!(
            no_root.diagnostics.iter().any(|diagnostic| matches!(
                diagnostic.code.as_str(),
                "go.list_failed" | "go.package_incomplete"
            )),
            "{no_root:?}"
        );
        assert!(
            context(&workspace, "nested").2,
            "nested source context still publishes without semantic root"
        );
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
        config.dependency_discovery.timeout = Duration::from_secs(30);
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

    #[test]
    fn curated_evidence_keeps_only_exact_reachable_modules_without_sources() {
        let temporary = tempfile::tempdir().unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let package_stream = format!(
            "{}\n{}\n{}\n{}\n",
            serde_json::json!({
                "ImportPath": "net",
                "Standard": true,
                "IgnoredGoFiles": ["cgo_linux.go"]
            }),
            serde_json::json!({
                "ImportPath": "example.com/main",
                "Module": { "Path": "example.com/main", "Main": true }
            }),
            serde_json::json!({
                "ImportPath": "github.com/stretchr/testify/require",
                "Module": {
                    "Path": "github.com/stretchr/testify",
                    "Version": "v1.11.1",
                    "Sum": "h1:reviewed"
                }
            }),
            serde_json::json!({
                "ImportPath": "github.com/stretchr/testify/assert",
                "Module": {
                    "Path": "github.com/stretchr/testify",
                    "Version": "v1.11.1",
                    "Sum": "h1:reviewed"
                }
            })
        )
        .into_bytes();
        let runner = FakeRunner::with_outputs([environment(temporary.path()), package_stream]);
        let mut config = config();
        config.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
        let outcome = resolve_with_runner(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );

        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert_eq!(runner.invocations.borrow().len(), 2);
        assert_eq!(outcome.dependencies.len(), 1);
        let dependency = &outcome.dependencies[0];
        assert_eq!(
            dependency.id,
            "go:curated:github.com/stretchr/testify@v1.11.1"
        );
        assert!(dependency.artifacts.is_empty());
        assert_eq!(
            dependency.evidence.module,
            Some(CatalogCoordinate {
                name: "github.com/stretchr/testify".to_owned(),
                version: Some(Version::new(1, 11, 1)),
            })
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|fact| { fact.key == "module.sum" && fact.value == "h1:reviewed" })
        );
    }

    #[test]
    fn curated_evidence_reports_incomplete_workspace_packages() {
        let temporary = tempfile::tempdir().unwrap();
        let project = TestProject::new(temporary.path(), Language::Go);
        let package_stream = serde_json::to_vec(&serde_json::json!({
            "ImportPath": "example.com/main",
            "Incomplete": true,
            "Error": { "Err": "cannot find module providing package example.com/missing" },
            "Module": { "Path": "example.com/main", "Main": true }
        }))
        .unwrap();
        let runner = FakeRunner::with_outputs([environment(temporary.path()), package_stream]);
        let mut config = config();
        config.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
        let outcome = resolve_with_runner(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
            &runner,
        );

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty());
        assert!(outcome.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "go.package_incomplete"
                && diagnostic.message.contains("example.com/missing")
        }));
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
    fn discovery_tracks_workspace_metadata_and_local_replacements() {
        let temporary = tempfile::tempdir().unwrap();
        let main_root = temporary.path().join("main");
        let replacement_root = temporary.path().join("replacement");
        std::fs::create_dir_all(&main_root).unwrap();
        std::fs::create_dir_all(replacement_root.join("pkg")).unwrap();
        let go_mod = main_root.join("go.mod");
        std::fs::write(&go_mod, "module example.com/main\n").unwrap();
        std::fs::write(
            main_root.join("go.sum"),
            "example.com/dep v1.2.3 h1:first\n",
        )
        .unwrap();
        std::fs::write(replacement_root.join("pkg/api.go"), "package pkg").unwrap();
        let package_stream = || {
            format!(
                "{}\n{}\n",
                serde_json::json!({
                    "ImportPath": "example.com/main",
                    "Dir": main_root,
                    "GoFiles": ["main.go"],
                    "Module": {
                        "Path": "example.com/main",
                        "Main": true,
                        "GoMod": go_mod
                    }
                }),
                serde_json::json!({
                    "ImportPath": "example.com/dep/pkg",
                    "Dir": replacement_root.join("pkg"),
                    "GoFiles": ["api.go"],
                    "Module": {
                        "Path": "example.com/dep",
                        "Version": "v1.2.3",
                        "Sum": "h1:exact",
                        "Replace": {
                            "Path": "../replacement",
                            "Dir": replacement_root
                        }
                    }
                })
            )
            .into_bytes()
        };
        let discover = || {
            let runner =
                FakeRunner::with_outputs([environment(temporary.path()), package_stream()]);
            resolve_with_runner(
                &config(),
                &TestProject::new(temporary.path(), Language::Go),
                &DependencyPackLimits::default(),
                None,
                &runner,
            )
        };
        let first = discover();
        assert!(first.complete, "{:?}", first.diagnostics);
        let dependency = &first.dependencies[0];
        let workspace = dependency
            .provenance
            .iter()
            .find(|entry| entry.key == "go.workspace")
            .unwrap()
            .value
            .clone();
        assert!(dependency.provenance.iter().any(|entry| {
            entry.key == "module.replacement" && entry.value == "local:../replacement"
        }));
        let ResolvedDependencyArtifactInput::SourceSet { root, .. } =
            &dependency.artifacts[0].input
        else {
            panic!("expected replacement source set");
        };
        assert_eq!(root, &replacement_root);

        std::fs::write(
            main_root.join("go.sum"),
            "example.com/dep v1.2.3 h1:second\n",
        )
        .unwrap();
        let second = discover();
        assert!(second.complete, "{:?}", second.diagnostics);
        let changed_workspace = second.dependencies[0]
            .provenance
            .iter()
            .find(|entry| entry.key == "go.workspace")
            .unwrap();
        assert_ne!(workspace, changed_workspace.value);
    }
}
