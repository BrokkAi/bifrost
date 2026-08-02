use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use semver::Version;
use serde_json::Value;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    CatalogCoordinate, DependencyArtifactRole, DependencyDiscoveryOutcome,
    DependencyDiscoveryProfile, DependencyPackDiagnostic, DependencyPackDiagnosticSeverity,
    DependencyPackLimits, DependencyProvenance, ExternalArtifactKind, ResolvedDependency,
    ResolvedDependencyArtifact, SemanticModelActivationEvidence,
};
use crate::analyzer::{JsTsDependencyDiscoveryConfig, Project};

#[derive(Debug)]
struct NpmDiagnostic {
    code: &'static str,
    dependency_id: Option<String>,
    location: Option<String>,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeclarationEntry {
    module: String,
    relative_path: PathBuf,
    route: String,
}

/// Resolve exact locally installed npm declaration entry points without adding dependency files
/// to the project's workspace source set.
pub fn resolve_js_ts_semantic_pack_dependencies(
    config: &JsTsDependencyDiscoveryConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    if cancelled(cancellation) {
        return cancelled_outcome();
    }

    let root = project.root();
    let lockfiles = lockfile_candidates(config, root);
    let approved_roots = approved_package_roots(config, root);
    let mut dependencies = Vec::new();
    let mut diagnostics = Vec::new();
    let mut metadata_inputs_considered = 0usize;

    for lockfile in lockfiles {
        if cancelled(cancellation) {
            return cancelled_outcome();
        }
        if !lockfile.is_file() {
            if config
                .lockfile_paths
                .iter()
                .any(|path| resolve(root, path) == lockfile)
            {
                diagnostics.push(NpmDiagnostic {
                    code: "npm.lockfile.missing",
                    dependency_id: None,
                    location: Some(lockfile.display().to_string()),
                    message: "configured npm lockfile does not exist".to_owned(),
                });
            }
            continue;
        }
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
        let lock = match read_json_bounded(&lockfile, config.max_lockfile_bytes) {
            Ok(lock) => lock,
            Err(message) => {
                diagnostics.push(NpmDiagnostic {
                    code: "npm.lockfile.invalid",
                    dependency_id: None,
                    location: Some(lockfile.display().to_string()),
                    message,
                });
                continue;
            }
        };
        let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
            diagnostics.push(NpmDiagnostic {
                code: "npm.lockfile.unsupported",
                dependency_id: None,
                location: Some(lockfile.display().to_string()),
                message: "npm lockfile does not contain an exact installed packages table"
                    .to_owned(),
            });
            continue;
        };
        let mut installed: Vec<_> = packages
            .iter()
            .filter(|(path, _)| !path.is_empty())
            .collect();
        installed.sort_by(|(left, _), (right, _)| left.cmp(right));

        for (lock_path, lock_entry) in installed {
            if cancelled(cancellation) {
                return cancelled_outcome();
            }
            if dependencies.len() >= limits.max_dependencies {
                diagnostics.push(NpmDiagnostic {
                    code: "limit.dependencies",
                    dependency_id: None,
                    location: Some(lockfile.display().to_string()),
                    message: format!(
                        "npm dependency discovery exceeded the configured limit {}",
                        limits.max_dependencies
                    ),
                });
                break;
            }
            metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
            match resolve_locked_package(
                &lockfile,
                lock_path,
                lock_entry,
                &approved_roots,
                config.max_package_manifest_bytes,
            ) {
                Ok(mut resolved) => dependencies.append(&mut resolved),
                Err(diagnostic) => diagnostics.push(diagnostic),
            }
        }
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup_by(|left, right| left.id == right.id);
    let mut suppressed_diagnostics = diagnostics.len().saturating_sub(limits.max_diagnostics);
    diagnostics.truncate(limits.max_diagnostics);
    if dependencies.len() > limits.max_dependencies {
        suppressed_diagnostics =
            suppressed_diagnostics.saturating_add(dependencies.len() - limits.max_dependencies);
        dependencies.truncate(limits.max_dependencies);
    }
    let diagnostics: Vec<_> = diagnostics
        .into_iter()
        .map(|diagnostic| DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: diagnostic.code.to_owned(),
            dependency_id: diagnostic.dependency_id,
            location: diagnostic.location,
            message: bounded_message(diagnostic.message, limits.max_diagnostic_message_bytes),
        })
        .collect();
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
        },
        dependencies,
        complete: diagnostics.is_empty() && suppressed_diagnostics == 0,
        diagnostics,
        suppressed_diagnostics,
        cancelled: false,
    }
}

fn resolve_locked_package(
    lockfile: &Path,
    lock_path: &str,
    lock_entry: &Value,
    approved_roots: &[PathBuf],
    max_manifest_bytes: u64,
) -> Result<Vec<ResolvedDependency>, NpmDiagnostic> {
    let dependency_hint = lock_entry
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let failure = |code, message: String| NpmDiagnostic {
        code,
        dependency_id: dependency_hint.clone(),
        location: Some(lock_path.to_owned()),
        message,
    };
    let Some(relative_package_path) = safe_lock_package_path(lock_path) else {
        return Err(failure(
            "npm.package.path",
            "lockfile package path is not a safe installed node_modules path".to_owned(),
        ));
    };
    let package_path = lockfile
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(relative_package_path);
    let canonical_package = package_path.canonicalize().map_err(|error| {
        failure(
            "npm.package.missing",
            format!("installed package directory is unavailable: {error}"),
        )
    })?;
    if !approved_roots
        .iter()
        .any(|approved| canonical_package.starts_with(approved))
    {
        return Err(failure(
            "npm.package.outside_root",
            "installed package is outside the approved node_modules roots".to_owned(),
        ));
    }

    let manifest_path = canonical_package.join("package.json");
    let manifest = read_json_bounded(&manifest_path, max_manifest_bytes)
        .map_err(|message| failure("npm.package.manifest", message))?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failure("npm.package.identity", "package name is missing".to_owned()))?;
    let version_text = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            failure(
                "npm.package.identity",
                "package version is missing".to_owned(),
            )
        })?;
    let version = Version::parse(version_text).map_err(|_| {
        failure(
            "npm.package.version",
            format!("package version is not exact semantic version evidence: {version_text}"),
        )
    })?;
    let locked_version = lock_entry
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            failure(
                "npm.lockfile.version",
                "lockfile package entry has no exact version".to_owned(),
            )
        })?;
    if locked_version != version_text {
        return Err(failure(
            "npm.package.version_mismatch",
            format!(
                "installed package version {version_text} does not match locked version {locked_version}"
            ),
        ));
    }
    if let Some(locked_name) = lock_entry.get("name").and_then(Value::as_str)
        && locked_name != name
    {
        return Err(failure(
            "npm.package.name_mismatch",
            format!("installed package name {name} does not match locked name {locked_name}"),
        ));
    }

    let entries = declaration_entries(name, &manifest, &canonical_package)
        .map_err(|message| failure("npm.declarations.incomplete", message))?;
    let integrity = lock_entry.get("integrity").and_then(Value::as_str);
    Ok(entries
        .into_iter()
        .map(|entry| {
            let mut provenance = vec![
                DependencyProvenance {
                    key: "lockfile_format".to_owned(),
                    value: "npm-packages-v2".to_owned(),
                },
                DependencyProvenance {
                    key: "lockfile_entry".to_owned(),
                    value: lock_path.to_owned(),
                },
                DependencyProvenance {
                    key: "package".to_owned(),
                    value: name.to_owned(),
                },
                DependencyProvenance {
                    key: "version".to_owned(),
                    value: version_text.to_owned(),
                },
                DependencyProvenance {
                    key: "declaration_route".to_owned(),
                    value: entry.route.clone(),
                },
                DependencyProvenance {
                    key: "declaration_path".to_owned(),
                    value: slash_path(&entry.relative_path),
                },
            ];
            if let Some(integrity) = integrity {
                provenance.push(DependencyProvenance {
                    key: "integrity".to_owned(),
                    value: integrity.to_owned(),
                });
            }
            ResolvedDependency {
                id: format!("npm:{name}@{version_text}:{}", entry.module),
                evidence: SemanticModelActivationEvidence {
                    language: "typescript".to_owned(),
                    ecosystem: "npm".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: name.to_owned(),
                        version: Some(version.clone()),
                    }),
                    module: Some(CatalogCoordinate {
                        name: entry.module,
                        version: None,
                    }),
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                provenance,
                artifacts: vec![
                    ResolvedDependencyArtifact {
                        role: DependencyArtifactRole::Metadata,
                        kind: ExternalArtifactKind::NpmPackageManifest,
                        path: manifest_path.clone(),
                    },
                    ResolvedDependencyArtifact {
                        role: DependencyArtifactRole::Declarations,
                        kind: ExternalArtifactKind::TypeScriptDeclarationFile,
                        path: canonical_package.join(entry.relative_path),
                    },
                ],
            }
        })
        .collect())
}

fn declaration_entries(
    package_name: &str,
    manifest: &Value,
    package_root: &Path,
) -> Result<Vec<DeclarationEntry>, String> {
    let imported_name = declaration_import_name(package_name);
    let mut entries = Vec::new();
    let root_declaration = ["types", "typings"].into_iter().find_map(|field| {
        manifest
            .get(field)
            .and_then(Value::as_str)
            .map(|path| (field, path))
    });
    if let Some((field, path)) = root_declaration {
        entries.push(DeclarationEntry {
            module: imported_name.clone(),
            relative_path: declaration_path(path)?,
            route: field.to_owned(),
        });
    }
    if let Some(exports) = manifest.get("exports") {
        collect_export_entries(
            &imported_name,
            exports,
            root_declaration.is_some(),
            &mut entries,
        )?;
    }
    if entries.is_empty() {
        let conventional = PathBuf::from("index.d.ts");
        if package_root.join(&conventional).is_file() {
            entries.push(DeclarationEntry {
                module: imported_name,
                relative_path: conventional,
                route: "index.d.ts".to_owned(),
            });
        }
    }
    entries.sort();
    entries.dedup_by(|left, right| left.module == right.module);
    if entries.is_empty() {
        return Err("package has no proven declaration entry point".to_owned());
    }
    for entry in &entries {
        let path = package_root.join(&entry.relative_path);
        let canonical = path.canonicalize().map_err(|error| {
            format!(
                "declaration entry {} is unavailable: {error}",
                entry.relative_path.display()
            )
        })?;
        if !canonical.starts_with(package_root) || !canonical.is_file() {
            return Err(format!(
                "declaration entry {} escapes the installed package",
                entry.relative_path.display()
            ));
        }
    }
    Ok(entries)
}

fn collect_export_entries(
    package_name: &str,
    exports: &Value,
    root_already_selected: bool,
    entries: &mut Vec<DeclarationEntry>,
) -> Result<(), String> {
    match exports {
        Value::String(path) if !root_already_selected && is_declaration_path(path) => {
            entries.push(DeclarationEntry {
                module: package_name.to_owned(),
                relative_path: declaration_path(path)?,
                route: "exports:.".to_owned(),
            });
        }
        Value::Object(object) if object.keys().any(|key| key.starts_with('.')) => {
            for (subpath, value) in object {
                if subpath.contains('*') {
                    return Err(format!("wildcard export {subpath} is not exact"));
                }
                if subpath != "." && !subpath.starts_with("./") {
                    return Err(format!("export key {subpath} is not a package subpath"));
                }
                if subpath == "." && root_already_selected {
                    continue;
                }
                if let Some(path) = explicit_types_export(value)? {
                    let module = if subpath == "." {
                        package_name.to_owned()
                    } else {
                        format!("{package_name}/{}", &subpath[2..])
                    };
                    entries.push(DeclarationEntry {
                        module,
                        relative_path: declaration_path(path)?,
                        route: format!("exports:{subpath}"),
                    });
                }
            }
        }
        Value::Object(_) if !root_already_selected => {
            if let Some(path) = explicit_types_export(exports)? {
                entries.push(DeclarationEntry {
                    module: package_name.to_owned(),
                    relative_path: declaration_path(path)?,
                    route: "exports:.".to_owned(),
                });
            }
        }
        Value::Null | Value::String(_) | Value::Object(_) => {}
        _ => return Err("exports declaration routing is not statically supported".to_owned()),
    }
    Ok(())
}

fn explicit_types_export(value: &Value) -> Result<Option<&str>, String> {
    match value {
        Value::String(path) => Ok(is_declaration_path(path).then_some(path.as_str())),
        Value::Object(object) => match object.get("types") {
            Some(Value::String(path)) if is_declaration_path(path) => Ok(Some(path)),
            Some(Value::String(_)) => {
                Err("exports types target is not a declaration file".to_owned())
            }
            Some(_) => Err("exports types condition is ambiguous".to_owned()),
            None => Ok(None),
        },
        Value::Null => Ok(None),
        _ => Err("exports target is not statically supported".to_owned()),
    }
}

fn declaration_path(value: &str) -> Result<PathBuf, String> {
    if !is_declaration_path(value) {
        return Err(format!("declaration target is not a .d.ts file: {value}"));
    }
    let path = Path::new(value.strip_prefix("./").unwrap_or(value));
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "declaration target is not package-relative: {value}"
        ));
    }
    Ok(path.to_path_buf())
}

fn is_declaration_path(value: &str) -> bool {
    value.ends_with(".d.ts") || value.ends_with(".d.mts") || value.ends_with(".d.cts")
}

fn declaration_import_name(package_name: &str) -> String {
    let Some(suffix) = package_name.strip_prefix("@types/") else {
        return package_name.to_owned();
    };
    match suffix.split_once("__") {
        Some((scope, package)) => format!("@{scope}/{package}"),
        None => suffix.to_owned(),
    }
}

fn lockfile_candidates(config: &JsTsDependencyDiscoveryConfig, root: &Path) -> Vec<PathBuf> {
    let mut paths: BTreeSet<_> = config
        .lockfile_paths
        .iter()
        .map(|path| resolve(root, path))
        .collect();
    if config.discover_workspace_lockfiles {
        paths.extend([
            root.join("package-lock.json"),
            root.join("npm-shrinkwrap.json"),
        ]);
    }
    paths.into_iter().collect()
}

fn approved_package_roots(config: &JsTsDependencyDiscoveryConfig, root: &Path) -> Vec<PathBuf> {
    let candidates: Vec<_> = if config.node_modules_roots.is_empty() {
        vec![root.join("node_modules")]
    } else {
        config
            .node_modules_roots
            .iter()
            .map(|path| resolve(root, path))
            .collect()
    };
    candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn safe_lock_package_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !path
            .components()
            .any(|component| component.as_os_str() == "node_modules")
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn read_json_bounded(path: &Path, max_bytes: u64) -> Result<Value, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("could not inspect JSON metadata: {error}"))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "JSON metadata exceeds configured limit {max_bytes}"
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("could not open JSON metadata: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read JSON metadata: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "JSON metadata exceeds configured limit {max_bytes}"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse JSON metadata: {error}"))
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn slash_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn bounded_message(mut message: String, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message;
    }
    let mut end = max_bytes;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message
}

fn cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn cancelled_outcome() -> DependencyDiscoveryOutcome {
    DependencyDiscoveryOutcome {
        dependencies: Vec::new(),
        diagnostics: vec![DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.cancelled".to_owned(),
            dependency_id: None,
            location: None,
            message: "npm dependency discovery was cancelled".to_owned(),
        }],
        complete: false,
        suppressed_diagnostics: 0,
        cancelled: true,
        profile: DependencyDiscoveryProfile::default(),
    }
}
