//! Cargo-only preparation for persisted crate derivation. All state is request-local.
use super::*;

#[derive(Clone, Debug)]
pub struct RustCrateDependency {
    pub extern_name: String,
    pub kind: RustCargoDependencyKind,
    pub manifest_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RustCrateTarget {
    pub manifest_path: PathBuf,
    pub root_path: PathBuf,
    pub kind: RustCallerTargetKind,
    pub name: String,
    pub edition: RustCargoEdition,
    pub cfg_atoms: BTreeSet<String>,
    pub features: BTreeSet<String>,
    pub dependencies: Vec<RustCrateDependency>,
    pub inventory_complete: bool,
}

/// Reuse Cargo's target discovery over an exact path inventory, without loading
/// any source usage facts or compiling a selected resolution context.
///
/// `configuration` is the workspace's Cargo configuration files. Each target
/// takes the cfg set and patches of the levels its Cargo workspace root reads.
/// Placement describes one fixed build per workspace: `cargo tree --workspace`
/// with default features and every target kind (including tests, examples
/// and benches). `default-members` does not narrow it. Normal and development
/// requests unify; resolver-2 host build/proc-macro requests resolve separately.
/// The target platform is Cargo configuration's `build.target` when it is set
/// and the host otherwise; build scripts and proc-macros always use the host.
/// Missing manifests or differing host/target feature sets leave placement
/// incomplete rather than choosing a feature configuration.
pub fn rust_crate_targets(
    paths: impl IntoIterator<Item = (PathBuf, Oid)>,
    manifests: Vec<RustSelectedManifestMount>,
    configuration: &RustCargoConfiguration,
) -> Result<Vec<RustCrateTarget>, String> {
    let input = prepare_rust_selected_topology_input(
        paths.into_iter().map(
            |(relative_path, content_oid)| RustSelectedTopologySourceMount {
                relative_path,
                content_oid,
                facts: RustUsageFacts::default(),
            },
        ),
        manifests,
    )?;
    let inventory = rust_selected_workspace_profiles_from_prepared(&input)?;
    // Cargo's own dependency lookup, `[patch]` and workspace inheritance
    // included, reads manifests by package directory.
    let cargo_manifests = input
        .manifests
        .values()
        .map(|manifest| {
            (
                manifest
                    .relative_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_path_buf(),
                manifest.document.clone(),
            )
        })
        .collect::<CargoHashMap<_, _>>();
    let features = fixed_build_features(&input.manifests, &cargo_manifests, configuration)?;
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cfg_atoms_by_workspace =
        BTreeMap::<(PathBuf, FeaturePlatform), BTreeSet<String>>::new();
    for profile in inventory.profiles {
        if !seen.insert((
            profile.manifest_path.clone(),
            profile.target_kind,
            profile.target_root.clone(),
        )) {
            continue;
        }
        let manifest = &input.manifests[&profile.manifest_path];
        let package = manifest
            .facts
            .package
            .as_ref()
            .expect("target owns a package");
        let RustSelectedBuildOutcome::Ready(edition) =
            effective_cargo_edition(&profile.manifest_path, &input.manifests, &mut |_| true)?
        else {
            unreachable!()
        };
        let kind = profile.target_kind;
        let name = if kind == RustCallerTargetKind::Library {
            package.library_name.clone()
        } else if kind == RustCallerTargetKind::Build {
            "build_script_build".into()
        } else {
            let (table, cargo_kind) = match kind {
                RustCallerTargetKind::Binary => ("bin", RustCargoTargetKind::Binary),
                RustCallerTargetKind::Test => ("test", RustCargoTargetKind::Test),
                RustCallerTargetKind::Example => ("example", RustCargoTargetKind::Example),
                RustCallerTargetKind::Bench => ("bench", RustCargoTargetKind::Bench),
                _ => unreachable!(),
            };
            let explicit = manifest
                .document
                .get(table)
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .find_map(|target| {
                    let name = target.get("name")?.as_str()?;
                    let paths = target
                        .get("path")
                        .and_then(toml::Value::as_str)
                        .map(|path| vec![PathBuf::from(path)])
                        .unwrap_or_else(|| {
                            inferred_cargo_target_paths(cargo_kind, name, &package.package_name)
                        });
                    paths
                        .contains(&profile.target_root)
                        .then(|| normalize_crate_name(name))
                });
            explicit.unwrap_or_else(|| {
                if profile.target_root == Path::new("src/main.rs") {
                    normalize_crate_name(&package.package_name)
                } else {
                    let path = if profile
                        .target_root
                        .file_name()
                        .is_some_and(|name| name == "main.rs")
                    {
                        profile
                            .target_root
                            .parent()
                            .expect("automatic main has a directory")
                    } else {
                        &profile.target_root
                    };
                    normalize_crate_name(
                        path.file_stem()
                            .expect("target has a name")
                            .to_str()
                            .expect("Cargo target is UTF-8"),
                    )
                }
            })
        };
        let mut dependencies: Vec<_> = manifest
            .facts
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency_available(dependency.kind, kind, kind != RustCallerTargetKind::Build)
            })
            .map(|fact| RustCrateDependency {
                extern_name: fact.exposed_name.clone(),
                kind: fact.kind,
                manifest_path: dependency_manifest(
                    &profile.manifest_path,
                    fact,
                    &input.manifests,
                    &cargo_manifests,
                    configuration,
                ),
            })
            .collect();
        if same_package_library_root(&profile, package, &input.sources)?.is_some() {
            dependencies.push(RustCrateDependency {
                extern_name: package.library_name.clone(),
                kind: RustCargoDependencyKind::Normal,
                manifest_path: Some(profile.manifest_path.clone()),
            });
        }
        dependencies.sort_by(|left, right| {
            (&left.extern_name, left.kind).cmp(&(&right.extern_name, right.kind))
        });
        if dependencies.windows(2).any(|pair| {
            pair[0].extern_name == pair[1].extern_name
                && pair[0].manifest_path != pair[1].manifest_path
        }) {
            return Err(format!(
                "conflicting crate dependency routes: {dependencies:?}"
            ));
        }
        dependencies.dedup_by(|left, right| left.extern_name == right.extern_name);
        // Cargo reads its configuration from where the workspace build runs.
        let manifest_directory = profile.manifest_path.parent().unwrap_or(Path::new(""));
        let workspace = cargo_workspace_manifest_directory(
            Path::new(""),
            manifest_directory,
            &manifest.document,
            &cargo_manifests,
        )
        .expect("a target's manifest declares a package");
        let mut cfg_atoms = cfg_atoms_by_workspace
            .entry((
                workspace,
                if kind == RustCallerTargetKind::Build {
                    FeaturePlatform::Host
                } else {
                    manifest_feature_platform(&manifest.document)
                },
            ))
            .or_insert_with_key(|(workspace, platform)| match platform {
                FeaturePlatform::Host => configuration.host_cfg_atoms(workspace),
                FeaturePlatform::Target => configuration.cfg_atoms(workspace),
            })
            .clone();
        if !features[&profile.manifest_path].complete {
            cfg_atoms.insert(crate::cfg::INCOMPLETE_FEATURES_ATOM.to_string());
        }
        targets.push(RustCrateTarget {
            root_path: normalize_selected_path(
                profile.manifest_path.parent().unwrap_or(Path::new("")),
                &profile.target_root,
            )
            .expect("enumerated target is in workspace"),
            manifest_path: profile.manifest_path.clone(),
            kind,
            name,
            edition,
            cfg_atoms,
            features: features[&profile.manifest_path].enabled.clone(),
            dependencies,
            inventory_complete: inventory.target_inventory_complete
                && features[&profile.manifest_path].complete,
        });
    }
    Ok(targets)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FeaturePlatform {
    Target,
    Host,
}

fn manifest_feature_platform(manifest: &RustCargoManifestDocument) -> FeaturePlatform {
    if manifest
        .get("lib")
        .and_then(|lib| lib.get("proc-macro"))
        .and_then(toml::Value::as_bool)
        == Some(true)
    {
        FeaturePlatform::Host
    } else {
        FeaturePlatform::Target
    }
}

#[derive(Default)]
struct FeatureUnit {
    enabled: BTreeSet<String>,
    dependencies: BTreeSet<String>,
}

#[derive(Default)]
struct BuildFeatures {
    enabled: BTreeSet<String>,
    complete: bool,
}

// One inventory request owns these maps. No activation graph survives it.
fn fixed_build_features(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> Result<BTreeMap<PathBuf, BuildFeatures>, String> {
    use crate::cargo_routes::cargo_dependency_tables_with_kind;
    let mut roots = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for (path, manifest) in manifests.iter().filter(|(_, m)| m.facts.package.is_some()) {
        let directory = path.parent().expect("manifest has a directory");
        let workspace = cargo_workspace_manifest_directory(
            Path::new(""),
            directory,
            &manifest.document,
            cargo_manifests,
        )
        .expect("package has a workspace directory");
        let workspace_manifest = &manifests[&workspace.join("Cargo.toml")];
        if !cargo_workspace_claims_package(&workspace, &workspace_manifest.facts, directory) {
            // Retaining an excluded manifest does not include its package in
            // this build. Its own explicit workspace would be a separate root.
            continue;
        }
        let member = directory == workspace
            || workspace_manifest
                .facts
                .workspace_members
                .iter()
                .any(|member| {
                    normalize_selected_path(&workspace, member).is_some_and(|member| {
                        member == directory
                            || member.to_str().is_some_and(|pattern| {
                                glob::Pattern::new(pattern).is_ok_and(|pattern| {
                                    pattern.matches_path_with(
                                        directory,
                                        glob::MatchOptions {
                                            require_literal_separator: true,
                                            ..Default::default()
                                        },
                                    )
                                })
                            })
                    })
                });
        if member {
            roots.entry(workspace).or_default().insert(path.clone());
        }
    }
    // Path dependencies under a workspace root automatically become members,
    // even when optional; an excluded or nested workspace keeps its boundary.
    for (workspace, members) in &mut roots {
        let mut pending: Vec<_> = members.iter().cloned().collect();
        while let Some(path) = pending.pop() {
            let manifest = &manifests[&path];
            for (_, _, table) in cargo_dependency_tables_with_kind(&manifest.document) {
                for (name, value) in table {
                    let Some(target) = inventory_dependency_manifest(
                        &path,
                        name,
                        value,
                        manifests,
                        cargo_manifests,
                        configuration,
                    ) else {
                        continue;
                    };
                    let target_directory = target.parent().expect("manifest has a directory");
                    let target_workspace = cargo_workspace_manifest_directory(
                        Path::new(""),
                        target_directory,
                        &manifests[&target].document,
                        cargo_manifests,
                    )
                    .expect("dependency declares a package");
                    if target_workspace == *workspace
                        && cargo_workspace_claims_package(
                            workspace,
                            &manifests[&workspace.join("Cargo.toml")].facts,
                            target_directory,
                        )
                        && members.insert(target.clone())
                    {
                        pending.push(target);
                    }
                }
            }
        }
    }
    let mut results = BTreeMap::<PathBuf, Vec<BuildFeatures>>::new();
    for (workspace, members) in roots {
        let platform = |path: &Path| manifest_feature_platform(&manifests[path].document);
        let mut units = BTreeMap::<(PathBuf, FeaturePlatform), FeatureUnit>::new();
        for path in &members {
            let unit = units.entry((path.clone(), platform(path))).or_default();
            if manifests[path]
                .document
                .get("features")
                .and_then(|table| table.get("default"))
                .is_some()
            {
                unit.enabled.insert("default".to_string());
            }
        }
        let mut complete = true;
        loop {
            let mut additions = Vec::new();
            for ((path, context), unit) in &units {
                let manifest = &manifests[path];
                let feature_table = manifest
                    .document
                    .get("features")
                    .and_then(toml::Value::as_table);
                let mut enabled_dependencies = unit.dependencies.clone();
                let mut forwarding = Vec::new();
                for feature in &unit.enabled {
                    if let Some(values) = feature_table
                        .and_then(|table| table.get(feature))
                        .and_then(toml::Value::as_array)
                    {
                        for value in values {
                            let value = value
                                .as_str()
                                .ok_or_else(|| format!("invalid feature in {path:?}"))?;
                            if let Some(dependency) = value.strip_prefix("dep:") {
                                enabled_dependencies.insert(dependency.to_string());
                            } else if let Some((dependency, feature)) = value.split_once('/') {
                                let weak = dependency.ends_with('?');
                                let dependency = dependency.trim_end_matches('?');
                                if !weak {
                                    enabled_dependencies.insert(dependency.to_string());
                                    let suppressed = feature_table.is_some_and(|table| {
                                        table
                                            .values()
                                            .filter_map(toml::Value::as_array)
                                            .flatten()
                                            .any(|value| {
                                                value.as_str() == Some(&format!("dep:{dependency}"))
                                            })
                                    });
                                    let optional =
                                        cargo_dependency_tables_with_kind(&manifest.document)
                                            .iter()
                                            .any(|(_, _, table)| {
                                                table.get(dependency).is_some_and(|raw| {
                                                    raw.get("optional")
                                                        .and_then(toml::Value::as_bool)
                                                        == Some(true)
                                                })
                                            });
                                    if optional && !suppressed {
                                        additions.push((
                                            (path.clone(), *context),
                                            Some(dependency.to_string()),
                                            None,
                                        ));
                                    }
                                }
                                forwarding.push((dependency, feature));
                            } else {
                                additions.push((
                                    (path.clone(), *context),
                                    Some(value.to_string()),
                                    None,
                                ));
                            }
                        }
                    } else {
                        // Cargo's implicit optional-dependency feature is absent
                        // when an explicit dep:name reference suppresses it.
                        enabled_dependencies.insert(feature.clone());
                    }
                }
                let mut dependency_tables = Vec::new();
                for (kind, predicate, dependencies) in
                    cargo_dependency_tables_with_kind(&manifest.document)
                {
                    if kind == crate::cargo_routes::RustCargoDependencyKind::Development
                        && (!members.contains(path) || *context != platform(path))
                    {
                        continue;
                    }
                    let selected = predicate.map(|predicate| {
                        if kind == crate::cargo_routes::RustCargoDependencyKind::Build
                            || *context == FeaturePlatform::Host
                        {
                            crate::cargo_config::host_dependency_predicate(predicate)
                        } else {
                            configuration.dependency_predicate(&workspace, predicate)
                        }
                    });
                    match selected {
                        Some(Some(false)) => continue,
                        Some(None) => {
                            complete = false;
                            continue;
                        }
                        _ => dependency_tables.push((kind, dependencies)),
                    }
                }
                let mut normal_dependencies = BTreeSet::new();
                let mut build_dependencies = BTreeSet::new();
                for (kind, dependencies) in &dependency_tables {
                    for (name, raw) in *dependencies {
                        if raw.get("optional").and_then(toml::Value::as_bool) != Some(true) {
                            if *kind == crate::cargo_routes::RustCargoDependencyKind::Build {
                                build_dependencies.insert(name);
                            } else {
                                // Dev requests unify with normal requests, while
                                // a build edge cannot enable an optional normal edge.
                                normal_dependencies.insert(name);
                            }
                        }
                    }
                }
                for name in &enabled_dependencies {
                    additions.push(((path.clone(), *context), None, Some(name.clone())));
                }
                for (kind, dependencies) in dependency_tables {
                    for (name, raw) in dependencies {
                        let nonoptional =
                            if kind == crate::cargo_routes::RustCargoDependencyKind::Build {
                                &build_dependencies
                            } else {
                                &normal_dependencies
                            };
                        if raw.get("optional").and_then(toml::Value::as_bool) == Some(true)
                            && !enabled_dependencies.contains(name)
                            && !nonoptional.contains(name)
                        {
                            continue;
                        }
                        let Some(target) = inventory_dependency_manifest(
                            path,
                            name,
                            raw,
                            manifests,
                            cargo_manifests,
                            configuration,
                        ) else {
                            // An unretained dependency's own requests may enable
                            // features on retained packages. Absence is unproved.
                            complete = false;
                            continue;
                        };
                        let target_platform = if kind
                            == crate::cargo_routes::RustCargoDependencyKind::Build
                            || *context == FeaturePlatform::Host
                        {
                            FeaturePlatform::Host
                        } else {
                            platform(&target)
                        };
                        let key = (target, target_platform);
                        additions.push((key.clone(), None, None));
                        let inherited = cargo_dependency_value(
                            Path::new(""),
                            path.parent().expect("manifest directory"),
                            &manifest.document,
                            name,
                            raw,
                            cargo_manifests,
                        )
                        .map(|(value, _)| value);
                        let sources = [Some(raw), inherited];
                        let defaults = inherited
                            .unwrap_or(raw)
                            .get("default-features")
                            .and_then(toml::Value::as_bool)
                            != Some(false)
                            || (raw.get("workspace").and_then(toml::Value::as_bool) == Some(true)
                                && raw.get("default-features").and_then(toml::Value::as_bool)
                                    == Some(true));
                        if defaults
                            && manifests[&key.0]
                                .document
                                .get("features")
                                .and_then(|table| table.get("default"))
                                .is_some()
                        {
                            additions.push((key.clone(), Some("default".to_string()), None));
                        }
                        for source in sources.into_iter().flatten() {
                            for feature in source
                                .get("features")
                                .and_then(toml::Value::as_array)
                                .into_iter()
                                .flatten()
                            {
                                let feature = feature.as_str().ok_or_else(|| {
                                    format!("invalid dependency feature in {path:?}")
                                })?;
                                additions.push((key.clone(), Some(feature.to_string()), None));
                            }
                        }
                        for (dependency, feature) in &forwarding {
                            if *dependency == name {
                                additions.push((key.clone(), Some(feature.to_string()), None));
                            }
                        }
                    }
                }
            }
            let mut changed = false;
            for (key, feature, dependency) in additions {
                changed |= !units.contains_key(&key);
                let unit = units.entry(key).or_default();
                if let Some(feature) = feature {
                    changed |= unit.enabled.insert(feature);
                }
                if let Some(dependency) = dependency {
                    changed |= unit.dependencies.insert(dependency);
                }
            }
            if !changed {
                break;
            }
        }
        for ((path, _), unit) in units {
            results.entry(path).or_default().push(BuildFeatures {
                enabled: unit.enabled,
                complete,
            });
        }
    }
    Ok(manifests
        .iter()
        .filter(|(_, m)| m.facts.package.is_some())
        .map(|(path, _)| {
            let configurations = results.remove(path).unwrap_or_default();
            let enabled = configurations
                .iter()
                .map(|features| features.enabled.clone())
                .reduce(|left, right| left.intersection(&right).cloned().collect())
                .unwrap_or_default();
            let complete = !configurations.is_empty()
                && configurations
                    .iter()
                    .all(|features| features.complete && features.enabled == enabled);
            (path.clone(), BuildFeatures { enabled, complete })
        })
        .collect())
}

fn inventory_dependency_manifest(
    path: &Path,
    name: &str,
    value: &toml::Value,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> Option<PathBuf> {
    let directory = cargo_dependency_directory_with(
        Path::new(""),
        path.parent().expect("manifest directory"),
        &manifests[path].document,
        name,
        value,
        cargo_manifests,
        configuration,
        &mut normalize_selected_path,
    )?;
    let target = directory.join("Cargo.toml");
    manifests
        .get(&target)
        .filter(|manifest| manifest.facts.package.is_some())
        .map(|_| target)
}

/// The workspace manifest a dependency resolves to, by the same lookup the
/// selected context uses: a `path`, a `workspace = true` entry, or a
/// `[patch]` on the workspace manifest or in its Cargo configuration whose
/// package version satisfies the dependency's requirement.
fn dependency_manifest(
    path: &Path,
    dependency: &RustCargoDependencyFact,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> Option<PathBuf> {
    let manifest = manifests.get(path)?;
    let table = match dependency.kind {
        RustCargoDependencyKind::Normal => "dependencies",
        RustCargoDependencyKind::Development => "dev-dependencies",
        RustCargoDependencyKind::Build => "build-dependencies",
    };
    let raw_dependency = manifest
        .document
        .get(table)?
        .get(&dependency.manifest_name)?;
    inventory_dependency_manifest(
        path,
        &dependency.manifest_name,
        raw_dependency,
        manifests,
        cargo_manifests,
        configuration,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    /// A registry dependency that the workspace manifest patches to a member
    /// with a matching version is that member, as Cargo builds it; a patch
    /// whose version does not satisfy the requirement leaves it external.
    #[test]
    #[hardwon(
        "5f781c22c33c: Version-compatible workspace patch facts link a registry requirement to a member while an incompatible version stays external."
    )]
    fn crate_inventory_follows_a_workspace_patch_to_a_member() {
        for (requirement, patched) in [("0.1.0", true), ("2", false)] {
            let manifests = vec![
                RustSelectedManifestMount::from_source(
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"a\",\"b\"]\n[patch.crates-io]\nb={path=\"b\"}\n",
                )
                .unwrap(),
                RustSelectedManifestMount::from_source(
                    "a/Cargo.toml",
                    &format!(
                        "[package]\nname=\"a\"\nedition=\"2021\"\n[dependencies]\nb=\"{requirement}\"\n"
                    ),
                )
                .unwrap(),
                RustSelectedManifestMount::from_source(
                    "b/Cargo.toml",
                    "[package]\nname=\"b\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
                )
                .unwrap(),
            ];
            let targets = rust_crate_targets(
                ["a/src/lib.rs", "b/src/lib.rs"]
                    .into_iter()
                    .map(|path| (PathBuf::from(path), Oid::zero())),
                manifests,
                &RustCargoConfiguration::default(),
            )
            .unwrap();
            let a = targets
                .iter()
                .find(|target| target.manifest_path == Path::new("a/Cargo.toml"))
                .expect("a has a library target");
            let routes = a
                .dependencies
                .iter()
                .map(|dependency| {
                    (
                        dependency.extern_name.as_str(),
                        dependency.manifest_path.as_deref(),
                    )
                })
                .collect::<Vec<_>>();
            let expected = patched.then_some(Path::new("b/Cargo.toml"));
            assert_eq!(routes, vec![("b", expected)], "{requirement}: {a:?}");
        }
    }

    #[test]
    #[hardwon(
        "3dc93c95f31f: quicksilver round 3 on brokk-bifrost-rust: patched package version omitted from topology identity"
    )]
    fn patch_version_route_changes_require_a_new_topology_identity() {
        for inherited in [false, true] {
            let evaluate = |version: &str| {
                let workspace = format!(
                    "[workspace]\nmembers=[\"a\",\"b\"]\n[workspace.package]\nversion=\"{version}\"\n[patch.crates-io]\nb={{path=\"b\"}}\n"
                );
                let package_version = if inherited {
                    "version.workspace=true".to_string()
                } else {
                    format!("version=\"{version}\"")
                };
                let manifests = vec![
                    RustSelectedManifestMount::from_source("Cargo.toml", &workspace).unwrap(),
                    RustSelectedManifestMount::from_source(
                        "a/Cargo.toml",
                        "[package]\nname=\"a\"\nedition=\"2021\"\n[dependencies]\nb=\"0.1\"\n",
                    )
                    .unwrap(),
                    RustSelectedManifestMount::from_source(
                        "b/Cargo.toml",
                        &format!("[package]\nname=\"b\"\nedition=\"2021\"\n{package_version}\n"),
                    )
                    .unwrap(),
                ];
                let identity = manifests
                    .iter()
                    .map(|m| m.document.topology_digest())
                    .collect::<Vec<_>>();
                let targets = rust_crate_targets(
                    ["a/src/lib.rs", "b/src/lib.rs"]
                        .into_iter()
                        .map(|p| (PathBuf::from(p), Oid::zero())),
                    manifests,
                    &RustCargoConfiguration::default(),
                )
                .unwrap();
                let a = targets.iter().find(|t| t.name == "a").unwrap();
                (identity, a.dependencies[0].manifest_path.clone())
            };
            let (compatible_identity, compatible_route) = evaluate("0.1.0");
            let (incompatible_identity, incompatible_route) = evaluate("2.0.0");
            assert_eq!(compatible_route, Some(PathBuf::from("b/Cargo.toml")));
            assert_eq!(incompatible_route, None);
            assert_ne!(
                compatible_identity, incompatible_identity,
                "inherited={inherited}"
            );
        }
    }

    #[test]
    #[hardwon(
        "3dc93c95f31f: quicksilver round 3 on brokk-bifrost-rust: weak dependency feature propagated unconditionally"
    )]
    fn crate_inventory_weak_feature_requires_an_enabled_optional_dependency() {
        // Cargo's feature graph, including weak edges and dev unification.
        // The rows follow pinned Cargo 1.99.1 feature graphs.
        for (label, a_features, extra, expected_b) in [
            ("weak off", "default=[\"b?/on\"]", "", false),
            ("nonoptional edge", "default=[\"b?/on\"]", "", true),
            (
                "enabled by feature",
                "default=[\"enable\",\"b?/on\"]\nenable=[\"dep:b\"]",
                "",
                true,
            ),
            (
                "enabled by dev edge",
                "default=[\"b?/on\"]",
                "[dev-dependencies]\nb={path=\"../b\"}",
                true,
            ),
            ("non-default off", "extra=[\"b/on\"]", "", false),
            ("strong forwarding", "default=[\"b/on\"]", "", true),
            ("implicit activation", "default=[\"b\",\"b?/on\"]", "", true),
            (
                "normal edge",
                "default=[\"b?/on\"]",
                "[dev-dependencies]\nb={path=\"../b\",features=[\"other\"]}",
                true,
            ),
        ] {
            let optional = label != "nonoptional edge";
            let manifests = vec![
                RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nresolver=\"2\"\nmembers=[\"a\",\"b\"]\ndefault-members=[\"a\"]\n").unwrap(),
                RustSelectedManifestMount::from_source("a/Cargo.toml", &format!("[package]\nname=\"a\"\nedition=\"2021\"\n[dependencies]\nb={{path=\"../b\",optional={optional}}}\n[features]\n{a_features}\n{extra}\n")).unwrap(),
                RustSelectedManifestMount::from_source("b/Cargo.toml", "[package]\nname=\"b\"\nedition=\"2021\"\n[features]\non=[]\nother=[]\n").unwrap(),
            ];
            let targets = rust_crate_targets(
                ["a/src/lib.rs", "b/src/lib.rs"]
                    .into_iter()
                    .map(|p| (PathBuf::from(p), Oid::zero())),
                manifests,
                &RustCargoConfiguration::default(),
            )
            .unwrap();
            let b = targets.iter().find(|t| t.name == "b").unwrap();
            assert_eq!(
                b.features.contains("on"),
                expected_b,
                "{label}: {targets:?}"
            );
            assert!(b.inventory_complete, "{label}: {targets:?}");
            if label == "normal edge" {
                assert!(b.features.contains("other"), "{targets:?}");
            }
            let a = targets.iter().find(|t| t.name == "a").unwrap();
            if label == "strong forwarding" || label == "implicit activation" {
                assert!(a.features.contains("b"), "{label}: {targets:?}");
            } else if label == "enabled by feature" {
                assert!(
                    !a.features.contains("b"),
                    "dep:b suppresses the implicit feature: {targets:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon("#6846: defaults and host-only requests leaked into fixed-build placement")]
    fn crate_inventory_fixed_build_activation_boundaries() {
        for (label, dependency, b_features, b_library, expected, complete) in [
            (
                "excluded optional",
                "[dependencies]\nb={path=\"../b\",optional=true}",
                "default=[\"on\"]\non=[]",
                "",
                false,
                false,
            ),
            (
                "excluded enabled without defaults",
                "[dependencies]\nb={path=\"../b\",default-features=false}",
                "default=[\"on\"]\non=[]",
                "",
                false,
                true,
            ),
            (
                "excluded enabled defaults",
                "[dependencies]\nb={path=\"../b\"}",
                "default=[\"on\"]\non=[]",
                "",
                true,
                true,
            ),
            (
                "build-only feature",
                "[dependencies]\nb={path=\"../b\",default-features=false}\n[build-dependencies]\nb={path=\"../b\",features=[\"on\"]}",
                "on=[]",
                "",
                false,
                false,
            ),
            (
                "proc macro",
                "[dependencies]\nb={path=\"../b\",features=[\"on\"]}",
                "on=[]",
                "[lib]\nproc-macro=true",
                true,
                true,
            ),
            (
                "missing external graph",
                "[dependencies]\nb={path=\"../b\"}\nexternal={path=\"../external\"}",
                "on=[]",
                "",
                false,
                false,
            ),
        ] {
            let manifests = vec![
                RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nresolver=\"2\"\nmembers=[\"a\"]\nexclude=[\"b\"]\n").unwrap(),
                RustSelectedManifestMount::from_source("a/Cargo.toml", &format!("[package]\nname=\"a\"\nedition=\"2021\"\n{dependency}\n")).unwrap(),
                RustSelectedManifestMount::from_source("b/Cargo.toml", &format!("[package]\nname=\"b\"\nedition=\"2021\"\n{b_library}\n[features]\n{b_features}\n")).unwrap(),
            ];
            let targets = rust_crate_targets(
                ["a/src/lib.rs", "a/build.rs", "b/src/lib.rs"]
                    .into_iter()
                    .map(|p| (PathBuf::from(p), Oid::zero())),
                manifests,
                &RustCargoConfiguration::default(),
            )
            .unwrap();
            let b = targets.iter().find(|t| t.name == "b").unwrap();
            assert_eq!(b.features.contains("on"), expected, "{label}: {targets:?}");
            assert_eq!(b.inventory_complete, complete, "{label}: {targets:?}");
            let condition = RustCfgCondition::Expression(
                vec![
                    brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction::KeyValue {
                        key: "feature".into(),
                        value: "on".into(),
                    },
                ]
                .into_boxed_slice(),
            );
            let mut atoms = b.cfg_atoms.clone();
            atoms.extend(
                b.features
                    .iter()
                    .map(|feature| format!("feature = {feature:?}")),
            );
            let activation = crate::cfg::crate_activation(&atoms, &condition);
            assert_eq!(
                crate::cfg::crate_activation(
                    &atoms,
                    &RustCfgCondition::Atom("feature = \"on\"".into())
                ),
                activation,
                "{label}: compact atom activation"
            );
            let (site_activation, assumed, assignment) =
                crate::cfg::crate_site_cfg_activation(&atoms, &condition);
            let unknown = activation == RustSelectedActivation::Unknown;
            assert_eq!(
                site_activation,
                if unknown {
                    RustSelectedActivation::Active
                } else {
                    activation
                },
                "{label}: site activation chooses a satisfying assignment"
            );
            assert_eq!(assumed, unknown, "{label}: site assumption");
            assert_eq!(assignment.is_some(), unknown, "{label}: site assignment");
            assert_eq!(
                crate::cfg::crate_activation_under_site_cfg(
                    &atoms,
                    &condition,
                    assignment.as_ref()
                ),
                site_activation,
                "{label}: candidate under the site's assignment"
            );
            assert_eq!(
                crate::cfg::crate_activation_under_site_cfg(&atoms, &condition, None),
                activation,
                "{label}: candidate activation"
            );
            assert_eq!(
                activation,
                if expected {
                    RustSelectedActivation::Active
                } else if complete {
                    RustSelectedActivation::Inactive
                } else {
                    RustSelectedActivation::Unknown
                },
                "{label}"
            );
        }
    }

    #[test]
    fn crate_inventory_uses_test_dependencies_and_same_package_library() {
        let manifests = vec![
            RustSelectedManifestMount::from_source(
                "Cargo.toml",
                "[workspace]\nmembers=[\"a\",\"b\"]\n",
            )
            .unwrap(),
            RustSelectedManifestMount::from_source(
                "a/Cargo.toml",
                "[package]\nname=\"a\"\nedition=\"2021\"\n[dev-dependencies]\nb={path=\"../b\"}\n",
            )
            .unwrap(),
            RustSelectedManifestMount::from_source(
                "b/Cargo.toml",
                "[package]\nname=\"b\"\nedition=\"2021\"\n",
            )
            .unwrap(),
        ];
        let targets = rust_crate_targets(
            [
                "a/src/lib.rs",
                "a/src/main.rs",
                "a/tests/x.rs",
                "b/src/lib.rs",
            ]
            .into_iter()
            .map(|path| (PathBuf::from(path), Oid::zero())),
            manifests,
            &RustCargoConfiguration::default(),
        )
        .unwrap();
        assert_eq!(targets.len(), 4);
        for target in targets
            .iter()
            .filter(|target| target.manifest_path == Path::new("a/Cargo.toml"))
        {
            let dependencies = target
                .dependencies
                .iter()
                .map(|dependency| (dependency.extern_name.as_str(), dependency.kind))
                .collect::<Vec<_>>();
            let mut expected = vec![("b", RustCargoDependencyKind::Development)];
            if target.kind != RustCallerTargetKind::Library {
                expected.insert(0, ("a", RustCargoDependencyKind::Normal));
            }
            assert_eq!(dependencies, expected, "{target:?}");
        }
    }

    /// A registry dependency that the workspace manifest patches to a member
    /// with a matching version is that member, as Cargo builds it; a patch
    /// whose version does not satisfy the requirement leaves it external.

    #[test]
    fn crate_inventory_follows_cargo_configuration_patches_and_cfg() {
        let manifests = vec![
            RustSelectedManifestMount::from_source(
                "ws/Cargo.toml",
                "[workspace]\nmembers=[\"a\",\"b\"]\n",
            )
            .unwrap(),
            RustSelectedManifestMount::from_source(
                "ws/a/Cargo.toml",
                "[package]\nname=\"a\"\nedition=\"2021\"\n[dependencies]\nb=\"0.1\"\n",
            )
            .unwrap(),
            RustSelectedManifestMount::from_source(
                "ws/b/Cargo.toml",
                "[package]\nname=\"b\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .unwrap(),
        ];
        let configuration = |source: &str| {
            RustCargoConfiguration::from_files([(
                PathBuf::from("ws/.cargo/config.toml"),
                crate::cargo_config::RustCargoConfigDocument::from_source_bytes(source.as_bytes())
                    .unwrap(),
            )])
        };
        let targets = |configuration: &RustCargoConfiguration| {
            rust_crate_targets(
                ["ws/a/src/lib.rs", "ws/b/src/lib.rs"]
                    .into_iter()
                    .map(|path| (PathBuf::from(path), Oid::zero())),
                manifests.clone(),
                configuration,
            )
            .unwrap()
        };
        let route = |targets: &[RustCrateTarget]| {
            let a = targets
                .iter()
                .find(|target| target.manifest_path == Path::new("ws/a/Cargo.toml"))
                .expect("a has a library target");
            a.dependencies[0].manifest_path.clone()
        };

        let unconfigured = targets(&RustCargoConfiguration::default());
        assert_eq!(route(&unconfigured), None, "b stays a registry dependency");
        assert!(
            unconfigured
                .iter()
                .all(|target| !target.cfg_atoms.contains("fast"))
        );

        let configured = targets(&configuration(
            "[build]\ntarget = \"wasm32-unknown-unknown\"\nrustflags = [\"--cfg\", \"fast\"]\n\
             [patch.crates-io]\nb = { path = \"b\" }\n",
        ));
        assert_eq!(route(&configured), Some(PathBuf::from("ws/b/Cargo.toml")));
        for target in &configured {
            assert!(target.cfg_atoms.contains("fast"), "{target:?}");
            assert!(
                target.cfg_atoms.contains("target_arch = \"wasm32\""),
                "{target:?}"
            );
            assert!(!target.cfg_atoms.contains("unix"), "{target:?}");
        }
    }

    #[test]
    fn crate_inventory_unifies_features_and_has_one_row_per_target() {
        let manifests = vec![
            RustSelectedManifestMount::from_source("Cargo.toml", "[workspace]\nmembers = [\"a\", \"b\"]\n").unwrap(),
            RustSelectedManifestMount::from_source("a/Cargo.toml", "[package]\nname = \"a\"\nedition = \"2021\"\n[dependencies]\nb = { path = \"../b\", features = [\"on\"] }\n[[bin]]\nname = \"special\"\npath = \"src/entry.rs\"\n").unwrap(),
            RustSelectedManifestMount::from_source("b/Cargo.toml", "[package]\nname = \"b\"\nedition = \"2021\"\n[features]\ndefault = [\"base\"]\nbase = []\non = [\"transitive\"]\ntransitive = []\n").unwrap(),
        ];
        let targets = rust_crate_targets(
            [
                "a/src/lib.rs",
                "a/src/entry.rs",
                "a/tests/x.rs",
                "b/src/lib.rs",
            ]
            .into_iter()
            .map(|path| (PathBuf::from(path), Oid::zero())),
            manifests,
            &RustCargoConfiguration::default(),
        )
        .unwrap();
        assert_eq!(targets.len(), 4, "{targets:?}");
        assert!(
            targets
                .iter()
                .any(|target| target.name == "special"
                    && target.kind == RustCallerTargetKind::Binary),
            "{targets:?}"
        );
        let b = targets.iter().find(|target| target.name == "b").unwrap();
        assert_eq!(
            b.features,
            BTreeSet::from([
                "default".into(),
                "base".into(),
                "on".into(),
                "transitive".into()
            ])
        );
        assert!(b.cfg_atoms.contains("test"));
    }
}
