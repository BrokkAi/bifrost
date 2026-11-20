//! Cargo-only preparation for persisted crate derivation. All state is request-local.
use super::*;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct RustCrateDependency {
    pub extern_name: String,
    pub kind: RustCargoDependencyKind,
    pub manifest_path: Option<PathBuf>,
}

/// A local dev edge omitted to keep the target graph acyclic. This affects
/// only test-cfg lookups that need this extern name, never target completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevDependencyCycleEdgeDropped {
    pub from_manifest: PathBuf,
    pub to_manifest: PathBuf,
    pub extern_name: String,
}

/// Discovery's independent feature output for one directly consumed package.
#[derive(Clone, Debug)]
pub struct RustFeatureActivation {
    pub manifest_path: PathBuf,
    pub features: BTreeSet<String>,
    pub complete: bool,
}

#[derive(Clone, Debug)]
pub struct RustCrateTarget {
    pub manifest_path: PathBuf,
    /// Workspace-relative when normalized_root is available; otherwise the declared unavailable path.
    pub root_path: PathBuf,
    pub root_unavailable: Option<RustUnavailableTargetRoot>,
    pub kind: RustCallerTargetKind,
    pub name: String,
    pub edition: RustCargoEdition,
    pub cfg_atoms: BTreeSet<String>,
    pub features: BTreeSet<String>,
    /// Whether discovery established the feature activation independently of target inventory.
    pub features_complete: bool,
    pub feature_projection: Vec<RustFeatureActivation>,
    pub configuration_directory: PathBuf,
    pub dependencies: Vec<RustCrateDependency>,
    pub dropped_dev_dependencies: Vec<DevDependencyCycleEdgeDropped>,
    pub inventory_complete: bool,
    pub inventory_error: Option<String>,
}

/// Reuse Cargo's target discovery over an exact path inventory, without loading
/// any source usage facts or compiling a selected resolution context.
///
/// `configuration` is the workspace's Cargo configuration files. Each target
/// takes the cfg set and patches of the levels its Cargo workspace root reads.
/// Placement describes one fixed build per workspace: `cargo tree --workspace`
/// with all member features and every target kind (including tests, examples
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
    let source_paths = input.sources.keys().cloned().collect();
    // Share the directory index with feature placement and all context folds.
    let cargo_manifests = super::target_discovery::cargo_manifest_documents(&input.manifests);
    let discovery_complete = super::broad_discovery::manifest_discovery_completeness(
        &input.manifests,
        &source_paths,
        configuration,
        &cargo_manifests,
    );
    let features = fixed_build_features(&input.manifests, &cargo_manifests, configuration)?;
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();
    let library_manifests: HashSet<_> = inventory
        .profiles
        .iter()
        .filter(|profile| profile.target_kind == RustCallerTargetKind::Library)
        .map(|profile| profile.manifest_path.clone())
        .chain(
            inventory
                .unavailable_roots
                .iter()
                .filter(|root| root.target_kind == RustCallerTargetKind::Library)
                .map(|root| root.manifest_path.clone()),
        )
        .collect();
    let unavailable = inventory.unavailable_roots;
    let profiles = inventory
        .profiles
        .into_vec()
        .into_iter()
        .map(|profile| (profile, None));
    let rejected = unavailable.into_iter().map(|gap| {
        let profile = default_workspace_profile(
            &gap.manifest_path,
            gap.target_kind,
            gap.declared_root.clone(),
            false,
        );
        (profile, Some(gap))
    });
    for (profile, root_unavailable) in profiles.chain(rejected) {
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
        let mut dependencies = configuration_dependencies(
            &profile.manifest_path,
            kind,
            &input.manifests,
            &cargo_manifests,
            configuration,
        );
        if has_same_package_library_dependency(kind, package)
            && library_manifests.contains(&profile.manifest_path)
        {
            dependencies.push(RustCrateDependency {
                extern_name: package.library_name.clone(),
                kind: RustCargoDependencyKind::Normal,
                manifest_path: Some(profile.manifest_path.clone()),
            });
        }
        dependencies.sort_by(|left, right| {
            (&left.extern_name, left.kind).cmp(&(&right.extern_name, right.kind))
        });
        let conflicts: BTreeSet<_> = dependencies
            .windows(2)
            .filter(|pair| {
                pair[0].extern_name == pair[1].extern_name
                    && pair[0].manifest_path != pair[1].manifest_path
            })
            .map(|pair| pair[0].extern_name.clone())
            .collect();
        dependencies.retain(|dependency| !conflicts.contains(&dependency.extern_name));
        // Rows are keyed by extern name. Normal sorts before development and
        // already grants every non-build target that can use the dev route.
        dependencies.dedup_by(|left, right| left.extern_name == right.extern_name);
        let (cfg_atoms, configuration_directory) = configuration_atoms(
            &profile.manifest_path,
            kind,
            &input.manifests,
            &cargo_manifests,
            configuration,
            &features,
        );
        // Only direct activations belong here. Further effects flow through
        // the direct dependency's consumed summary output, with early cutoff.
        let mut projected_paths = BTreeSet::from([profile.manifest_path.clone()]);
        projected_paths.extend(
            dependencies
                .iter()
                .filter_map(|dependency| dependency.manifest_path.clone()),
        );
        let feature_projection = projected_paths
            .into_iter()
            .map(|path| {
                let activation = &features[&path];
                RustFeatureActivation {
                    manifest_path: path,
                    features: activation.enabled.clone(),
                    complete: activation.complete,
                }
            })
            .collect();
        targets.push(RustCrateTarget {
            root_path: root_unavailable.as_ref().map_or_else(
                || {
                    normalize_selected_path(
                        profile.manifest_path.parent().unwrap_or(Path::new("")),
                        &profile.target_root,
                    )
                    .expect("enumerated target is in workspace")
                },
                |gap| {
                    gap.normalized_root
                        .clone()
                        .unwrap_or_else(|| gap.declared_root.clone())
                },
            ),
            root_unavailable,
            manifest_path: profile.manifest_path.clone(),
            kind,
            name,
            edition,
            cfg_atoms,
            features: features[&profile.manifest_path].enabled.clone(),
            features_complete: features[&profile.manifest_path].complete,
            feature_projection,
            configuration_directory,
            dependencies,
            dropped_dev_dependencies: Vec::new(),
            inventory_error: (!conflicts.is_empty())
                .then(|| format!("conflicting target-specific destinations for {conflicts:?}")),
            inventory_complete: conflicts.is_empty()
                && discovery_complete[&profile.manifest_path]
                && features[&profile.manifest_path].inventory_complete,
        });
    }
    reject_cyclic_dev_dependencies(&mut targets, &input.manifests);
    Ok(targets)
}

/// Configuration facts for an already selected target. This does not discover targets or read sources.
#[derive(Clone, Debug)]
pub struct RustTargetConfiguration {
    pub cfg_atoms: BTreeSet<String>,
    pub features: BTreeSet<String>,
    pub edition: RustCargoEdition,
    pub extern_names: BTreeSet<String>,
    pub rustflags_extern: bool,
    pub complete: bool,
}

fn reject_cyclic_dev_dependencies(
    targets: &mut [RustCrateTarget],
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
) {
    let libraries: std::collections::HashMap<_, _> = targets
        .iter()
        .enumerate()
        .filter(|(_, target)| target.kind == RustCallerTargetKind::Library)
        .map(|(id, target)| (target.manifest_path.clone(), id))
        .collect();
    let mut edges = vec![Vec::new(); targets.len()];
    let mut development = Vec::new();
    for (owner, target) in targets.iter().enumerate() {
        for (ordinal, dependency) in target.dependencies.iter().enumerate() {
            let Some(to) = dependency
                .manifest_path
                .as_ref()
                .and_then(|path| libraries.get(path))
                .copied()
            else {
                continue;
            };
            if dependency.kind == RustCargoDependencyKind::Development {
                development.push((owner, ordinal, to));
            } else {
                edges[owner].push(to);
            }
        }
    }
    // Cargo package identity, then target identity and extern name, determine
    // which dev edge is retained. Neither discovery nor hash iteration decides.
    development.sort_by(
        |&(left, left_edge, left_to), &(right, right_edge, right_to)| {
            let identity = |id: usize| {
                let target = &targets[id];
                (
                    &target.manifest_path,
                    &manifests[&target.manifest_path]
                        .facts
                        .package
                        .as_ref()
                        .expect("target owns a package")
                        .package_name,
                    &target.name,
                    target.kind,
                    &target.root_path,
                )
            };
            (
                identity(left),
                identity(left_to),
                &targets[left].dependencies[left_edge].extern_name,
            )
                .cmp(&(
                    identity(right),
                    identity(right_to),
                    &targets[right].dependencies[right_edge].extern_name,
                ))
        },
    );
    let mut dropped = HashSet::new();
    for (owner, ordinal, to) in development {
        let mut stack = vec![to];
        let mut seen = HashSet::new();
        let mut cyclic = false;
        while let Some(next) = stack.pop() {
            if next == owner {
                cyclic = true;
                break;
            }
            if seen.insert(next) {
                stack.extend(edges[next].iter().copied());
            }
        }
        if cyclic {
            targets[owner]
                .dropped_dev_dependencies
                .push(DevDependencyCycleEdgeDropped {
                    from_manifest: targets[owner].manifest_path.clone(),
                    to_manifest: targets[to].manifest_path.clone(),
                    extern_name: targets[owner].dependencies[ordinal].extern_name.clone(),
                });
            dropped.insert((owner, ordinal));
        } else {
            edges[owner].push(to);
        }
    }
    for (owner, target) in targets.iter_mut().enumerate() {
        let mut ordinal = 0;
        target.dependencies.retain(|_| {
            let keep = !dropped.contains(&(owner, ordinal));
            ordinal += 1;
            keep
        });
    }
}

pub fn rust_target_configuration(
    manifest_path: &Path,
    kind: RustCallerTargetKind,
    manifests: Vec<RustSelectedManifestMount>,
    configuration: &RustCargoConfiguration,
) -> Result<RustTargetConfiguration, String> {
    let manifests = manifests
        .into_iter()
        .map(|m| (m.relative_path.clone(), m))
        .collect::<BTreeMap<_, _>>();
    if !manifests.contains_key(manifest_path) {
        return Err(format!("missing manifest {manifest_path:?}"));
    }
    let cargo_manifests = manifests
        .values()
        .map(|m| {
            (
                m.relative_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_path_buf(),
                m.document.clone(),
            )
        })
        .collect::<CargoHashMap<_, _>>();
    let features = fixed_build_features(&manifests, &cargo_manifests, configuration)?;
    let (cfg_atoms, workspace) = configuration_atoms(
        manifest_path,
        kind,
        &manifests,
        &cargo_manifests,
        configuration,
        &features,
    );
    let RustSelectedBuildOutcome::Ready(edition) =
        effective_cargo_edition(manifest_path, &manifests, &mut |_| true)?
    else {
        unreachable!()
    };
    let mut extern_names: BTreeSet<_> = configuration_dependencies(
        manifest_path,
        kind,
        &manifests,
        &cargo_manifests,
        configuration,
    )
    .into_iter()
    .map(|d| d.extern_name)
    .collect();
    // The parsed package fact owns Cargo's [lib].name / normalized package-name
    // rule, also used above by the membership-proved same-package library edge.
    // Configuration cannot discover src/lib.rs, so every non-library target
    // conservatively treats that name as a potential extern.
    if kind != RustCallerTargetKind::Library {
        let package = manifests[manifest_path]
            .facts
            .package
            .as_ref()
            .ok_or_else(|| format!("target manifest has no package: {manifest_path:?}"))?;
        extern_names.insert(package.library_name.clone());
    }
    Ok(RustTargetConfiguration {
        cfg_atoms: merge_rust_configuration_atoms(&cfg_atoms, &features[manifest_path].enabled),
        features: features[manifest_path].enabled.clone(),
        edition,
        extern_names,
        rustflags_extern: configuration.has_extern_rustflags(&workspace),
        complete: features[manifest_path].inventory_complete,
    })
}

/// The same feature-atom encoding used by persisted crate contexts.
pub fn merge_rust_configuration_atoms(
    cfg: &BTreeSet<String>,
    features: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut atoms = cfg.clone();
    atoms.extend(
        features
            .iter()
            .map(|feature| format!("feature = {feature:?}")),
    );
    atoms
}

fn configuration_atoms(
    manifest_path: &Path,
    kind: RustCallerTargetKind,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
    features: &BTreeMap<PathBuf, BuildFeatures>,
) -> (BTreeSet<String>, PathBuf) {
    let manifest = &manifests[manifest_path];
    let directory = manifest_path.parent().unwrap_or(Path::new(""));
    let workspace = cargo_workspace_manifest_directory(
        Path::new(""),
        directory,
        &manifest.document,
        cargo_manifests,
    )
    .unwrap_or_else(|| directory.to_path_buf());
    let mut atoms = if kind == RustCallerTargetKind::Build
        || manifest_feature_platform(&manifest.document) == FeaturePlatform::Host
    {
        configuration.host_cfg_atoms(&workspace)
    } else {
        configuration.cfg_atoms(&workspace)
    };
    if !features[manifest_path].complete {
        atoms.insert(crate::cfg::INCOMPLETE_FEATURES_ATOM.to_string());
    }
    (atoms, workspace)
}

fn configuration_dependencies(
    manifest_path: &Path,
    kind: RustCallerTargetKind,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> Vec<RustCrateDependency> {
    let manifest = &manifests[manifest_path];
    manifest
        .facts
        .dependencies
        .iter()
        .filter(|dependency| {
            dependency_available(dependency.kind, kind, kind != RustCallerTargetKind::Build)
        })
        .map(|fact| {
            let dependency_path = dependency_manifest(
                manifest_path,
                fact,
                manifests,
                cargo_manifests,
                configuration,
            );
            let renamed = crate::cargo_routes::effective_cargo_dependency(
                Path::new(""),
                manifest_path.parent().unwrap_or(Path::new("")),
                &manifest.document,
                &fact.manifest_name,
                fact.source_value(&manifest.document),
                cargo_manifests,
            )
            .is_some_and(|(value, _)| value.contains_key("package"));
            let extern_name = if renamed {
                None
            } else {
                dependency_path
                    .as_ref()
                    .and_then(|path| manifests.get(path))
                    .and_then(|manifest| manifest.facts.package.as_ref())
                    .map(|package| package.library_name.clone())
            }
            .unwrap_or_else(|| fact.exposed_name.clone());
            RustCrateDependency {
                extern_name,
                kind: fact.kind,
                manifest_path: dependency_path,
            }
        })
        .collect()
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
    inventory_complete: bool,
}

// Shared by parsed member discovery and expected-but-unparsed identities.
pub(super) fn workspace_member_pattern_matches(
    workspace: &Path,
    member: &Path,
    directory: &Path,
) -> bool {
    normalize_selected_path(workspace, member).is_none_or(|member| {
        member == directory
            || member.to_str().is_none_or(|pattern| {
                glob::Pattern::new(pattern).map_or(true, |pattern| {
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
}

// Shared Cargo workspace membership, including optional path dependencies and
// exclusions. Discovery must use the same membership as feature unification.
pub(super) fn workspace_member_manifests(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> BTreeMap<PathBuf, BTreeSet<PathBuf>> {
    use crate::cargo_routes::cargo_dependency_tables_with_kind;
    let mut roots = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for (path, manifest) in manifests.iter().filter(|(_, m)| m.facts.package.is_some()) {
        let directory = path.parent().expect("manifest has a directory");
        let Some(workspace) = cargo_workspace_manifest_directory(
            Path::new(""),
            directory,
            &manifest.document,
            cargo_manifests,
        ) else {
            // A broken package.workspace pointer has no feature-unification root.
            // The result below retains the package with incomplete features.
            continue;
        };
        let Some(workspace_manifest) = manifests.get(&workspace.join("Cargo.toml")) else {
            // The selected listing can omit the workspace manifest.
            continue;
        };
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
                .any(|member| workspace_member_pattern_matches(&workspace, member, directory));
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
                    let Some(target_workspace) = cargo_workspace_manifest_directory(
                        Path::new(""),
                        target_directory,
                        &manifests[&target].document,
                        cargo_manifests,
                    ) else {
                        // A retained dependency can have an unresolved workspace pointer.
                        continue;
                    };
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
    roots
}

fn dependency_feature_suppressed(feature_table: Option<&toml::Table>, dependency: &str) -> bool {
    feature_table.is_some_and(|table| {
        table
            .values()
            .filter_map(toml::Value::as_array)
            .flatten()
            .any(|value| value.as_str() == Some(&format!("dep:{dependency}")))
    })
}

// One inventory request owns these maps. No activation graph survives it.
fn fixed_build_features(
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
    configuration: &RustCargoConfiguration,
) -> Result<BTreeMap<PathBuf, BuildFeatures>, String> {
    use crate::cargo_routes::cargo_dependency_tables_with_kind;
    let roots = workspace_member_manifests(manifests, cargo_manifests, configuration);
    let mut results = BTreeMap::<PathBuf, Vec<BuildFeatures>>::new();
    let mut member_features = BTreeMap::new();
    for (workspace, members) in roots {
        let platform = |path: &Path| manifest_feature_platform(&manifests[path].document);
        let mut units = BTreeMap::<(PathBuf, FeaturePlatform), FeatureUnit>::new();
        for path in &members {
            let unit = units.entry((path.clone(), platform(path))).or_default();
            let manifest = &manifests[path].document;
            let feature_table = manifest.get("features").and_then(toml::Value::as_table);
            unit.enabled.extend(
                feature_table
                    .into_iter()
                    .flat_map(|table| table.keys())
                    .cloned(),
            );
            // Cargo's optional dependency names are features unless dep:name
            // explicitly suppresses them anywhere in the feature table.
            for (_, _, dependencies) in cargo_dependency_tables_with_kind(manifest) {
                for (name, raw) in dependencies {
                    if raw.get("optional").and_then(toml::Value::as_bool) == Some(true)
                        && !dependency_feature_suppressed(feature_table, name)
                    {
                        unit.enabled.insert(name.clone());
                    }
                }
            }
            member_features.insert(path.clone(), unit.enabled.clone());
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
                                    let suppressed =
                                        dependency_feature_suppressed(feature_table, dependency);
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
                            configuration.host_dependency_predicate(predicate)
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
                inventory_complete: complete,
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
            // A member's all-features selection certifies its own feature
            // universe even when an outgoing dependency is missing. Preserve
            // the separate topology incompleteness and host/target disagreement.
            let inventory_complete = complete;
            let (enabled, complete) = member_features
                .remove(path)
                .map(|enabled| (enabled, true))
                .unwrap_or((enabled, complete));
            (
                path.clone(),
                BuildFeatures {
                    enabled,
                    complete,
                    inventory_complete,
                },
            )
        })
        .collect())
}

pub(super) fn inventory_dependency_manifest(
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
    inventory_dependency_manifest(
        path,
        &dependency.manifest_name,
        dependency.source_value(&manifests.get(path)?.document),
        manifests,
        cargo_manifests,
        configuration,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11825: scoped operations refused configuration-only derivations as UnprovedStage"
    )]
    fn configuration_bin_includes_same_package_library_extern() {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"library-name\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let configuration = RustCargoConfiguration::default();
        let targets = rust_crate_targets(
            [
                (PathBuf::from("src/lib.rs"), Oid::zero()),
                (PathBuf::from("src/main.rs"), Oid::zero()),
            ],
            vec![manifest.clone()],
            &configuration,
        )
        .unwrap();
        let binary = targets
            .iter()
            .find(|target| target.kind == RustCallerTargetKind::Binary)
            .unwrap();
        let facts = rust_target_configuration(
            &binary.manifest_path,
            binary.kind,
            vec![manifest],
            &configuration,
        )
        .unwrap();
        assert!(facts.extern_names.contains("library_name"));
    }
    use super::*;
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction;
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
            // Dev requests belong to workspace members. Other cases exercise
            // request-driven dependency features rather than all-features roots.
            let workspace = if extra.is_empty() {
                "[workspace]\nresolver=\"2\"\nmembers=[\"driver\"]\nexclude=[\"a\",\"b\"]\n"
            } else {
                "[workspace]\nresolver=\"2\"\nmembers=[\"a\"]\nexclude=[\"driver\",\"b\"]\n"
            };
            let manifests = vec![
                RustSelectedManifestMount::from_source("Cargo.toml", workspace).unwrap(),
                RustSelectedManifestMount::from_source("driver/Cargo.toml", "[package]\nname=\"driver\"\nedition=\"2021\"\n[dependencies]\na={path=\"../a\"}\n").unwrap(),
                RustSelectedManifestMount::from_source("a/Cargo.toml", &format!("[package]\nname=\"a\"\nedition=\"2021\"\n[dependencies]\nb={{path=\"../b\",optional={optional}}}\n[features]\n{a_features}\n{extra}\n")).unwrap(),
                RustSelectedManifestMount::from_source("b/Cargo.toml", "[package]\nname=\"b\"\nedition=\"2021\"\n[features]\non=[]\nother=[]\n").unwrap(),
            ];
            let targets = rust_crate_targets(
                ["driver/src/lib.rs", "a/src/lib.rs", "b/src/lib.rs"]
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
            assert_eq!(b.inventory_complete, expected_b, "{label}: {targets:?}");
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
                "optional activated by all features",
                "[dependencies]\nb={path=\"../b\",optional=true}",
                "default=[\"on\"]\non=[]",
                "",
                true,
                true,
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
        // Acyclic dev edges remain available even in the merged library unit.
        assert!(
            targets
                .iter()
                .all(|target| target.dropped_dev_dependencies.is_empty())
        );
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
    fn crate_inventory_all_features_survives_missing_dependency() {
        let manifests = vec![RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname=\"root\"\nedition=\"2021\"\n[dependencies]\nmissing=\"1\"\noptional_dep={version=\"1\",optional=true}\nsecret={version=\"1\",optional=true}\n[features]\nleft=[]\nright=[]\nsuppressed=[\"dep:secret\"]\n",
        ).unwrap()];
        let targets = rust_crate_targets(
            [(PathBuf::from("src/lib.rs"), Oid::zero())],
            manifests,
            &RustCargoConfiguration::default(),
        )
        .unwrap();
        let root = targets.iter().find(|target| target.name == "root").unwrap();
        assert_eq!(
            root.features,
            BTreeSet::from([
                "left".into(),
                "right".into(),
                "suppressed".into(),
                "optional_dep".into(),
            ])
        );
        assert!(
            !root.inventory_complete,
            "missing dependency inventory: {root:?}"
        );
        assert!(
            !root
                .cfg_atoms
                .contains(crate::cfg::INCOMPLETE_FEATURES_ATOM)
        );
        let atoms = merge_rust_configuration_atoms(&root.cfg_atoms, &root.features);
        assert_eq!(
            crate::cfg::crate_activation(
                &atoms,
                &RustCfgCondition::Atom("feature = \"absent\"".into())
            ),
            RustSelectedActivation::Inactive
        );
        assert_eq!(
            crate::cfg::crate_activation(&atoms, &RustCfgCondition::Atom("loom".into())),
            RustSelectedActivation::Unknown
        );
    }

    /// #12748: an unknown Cargo configuration acquisition must not turn
    /// `cfg(test)` or `cfg(debug_assertions)` into certain falsehoods. An atom
    /// is unknown there exactly when its known derivation reads configuration.
    /// The known derivation gives `test` and `debug_assertions` to every
    /// non-build, non-host target (a lib target included), so the unknown
    /// derivation must agree target by target.
    #[test]
    #[hardwon(
        "#12748: unknown Cargo configuration acquisition made cfg(test) certainly inactive in every target"
    )]
    fn unknown_acquisition_keeps_configuration_free_atoms_and_unknowns_the_rest() {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"app\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let targets = |configuration: &RustCargoConfiguration| {
            rust_crate_targets(
                ["src/lib.rs", "tests/x.rs"]
                    .into_iter()
                    .map(|path| (PathBuf::from(path), Oid::zero())),
                vec![manifest.clone()],
                configuration,
            )
            .unwrap()
        };
        let known = targets(&RustCargoConfiguration::default());
        let unknown = targets(&RustCargoConfiguration::unknown_acquired());
        let activation = |atoms: &BTreeSet<String>, condition: &RustCfgCondition| {
            crate::cfg::crate_activation(atoms, condition)
        };
        let atom_condition = |atom: &str| RustCfgCondition::Atom(atom.to_string());
        let target_os_condition = |value: &str| {
            RustCfgCondition::Expression(
                vec![RustCfgInstruction::KeyValue {
                    key: "target_os".into(),
                    value: value.into(),
                }]
                .into_boxed_slice(),
            )
        };
        // A target value is a KeyValue predicate; as a bare atom it is
        // Unknown outside the host whose value it names.
        let (host_os, _) =
            crate::cargo_config::builtin_target_platform(crate::cargo_config::host_target_triple())
                .expect("the host triple is a built-in target");
        let other_os = if host_os == "linux" { "macos" } else { "linux" };
        for kind in [RustCallerTargetKind::Library, RustCallerTargetKind::Test] {
            let known = known.iter().find(|target| target.kind == kind).unwrap();
            let unknown = unknown.iter().find(|target| target.kind == kind).unwrap();
            for atom in ["test", "debug_assertions"] {
                assert_eq!(
                    activation(&known.cfg_atoms, &atom_condition(atom)),
                    RustSelectedActivation::Active
                );
                assert_eq!(
                    activation(&unknown.cfg_atoms, &atom_condition(atom)),
                    activation(&known.cfg_atoms, &atom_condition(atom)),
                    "{kind:?} {atom}: {:?}",
                    unknown.cfg_atoms
                );
            }
            // The known derivation reads build.target to describe the target,
            // so the unknown one cannot say what the target is.
            for atom in ["unix", "windows"] {
                assert_ne!(
                    activation(&known.cfg_atoms, &atom_condition(atom)),
                    RustSelectedActivation::Unknown,
                    "{atom}"
                );
                assert_eq!(
                    activation(&unknown.cfg_atoms, &atom_condition(atom)),
                    RustSelectedActivation::Unknown,
                    "{kind:?} {atom}: {:?}",
                    unknown.cfg_atoms
                );
            }
            assert_eq!(
                activation(&known.cfg_atoms, &target_os_condition(host_os)),
                RustSelectedActivation::Active,
                "host target_os = {host_os:?}: {:?}",
                known.cfg_atoms
            );
            assert_eq!(
                activation(&known.cfg_atoms, &target_os_condition(other_os)),
                RustSelectedActivation::Inactive,
                "other target_os = {other_os:?}: {:?}",
                known.cfg_atoms
            );
            for value in [host_os, other_os] {
                assert_eq!(
                    activation(&unknown.cfg_atoms, &target_os_condition(value)),
                    RustSelectedActivation::Unknown,
                    "{kind:?} target_os = {value:?}: {:?}",
                    unknown.cfg_atoms
                );
            }
            // Feature atoms stay unproven: the marker is in the unknown set.
            assert!(
                unknown
                    .cfg_atoms
                    .contains(crate::cfg::INCOMPLETE_FEATURES_ATOM)
            );
            // A `--cfg` rustflag reaches the known set only through
            // configuration, so the unknown set cannot say it is false.
            let flagged = RustCargoConfiguration::from_files([(
                PathBuf::from(".cargo/config.toml"),
                crate::cargo_config::RustCargoConfigDocument::from_source_bytes(
                    b"[build]\nrustflags = [\"--cfg\", \"from_rustflags\"]\n",
                )
                .unwrap(),
            )]);
            let flagged = targets(&flagged);
            let flagged = flagged.iter().find(|target| target.kind == kind).unwrap();
            assert_eq!(
                activation(&flagged.cfg_atoms, &atom_condition("from_rustflags")),
                RustSelectedActivation::Active
            );
            assert_eq!(
                activation(&unknown.cfg_atoms, &atom_condition("from_rustflags")),
                RustSelectedActivation::Unknown
            );
        }
        assert_eq!(known.len(), unknown.len());
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
    #[test]
    #[hardwon(
        "#12358: legal dev-dependency cycles forced library crates incomplete and made every Rust route partial"
    )]
    fn dev_cycles_drop_canonical_edges_without_losing_test_target_dependencies() {
        let package = |name: &str, dependencies: &str| {
            RustSelectedManifestMount::from_source(
                format!("{name}/Cargo.toml"),
                &format!(
                    "[package]\nname={name:?}\nversion=\"0.1.0\"\nedition=\"2021\"\n{dependencies}"
                ),
            )
            .unwrap()
        };
        let manifests = vec![
            RustSelectedManifestMount::from_source(
                "Cargo.toml",
                "[workspace]\nmembers=[\"a\",\"b\",\"c\"]\n",
            )
            .unwrap(),
            package(
                "a",
                "[dev-dependencies]\nb={path=\"../b\"}\nc={path=\"../c\"}\n",
            ),
            package("b", "[dependencies]\na={path=\"../a\"}\n"),
            package(
                "c",
                "[dev-dependencies]\na={path=\"../a\"}\nb={path=\"../b\"}\n",
            ),
        ];
        let paths = [
            "a/src/lib.rs",
            "a/tests/check.rs",
            "b/src/lib.rs",
            "c/src/lib.rs",
        ];
        let inventory = |manifests| {
            rust_crate_targets(
                paths.iter().map(|path| (PathBuf::from(path), Oid::zero())),
                manifests,
                &RustCargoConfiguration::default(),
            )
            .unwrap()
        };
        let first = inventory(manifests.clone());
        let mut reversed = manifests;
        reversed.reverse();
        let second = inventory(reversed);
        let normalized = |targets: &[RustCrateTarget]| {
            let mut dropped = targets
                .iter()
                .flat_map(|target| {
                    target.dropped_dev_dependencies.iter().map(|gap| {
                        (
                            gap.from_manifest.clone(),
                            gap.to_manifest.clone(),
                            gap.extern_name.clone(),
                        )
                    })
                })
                .collect::<Vec<_>>();
            dropped.sort();
            dropped
        };
        assert_eq!(normalized(&first), normalized(&second));
        assert_eq!(
            normalized(&first),
            vec![
                (
                    PathBuf::from("a/Cargo.toml"),
                    PathBuf::from("b/Cargo.toml"),
                    "b".into()
                ),
                (
                    PathBuf::from("c/Cargo.toml"),
                    PathBuf::from("a/Cargo.toml"),
                    "a".into()
                ),
                (
                    PathBuf::from("c/Cargo.toml"),
                    PathBuf::from("b/Cargo.toml"),
                    "b".into()
                )
            ]
        );
        assert!(first.iter().all(|target| target.inventory_complete));
        let test = first
            .iter()
            .find(|target| target.kind == RustCallerTargetKind::Test)
            .unwrap();
        assert!(
            test.dependencies
                .iter()
                .any(|dependency| dependency.extern_name == "b")
        );
        assert!(test.dropped_dev_dependencies.is_empty());
        let b = first.iter().find(|target| target.name == "b").unwrap();
        assert!(
            b.dependencies
                .iter()
                .any(|dependency| dependency.extern_name == "a")
        );
    }
}
