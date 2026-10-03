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
pub fn rust_crate_targets(
    paths: impl IntoIterator<Item = (PathBuf, Oid)>,
    manifests: Vec<RustSelectedManifestMount>,
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
    let mut features: BTreeMap<PathBuf, BTreeSet<String>> = input
        .manifests
        .iter()
        .filter(|(_, manifest)| manifest.facts.package.is_some())
        .map(|(path, manifest)| {
            let defaults = manifest
                .document
                .get("features")
                .and_then(|features| features.get("default"));
            (
                path.clone(),
                if defaults.is_some() {
                    BTreeSet::from(["default".into()])
                } else {
                    BTreeSet::new()
                },
            )
        })
        .collect();
    // Manifest feature values are Cargo strings, not Rust source syntax.
    loop {
        let mut additions = Vec::new();
        for (path, enabled) in &features {
            let manifest = &input.manifests[path];
            if let Some(table) = manifest
                .document
                .get("features")
                .and_then(toml::Value::as_table)
            {
                for feature in enabled {
                    for value in table
                        .get(feature)
                        .and_then(toml::Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let Some(value) = value.as_str() else {
                            return Err(format!("invalid feature in {path:?}"));
                        };
                        if let Some((dependency, feature)) = value.split_once('/') {
                            let dependency = dependency.trim_end_matches('?');
                            if let Some(fact) = manifest
                                .facts
                                .dependencies
                                .iter()
                                .find(|fact| fact.manifest_name == dependency)
                                && let Some(target) = dependency_manifest(
                                    path,
                                    fact,
                                    &input.manifests,
                                    &cargo_manifests,
                                )
                            {
                                additions.push((target, feature.to_string()));
                            }
                        } else if !value.starts_with("dep:") {
                            additions.push((path.clone(), value.to_string()));
                        }
                    }
                }
            }
            for (table, _) in dependency_tables() {
                for (name, value) in manifest
                    .document
                    .get(table)
                    .and_then(toml::Value::as_table)
                    .into_iter()
                    .flatten()
                {
                    let Some(fact) = manifest
                        .facts
                        .dependencies
                        .iter()
                        .find(|fact| fact.manifest_name == *name)
                    else {
                        continue;
                    };
                    let Some(target) =
                        dependency_manifest(path, fact, &input.manifests, &cargo_manifests)
                    else {
                        continue;
                    };
                    for source in std::iter::once(value).chain(
                        dependency_value(path, fact, &input.manifests).map(|(value, _)| value),
                    ) {
                        for feature in source
                            .get("features")
                            .and_then(toml::Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            let feature = feature
                                .as_str()
                                .ok_or_else(|| format!("invalid dependency feature in {path:?}"))?;
                            additions.push((target.clone(), feature.to_string()));
                        }
                    }
                }
            }
        }
        let mut changed = false;
        for (path, feature) in additions {
            changed |= features
                .get_mut(&path)
                .expect("workspace dependency has a package")
                .insert(feature);
        }
        if !changed {
            break;
        }
    }
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();
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
            let table = match kind {
                RustCallerTargetKind::Binary => "bin",
                RustCallerTargetKind::Test => "test",
                RustCallerTargetKind::Example => "example",
                RustCallerTargetKind::Bench => "bench",
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
                            inferred_cargo_target_paths(table, name, &package.package_name)
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
            cfg_atoms: crate::cfg::default_cfg_atoms(),
            features: features[&profile.manifest_path].clone(),
            dependencies,
            inventory_complete: inventory.target_inventory_complete,
        });
    }
    Ok(targets)
}

fn dependency_tables() -> [(&'static str, RustCargoDependencyKind); 3] {
    [
        ("dependencies", RustCargoDependencyKind::Normal),
        ("dev-dependencies", RustCargoDependencyKind::Development),
        ("build-dependencies", RustCargoDependencyKind::Build),
    ]
}

fn dependency_value<'a>(
    path: &Path,
    dependency: &RustCargoDependencyFact,
    manifests: &'a BTreeMap<PathBuf, RustSelectedManifestMount>,
) -> Option<(&'a toml::Value, &'a Path)> {
    let manifest = manifests.get(path)?;
    let table = match dependency.kind {
        RustCargoDependencyKind::Normal => "dependencies",
        RustCargoDependencyKind::Development => "dev-dependencies",
        RustCargoDependencyKind::Build => "build-dependencies",
    };
    let value = manifest
        .document
        .get(table)?
        .get(&dependency.manifest_name)?;
    let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
    if value.get("workspace").and_then(toml::Value::as_bool) != Some(true) {
        return Some((value, directory));
    }
    let workspace = manifests
        .values()
        .filter(|candidate| {
            candidate.facts.is_workspace
                && cargo_workspace_claims_package(
                    candidate.relative_path.parent().unwrap_or(Path::new("")),
                    &candidate.facts,
                    directory,
                )
        })
        .max_by_key(|candidate| candidate.relative_path.components().count())?;
    Some((
        workspace
            .document
            .get("workspace")?
            .get("dependencies")?
            .get(&dependency.manifest_name)?,
        workspace.relative_path.parent().unwrap_or(Path::new("")),
    ))
}

/// The workspace manifest a dependency resolves to, by the same lookup the
/// selected context uses: a `path`, a `workspace = true` entry, or a
/// `[patch]` on the workspace manifest whose package version satisfies the
/// dependency's requirement.
fn dependency_manifest(
    path: &Path,
    dependency: &RustCargoDependencyFact,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    cargo_manifests: &CargoHashMap<PathBuf, RustCargoManifestDocument>,
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
    let directory = cargo_dependency_directory_with(
        Path::new(""),
        path.parent().unwrap_or(Path::new("")),
        &manifest.document,
        &dependency.manifest_name,
        raw_dependency,
        cargo_manifests,
        &mut normalize_selected_path,
    )?;
    let target = directory.join("Cargo.toml");
    manifests
        .get(&target)
        .filter(|manifest| manifest.facts.package.is_some())
        .map(|_| target)
}

#[cfg(test)]
mod tests {
    use super::*;

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
