//! Gradle and sbt rows of the JVM dependency evidence (#9325).
//!
//! Gradle selects the highest version any path of the graph requests, and
//! sbt evicts older versions the same way, so a declaration is only a floor.
//! Exact versions come from the lock each tool can write: `gradle.lockfile`
//! for Gradle and `build.sbt.lock` from sbt-dependency-lock. A project that
//! declares dependencies without one is a Missing gap (#8357).
//!
//! Gradle rows, all `maven` ecosystem:
//! - each `build.gradle.kts` `dependencies { }` entry is `declared`, with
//!   `gradle.configuration`; a `platform(...)` BOM is a `constraint`;
//! - a `libs.*` accessor takes its coordinate and version from the build's
//!   `gradle/libs.versions.toml`, recorded as `gradle.catalog_alias`, and
//!   each catalog library is itself a `constraint`;
//! - each `gradle.lockfile` line is `locked` for its configurations.
//!
//! sbt rows: each `libraryDependencies` entry is `declared`, a `%%` artifact
//! carrying the Scala binary suffix it resolves to (`akka-http_2.13`) and
//! `sbt.cross_version=binary`; `scalaVersion` declares the Scala library;
//! each `build.sbt.lock` entry is `locked`.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::configuration::{DocumentRouteStep, decode_json_document};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind, DependencyEvidenceKind,
};
use brokk_bifrost_analysis::analyzer::topology::DependencyScope;
use brokk_bifrost_core::path_utils::normalize_relative_path_from;
use serde_json::Value;
use toml_edit::{ImDocument, Item};

use super::build_scripts::{GradleTarget, read_gradle_build, read_sbt_build, scala_binary_version};
use super::dependency_evidence::{
    Input, JAVA, JVM_TOOLCHAIN_ECOSYSTEM, MAVEN_ECOSYSTEM, condition, gap, row, runtime_rows,
};
use super::topology::{BuildSystem, DeclaredBuildProject, gradle_configuration_scope};

const CATALOG: &str = "gradle/libs.versions.toml";
const GRADLE_LOCKFILE: &str = "gradle.lockfile";
const SBT_LOCKFILE: &str = "build.sbt.lock";

fn named<'a>(inputs: &'a [Input<'a>], path: &Path) -> Option<&'a Input<'a>> {
    inputs.iter().find(|input| input.path == path)
}

/// One `[libraries]` entry of a version catalog.
struct CatalogLibrary {
    /// The alias with its `-`, `_` and `.` separators as `.`, the form of
    /// its `libs.` accessor.
    accessor: String,
    alias: String,
    package: String,
    version: Option<String>,
    /// `strictly`, `require` or `prefer` for a rich version.
    constraint: Option<&'static str>,
    range: Range<usize>,
}

fn catalog_libraries(input: &Input<'_>) -> Result<Vec<CatalogLibrary>, String> {
    let document = ImDocument::parse(input.source).map_err(|error| error.to_string())?;
    let versions = document.get("versions").and_then(Item::as_table_like);
    let Some(libraries) = document.get("libraries").and_then(Item::as_table_like) else {
        return Ok(Vec::new());
    };
    let version_of = |item: &Item| -> Result<(Option<String>, Option<&'static str>), String> {
        let rich = |item: &Item| -> Result<(Option<String>, Option<&'static str>), String> {
            if let Some(version) = item.as_str() {
                return Ok((Some(version.to_owned()), None));
            }
            let table = item
                .as_table_like()
                .ok_or_else(|| "a version that is neither a string nor a table".to_owned())?;
            for kind in ["strictly", "require", "prefer"] {
                if let Some(version) = table.get(kind).and_then(Item::as_str) {
                    return Ok((Some(version.to_owned()), Some(kind)));
                }
            }
            Err("a rich version without strictly, require or prefer".to_owned())
        };
        match item.as_table_like().and_then(|table| table.get("ref")) {
            Some(reference) => {
                let name = reference
                    .as_str()
                    .ok_or_else(|| "a version.ref that is not a string".to_owned())?;
                let referenced = versions
                    .and_then(|versions| versions.get(name))
                    .ok_or_else(|| format!("version.ref {name:?} names no [versions] entry"))?;
                rich(referenced)
            }
            None => rich(item),
        }
    };
    let mut result = Vec::new();
    for (alias, item) in libraries.iter() {
        let (key, _) = libraries
            .get_key_value(alias)
            .expect("an iterated key is present");
        let range = key
            .span()
            .map(|key| key.start..item.span().map_or(key.end, |value| value.end))
            .unwrap_or(0..0);
        let parsed: Result<_, String> = if let Some(notation) = item.as_str() {
            match notation.split(':').collect::<Vec<_>>().as_slice() {
                [group, name] => Ok((format!("{group}:{name}"), None, None)),
                [group, name, version] => {
                    Ok((format!("{group}:{name}"), Some((*version).to_owned()), None))
                }
                _ => Err(format!("{notation:?} is not a group:name:version notation")),
            }
        } else if let Some(table) = item.as_table_like() {
            let text = |key: &str| table.get(key).and_then(Item::as_str);
            let package = match (text("module"), text("group"), text("name")) {
                (Some(module), None, None) => Ok(module.to_owned()),
                (None, Some(group), Some(name)) => Ok(format!("{group}:{name}")),
                _ => Err("a library without module or group and name".to_owned()),
            };
            package.and_then(|package| {
                let (version, constraint) = match table.get("version") {
                    Some(version) => version_of(version)?,
                    None => (None, None),
                };
                Ok((package, version, constraint))
            })
        } else {
            Err("a library that is neither a string nor a table".to_owned())
        };
        match parsed {
            Ok((package, version, constraint)) => result.push(CatalogLibrary {
                accessor: alias.replace(['-', '_'], "."),
                alias: alias.to_owned(),
                package,
                version,
                constraint,
                range,
            }),
            Err(reason) => return Err(format!("library {alias:?}: {reason}")),
        }
    }
    Ok(result)
}

/// The version catalog of the build `directory` belongs to: the nearest
/// `gradle/libs.versions.toml` from the directory upward.
fn catalog_for<'a>(inputs: &'a [Input<'a>], directory: &Path) -> Option<&'a Input<'a>> {
    directory
        .ancestors()
        .find_map(|level| named(inputs, &level.join(CATALOG)))
}

/// The scope a set of resolution configurations implies.
fn configurations_scope<'a>(
    configurations: impl IntoIterator<Item = &'a str> + Clone,
) -> DependencyScope {
    let names = configurations.clone().into_iter().collect::<Vec<_>>();
    if !names.is_empty() && names.iter().all(|name| name.starts_with("test")) {
        DependencyScope::Test
    } else if names
        .iter()
        .any(|name| matches!(*name, "compileClasspath" | "compile"))
    {
        DependencyScope::Compile
    } else if names
        .iter()
        .any(|name| matches!(*name, "runtimeClasspath" | "runtime"))
    {
        DependencyScope::Runtime
    } else if names.contains(&"provided") {
        DependencyScope::Provided
    } else {
        DependencyScope::Unknown
    }
}

pub(super) fn gradle_rows(
    inputs: &[Input<'_>],
    projects: &[DeclaredBuildProject],
    runtime_pins: &BTreeMap<&Path, &Input<'_>>,
    rows: &mut Vec<DependencyEvidence>,
    gaps: &mut Vec<DependencyEvidenceGap>,
) {
    let gradle = projects
        .iter()
        .filter(|project| project.system == BuildSystem::Gradle)
        .collect::<Vec<_>>();
    // Each catalog's libraries are constraints of the build root it serves.
    let mut catalogs = BTreeMap::<&Path, Vec<CatalogLibrary>>::new();
    for input in inputs.iter().filter(|input| input.path.ends_with(CATALOG)) {
        let root = input
            .path
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new(""));
        let owner = gradle
            .iter()
            .find(|project| project.directory == root)
            .map(|project| project.id.as_str());
        match catalog_libraries(input) {
            Ok(libraries) => {
                for library in &libraries {
                    let mut constraint = row(
                        input,
                        owner,
                        MAVEN_ECOSYSTEM,
                        &library.package,
                        DependencyEvidenceKind::Constraint,
                        DependencyScope::Unknown,
                        library.range.clone(),
                    );
                    constraint.version_requirement.clone_from(&library.version);
                    constraint.conditions = vec![condition("gradle.catalog_alias", &library.alias)];
                    if let Some(kind) = library.constraint {
                        constraint
                            .conditions
                            .push(condition("gradle.version_constraint", kind));
                    }
                    rows.push(constraint);
                }
                catalogs.insert(input.path, libraries);
            }
            Err(reason) => gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                0..0,
                format!("the version catalog does not parse: {reason}"),
            )),
        }
    }
    for project in gradle {
        let owner = Some(project.id.as_str());
        let script = named(inputs, &project.directory.join("build.gradle.kts"));
        let mut requested_runtime = false;
        let mut declares = false;
        if let Some(script) = script {
            let Some(build) = read_gradle_build(script.source) else {
                gaps.push(gap(
                    DependencyEvidenceGapKind::Malformed,
                    script.path,
                    0..0,
                    "the build script does not parse cleanly, so its dependencies are unknown",
                ));
                continue;
            };
            for (range, reason) in build.unread {
                gaps.push(gap(
                    DependencyEvidenceGapKind::Unsupported,
                    script.path,
                    range,
                    reason,
                ));
            }
            let catalog = catalog_for(inputs, &project.directory)
                .and_then(|input| Some((input.path, catalogs.get(input.path)?)));
            for declaration in &build.declarations {
                let scope = gradle_configuration_scope(&declaration.configuration);
                let (package, version, mut conditions) = match &declaration.target {
                    GradleTarget::Project(_) => continue,
                    GradleTarget::Module {
                        group,
                        name,
                        version,
                        ..
                    } => (format!("{group}:{name}"), version.clone(), Vec::new()),
                    GradleTarget::Catalog(accessor) => {
                        let library = catalog.and_then(|(_, libraries)| {
                            libraries
                                .iter()
                                .find(|library| library.accessor == *accessor)
                        });
                        let Some(library) = library else {
                            gaps.push(gap(
                                DependencyEvidenceGapKind::Unresolved,
                                script.path,
                                declaration.range.clone(),
                                format!(
                                    "libs.{accessor} names no library of the build's {CATALOG}"
                                ),
                            ));
                            continue;
                        };
                        (
                            library.package.clone(),
                            library.version.clone(),
                            vec![condition("gradle.catalog_alias", &library.alias)],
                        )
                    }
                };
                declares = true;
                let kind = if declaration.platform.is_some() {
                    DependencyEvidenceKind::Constraint
                } else {
                    DependencyEvidenceKind::Declared
                };
                let mut declared = row(
                    script,
                    owner,
                    MAVEN_ECOSYSTEM,
                    &package,
                    kind,
                    scope,
                    declaration.range.clone(),
                );
                declared.version_requirement = version;
                conditions.insert(
                    0,
                    condition("gradle.configuration", &declaration.configuration),
                );
                if let Some(platform) = declaration.platform {
                    conditions.push(condition("gradle.platform", platform));
                }
                declared.conditions = conditions;
                rows.push(declared);
            }
            for (version, range) in &build.toolchains {
                requested_runtime = true;
                let mut toolchain = row(
                    script,
                    owner,
                    JVM_TOOLCHAIN_ECOSYSTEM,
                    JAVA,
                    DependencyEvidenceKind::Constraint,
                    DependencyScope::Unknown,
                    range.clone(),
                );
                toolchain.version_requirement = Some(version.clone());
                toolchain.conditions = vec![
                    condition("java.runtime_evidence", "gradle.toolchain"),
                    condition("java.runtime_override", "unobserved"),
                ];
                rows.push(toolchain);
            }
        }
        match named(inputs, &project.directory.join(GRADLE_LOCKFILE)) {
            Some(lockfile) => gradle_lock_rows(lockfile, owner, rows, gaps),
            None if declares => gaps.push(gap(
                DependencyEvidenceGapKind::Missing,
                script.map_or(project.declaration.as_path(), |script| script.path),
                0..0,
                "the project has no gradle.lockfile, and Gradle selects the highest version any dependency requests, so the resolved versions are unknown",
            )),
            None => {}
        }
        if let Some(declaration) = named(inputs, &project.declaration) {
            runtime_rows(declaration, owner, requested_runtime, runtime_pins, rows);
        }
    }
}

/// `group:name:version=configuration,...` lines; `empty=` lists
/// configurations that resolve nothing.
fn gradle_lock_rows(
    input: &Input<'_>,
    owner: Option<&str>,
    rows: &mut Vec<DependencyEvidence>,
    gaps: &mut Vec<DependencyEvidenceGap>,
) {
    for line in input.source.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') || entry.starts_with("empty=") {
            continue;
        }
        // `entry` is a slice of the source, so its offset is exact.
        let start = entry.as_ptr() as usize - input.source.as_ptr() as usize;
        let range = start..start + entry.len();
        let parsed =
            entry
                .split_once('=')
                .and_then(|(coordinate, configurations)| {
                    match coordinate.split(':').collect::<Vec<_>>().as_slice() {
                        [group, name, version] if !version.is_empty() => {
                            Some((format!("{group}:{name}"), *version, configurations))
                        }
                        _ => None,
                    }
                });
        let Some((package, version, configurations)) = parsed else {
            gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                range,
                format!("{entry:?} is not a gradle.lockfile entry"),
            ));
            continue;
        };
        let configurations = configurations.split(',').filter(|name| !name.is_empty());
        let mut locked = row(
            input,
            owner,
            MAVEN_ECOSYSTEM,
            &package,
            DependencyEvidenceKind::Locked,
            configurations_scope(configurations.clone()),
            range,
        );
        locked.exact_version = Some(version.to_owned());
        locked.conditions = configurations
            .map(|name| condition("gradle.configuration", name))
            .collect();
        rows.push(locked);
    }
}

/// The scope an sbt configuration name implies.
fn sbt_configuration_scope(configuration: Option<&str>) -> DependencyScope {
    match configuration {
        None | Some("compile") => DependencyScope::Compile,
        Some("test") => DependencyScope::Test,
        Some("provided") => DependencyScope::Provided,
        Some("runtime") => DependencyScope::Runtime,
        Some("optional") => DependencyScope::Optional,
        Some(_) => DependencyScope::Unknown,
    }
}

pub(super) fn sbt_rows(
    inputs: &[Input<'_>],
    projects: &[DeclaredBuildProject],
    runtime_pins: &BTreeMap<&Path, &Input<'_>>,
    rows: &mut Vec<DependencyEvidence>,
    gaps: &mut Vec<DependencyEvidenceGap>,
) {
    let sbt = projects
        .iter()
        .filter(|project| project.system == BuildSystem::Sbt)
        .collect::<Vec<_>>();
    let owner_at = |directory: &Path| {
        sbt.iter()
            .find(|project| project.directory == directory)
            .map(|project| project.id.as_str())
    };
    let mut declaring = Vec::<PathBuf>::new();
    for input in inputs
        .iter()
        .filter(|input| input.path.ends_with("build.sbt"))
    {
        let directory = input.path.parent().unwrap_or(Path::new(""));
        let Some(build) = read_sbt_build(input.source) else {
            gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                0..0,
                "the build.sbt does not parse cleanly, so its dependencies are unknown",
            ));
            continue;
        };
        for (range, reason) in &build.unread {
            gaps.push(gap(
                DependencyEvidenceGapKind::Unsupported,
                input.path,
                range.clone(),
                reason.clone(),
            ));
        }
        let binary = build
            .scala_version
            .as_ref()
            .and_then(|(version, _)| scala_binary_version(version));
        let base = |relative: &str| {
            normalize_relative_path_from(directory, Path::new(relative))
                .unwrap_or_else(|| directory.to_path_buf())
        };
        for project in build.projects.iter().chain(std::iter::once(&build.root)) {
            let project_directory = base(&project.directory);
            let owner = owner_at(&project_directory);
            if !project.dependencies.is_empty() {
                declaring.push(project_directory.clone());
            }
            for dependency in &project.dependencies {
                let (artifact, complete) = match (dependency.cross_binary, &binary) {
                    (false, _) => (dependency.artifact.clone(), true),
                    (true, Some(binary)) => (format!("{}_{binary}", dependency.artifact), true),
                    (true, None) => {
                        gaps.push(gap(
                            DependencyEvidenceGapKind::Unresolved,
                            input.path,
                            dependency.range.clone(),
                            format!(
                                "{} is cross-built with %% and the build sets no literal scalaVersion, so its artifact suffix is unknown",
                                dependency.artifact
                            ),
                        ));
                        (dependency.artifact.clone(), false)
                    }
                };
                let mut declared = row(
                    input,
                    owner,
                    MAVEN_ECOSYSTEM,
                    &format!("{}:{artifact}", dependency.group),
                    DependencyEvidenceKind::Declared,
                    sbt_configuration_scope(dependency.configuration.as_deref()),
                    dependency.range.clone(),
                );
                declared.version_requirement = Some(dependency.version.clone());
                declared.complete = complete;
                if let Some(configuration) = &dependency.configuration {
                    declared
                        .conditions
                        .push(condition("sbt.configuration", configuration));
                }
                if dependency.cross_binary {
                    declared
                        .conditions
                        .push(condition("sbt.cross_version", "binary"));
                }
                rows.push(declared);
            }
            if let Some((version, range)) = &build.scala_version
                && owner.is_some()
            {
                let library = if binary.as_deref() == Some("3") {
                    "org.scala-lang:scala3-library_3"
                } else {
                    "org.scala-lang:scala-library"
                };
                let mut scala = row(
                    input,
                    owner,
                    MAVEN_ECOSYSTEM,
                    library,
                    DependencyEvidenceKind::Declared,
                    DependencyScope::Compile,
                    range.clone(),
                );
                scala.version_requirement = Some(version.clone());
                scala.conditions = vec![condition("sbt.setting", "scalaVersion")];
                rows.push(scala);
            }
        }
    }
    for project in sbt {
        let owner = Some(project.id.as_str());
        match named(inputs, &project.directory.join(SBT_LOCKFILE)) {
            Some(lock) => sbt_lock_rows(lock, owner, rows, gaps),
            None if declaring.contains(&project.directory) => gaps.push(gap(
                DependencyEvidenceGapKind::Missing,
                &project.declaration,
                0..0,
                format!(
                    "project {} has no build.sbt.lock, and sbt evicts older versions in favor of the newest any dependency requests, so the resolved versions are unknown",
                    project.directory.display()
                ),
            )),
            None => {}
        }
        if let Some(declaration) = named(inputs, &project.declaration) {
            runtime_rows(declaration, owner, false, runtime_pins, rows);
        }
    }
}

/// The `dependencies` of an sbt-dependency-lock `build.sbt.lock`.
fn sbt_lock_rows(
    input: &Input<'_>,
    owner: Option<&str>,
    rows: &mut Vec<DependencyEvidence>,
    gaps: &mut Vec<DependencyEvidenceGap>,
) {
    let (document, spans) =
        match decode_json_document(Path::new("build.sbt.lock.json"), input.source) {
            Ok(decoded) => decoded,
            Err(reason) => {
                gaps.push(gap(
                    DependencyEvidenceGapKind::Malformed,
                    input.path,
                    0..0,
                    format!("the build.sbt.lock does not parse: {reason}"),
                ));
                return;
            }
        };
    let Some(dependencies) = document.get("dependencies").and_then(Value::as_array) else {
        gaps.push(gap(
            DependencyEvidenceGapKind::Malformed,
            input.path,
            0..0,
            "the build.sbt.lock has no dependencies array",
        ));
        return;
    };
    for (index, dependency) in dependencies.iter().enumerate() {
        let range = spans
            .get(&[
                DocumentRouteStep::Key("dependencies".to_owned()),
                DocumentRouteStep::Index(index),
            ])
            .map_or(0..0, |range| range.start_byte()..range.end_byte());
        let field = |name: &str| dependency.get(name).and_then(Value::as_str);
        let (Some(organization), Some(name), Some(version)) =
            (field("org"), field("name"), field("version"))
        else {
            gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                range,
                "a build.sbt.lock dependency without org, name and version",
            ));
            continue;
        };
        let configurations = dependency
            .get("configurations")
            .and_then(Value::as_array)
            .map(|names| names.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut locked = row(
            input,
            owner,
            MAVEN_ECOSYSTEM,
            &format!("{organization}:{name}"),
            DependencyEvidenceKind::Locked,
            configurations_scope(configurations.iter().copied()),
            range,
        );
        locked.exact_version = Some(version.to_owned());
        locked.conditions = configurations
            .iter()
            .map(|name| condition("sbt.configuration", *name))
            .collect();
        rows.push(locked);
    }
}
