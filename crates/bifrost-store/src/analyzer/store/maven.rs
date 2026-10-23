use crate::analyzer::store::maven_xml::MAX_BUILD_METADATA_BYTES;
use crate::analyzer::store::maven_xml::expand_maven_value;
use crate::analyzer::store::maven_xml::maven_project_properties;
use crate::analyzer::store::maven_xml::parse_xml;
use std::path::Path;
use std::path::PathBuf;

use crate::analyzer::topology::DependencyScope;
use crate::hash::HashMap;

/// A source visibility domain derived from selected package metadata and paths.
/// It is query-owned evidence, not a discovered build project.
#[derive(Debug, PartialEq, Eq)]
pub struct JvmSourceDomain {
    pub root: PathBuf,
}

impl JvmSourceDomain {
    pub fn discover(path: &Path, package: &str, requires_directory: bool) -> Option<Self> {
        let directory = path.parent()?;
        // Layout conventions also support Kotlin/Scala packages whose directory
        // does not mirror the declared package. Prefer the innermost source root.
        for root in directory.ancestors() {
            if source_set(root).is_some() {
                return Some(Self {
                    root: root.to_owned(),
                });
            }
        }
        let mut root = directory;
        for segment in package
            .split('.')
            .rev()
            .filter(|segment| !segment.is_empty())
        {
            if root.file_name() != Some(std::ffi::OsStr::new(segment)) {
                return (!requires_directory).then(|| Self {
                    root: directory.to_owned(),
                });
            }
            root = root.parent()?;
        }
        Some(Self {
            root: root.to_owned(),
        })
    }

    pub fn can_access(&self, target: &Self) -> bool {
        if self.root == target.root {
            return true;
        }
        let (Some((module, caller_set)), Some((target_module, target_set))) =
            (source_set(&self.root), source_set(&target.root))
        else {
            return false;
        };
        module == target_module && source_set_sees(caller_set, target_set)
    }
}

/// JVM layout rule. These are path components, not source syntax.
pub fn source_set(root: &Path) -> Option<(&Path, &str)> {
    let name = root.file_name()?.to_str()?;
    let set = if matches!(name, "java" | "kotlin" | "scala") {
        root.parent()?
    } else if matches!(name, "main" | "test") {
        root
    } else {
        return None;
    };
    let name = set.file_name()?.to_str()?;
    let src = set.parent()?;
    (src.file_name()? == "src").then_some((src.parent().unwrap_or(Path::new("")), name))
}

/// Conventional JVM source-set dependencies, directed from caller to target.
pub fn source_set_sees(caller: &str, target: &str) -> bool {
    const DEPENDENCIES: &[(&str, &str)] = &[
        ("test", "main"),
        ("jvmTest", "jvmMain"),
        ("jvmTest", "commonMain"),
    ];
    caller == target
        || DEPENDENCIES.contains(&(caller, target))
        || (target == "commonMain" && caller.ends_with("Main"))
}

/// The `src/main` and `src/test` roles Maven's default lifecycle fixes.
pub const MAVEN_SOURCE_SETS: [(&str, &str); 2] = [("main", "src/main"), ("test", "src/test")];

/// A declared value retains failed interpolation separately from absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MavenValue {
    Missing,
    Unresolved,
    Resolved(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MavenModelLimitation {
    ParentModel,
    Profiles,
    DependencyManagement,
    CustomSourceRoots,
    BuildPlugins,
}

/// Direct declarations in one selected pom, not an effective Maven model.
/// The caller retains the selected configuration file-version/content identity.
#[derive(Debug)]
pub struct MavenConfigurationFacts {
    pub directory: PathBuf,
    pub group_id: String,
    pub artifact_id: String,
    pub version: MavenValue,
    pub modules: Vec<MavenValue>,
    pub dependencies: Vec<MavenDependencyFacts>,
    pub limitations: Vec<MavenModelLimitation>,
}

impl MavenConfigurationFacts {
    pub fn default_source_roots(&self) -> [(&'static str, PathBuf); 2] {
        MAVEN_SOURCE_SETS.map(|(role, relative)| (role, self.directory.join(relative)))
    }
}

#[derive(Debug)]
pub struct MavenDependencyFacts {
    pub ordinal: u32,
    pub group_id: MavenValue,
    pub artifact_id: MavenValue,
    pub version: MavenValue,
    pub artifact_type: MavenValue,
    pub classifier: MavenValue,
    pub scope: MavenValue,
    pub optional: MavenValue,
    // Keep the established display topology's literal optional interpretation.
    pub topology_kind: DependencyScope,
}

/// Parse one exact configuration without consulting other files or the host.
/// Absence, malformed XML, invalid UTF-8, an oversized input or an unresolved
/// required project coordinate cannot supply a named Maven project.
pub fn maven_configuration_from_bytes(
    pom_path: &Path,
    source: &[u8],
) -> Option<MavenConfigurationFacts> {
    if source.len() > MAX_BUILD_METADATA_BYTES {
        return None;
    }
    read_maven_configuration(pom_path, std::str::from_utf8(source).ok()?)
}

pub fn maven_value(value: Option<&str>, properties: &HashMap<String, String>) -> MavenValue {
    match value {
        None => MavenValue::Missing,
        Some(value) => expand_maven_value(value, properties)
            .map(MavenValue::Resolved)
            .unwrap_or(MavenValue::Unresolved),
    }
}

pub fn read_maven_configuration(path: &Path, source: &str) -> Option<MavenConfigurationFacts> {
    let node = parse_xml(source)?;
    if node.name != "project" {
        return None;
    }
    let properties = maven_project_properties(&node);
    let parent = node.child("parent");
    let MavenValue::Resolved(group_id) = maven_value(
        node.child_text("groupId")
            .or_else(|| parent.and_then(|parent| parent.child_text("groupId"))),
        &properties,
    ) else {
        return None;
    };
    let MavenValue::Resolved(artifact_id) = maven_value(node.child_text("artifactId"), &properties)
    else {
        return None;
    };
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let version = maven_value(
        node.child_text("version")
            .or_else(|| parent.and_then(|parent| parent.child_text("version"))),
        &properties,
    );
    let directory = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let modules = node
        .child("modules")
        .map(|modules| {
            modules
                .children_named("module")
                .map(|module| maven_value(Some(module.text.trim()), &properties))
                .collect()
        })
        .unwrap_or_default();
    let dependencies = node
        .child("dependencies")
        .map(|dependencies| {
            dependencies
                .children_named("dependency")
                .enumerate()
                .map(|(ordinal, dependency)| {
                    let scope = maven_value(dependency.child_text("scope"), &properties);
                    let optional_literal = dependency
                        .child_text("optional")
                        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                    let topology_kind = if optional_literal {
                        DependencyScope::Optional
                    } else {
                        maven_scope_edge_kind(match &scope {
                            MavenValue::Resolved(value) => Some(value),
                            _ => None,
                        })
                    };
                    MavenDependencyFacts {
                        ordinal: u32::try_from(ordinal)
                            .expect("bounded XML node inventory fits u32"),
                        group_id: maven_value(dependency.child_text("groupId"), &properties),
                        artifact_id: maven_value(dependency.child_text("artifactId"), &properties),
                        version: maven_value(dependency.child_text("version"), &properties),
                        artifact_type: maven_value(dependency.child_text("type"), &properties),
                        classifier: maven_value(dependency.child_text("classifier"), &properties),
                        scope,
                        optional: maven_value(dependency.child_text("optional"), &properties),
                        topology_kind,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let mut limitations = Vec::new();
    if parent.is_some() {
        limitations.push(MavenModelLimitation::ParentModel);
    }
    if node.child("profiles").is_some() {
        limitations.push(MavenModelLimitation::Profiles);
    }
    if node.child("dependencyManagement").is_some() {
        limitations.push(MavenModelLimitation::DependencyManagement);
    }
    if let Some(build) = node.child("build") {
        if build.child("sourceDirectory").is_some() || build.child("testSourceDirectory").is_some()
        {
            limitations.push(MavenModelLimitation::CustomSourceRoots);
        }
        if build.child("plugins").is_some()
            || build.child("pluginManagement").is_some()
            || build.child("extensions").is_some()
        {
            limitations.push(MavenModelLimitation::BuildPlugins);
        }
    }
    Some(MavenConfigurationFacts {
        directory,
        group_id,
        artifact_id,
        version,
        modules,
        dependencies,
        limitations,
    })
}

/// The Maven scope vocabulary as topology edge kinds. An absent scope is
/// `compile` by Maven's own default; a scope this reader does not model stays
/// [`DependencyScope::Unknown`] rather than being folded into the nearest
/// match.
pub fn maven_scope_edge_kind(scope: Option<&str>) -> DependencyScope {
    match scope.map(str::trim) {
        None | Some("") | Some("compile") => DependencyScope::Compile,
        Some("runtime") => DependencyScope::Runtime,
        Some("test") => DependencyScope::Test,
        Some("provided") => DependencyScope::Provided,
        Some(_) => DependencyScope::Unknown,
    }
}
