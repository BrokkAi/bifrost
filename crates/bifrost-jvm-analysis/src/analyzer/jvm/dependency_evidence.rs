//! Files-only Maven, Gradle, sbt and JDK evidence projected into the shared
//! #2442 dependency contract (#9325). Gradle and sbt rows are produced in
//! `super::gradle_sbt_evidence`; this module owns Maven, the JDK and the
//! shared row helpers.
//!
//! Java, Kotlin and Scala publish the same rows from the same retained
//! configuration snapshots; the multi-language reader deduplicates them by
//! row identity. Nothing here runs Maven, reads `~/.m2` or contacts a
//! repository. Every row of a pom names that pom's BuildProject, the identity
//! the Maven topology publishes, in `declared_by`:
//!
//! - each `<dependencies>` entry is a `declared` `maven` row whose requirement
//!   is the version after property interpolation, with Maven's scope, type,
//!   classifier and `optional` as conditions;
//! - when that version is a plain version rather than a range, it is also a
//!   `locked` row: Maven's nearest-wins mediation always selects a direct
//!   declaration, so `maven.selection=direct` says why the version is exact.
//!   A version supplied by `dependencyManagement`, in this pom or a parent
//!   pom of the workspace, is exact the same way and names its manager;
//! - each `dependencyManagement` entry is a `constraint`, a BOM import
//!   (`<scope>import</scope>`) included, and a `<parent>` is a `declared`
//!   row with `maven.parent`;
//! - the JDK is the `jvm-toolchain` ecosystem, package `java`: a compiler
//!   `release`, `source` or `target` is a `constraint`, an exact
//!   `.java-version`, `.sdkmanrc` or `.tool-versions` pin found from the
//!   project upward is `locked`, and a project with neither has a
//!   `java.runtime_evidence=none` constraint. None of these is the JDK that
//!   runs the program, which `java.runtime_override=unobserved` says.
//!
//! An unresolved property, a parent or BOM outside the workspace, a version
//! range, profiles, a Groovy Gradle file, and a workspace with no build at
//! all are typed gaps, so missing evidence is never a complete empty answer
//! (#8357). A Gradle or sbt project's JDK rows follow the same rules, with a
//! Gradle `jvmToolchain`/`JavaLanguageVersion.of` request as a constraint.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
    VersionComparator, parse_version_comparators, parse_version_interval, version_bounds_admit,
};
use brokk_bifrost_analysis::analyzer::store::maven::maven_scope_edge_kind;
use brokk_bifrost_analysis::analyzer::store::maven_xml::{
    MavenValueToken, XmlNode, expand_maven_value, maven_project_properties, maven_value_tokens,
    parse_xml,
};
use brokk_bifrost_analysis::analyzer::topology::DependencyScope;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
use brokk_bifrost_core::path_utils::normalize_relative_path_from;

use super::topology::{BuildSystem, build_definition_system, declared_build_projects};

/// Package rows from Maven build files.
pub const MAVEN_ECOSYSTEM: &str = "maven";
/// JDK rows: compile targets and runtime pins.
pub const JVM_TOOLCHAIN_ECOSYSTEM: &str = "jvm-toolchain";

const POM: &str = "pom.xml";
pub(super) const JAVA: &str = "java";
/// Version-manager pins, nearest first: jenv, SDKMAN! and asdf/mise.
const RUNTIME_FILES: [&str; 3] = [".java-version", ".sdkmanrc", ".tool-versions"];
/// Bounds the parent and BOM walks; Maven itself rejects cycles.
const MAX_MODEL_DEPTH: usize = 32;

/// Whether `path` is a JDK version-manager pin this producer reads.
pub(crate) fn is_jvm_runtime_pin(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| RUNTIME_FILES.contains(&name))
}

/// Retain the runtime pins that apply to each selected pom: version managers
/// read the nearest file upward, and a listing may omit dotfiles.
pub(crate) fn include_runtime_pins(
    project: &dyn brokk_bifrost_core::analyzer::project::Project,
    inputs: &mut BTreeSet<ProjectFile>,
) {
    use brokk_bifrost_analysis::analyzer::store::workspace_inputs::metadata_ancestor_directories;
    let directories = metadata_ancestor_directories(
        inputs
            .iter()
            .filter(|file| build_definition_system(file.rel_path()).is_some()),
    );
    for directory in directories {
        for name in RUNTIME_FILES {
            if let Some(file) = project.file_by_rel_path(&directory.join(name)) {
                inputs.insert(file);
            }
        }
    }
}

pub(super) struct Input<'a> {
    pub(super) path: &'a Path,
    pub(super) source: &'a str,
    pub(super) digest: String,
}

/// One parsed pom with the coordinates it declares itself.
struct Pom<'a> {
    input: &'a Input<'a>,
    node: XmlNode,
    /// The pom's own properties and `project.*` values, before inheritance.
    properties: brokk_bifrost_core::hash::HashMap<String, String>,
    group_id: Option<String>,
    artifact_id: Option<String>,
    version: Option<String>,
}

impl Pom<'_> {
    fn directory(&self) -> &Path {
        self.input.path.parent().unwrap_or(Path::new(""))
    }

    fn coordinates(&self) -> Option<(&str, &str)> {
        Some((self.group_id.as_deref()?, self.artifact_id.as_deref()?))
    }
}

pub(super) fn condition(kind: &str, value: impl Into<String>) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.into(),
    }
}

pub(super) fn gap(
    kind: DependencyEvidenceGapKind,
    path: &Path,
    range: Range<usize>,
    message: impl Into<String>,
) -> DependencyEvidenceGap {
    DependencyEvidenceGap {
        kind,
        build_file: path.to_path_buf(),
        byte_range: range,
        message: message.into(),
    }
}

/// A complete row with no requirement, version or condition, for the caller
/// to fill in.
pub(super) fn row(
    input: &Input<'_>,
    owner: Option<&str>,
    ecosystem: &str,
    package: &str,
    kind: DependencyEvidenceKind,
    scope: DependencyScope,
    range: Range<usize>,
) -> DependencyEvidence {
    DependencyEvidence {
        ecosystem: ecosystem.to_owned(),
        package: package.to_owned(),
        kind,
        version_requirement: None,
        exact_version: None,
        source: None,
        locator: None,
        declared_by: owner.map(str::to_owned),
        scope,
        conditions: Vec::new(),
        build_file: input.path.to_path_buf(),
        source_digest: input.digest.clone(),
        byte_range: range,
        complete: true,
    }
}

/// Acquire Maven and JDK rows from the selected configuration snapshots of
/// one JVM language revision. Nothing survives the return but the rows.
pub(crate) fn collect_jvm_dependency_evidence(
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let mut result = DependencyFileEvidence::default();
    let inputs = selected
        .iter()
        .filter(|(file, _)| is_dependency_evidence_input(file.rel_path()))
        .map(|(file, source)| Input {
            path: file.rel_path(),
            source: source.source(),
            digest: source.oid().to_string(),
        })
        .collect::<Vec<_>>();
    result.files_read = inputs.len();
    result.bytes_read = inputs.iter().map(|input| input.source.len()).sum();
    for input in &inputs {
        if input
            .path
            .file_name()
            .is_some_and(|name| name == "build.gradle" || name == "settings.gradle")
        {
            result.gaps.push(gap(
                DependencyEvidenceGapKind::Unsupported,
                input.path,
                0..0,
                "Gradle's Groovy DSL has no grammar here, so the projects and dependencies this file declares are unknown",
            ));
        }
    }

    let mut poms = Vec::new();
    for input in inputs
        .iter()
        .filter(|input| input.path.file_name().is_some_and(|name| name == POM))
    {
        match parse_xml(input.source).filter(|node| node.name == "project") {
            Some(node) => {
                let properties = maven_project_properties(&node);
                let parent = node.child("parent");
                let own = |name: &'static str| {
                    node.child_text(name)
                        .or_else(|| parent.and_then(|parent| parent.child_text(name)))
                        .and_then(|value| expand_maven_value(value, &properties))
                };
                let group_id = own("groupId");
                let version = own("version");
                let artifact_id = node
                    .child_text("artifactId")
                    .and_then(|value| expand_maven_value(value, &properties));
                poms.push(Pom {
                    input,
                    properties,
                    group_id,
                    artifact_id,
                    version,
                    node,
                });
            }
            None => result.gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                0..0,
                "the pom.xml is not a well-formed Maven project, so its dependencies are unknown",
            )),
        }
    }
    let projects = declared_build_projects(
        inputs
            .iter()
            .filter(|input| build_definition_system(input.path).is_some())
            .map(|input| (input.path, input.source)),
    );
    let runtime_pins = inputs
        .iter()
        .filter(|input| is_jvm_runtime_pin(input.path))
        .map(|input| (input.path, input))
        .collect::<BTreeMap<_, _>>();

    let mut rows = Vec::new();
    for (index, pom) in poms.iter().enumerate() {
        let owner = projects
            .iter()
            .find(|project| {
                project.system == BuildSystem::Maven && project.declaration == pom.input.path
            })
            .map(|project| project.id.as_str());
        let model = EffectiveModel::new(&poms, index, &mut result.gaps);
        pom_rows(pom, owner, &model, &poms, &mut rows, &mut result.gaps);
        toolchain_rows(pom, owner, &model, &poms, &runtime_pins, &mut rows);
    }
    super::gradle_sbt_evidence::gradle_rows(
        &inputs,
        &projects,
        &runtime_pins,
        &mut rows,
        &mut result.gaps,
    );
    super::gradle_sbt_evidence::sbt_rows(
        &inputs,
        &projects,
        &runtime_pins,
        &mut rows,
        &mut result.gaps,
    );
    if poms.is_empty() && projects.is_empty() {
        result.gaps.push(gap(
            DependencyEvidenceGapKind::Missing,
            Path::new(POM),
            0..0,
            "no pom.xml, Gradle build or build.sbt was supplied, so the libraries a JVM program loads are unknown",
        ));
    }
    for row in rows {
        if result.rows.len() >= limits.max_rows {
            result.gaps.push(gap(
                DependencyEvidenceGapKind::Limit,
                &row.build_file,
                row.byte_range,
                "JVM dependency evidence row limit",
            ));
            break;
        }
        result.rows.push(row);
    }
    result
}

/// Whether this producer reads `path`: a build definition, a Gradle lockfile
/// or version catalog, an sbt lock, or a JDK pin.
fn is_dependency_evidence_input(path: &Path) -> bool {
    build_definition_system(path).is_some()
        || is_jvm_runtime_pin(path)
        || path.file_name().is_some_and(|name| {
            name == "gradle.lockfile" || name == "libs.versions.toml" || name == "build.sbt.lock"
        })
}

/// A managed version and the pom whose `dependencyManagement` declares it.
struct Managed<'a> {
    version: String,
    manager: &'a Path,
}

/// What inheritance supplies to one pom: the parent chain inside the
/// workspace, merged properties, and the managed versions of the chain and
/// of the BOMs it imports from the workspace.
struct EffectiveModel<'a> {
    /// This pom, then each parent the workspace holds.
    chain: Vec<usize>,
    properties: brokk_bifrost_core::hash::HashMap<String, String>,
    managed: BTreeMap<(String, String), Managed<'a>>,
    /// Why some inherited value may be missing: a parent or BOM outside the
    /// workspace.
    unseen: Vec<String>,
    /// The parent outside the workspace, the only place an undefined
    /// property may come from; BOMs supply managed versions only.
    unseen_parent: Option<String>,
    /// Properties some profile of the chain redefines.
    profile_properties: BTreeSet<String>,
}

impl<'a> EffectiveModel<'a> {
    fn new(poms: &'a [Pom<'a>], index: usize, gaps: &mut Vec<DependencyEvidenceGap>) -> Self {
        let mut chain = vec![index];
        let mut unseen = Vec::new();
        while let Some(parent) = poms[*chain.last().expect("nonempty")].node.child("parent") {
            let child = &poms[*chain.last().expect("nonempty")];
            let text = |name: &'static str| parent.child_text(name).unwrap_or("");
            let coordinates = format!(
                "{}:{}:{}",
                text("groupId"),
                text("artifactId"),
                text("version")
            );
            // An empty `<relativePath/>` tells Maven not to look locally.
            let relative = match parent.child("relativePath") {
                Some(element) => element.text.trim(),
                None => "../pom.xml",
            };
            let located = (!relative.is_empty())
                .then(|| normalize_relative_path_from(child.directory(), Path::new(relative)))
                .flatten()
                .map(|path| {
                    if path.file_name().is_some_and(|name| name == POM) {
                        path
                    } else {
                        path.join(POM)
                    }
                })
                .and_then(|path| {
                    poms.iter().position(|candidate| {
                        candidate.input.path == path
                            && candidate.coordinates()
                                == Some((text("groupId"), text("artifactId")))
                    })
                });
            match located {
                Some(found) if chain.contains(&found) || chain.len() >= MAX_MODEL_DEPTH => {
                    gaps.push(gap(
                        DependencyEvidenceGapKind::Cycle,
                        child.input.path,
                        parent.range.clone(),
                        format!("the parent chain through {coordinates} does not end"),
                    ));
                    break;
                }
                Some(found) => chain.push(found),
                None => {
                    gaps.push(gap(
                        DependencyEvidenceGapKind::Unresolved,
                        child.input.path,
                        parent.range.clone(),
                        format!(
                            "the parent {coordinates} is not in the workspace, so the dependencies, managed versions and properties it supplies are unknown"
                        ),
                    ));
                    unseen.push(format!("parent {coordinates}"));
                    break;
                }
            }
        }
        let mut properties = brokk_bifrost_core::hash::HashMap::default();
        for &pom in chain.iter().rev() {
            properties.extend(
                poms[pom]
                    .properties
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        let profile_properties = chain
            .iter()
            .flat_map(|&pom| profile_property_names(&poms[pom].node))
            .collect();
        let mut model = Self {
            chain: chain.clone(),
            properties,
            managed: BTreeMap::new(),
            unseen_parent: unseen.first().cloned(),
            unseen,
            profile_properties,
        };
        // Nearest manager wins: this pom, then each parent, then the BOMs
        // each imports, in declaration order.
        let mut managers = chain.iter().map(|&pom| (pom, 0_usize)).collect::<Vec<_>>();
        let mut visited = BTreeSet::new();
        let mut next = 0;
        while next < managers.len() {
            let (pom, depth) = managers[next];
            next += 1;
            if !visited.insert(pom) {
                continue;
            }
            for entry in management_entries(&poms[pom].node) {
                let value = |name: &'static str| model.expand(entry.child_text(name));
                let (Some(group), Some(artifact)) = (value("groupId"), value("artifactId")) else {
                    continue;
                };
                if entry.child_text("scope") == Some("import") {
                    let version = value("version").unwrap_or_default();
                    match poms.iter().position(|candidate| {
                        candidate.coordinates() == Some((group.as_str(), artifact.as_str()))
                            && candidate.version.as_deref() == Some(version.as_str())
                    }) {
                        Some(bom) if depth < MAX_MODEL_DEPTH => managers.push((bom, depth + 1)),
                        _ => model
                            .unseen
                            .push(format!("BOM {group}:{artifact}:{version}")),
                    }
                    continue;
                }
                if let Some(version) = value("version") {
                    model.managed.entry((group, artifact)).or_insert(Managed {
                        version,
                        manager: poms[pom].input.path,
                    });
                }
            }
        }
        model
    }

    fn expand(&self, value: Option<&str>) -> Option<String> {
        expand_maven_value(value?, &self.properties).filter(|value| !value.is_empty())
    }

    /// Whether a profile may redefine a property `value` interpolates,
    /// directly or through another property. Only an expandable value
    /// reaches here, so the references are acyclic and bounded.
    fn profile_may_override(&self, value: &str) -> bool {
        if self.profile_properties.is_empty() {
            return false;
        }
        let Some(tokens) = maven_value_tokens(value) else {
            return true;
        };
        tokens.iter().any(|token| match token {
            MavenValueToken::Property(name) => {
                self.profile_properties.contains(name)
                    || self
                        .properties
                        .get(name)
                        .is_some_and(|inner| self.profile_may_override(inner))
            }
            MavenValueToken::Text(_) => false,
        })
    }
}

fn management_entries(project: &XmlNode) -> impl Iterator<Item = &XmlNode> {
    project
        .child("dependencyManagement")
        .and_then(|management| management.child("dependencies"))
        .into_iter()
        .flat_map(|dependencies| dependencies.children_named("dependency"))
}

fn profile_property_names(project: &XmlNode) -> Vec<String> {
    project
        .child("profiles")
        .into_iter()
        .flat_map(|profiles| profiles.children_named("profile"))
        .filter_map(|profile| profile.child("properties"))
        .flat_map(|properties| properties.children.iter().map(|child| child.name.clone()))
        .collect()
}

/// Maven's range syntax; a plain version is a soft requirement that a direct
/// declaration always selects.
fn is_maven_range(version: &str) -> bool {
    version.starts_with(['[', '('])
}

fn pom_rows(
    pom: &Pom<'_>,
    owner: Option<&str>,
    model: &EffectiveModel<'_>,
    poms: &[Pom<'_>],
    rows: &mut Vec<DependencyEvidence>,
    gaps: &mut Vec<DependencyEvidenceGap>,
) {
    let path = pom.input.path;
    if pom.node.child("profiles").is_some() {
        gaps.push(gap(
            DependencyEvidenceGapKind::Unsupported,
            path,
            pom.node.child("profiles").expect("present").range.clone(),
            "Maven profiles are not evaluated, so an active profile's dependencies and property overrides are unknown",
        ));
    }
    if let Some(parent) = pom.node.child("parent") {
        let value = |name: &'static str| model.expand(parent.child_text(name));
        if let (Some(group), Some(artifact)) = (value("groupId"), value("artifactId")) {
            let mut parent_row = row(
                pom.input,
                owner,
                MAVEN_ECOSYSTEM,
                &format!("{group}:{artifact}"),
                DependencyEvidenceKind::Declared,
                DependencyScope::Unknown,
                parent.range.clone(),
            );
            parent_row.version_requirement = value("version");
            parent_row
                .conditions
                .push(condition("maven.parent", "true"));
            rows.push(parent_row);
        }
    }
    for entry in management_entries(&pom.node) {
        let Some((package, version)) =
            coordinates_of(pom, entry, model, gaps, "managed dependency")
        else {
            continue;
        };
        let scope = entry.child_text("scope");
        let mut managed = row(
            pom.input,
            owner,
            MAVEN_ECOSYSTEM,
            &package,
            DependencyEvidenceKind::Constraint,
            scope_of(scope),
            entry.range.clone(),
        );
        managed.version_requirement = version.requirement();
        managed.complete = version.complete();
        managed
            .conditions
            .push(condition("maven.dependency_management", "true"));
        if scope == Some("import") {
            managed.conditions.push(condition("maven.bom", "import"));
            let imported = poms.iter().any(|candidate| {
                candidate
                    .coordinates()
                    .is_some_and(|(group, artifact)| format!("{group}:{artifact}") == package)
                    && candidate.version == managed.version_requirement
            });
            if !imported {
                gaps.push(gap(
                    DependencyEvidenceGapKind::Unresolved,
                    path,
                    entry.range.clone(),
                    format!(
                        "the BOM {package} is not in the workspace, so the versions it manages are unknown"
                    ),
                ));
            }
        }
        managed.conditions.extend(artifact_conditions(entry, model));
        rows.push(managed);
    }
    let Some(dependencies) = pom.node.child("dependencies") else {
        return;
    };
    for entry in dependencies.children_named("dependency") {
        let Some((package, version)) = coordinates_of(pom, entry, model, gaps, "dependency") else {
            continue;
        };
        let scope = scope_of(entry.child_text("scope"));
        let conditions = artifact_conditions(entry, model);
        let mut declared = row(
            pom.input,
            owner,
            MAVEN_ECOSYSTEM,
            &package,
            DependencyEvidenceKind::Declared,
            scope,
            entry.range.clone(),
        );
        declared.version_requirement = version.requirement();
        declared.complete = version.complete();
        declared.conditions = conditions.clone();
        rows.push(declared);
        // A version a profile may redefine is still the default selection,
        // so it stays a row whose version predicate is unknown.
        let complete = version.complete();
        let (selected, manager) = match version {
            DeclaredVersion::Unresolved(_) => continue,
            DeclaredVersion::Expanded { value, .. } => (value, None),
            DeclaredVersion::Absent => {
                match package.split_once(':').and_then(|(group, artifact)| {
                    model.managed.get(&(group.to_owned(), artifact.to_owned()))
                }) {
                    Some(managed) => (managed.version.clone(), Some(managed.manager)),
                    None if model.unseen.is_empty() => {
                        gaps.push(gap(
                        DependencyEvidenceGapKind::Malformed,
                        path,
                        entry.range.clone(),
                        format!(
                            "{package} has no version and no dependencyManagement entry supplies one"
                        ),
                    ));
                        continue;
                    }
                    None => {
                        gaps.push(gap(
                        DependencyEvidenceGapKind::Unresolved,
                        path,
                        entry.range.clone(),
                        format!(
                            "{package} has no version of its own; it may be managed by {:?}, which the workspace does not hold",
                            model.unseen
                        ),
                    ));
                        continue;
                    }
                }
            }
        };
        if is_maven_range(&selected) {
            gaps.push(gap(
                DependencyEvidenceGapKind::Unresolved,
                path,
                entry.range.clone(),
                format!(
                    "{package} requests the range {selected}, which Maven resolves against repository metadata"
                ),
            ));
            continue;
        }
        let mut locked = row(
            pom.input,
            owner,
            MAVEN_ECOSYSTEM,
            &package,
            DependencyEvidenceKind::Locked,
            scope,
            entry.range.clone(),
        );
        locked.exact_version = Some(selected);
        locked.complete = complete;
        locked.conditions = conditions;
        locked
            .conditions
            .push(condition("maven.selection", "direct"));
        if let Some(manager) = manager {
            locked.conditions.push(condition(
                "maven.managed_by",
                manager.to_string_lossy().replace('\\', "/"),
            ));
        }
        rows.push(locked);
    }
}

/// What one entry's `<version>` says after interpolation.
enum DeclaredVersion {
    Absent,
    /// The interpolated value, and whether an active profile may redefine a
    /// property it uses.
    Expanded {
        value: String,
        profile_may_override: bool,
    },
    /// The raw text of a version that interpolates an undefined property.
    Unresolved(String),
}

impl DeclaredVersion {
    fn requirement(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Expanded { value, .. } | Self::Unresolved(value) => Some(value.clone()),
        }
    }

    fn complete(&self) -> bool {
        match self {
            Self::Absent => true,
            Self::Expanded {
                profile_may_override,
                ..
            } => !profile_may_override,
            Self::Unresolved(_) => false,
        }
    }
}

/// `groupId:artifactId` and the interpolated version. Unresolved
/// coordinates are a gap.
fn coordinates_of(
    pom: &Pom<'_>,
    entry: &XmlNode,
    model: &EffectiveModel<'_>,
    gaps: &mut Vec<DependencyEvidenceGap>,
    what: &str,
) -> Option<(String, DeclaredVersion)> {
    let path = pom.input.path;
    let unresolved = |gaps: &mut Vec<DependencyEvidenceGap>, field: &str, raw: &str| {
        gaps.push(gap(
            DependencyEvidenceGapKind::Unresolved,
            path,
            entry.range.clone(),
            format!(
                "the {what} {field} {raw:?} interpolates a property the workspace does not define{}",
                match &model.unseen_parent {
                    Some(parent) => format!("; it may come from the {parent}"),
                    None => String::new(),
                }
            ),
        ));
    };
    let mut coordinates = Vec::new();
    for field in ["groupId", "artifactId"] {
        let Some(raw) = entry.child_text(field) else {
            gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                path,
                entry.range.clone(),
                format!("a {what} has no {field}"),
            ));
            return None;
        };
        match model.expand(Some(raw)) {
            Some(value) => coordinates.push(value),
            None => {
                unresolved(gaps, field, raw);
                return None;
            }
        }
    }
    let package = coordinates.join(":");
    let Some(raw) = entry.child_text("version") else {
        return Some((package, DeclaredVersion::Absent));
    };
    let version = match model.expand(Some(raw)) {
        Some(value) => DeclaredVersion::Expanded {
            value,
            profile_may_override: model.profile_may_override(raw),
        },
        None => {
            unresolved(gaps, "version", raw);
            DeclaredVersion::Unresolved(raw.to_owned())
        }
    };
    Some((package, version))
}

fn scope_of(scope: Option<&str>) -> DependencyScope {
    match scope {
        Some("import") => DependencyScope::Unknown,
        scope => maven_scope_edge_kind(scope),
    }
}

/// The artifact selectors and flags Maven records beside a coordinate.
fn artifact_conditions(entry: &XmlNode, model: &EffectiveModel<'_>) -> Vec<DependencyCondition> {
    ["scope", "type", "classifier", "optional"]
        .into_iter()
        .filter_map(|field| {
            let raw = entry.child_text(field)?;
            Some(condition(
                &format!("maven.{field}"),
                model.expand(Some(raw)).unwrap_or_else(|| raw.to_owned()),
            ))
        })
        .collect()
}

/// The JDK a Maven project compiles for and the runtime its directory pins.
fn toolchain_rows(
    pom: &Pom<'_>,
    owner: Option<&str>,
    model: &EffectiveModel<'_>,
    poms: &[Pom<'_>],
    runtime_pins: &BTreeMap<&Path, &Input<'_>>,
    rows: &mut Vec<DependencyEvidence>,
) {
    let mut runtime = false;
    for name in [
        "maven.compiler.release",
        "maven.compiler.source",
        "maven.compiler.target",
    ] {
        // The nearest pom of the chain that defines the property cites it.
        let Some((defining, property)) = model.chain.iter().find_map(|&index| {
            let property = poms[index].node.child("properties")?.child(name)?;
            Some((&poms[index], property))
        }) else {
            continue;
        };
        let Some(version) = model.expand(Some(property.text.trim())) else {
            continue;
        };
        runtime = true;
        let mut target = row(
            defining.input,
            owner,
            JVM_TOOLCHAIN_ECOSYSTEM,
            JAVA,
            DependencyEvidenceKind::Constraint,
            DependencyScope::Unknown,
            property.range.clone(),
        );
        target.version_requirement = Some(version);
        target.conditions = vec![
            condition("java.runtime_evidence", name),
            condition("java.runtime_override", "unobserved"),
        ];
        rows.push(target);
    }
    let compiler = pom
        .node
        .child("build")
        .and_then(|build| build.child("plugins"))
        .into_iter()
        .flat_map(|plugins| plugins.children_named("plugin"))
        .filter(|plugin| plugin.child_text("artifactId") == Some("maven-compiler-plugin"))
        .filter_map(|plugin| plugin.child("configuration"));
    for configuration in compiler {
        for option in ["release", "source", "target"] {
            let Some(element) = configuration.child(option) else {
                continue;
            };
            let Some(version) = model.expand(Some(element.text.trim())) else {
                continue;
            };
            runtime = true;
            let mut target = row(
                pom.input,
                owner,
                JVM_TOOLCHAIN_ECOSYSTEM,
                JAVA,
                DependencyEvidenceKind::Constraint,
                DependencyScope::Unknown,
                element.range.clone(),
            );
            target.version_requirement = Some(version);
            target.conditions = vec![
                condition(
                    "java.runtime_evidence",
                    format!("maven-compiler-plugin.{option}"),
                ),
                condition("java.runtime_override", "unobserved"),
            ];
            rows.push(target);
        }
    }
    runtime_rows(pom.input, owner, runtime, runtime_pins, rows);
}

/// The nearest runtime pin from `project`'s directory upward, else, when the
/// project also requests no JDK (`requested`), a `java.runtime_evidence=none`
/// constraint citing `project`.
pub(super) fn runtime_rows(
    project: &Input<'_>,
    owner: Option<&str>,
    requested: bool,
    runtime_pins: &BTreeMap<&Path, &Input<'_>>,
    rows: &mut Vec<DependencyEvidence>,
) {
    let directory = project.path.parent().unwrap_or(Path::new(""));
    let pin = directory.ancestors().find_map(|level| {
        RUNTIME_FILES
            .iter()
            .find_map(|name| runtime_pins.get(level.join(name).as_path()))
    });
    if let Some(pin_row) = pin.and_then(|pin| runtime_pin_row(pin, owner)) {
        rows.push(pin_row);
    } else if !requested {
        let mut none = row(
            project,
            owner,
            JVM_TOOLCHAIN_ECOSYSTEM,
            JAVA,
            DependencyEvidenceKind::Constraint,
            DependencyScope::Unknown,
            0..0,
        );
        none.conditions = vec![condition("java.runtime_evidence", "none")];
        rows.push(none);
    }
}

/// The JDK a version-manager file selects. `.java-version` holds the
/// version, `.sdkmanrc` a `java=` line and `.tool-versions` a `java` line;
/// a distribution name before or after the version (`temurin-17.0.2`,
/// `17.0.2-tem`) is kept as a condition. A pin with fewer than three numeric
/// parts names a release line, not one JDK, so it is a constraint.
fn runtime_pin_row(input: &Input<'_>, owner: Option<&str>) -> Option<DependencyEvidence> {
    let name = input.path.file_name()?.to_str()?;
    let value = input.source.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = match name {
            ".sdkmanrc" => trimmed.strip_prefix("java=")?.trim(),
            ".tool-versions" => {
                let mut fields = trimmed.split_whitespace();
                (fields.next()? == JAVA).then_some(())?;
                fields.next()?
            }
            _ => trimmed,
        };
        (!value.is_empty() && !trimmed.starts_with('#')).then_some(value)
    })?;
    // `value` is a slice of the source, so its offset is exact.
    let start = value.as_ptr() as usize - input.source.as_ptr() as usize;
    let (version, distribution) = match value.split_once('-') {
        Some((head, tail)) if head.starts_with(|c: char| c.is_ascii_digit()) => (head, Some(tail)),
        Some((head, tail)) => (tail, Some(head)),
        None => (value, None),
    };
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let exact = version.split('.').filter(|part| !part.is_empty()).count() >= 3;
    let mut pin = row(
        input,
        owner,
        JVM_TOOLCHAIN_ECOSYSTEM,
        JAVA,
        if exact {
            DependencyEvidenceKind::Locked
        } else {
            DependencyEvidenceKind::Constraint
        },
        DependencyScope::Unknown,
        start..start + value.len(),
    );
    if exact {
        pin.exact_version = Some(version.to_owned());
    } else {
        pin.version_requirement = Some(version.to_owned());
    }
    pin.conditions = vec![
        condition("java.runtime_evidence", name),
        condition("java.runtime_override", "unobserved"),
    ];
    if let Some(distribution) = distribution {
        pin.conditions
            .push(condition("java.distribution", distribution));
    }
    Some(pin)
}

/// One version in Maven's `ComparableVersion` order: items split at `.`,
/// `-` and digit/letter transitions, `-` and transitions opening a sublist;
/// trailing zeros and release qualifiers normalized away; qualifiers ordered
/// `alpha < beta < milestone < rc = cr < snapshot < "" = ga = final = release
/// < sp`, then any other qualifier lexically.
#[derive(Debug, Clone)]
pub struct MavenVersion {
    items: Vec<VersionItem>,
}

#[derive(Debug, Clone)]
enum VersionItem {
    /// Decimal digits without leading zeros; empty is zero.
    Int(String),
    /// A lowercase qualifier after aliasing.
    Text(String),
    List(Vec<VersionItem>),
}

const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
/// Index of the release qualifier in [`QUALIFIERS`].
const RELEASE: usize = 5;
/// Bounds the sublist depth that ordering recurses through.
const MAX_VERSION_BYTES: usize = 256;

impl MavenVersion {
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty()
            || text.len() > MAX_VERSION_BYTES
            || text.contains(|c: char| {
                c.is_whitespace() || matches!(c, ',' | '[' | ']' | '(' | ')' | '$' | '{' | '}')
            })
        {
            return Err(format!("{text:?} is not a Maven version"));
        }
        let version = text.to_ascii_lowercase();
        let bytes = version.as_bytes();
        // Each open list is the last element of the one below it, so the stack
        // holds the whole tree until the end folds it back together.
        let mut stack = vec![Vec::new()];
        let mut digit = false;
        let mut start = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            let list = stack.last_mut().expect("root list");
            match byte {
                b'.' | b'-' => {
                    list.push(if index == start {
                        VersionItem::Int(String::new())
                    } else {
                        version_item(digit, &version[start..index], false)
                    });
                    start = index + 1;
                    if byte == b'-' {
                        stack.push(Vec::new());
                    }
                }
                b'0'..=b'9' => {
                    if !digit && index > start {
                        // `1.0.0.X1 < 1.0.0-X2`: a qualifier before a number
                        // opens a sublist as `-` would.
                        if !list.is_empty() {
                            stack.push(Vec::new());
                        }
                        let list = stack.last_mut().expect("root list");
                        list.push(version_item(false, &version[start..index], true));
                        start = index;
                        stack.push(Vec::new());
                    }
                    digit = true;
                }
                _ => {
                    if digit && index > start {
                        list.push(version_item(true, &version[start..index], false));
                        start = index;
                        stack.push(Vec::new());
                    }
                    digit = false;
                }
            }
        }
        if bytes.len() > start {
            if !digit && !stack.last().expect("root list").is_empty() {
                stack.push(Vec::new());
            }
            stack.last_mut().expect("root list").push(version_item(
                digit,
                &version[start..],
                false,
            ));
        }
        while stack.len() > 1 {
            let mut child = stack.pop().expect("more than one list");
            normalize(&mut child);
            stack
                .last_mut()
                .expect("root list")
                .push(VersionItem::List(child));
        }
        let mut items = stack.pop().expect("root list");
        normalize(&mut items);
        Ok(Self { items })
    }
}

fn version_item(digit: bool, text: &str, followed_by_digit: bool) -> VersionItem {
    if digit {
        return VersionItem::Int(text.trim_start_matches('0').to_owned());
    }
    let text = match text {
        "a" if followed_by_digit => "alpha",
        "b" if followed_by_digit => "beta",
        "m" if followed_by_digit => "milestone",
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        text => text,
    };
    VersionItem::Text(text.to_owned())
}

impl VersionItem {
    fn is_null(&self) -> bool {
        match self {
            Self::Int(digits) => digits.is_empty(),
            Self::Text(text) => text.is_empty(),
            Self::List(items) => items.is_empty(),
        }
    }
}

/// Drop trailing null items, looking through trailing sublists.
fn normalize(items: &mut Vec<VersionItem>) {
    let mut index = items.len();
    while index > 0 {
        index -= 1;
        if items[index].is_null() {
            items.remove(index);
        } else if !matches!(items[index], VersionItem::List(_)) {
            break;
        }
    }
}

fn qualifier_rank(text: &str) -> String {
    match QUALIFIERS.iter().position(|qualifier| *qualifier == text) {
        Some(index) => index.to_string(),
        None => format!("{}-{text}", QUALIFIERS.len()),
    }
}

/// `ComparableVersion`'s item order; `None` is a missing item.
fn compare_items(left: &VersionItem, right: Option<&VersionItem>) -> Ordering {
    use VersionItem::{Int, List, Text};
    match (left, right) {
        (Int(digits), None) => {
            if digits.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Int(left), Some(Int(right))) => left.len().cmp(&right.len()).then(left.cmp(right)),
        (Int(_), Some(_)) => Ordering::Greater,
        (Text(text), None) => qualifier_rank(text).cmp(&RELEASE.to_string()),
        (Text(_), Some(Int(_))) => Ordering::Less,
        (Text(left), Some(Text(right))) => qualifier_rank(left).cmp(&qualifier_rank(right)),
        (Text(_), Some(List(_))) => Ordering::Less,
        (List(items), None) => items
            .iter()
            .map(|item| compare_items(item, None))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal),
        (List(_), Some(Int(_))) => Ordering::Less,
        (List(_), Some(Text(_))) => Ordering::Greater,
        (List(left), Some(List(right))) => compare_lists(left, right),
    }
}

fn compare_lists(left: &[VersionItem], right: &[VersionItem]) -> Ordering {
    for index in 0..left.len().max(right.len()) {
        let ordering = match (left.get(index), right.get(index)) {
            (Some(left), right) => compare_items(left, right),
            (None, Some(right)) => compare_items(right, None).reverse(),
            (None, None) => unreachable!("index below the longer length"),
        };
        if ordering.is_ne() {
            return ordering;
        }
    }
    Ordering::Equal
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_lists(&self.items, &other.items)
    }
}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for MavenVersion {}

/// An authored affected-version range over Maven versions. Alternatives are
/// joined by `||`; each is Maven range syntax, a comma-joined union of
/// intervals (`[1.0,2.0)`, `(,1.0],[1.2,)`, `[1.2.3]`), or whitespace-joined
/// comparators (`>=1.0 <1.11.0`). A bare version is Maven's soft
/// requirement, not a set of versions, so it is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenVersionRange {
    alternatives: Vec<Vec<(VersionComparator, MavenVersion)>>,
}

impl MavenVersionRange {
    pub fn parse(ecosystem: &str, text: &str) -> Result<Self, String> {
        assert!(
            ecosystem == MAVEN_ECOSYSTEM || ecosystem == JVM_TOOLCHAIN_ECOSYSTEM,
            "Maven version range for {ecosystem}"
        );
        let mut alternatives = Vec::new();
        for alternative in text.split("||").map(str::trim) {
            if alternative.starts_with(['[', '(']) {
                let mut rest = alternative;
                while !rest.is_empty() {
                    let end = rest
                        .find([']', ')'])
                        .ok_or_else(|| format!("{alternative:?} has an unclosed interval"))?;
                    alternatives.push(parse_version_interval(&rest[..=end], MavenVersion::parse)?);
                    rest = rest[end + 1..].trim_start();
                    if let Some(next) = rest.strip_prefix(',') {
                        rest = next.trim_start();
                        if rest.is_empty() {
                            return Err(format!("{alternative:?} ends with a comma"));
                        }
                    } else if !rest.is_empty() {
                        return Err(format!("{alternative:?} joins intervals without a comma"));
                    }
                }
            } else if alternative.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                return Err(format!(
                    "{alternative:?} is a Maven soft requirement, not a range; write [{alternative}] for one version"
                ));
            } else {
                let bounds = parse_version_comparators(alternative, MavenVersion::parse)?;
                if bounds.is_empty() {
                    return Err("an empty Maven version range alternative".into());
                }
                alternatives.push(bounds);
            }
        }
        Ok(Self { alternatives })
    }

    pub fn matches(&self, version: &MavenVersion) -> bool {
        version_bounds_admit(&self.alternatives, version)
    }
}

/// Whether one complete locked or installed Maven or JDK row's exact version
/// is in `range`. Other rows have no exact version to test and stay unknown.
pub fn maven_dependency_version_matches(
    row: &DependencyEvidence,
    range: &MavenVersionRange,
) -> Result<Option<bool>, String> {
    if !(row.ecosystem == MAVEN_ECOSYSTEM || row.ecosystem == JVM_TOOLCHAIN_ECOSYSTEM)
        || !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
    {
        return Ok(None);
    }
    row.exact_version
        .as_deref()
        .map(|version| MavenVersion::parse(version).map(|version| range.matches(&version)))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Maven's own `ComparableVersionTest` orderings, an oracle independent
    /// of this port.
    #[test]
    fn maven_version_order_matches_comparable_version() {
        let qualifiers = [
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ];
        let numbers = [
            "2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
            "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11",
            "11", "11.a", "11b", "11c", "11m",
        ];
        for ordered in [&qualifiers[..], &numbers[..]] {
            for (index, left) in ordered.iter().enumerate() {
                for right in &ordered[index + 1..] {
                    let (low, high) = (
                        MavenVersion::parse(left).unwrap(),
                        MavenVersion::parse(right).unwrap(),
                    );
                    assert!(low < high, "{left} < {right}");
                }
            }
        }
        for (left, right) in [
            ("1", "1.0.0"),
            ("1-ga", "1"),
            ("1.0-final", "1.0"),
            ("1-cr1", "1-rc1"),
            ("1a1", "1-alpha-1"),
            ("1.0.RELEASE", "1.0"),
        ] {
            assert_eq!(
                MavenVersion::parse(left).unwrap(),
                MavenVersion::parse(right).unwrap(),
                "{left} = {right}"
            );
        }
    }

    #[test]
    fn maven_ranges_accept_interval_unions_and_comparators() {
        let cases = [
            ("[1.0,2.0)", "1.5", true),
            ("[1.0,2.0)", "2.0", false),
            ("[1.0,2.0)", "2.0-rc1", true),
            ("(,1.0],[1.2,)", "1.1", false),
            ("(,1.0],[1.2,)", "1.2.1", true),
            ("[1.2.3]", "1.2.3.0", true),
            ("<10.2.10", "10.2.9", true),
            ("<10.2.10", "10.2.10", false),
            (">=2.0 <2.17.1 || [2.3.0]", "2.3", true),
        ];
        for (range, version, expected) in cases {
            let parsed = MavenVersionRange::parse(MAVEN_ECOSYSTEM, range).unwrap();
            assert_eq!(
                parsed.matches(&MavenVersion::parse(version).unwrap()),
                expected,
                "{version} in {range}"
            );
        }
        for invalid in [
            "1.0",
            "[1.0,2.0",
            "[1.0][2.0]",
            "[1.0],",
            "(1.0)",
            "[2.0,1.0]",
            "",
        ] {
            assert!(
                MavenVersionRange::parse(MAVEN_ECOSYSTEM, invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
