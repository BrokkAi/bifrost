//! Files-only NuGet evidence for the shared #2442 dependency contract (#8295).
//!
//! The store hands this module one bounded batch of retained configuration
//! snapshots; nothing here reads the filesystem, runs `dotnet`, or outlives the
//! publication call. Each file kind keeps its own evidence kind:
//!
//! - a project's `PackageReference` is a declared requirement, never a version;
//! - a central `PackageVersion` in `Directory.Packages.props` is a constraint;
//! - a `packages.lock.json` entry is a locked exact version;
//! - a `project.assets.json` target library is an installed (restored) version.
//!
//! `FrameworkReference` shared frameworks are declared rows with source
//! `framework`, separate from packages, because restore does not pin them.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::configuration::{
    ConfigurationIngestionOutcome, ingest_configuration_document,
};
use brokk_bifrost_analysis::analyzer::semantic::topology::DependencyScope;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
};
use brokk_bifrost_analysis::analyzer::topology::{
    TopologyCompleteness, TopologyEntity, TopologyEntityKind, TopologyProvenance,
    TopologyProvenanceKind,
};
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationNodeKind, ConfigurationRouteSelector,
};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value;

use super::compilation::{attribute, element_attributes};

const ECOSYSTEM: &str = "nuget";
const FRAMEWORK_SOURCE: &str = "framework";

pub(crate) fn is_nuget_evidence_input(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.eq_ignore_ascii_case("packages.lock.json")
        || name.eq_ignore_ascii_case("project.assets.json")
        || name.eq_ignore_ascii_case("Directory.Packages.props")
        || path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("csproj"))
}

/// The #2448 build-project identity a NuGet row names in `declared_by`.
fn project_owner(project: &Path) -> String {
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!("nuget:{}", portable(project)),
        owner: None,
        root: project.parent().map(Path::to_path_buf),
        provenance: vec![TopologyProvenance::new(
            project,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
    .id()
}

fn portable(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn condition(kind: &str, value: impl Into<String>) -> DependencyCondition {
    DependencyCondition {
        kind: kind.into(),
        value: value.into(),
    }
}

fn gap(
    kind: DependencyEvidenceGapKind,
    path: &Path,
    range: std::ops::Range<usize>,
    message: impl Into<String>,
) -> DependencyEvidenceGap {
    DependencyEvidenceGap {
        kind,
        build_file: path.to_path_buf(),
        byte_range: range,
        message: message.into(),
    }
}

/// Git blob identity of decoded text. A mismatch with the retained OID means
/// decoding was lossy, so the text cannot cite exact byte ranges.
fn blob_oid(text: &str) -> String {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(format!("blob {}\0", text.len()).as_bytes());
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

struct Input<'a> {
    path: &'a Path,
    text: &'a str,
    digest: String,
}

/// Prepare NuGet evidence from the retained configuration snapshots of one
/// selected C# revision.
pub(crate) fn csharp_selected_dependency_file_evidence(
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let mut evidence = DependencyFileEvidence::default();
    let mut inputs = Vec::new();
    for (file, source) in selected
        .iter()
        .filter(|(file, _)| is_nuget_evidence_input(file.rel_path()))
    {
        let digest = source.oid().to_string();
        if blob_oid(source.source()) != digest {
            evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                file.rel_path(),
                0..0,
                "NuGet input is not exact UTF-8 evidence",
            ));
            continue;
        }
        evidence.files_read += 1;
        evidence.bytes_read += source.source().len();
        inputs.push(Input {
            path: file.rel_path(),
            text: source.source(),
            digest,
        });
    }
    let projects = inputs
        .iter()
        .filter(|input| has_extension(input.path, "csproj"))
        .map(|input| input.path)
        .collect::<Vec<_>>();
    // Capture retains an absent Directory.Packages.props as empty bytes.
    let mut central = BTreeMap::<PathBuf, CentralVersions>::new();
    for input in inputs.iter().filter(|input| {
        is_named(input.path, "Directory.Packages.props") && !input.text.trim().is_empty()
    }) {
        match parse_msbuild(input.text) {
            Ok(document) => {
                let directory = parent(input.path);
                let versions = central.entry(directory).or_insert_with(|| CentralVersions {
                    path: input.path.to_path_buf(),
                    versions: BTreeMap::new(),
                });
                for item in document
                    .items
                    .iter()
                    .filter(|item| item.kind == "PackageVersion")
                {
                    versions
                        .versions
                        .insert(item.include.to_ascii_lowercase(), item.version.clone());
                    evidence.rows.push(item.row(
                        input,
                        DependencyEvidenceKind::Constraint,
                        None,
                        Vec::new(),
                    ));
                }
            }
            Err(error) => evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                0..0,
                format!("Directory.Packages.props is not well-formed MSBuild XML: {error}"),
            )),
        }
    }
    for input in &inputs {
        let result = if has_extension(input.path, "csproj") {
            project_rows(input, &central, &mut evidence)
        } else if is_named(input.path, "packages.lock.json") {
            lock_rows(input, &projects, &mut evidence)
        } else if is_named(input.path, "project.assets.json") {
            assets_rows(input, &projects, &mut evidence)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Malformed,
                input.path,
                0..0,
                error,
            ));
        }
        if evidence.rows.len() > limits.max_rows {
            evidence.rows.truncate(limits.max_rows);
            evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Limit,
                input.path,
                0..0,
                "NuGet dependency row cap exceeded",
            ));
            break;
        }
    }
    evidence
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn is_named(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn parent(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_default()
}

struct CentralVersions {
    path: PathBuf,
    versions: BTreeMap<String, Option<String>>,
}

/// The nearest ancestor `Directory.Packages.props`, as MSBuild imports it.
fn central_for<'a>(
    project: &Path,
    central: &'a BTreeMap<PathBuf, CentralVersions>,
) -> Option<&'a CentralVersions> {
    project
        .parent()?
        .ancestors()
        .find_map(|directory| central.get(directory))
}

/// One NuGet item read from MSBuild XML, with its exact element span.
struct MsbuildItem {
    kind: &'static str,
    include: String,
    version: Option<String>,
    version_override: Option<String>,
    private_assets: Option<String>,
    conditions: Vec<String>,
    range: std::ops::Range<usize>,
}

impl MsbuildItem {
    fn row(
        &self,
        input: &Input<'_>,
        kind: DependencyEvidenceKind,
        declared_by: Option<String>,
        mut conditions: Vec<DependencyCondition>,
    ) -> DependencyEvidence {
        conditions.extend(
            self.conditions
                .iter()
                .map(|value| condition("msbuild.condition", value)),
        );
        let requirement = self.version_override.clone().or(self.version.clone());
        DependencyEvidence {
            ecosystem: ECOSYSTEM.into(),
            package: self.include.clone(),
            kind,
            complete: requirement.as_deref().is_some_and(is_static_value),
            version_requirement: requirement,
            exact_version: None,
            source: None,
            locator: Some(format!(
                "{}#{}:{}",
                portable(input.path),
                self.kind,
                self.include
            )),
            declared_by,
            scope: DependencyScope::Compile,
            conditions,
            build_file: input.path.to_path_buf(),
            source_digest: input.digest.clone(),
            byte_range: self.range.clone(),
        }
    }
}

/// An MSBuild property or item function makes a value unknowable statically.
fn is_static_value(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains("$(") && !value.contains("@(")
}

struct MsbuildDocument {
    items: Vec<MsbuildItem>,
}

const NUGET_ITEMS: [&str; 3] = ["PackageReference", "PackageVersion", "FrameworkReference"];

/// Read NuGet items and their metadata. Unknown elements are skipped; any XML
/// error makes the whole file malformed rather than partially trusted.
fn parse_msbuild(source: &str) -> Result<MsbuildDocument, String> {
    let mut reader = Reader::from_str(source);
    let mut items = Vec::new();
    // Each open element's MSBuild `Condition`, so an item keeps its group's.
    let mut stack = Vec::<Option<String>>::new();
    let mut open_item = None::<(usize, MsbuildItem)>;
    let mut metadata = None::<(String, String)>;
    loop {
        let start = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|error| error.to_string())?;
        let end = reader.buffer_position() as usize;
        match event {
            Event::Start(ref element) | Event::Empty(ref element) => {
                let empty = matches!(event, Event::Empty(_));
                let attributes = element_attributes(&reader, element)
                    .ok_or("an attribute is not well-formed XML 1.0 text")?;
                let name = String::from_utf8_lossy(element.local_name().as_ref()).into_owned();
                if open_item.is_some() {
                    if !empty {
                        metadata = Some((name, String::new()));
                    }
                } else if let Some(kind) = NUGET_ITEMS
                    .into_iter()
                    .find(|kind| kind.eq_ignore_ascii_case(&name))
                    && let Some(include) = attribute(&attributes, "Include")
                {
                    let mut conditions = stack.iter().flatten().cloned().collect::<Vec<_>>();
                    conditions.extend(attribute(&attributes, "Condition").map(str::to_owned));
                    let item = MsbuildItem {
                        kind,
                        include: include.trim().to_owned(),
                        version: attribute(&attributes, "Version").map(str::to_owned),
                        version_override: attribute(&attributes, "VersionOverride")
                            .map(str::to_owned),
                        private_assets: attribute(&attributes, "PrivateAssets").map(str::to_owned),
                        conditions,
                        range: start..end,
                    };
                    if empty {
                        items.push(item);
                    } else {
                        open_item = Some((stack.len(), item));
                    }
                }
                if !empty {
                    stack.push(attribute(&attributes, "Condition").map(str::to_owned));
                }
            }
            Event::Text(text) => {
                if let Some((_, value)) = metadata.as_mut() {
                    value.push_str(&text.xml10_content().map_err(|error| error.to_string())?);
                }
            }
            Event::End(_) => {
                stack.pop();
                if let Some((name, value)) = metadata.take() {
                    let (_, item) = open_item.as_mut().expect("metadata belongs to an item");
                    let value = Some(value.trim().to_owned());
                    if name.eq_ignore_ascii_case("Version") {
                        item.version = value;
                    } else if name.eq_ignore_ascii_case("VersionOverride") {
                        item.version_override = value;
                    } else if name.eq_ignore_ascii_case("PrivateAssets") {
                        item.private_assets = value;
                    }
                } else if open_item
                    .as_ref()
                    .is_some_and(|(depth, _)| *depth == stack.len())
                {
                    let (_, mut item) = open_item.take().expect("open item was checked");
                    item.range.end = end;
                    items.push(item);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(MsbuildDocument { items })
}

fn project_rows(
    input: &Input<'_>,
    central: &BTreeMap<PathBuf, CentralVersions>,
    evidence: &mut DependencyFileEvidence,
) -> Result<(), String> {
    let document = parse_msbuild(input.text)
        .map_err(|error| format!("project is not well-formed MSBuild XML: {error}"))?;
    let owner = project_owner(input.path);
    for item in &document.items {
        let mut conditions = Vec::new();
        if let Some(private) = &item.private_assets {
            conditions.push(condition("nuget.private_assets", private.clone()));
        }
        let mut row = match item.kind {
            "PackageReference" => {
                let mut row = item.row(
                    input,
                    DependencyEvidenceKind::Declared,
                    Some(owner.clone()),
                    conditions,
                );
                if row.version_requirement.is_none()
                    && let Some(central) = central_for(input.path, central)
                    && let Some(version) = central.versions.get(&item.include.to_ascii_lowercase())
                {
                    row.complete = version.as_deref().is_some_and(is_static_value);
                    row.version_requirement = version.clone();
                    row.conditions.push(condition(
                        "nuget.central_version_file",
                        portable(&central.path),
                    ));
                }
                if row.version_requirement.is_none() {
                    evidence.gaps.push(gap(
                        DependencyEvidenceGapKind::Unresolved,
                        input.path,
                        item.range.clone(),
                        format!("PackageReference {} has no static version", item.include),
                    ));
                }
                row
            }
            "FrameworkReference" => {
                let mut row = item.row(
                    input,
                    DependencyEvidenceKind::Declared,
                    Some(owner.clone()),
                    conditions,
                );
                // The runtime, not restore, chooses the shared framework version.
                row.source = Some(FRAMEWORK_SOURCE.into());
                row.scope = DependencyScope::Provided;
                row.complete = true;
                row
            }
            // A central version outside Directory.Packages.props.
            _ => item.row(input, DependencyEvidenceKind::Constraint, None, conditions),
        };
        row.conditions
            .sort_by(|left, right| (&left.kind, &left.value).cmp(&(&right.kind, &right.value)));
        evidence.rows.push(row);
    }
    Ok(())
}

/// The one project in the lock or assets file's project directory. NuGet
/// writes these files per project, so two candidates cannot be told apart.
fn owning_project(
    directory: &Path,
    projects: &[&Path],
    project_name: Option<&str>,
) -> Result<String, String> {
    let candidates = projects
        .iter()
        .filter(|project| project.parent().unwrap_or(Path::new("")) == directory)
        .filter(|project| {
            project_name.is_none_or(|name| {
                project
                    .file_stem()
                    .is_some_and(|stem| stem.eq_ignore_ascii_case(name))
            })
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [project] => Ok(project_owner(project)),
        [] => Err(format!(
            "no selected project file in {} owns this NuGet evidence",
            portable(directory)
        )),
        _ => Err(format!(
            "projects {candidates:?} in {} cannot be told apart as this file's owner",
            portable(directory)
        )),
    }
}

/// Exact member spans keyed by the member's key route.
type JsonSpans = BTreeMap<Vec<String>, std::ops::Range<usize>>;

/// Parse JSON once for values and once through the configuration ingester for
/// exact member spans.
fn json_document(input: &Input<'_>) -> Result<(Value, JsonSpans), String> {
    let facts = match ingest_configuration_document(input.path, input.text.as_bytes()) {
        ConfigurationIngestionOutcome::Facts(facts) if facts.completeness().is_complete() => facts,
        outcome => {
            return Err(format!(
                "JSON parser did not establish clean input: {outcome:?}"
            ));
        }
    };
    let mut spans = BTreeMap::new();
    for fact in facts.facts() {
        if !matches!(fact.kind(), ConfigurationNodeKind::Member { .. }) {
            continue;
        }
        let mut route = Vec::new();
        for segment in fact.route().segments() {
            match segment.selector() {
                ConfigurationRouteSelector::Key { occurrence, .. } if *occurrence > 1 => {
                    return Err("duplicate JSON member".into());
                }
                ConfigurationRouteSelector::Key { name, .. } => route.push(name.clone()),
                ConfigurationRouteSelector::Index(_) => break,
            }
        }
        let range = fact.evidence();
        spans.insert(route, range.start_byte()..range.end_byte());
    }
    let value = serde_json::from_str(input.text).map_err(|error| error.to_string())?;
    Ok((value, spans))
}

fn span(spans: &JsonSpans, route: &[&str]) -> Result<std::ops::Range<usize>, String> {
    let key = route
        .iter()
        .map(|part| (*part).to_owned())
        .collect::<Vec<_>>();
    spans
        .get(&key)
        .cloned()
        .ok_or_else(|| format!("JSON member {route:?} has no source span"))
}

/// A target key is `<framework>` or `<framework>/<runtime identifier>`.
fn target_conditions(target: &str) -> Vec<DependencyCondition> {
    let (framework, runtime) = target
        .split_once('/')
        .map_or((target, None), |(framework, runtime)| {
            (framework, Some(runtime))
        });
    let mut conditions = vec![condition("nuget.target_framework", framework)];
    conditions.extend(runtime.map(|runtime| condition("nuget.runtime_identifier", runtime)));
    conditions
}

fn lock_rows(
    input: &Input<'_>,
    projects: &[&Path],
    evidence: &mut DependencyFileEvidence,
) -> Result<(), String> {
    let (value, spans) = json_document(input)?;
    let owner = match owning_project(&parent(input.path), projects, None) {
        Ok(owner) => Some(owner),
        Err(message) => {
            evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Unresolved,
                input.path,
                0..0,
                message,
            ));
            None
        }
    };
    let targets = value
        .get("dependencies")
        .and_then(Value::as_object)
        .ok_or("packages.lock.json has no dependencies object")?;
    for (target, packages) in targets {
        let packages = packages
            .as_object()
            .ok_or_else(|| format!("lock target {target} is not an object"))?;
        for (package, entry) in packages {
            let range = span(&spans, &["dependencies", target, package])?;
            let kind = entry.get("type").and_then(Value::as_str).unwrap_or("");
            // A project reference is workspace source, not a NuGet package.
            if kind.eq_ignore_ascii_case("Project") {
                continue;
            }
            let resolved = entry.get("resolved").and_then(Value::as_str);
            let complete = resolved.is_some_and(|version| NugetVersion::parse(version).is_ok());
            if !complete {
                evidence.gaps.push(gap(
                    DependencyEvidenceGapKind::Malformed,
                    input.path,
                    range.clone(),
                    format!("locked {package} has no exact NuGet version"),
                ));
            }
            let mut conditions = target_conditions(target);
            conditions.push(condition("nuget.dependency_type", kind));
            evidence.rows.push(DependencyEvidence {
                ecosystem: ECOSYSTEM.into(),
                package: package.clone(),
                kind: DependencyEvidenceKind::Locked,
                version_requirement: entry
                    .get("requested")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                exact_version: resolved.map(str::to_owned),
                source: None,
                locator: Some(format!(
                    "{}#dependencies/{target}/{package}",
                    portable(input.path)
                )),
                declared_by: owner.clone(),
                scope: DependencyScope::Compile,
                conditions,
                build_file: input.path.to_path_buf(),
                source_digest: input.digest.clone(),
                byte_range: range,
                complete,
            });
        }
    }
    Ok(())
}

/// Asset groups NuGet records per target library. `_._` is NuGet's
/// placeholder for an intentionally empty group, so it carries no asset.
const ASSET_ROLES: [&str; 6] = [
    "compile",
    "runtime",
    "native",
    "resource",
    "build",
    "contentFiles",
];

fn assets_rows(
    input: &Input<'_>,
    projects: &[&Path],
    evidence: &mut DependencyFileEvidence,
) -> Result<(), String> {
    // Capture retains an unrestored project's assets file as empty bytes.
    if input.text.trim().is_empty() {
        return Ok(());
    }
    let (value, spans) = json_document(input)?;
    let project_directory = input.path.parent().map(parent).unwrap_or_default();
    let project_name = value
        .pointer("/project/restore/projectName")
        .and_then(Value::as_str);
    let owner = match owning_project(&project_directory, projects, project_name) {
        Ok(owner) => Some(owner),
        Err(message) => {
            evidence.gaps.push(gap(
                DependencyEvidenceGapKind::Unresolved,
                input.path,
                0..0,
                message,
            ));
            None
        }
    };
    let frameworks = value
        .pointer("/project/frameworks")
        .and_then(Value::as_object);
    let targets = value
        .get("targets")
        .and_then(Value::as_object)
        .ok_or("project.assets.json has no targets object")?;
    for (target, libraries) in targets {
        let libraries = libraries
            .as_object()
            .ok_or_else(|| format!("assets target {target} is not an object"))?;
        let framework = target.split_once('/').map_or(target.as_str(), |(f, _)| f);
        // Restore lists each direct dependency of a framework as one
        // `<id> <requested range>` string under the target's framework name.
        let direct = value
            .get("projectFileDependencyGroups")
            .and_then(|groups| groups.get(framework))
            .and_then(Value::as_array);
        for (library, entry) in libraries {
            if entry.get("type").and_then(Value::as_str) != Some("package") {
                continue;
            }
            let range = span(&spans, &["targets", target, library])?;
            let Some((package, version)) = library.rsplit_once('/') else {
                evidence.gaps.push(gap(
                    DependencyEvidenceGapKind::Malformed,
                    input.path,
                    range,
                    format!("assets library {library} has no version"),
                ));
                continue;
            };
            let complete = NugetVersion::parse(version).is_ok();
            let requirement = direct
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .find_map(|dependency| {
                    let (name, requested) = dependency.split_once(' ').unwrap_or((dependency, ""));
                    let requested = requested.trim();
                    (name.eq_ignore_ascii_case(package) && !requested.is_empty())
                        .then_some(requested)
                });
            let mut conditions = target_conditions(target);
            conditions.push(condition("nuget.direct", requirement.is_some().to_string()));
            for role in ASSET_ROLES {
                let present = entry
                    .get(role)
                    .and_then(Value::as_object)
                    .is_some_and(|files| files.keys().any(|file| !file.ends_with("_._")));
                if present {
                    conditions.push(condition("nuget.asset_role", role));
                }
            }
            evidence.rows.push(DependencyEvidence {
                ecosystem: ECOSYSTEM.into(),
                package: package.to_owned(),
                kind: DependencyEvidenceKind::Installed,
                version_requirement: requirement.map(str::to_owned),
                exact_version: Some(version.to_owned()),
                source: None,
                locator: Some(format!(
                    "{}#targets/{target}/{library}",
                    portable(input.path)
                )),
                declared_by: owner.clone(),
                scope: DependencyScope::Compile,
                conditions,
                build_file: input.path.to_path_buf(),
                source_digest: input.digest.clone(),
                byte_range: range,
                complete,
            });
        }
    }
    // Restore's effective shared frameworks include SDK-implied ones, such as
    // Microsoft.AspNetCore.App for a web project with no FrameworkReference.
    for (alias, entry) in frameworks.into_iter().flatten() {
        for name in entry
            .get("frameworkReferences")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|references| references.keys())
        {
            let mut conditions = vec![condition("nuget.target_framework", alias)];
            conditions.push(condition("nuget.restore_framework_reference", "true"));
            evidence.rows.push(DependencyEvidence {
                ecosystem: ECOSYSTEM.into(),
                package: name.clone(),
                kind: DependencyEvidenceKind::Declared,
                version_requirement: None,
                exact_version: None,
                source: Some(FRAMEWORK_SOURCE.into()),
                locator: Some(format!(
                    "{}#project/frameworks/{alias}/frameworkReferences/{name}",
                    portable(input.path)
                )),
                declared_by: owner.clone(),
                scope: DependencyScope::Provided,
                conditions,
                build_file: input.path.to_path_buf(),
                source_digest: input.digest.clone(),
                byte_range: span(
                    &spans,
                    &["project", "frameworks", alias, "frameworkReferences", name],
                )?,
                complete: true,
            });
        }
    }
    Ok(())
}

/// A NuGet version: up to four numeric parts, then an optional dot-separated
/// prerelease. Build metadata does not take part in ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NugetVersion {
    release: [u64; 4],
    prerelease: Vec<PrereleaseLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseLabel {
    Numeric(u64),
    Text(String),
}

impl NugetVersion {
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let without_metadata = text.split_once('+').map_or(text, |(version, _)| version);
        let (release, prerelease) = without_metadata
            .split_once('-')
            .map_or((without_metadata, None), |(release, pre)| {
                (release, Some(pre))
            });
        let parts = release.split('.').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 4 {
            return Err(format!("{text:?} is not a NuGet version"));
        }
        let mut numbers = [0; 4];
        for (slot, part) in numbers.iter_mut().zip(&parts) {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("{text:?} is not a NuGet version"));
            }
            *slot = part
                .parse()
                .map_err(|_| format!("{text:?} has an out-of-range version part"))?;
        }
        let prerelease = match prerelease {
            None => Vec::new(),
            Some(labels) => labels
                .split('.')
                .map(|label| {
                    if label.is_empty()
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    {
                        Err(format!("{text:?} has an invalid prerelease label"))
                    } else if label.bytes().all(|byte| byte.is_ascii_digit()) {
                        label
                            .parse()
                            .map(PrereleaseLabel::Numeric)
                            .map_err(|_| format!("{text:?} has an out-of-range prerelease label"))
                    } else {
                        Ok(PrereleaseLabel::Text(label.to_owned()))
                    }
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            release: numbers,
            prerelease,
        })
    }
}

impl Ord for NugetVersion {
    /// NuGet's `VersionComparer.Default`: release parts, then a release above
    /// any prerelease, then labels pairwise, numeric below alphanumeric and
    /// alphanumeric case-insensitive; a shorter equal prefix sorts first.
    fn cmp(&self, other: &Self) -> Ordering {
        self.release.cmp(&other.release).then_with(|| {
            match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (left, right) in self.prerelease.iter().zip(&other.prerelease) {
                        let ordering = match (left, right) {
                            (PrereleaseLabel::Numeric(left), PrereleaseLabel::Numeric(right)) => {
                                left.cmp(right)
                            }
                            (PrereleaseLabel::Numeric(_), PrereleaseLabel::Text(_)) => {
                                Ordering::Less
                            }
                            (PrereleaseLabel::Text(_), PrereleaseLabel::Numeric(_)) => {
                                Ordering::Greater
                            }
                            (PrereleaseLabel::Text(left), PrereleaseLabel::Text(right)) => {
                                left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
                            }
                        };
                        if ordering != Ordering::Equal {
                            return ordering;
                        }
                    }
                    self.prerelease.len().cmp(&other.prerelease.len())
                }
            }
        })
    }
}

impl PartialOrd for NugetVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparator {
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Equal,
}

/// An authored affected-version range over NuGet versions. Alternatives are
/// joined by `||`; each is NuGet interval notation (`[1.0,2.0)`, `[1.2.3]`,
/// `(,1.0]`), a bare NuGet minimum (`1.0`), or whitespace-joined comparators
/// (`>=1.0 <1.11.0`). Floating versions name a restore policy, not a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NugetVersionRange {
    alternatives: Vec<Vec<(Comparator, NugetVersion)>>,
}

impl NugetVersionRange {
    pub fn parse(text: &str) -> Result<Self, String> {
        let alternatives = text
            .split("||")
            .map(|alternative| {
                let alternative = alternative.trim();
                if alternative.contains('*') {
                    return Err(format!(
                        "{alternative:?} is a floating version, not a version range"
                    ));
                }
                let bounds = if alternative.starts_with(['[', '(']) {
                    interval(alternative)?
                } else {
                    comparators(alternative)?
                };
                if bounds.is_empty() {
                    return Err("an empty NuGet version range alternative".into());
                }
                Ok(bounds)
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { alternatives })
    }

    pub fn matches(&self, version: &NugetVersion) -> bool {
        self.alternatives.iter().any(|bounds| {
            bounds.iter().all(|(comparator, bound)| {
                let ordering = version.cmp(bound);
                match comparator {
                    Comparator::Less => ordering == Ordering::Less,
                    Comparator::LessOrEqual => ordering != Ordering::Greater,
                    Comparator::Greater => ordering == Ordering::Greater,
                    Comparator::GreaterOrEqual => ordering != Ordering::Less,
                    Comparator::Equal => ordering == Ordering::Equal,
                }
            })
        })
    }
}

fn interval(text: &str) -> Result<Vec<(Comparator, NugetVersion)>, String> {
    let invalid = || format!("{text:?} is not NuGet interval notation");
    let inclusive_lower = text.starts_with('[');
    let inclusive_upper = text.ends_with(']');
    if !text.ends_with([']', ')']) || text.len() < 2 {
        return Err(invalid());
    }
    let inner = &text[1..text.len() - 1];
    let Some((lower, upper)) = inner.split_once(',') else {
        // Only `[1.0]` is an exact interval; `(1.0)` is empty.
        if !(inclusive_lower && inclusive_upper) {
            return Err(invalid());
        }
        return Ok(vec![(Comparator::Equal, NugetVersion::parse(inner)?)]);
    };
    let (lower, upper) = (lower.trim(), upper.trim());
    if (lower.is_empty() && upper.is_empty()) || upper.contains(',') {
        return Err(invalid());
    }
    let mut bounds = Vec::new();
    if !lower.is_empty() {
        let comparator = if inclusive_lower {
            Comparator::GreaterOrEqual
        } else {
            Comparator::Greater
        };
        bounds.push((comparator, NugetVersion::parse(lower)?));
    }
    if !upper.is_empty() {
        let comparator = if inclusive_upper {
            Comparator::LessOrEqual
        } else {
            Comparator::Less
        };
        bounds.push((comparator, NugetVersion::parse(upper)?));
    }
    if let [(_, lower), (_, upper)] = bounds.as_slice()
        && lower > upper
    {
        return Err(format!("{text:?} has a lower bound above its upper bound"));
    }
    Ok(bounds)
}

fn comparators(text: &str) -> Result<Vec<(Comparator, NugetVersion)>, String> {
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    if let [token] = tokens.as_slice()
        && token.starts_with(|first: char| first.is_ascii_digit())
    {
        // NuGet reads a bare version as an inclusive minimum.
        return Ok(vec![(
            Comparator::GreaterOrEqual,
            NugetVersion::parse(token)?,
        )]);
    }
    let mut bounds = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        let (comparator, rest) = [
            (">=", Comparator::GreaterOrEqual),
            ("<=", Comparator::LessOrEqual),
            (">", Comparator::Greater),
            ("<", Comparator::Less),
            ("=", Comparator::Equal),
        ]
        .into_iter()
        .find_map(|(prefix, comparator)| token.strip_prefix(prefix).map(|rest| (comparator, rest)))
        .ok_or_else(|| format!("{token:?} needs a comparator (<, <=, >, >=, =)"))?;
        // Accept `>= 1.0` as well as `>=1.0`.
        let version = if rest.is_empty() {
            index += 1;
            *tokens
                .get(index)
                .ok_or_else(|| format!("{token:?} has no version"))?
        } else {
            rest
        };
        bounds.push((comparator, NugetVersion::parse(version)?));
        index += 1;
    }
    Ok(bounds)
}

/// Whether one complete locked or installed NuGet row's exact version is in
/// `range`. Other rows have no exact version to test and stay unknown.
pub fn nuget_dependency_version_matches(
    row: &DependencyEvidence,
    range: &NugetVersionRange,
) -> Result<Option<bool>, String> {
    if row.ecosystem != ECOSYSTEM
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
        .map(|version| NugetVersion::parse(version).map(|version| range.matches(&version)))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuget_ordering_matches_version_comparer() {
        // NuGet's documented order, including four-part and mixed labels.
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-BETA",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.0.1",
            "1.0.1",
            "1.11.0-preview.1",
            "1.11.0",
        ];
        for pair in ordered.windows(2) {
            let (left, right) = (
                NugetVersion::parse(pair[0]).unwrap(),
                NugetVersion::parse(pair[1]).unwrap(),
            );
            assert!(left < right, "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(
            NugetVersion::parse("1.0").unwrap(),
            NugetVersion::parse("1.0.0.0+build").unwrap()
        );
        assert_eq!(
            NugetVersion::parse("1.0.0-Beta")
                .unwrap()
                .cmp(&NugetVersion::parse("1.0.0-beta").unwrap()),
            Ordering::Equal
        );
    }

    #[test]
    fn nuget_ranges_accept_interval_and_comparator_notation() {
        let cases = [
            ("<1.11.0", "1.11.0-beta", true),
            ("<1.11.0", "1.11.0", false),
            ("[1.0,2.0)", "2.0.0-rc.1", true),
            ("[1.0,2.0)", "2.0", false),
            ("(1.0,2.0]", "1.0", false),
            ("(,1.0]", "1.0.0", true),
            ("[1.2.3]", "1.2.3.0", true),
            ("[1.2.3]", "1.2.4", false),
            ("1.2", "1.2.0", true),
            ("1.2", "1.1.9", false),
            (">= 1.2.0 <1.5.51", "1.5.50", true),
            ("<1.0 || >=2.0", "1.5", false),
            ("<1.0 || >=2.0", "2.1", true),
        ];
        for (range, version, expected) in cases {
            let range_value = NugetVersionRange::parse(range).unwrap();
            assert_eq!(
                range_value.matches(&NugetVersion::parse(version).unwrap()),
                expected,
                "{version} in {range}"
            );
        }
        for invalid in [
            "1.*",
            "(1.0)",
            "[2.0,1.0]",
            "[,]",
            "~1.0",
            "1.0 2.0",
            "[1.0,2.0",
            "",
        ] {
            assert!(NugetVersionRange::parse(invalid).is_err(), "{invalid}");
        }
    }
}
