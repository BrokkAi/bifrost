//! Bounded static Python distribution evidence, independent of API packs.
//!
//! Parsing consumes exact supplied snapshots. No interpreter, environment,
//! package manager, or build backend is consulted. Results live for one
//! acquisition; durable publication belongs to the shared dependency store.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use pep440_rs::{Version, VersionSpecifiers};
use pep508_rs::{PackageName, Requirement, VerbatimUrl, VersionOrUrl};
use toml_edit::{ImDocument, Item, Value};

mod legacy;
mod locks;

pub use crate::analyzer::python::packaging::locks::associate_python_poetry_lock;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap,
    DependencyEvidenceGapKind as Gap, DependencyEvidenceKind as Kind, DependencyFileEvidence,
    DependencyFileEvidenceLimits,
};
use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;

use brokk_bifrost_analysis::analyzer::topology::TopologyCompleteness;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntity;

use brokk_bifrost_analysis::analyzer::topology::TopologyEntityKind;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenance;

use brokk_bifrost_analysis::analyzer::topology::TopologyProvenanceKind;

/// Read only caller-selected inputs through the project snapshot interface.
/// This function is an upstream acquisition seam, never a query-time discovery.
pub fn read_python_packaging_evidence(
    project: &dyn Project,
    paths: &[PathBuf],
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    let mut output = DependencyFileEvidence::default();
    for (attempt, path) in paths.iter().enumerate() {
        if attempt >= limits.max_files
            || output.rows.len().saturating_add(output.gaps.len()) >= limits.max_rows
        {
            push_gap(
                &mut output,
                path,
                0..0,
                Gap::Limit,
                "input/evidence budget exhausted",
            );
            break;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            push_gap(
                &mut output,
                path,
                0..0,
                Gap::Cancelled,
                "acquisition cancelled",
            );
            break;
        }
        if !safe_relative_path(path) {
            push_gap(
                &mut output,
                path,
                0..0,
                Gap::UnsafePath,
                "input must be workspace-relative",
            );
            continue;
        }
        if output.files_read >= limits.max_files || output.bytes_read >= limits.max_total_bytes {
            push_gap(
                &mut output,
                path,
                0..0,
                Gap::Limit,
                "file/total byte budget exhausted",
            );
            break;
        }
        if let Err(message) = check_snapshot_path_boundary(project.root(), path) {
            push_gap(&mut output, path, 0..0, Gap::UnsafePath, &message);
            continue;
        }
        let Some(file) = project.file_by_rel_path(path) else {
            push_gap(
                &mut output,
                path,
                0..0,
                Gap::Missing,
                "selected input is absent from snapshot",
            );
            continue;
        };
        let cap = limits
            .max_file_bytes
            .min(limits.max_total_bytes - output.bytes_read);
        let snapshot = match project.read_source_snapshot_limited(&file, cap) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                push_gap(
                    &mut output,
                    path,
                    0..0,
                    Gap::Limit,
                    "source byte budget exhausted",
                );
                continue;
            }
            Err(error) => {
                push_gap(&mut output, path, 0..0, Gap::Missing, &error.to_string());
                continue;
            }
        };
        let mut parsed = parse_python_packaging_file(
            path,
            &snapshot.oid().to_string(),
            snapshot.source(),
            limits,
            cancellation,
        );
        output.files_read += 1;
        output.bytes_read += snapshot.source().len();
        append_bounded_evidence(&mut output, &mut parsed, path, limits);
    }
    output
}

/// Parse one exact file. Its digest must identify the same bytes as `source`.
pub fn parse_python_packaging_file(
    path: &Path,
    digest: &str,
    source: &str,
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    let mut reader = Reader {
        path,
        digest,
        source,
        limits,
        cancellation,
        output: DependencyFileEvidence::default(),
        owner: None,
        lock_reference_work: 0,
    };
    if source.len() > limits.max_file_bytes || source.len() > limits.max_total_bytes {
        reader.gap(0..0, Gap::Limit, "source byte budget exhausted");
        return reader.output;
    }
    if reader.stopped() {
        return reader.output;
    }
    reader.output.files_read = 1;
    reader.output.bytes_read = source.len();
    match path.file_name().and_then(|name| name.to_str()) {
        Some("setup.py") => reader.setup_py(),
        Some("setup.cfg") => reader.setup_cfg(),
        Some("METADATA") => reader.installed_metadata(),
        Some(name @ ("pyproject.toml" | "uv.lock" | "poetry.lock")) => {
            match ImDocument::parse(source) {
                Ok(document) => match name {
                    "uv.lock" => reader.uv_lock(document.as_item()),
                    "poetry.lock" => reader.poetry_lock(document.as_item()),
                    _ => reader.pyproject(document.as_item()),
                },
                Err(error) => reader.gap(
                    error.span().unwrap_or(0..source.len()),
                    Gap::Malformed,
                    &error.to_string(),
                ),
            }
        }
        _ => reader.gap(
            0..source.len(),
            Gap::Unsupported,
            "unsupported Python packaging format",
        ),
    }
    reader.output
}

fn safe_relative_path(path: &Path) -> bool {
    path.is_relative()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

// Check filesystem authorization, not manifest facts. Missing disk paths can
// be legitimate overlay/revision inputs; their bytes still come exclusively
// from Project. Existing symlinks cannot authorize an outside-workspace read.
fn check_snapshot_path_boundary(root: &Path, path: &Path) -> Result<(), String> {
    let canonical_root = match root.canonicalize() {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot establish workspace path boundary: {error}")),
    };
    match root.join(path).canonicalize() {
        Ok(resolved) if resolved.starts_with(&canonical_root) => Ok(()),
        Ok(resolved) => Err(format!(
            "selected input resolves outside workspace: {}",
            resolved.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot establish selected input path boundary: {error}"
        )),
    }
}

fn push_gap(
    output: &mut DependencyFileEvidence,
    path: &Path,
    range: Range<usize>,
    kind: Gap,
    message: &str,
) {
    output.gaps.push(DependencyEvidenceGap {
        kind,
        build_file: path.to_owned(),
        byte_range: range,
        message: message.to_owned(),
    });
}

fn append_bounded_evidence(
    output: &mut DependencyFileEvidence,
    parsed: &mut DependencyFileEvidence,
    path: &Path,
    limits: &DependencyFileEvidenceLimits,
) {
    let remaining = limits
        .max_rows
        .saturating_sub(output.rows.len() + output.gaps.len());
    let exceeded = parsed.rows.len().saturating_add(parsed.gaps.len()) > remaining;
    // Preserve uncertainty before retaining otherwise complete rows.
    parsed.gaps.truncate(remaining);
    parsed
        .rows
        .truncate(remaining.saturating_sub(parsed.gaps.len()));
    output.rows.append(&mut parsed.rows);
    output.gaps.append(&mut parsed.gaps);
    if exceeded {
        push_gap(
            output,
            path,
            0..0,
            Gap::Limit,
            "aggregate evidence budget exhausted",
        );
    }
}

struct Reader<'a> {
    path: &'a Path,
    digest: &'a str,
    source: &'a str,
    limits: &'a DependencyFileEvidenceLimits,
    cancellation: Option<&'a CancellationToken>,
    output: DependencyFileEvidence,
    owner: Option<String>,
    lock_reference_work: usize,
}

impl Reader<'_> {
    fn gap(&mut self, range: Range<usize>, kind: Gap, message: &str) {
        if self.output.gaps.len() >= self.limits.max_rows {
            if !self.output.gaps.iter().any(|gap| gap.kind == Gap::Limit) {
                push_gap(
                    &mut self.output,
                    self.path,
                    0..0,
                    Gap::Limit,
                    "diagnostic budget exhausted",
                );
            }
            return;
        }
        push_gap(&mut self.output, self.path, range, kind, message);
    }

    fn stopped(&mut self) -> bool {
        let reason = if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            Some((Gap::Cancelled, "parsing cancelled"))
        } else if self
            .output
            .rows
            .len()
            .saturating_add(self.output.gaps.len())
            >= self.limits.max_rows
        {
            Some((Gap::Limit, "row budget exhausted"))
        } else {
            None
        };
        if let Some((kind, message)) = reason {
            if !self.output.gaps.iter().any(|gap| gap.kind == kind) {
                self.gap(0..0, kind, message);
            }
            true
        } else {
            false
        }
    }

    fn row(
        &self,
        package: String,
        kind: Kind,
        range: Range<usize>,
        scope: DependencyScope,
    ) -> DependencyEvidence {
        DependencyEvidence {
            ecosystem: "pypi".to_owned(),
            package,
            kind,
            version_requirement: None,
            exact_version: None,
            source: None,
            locator: None,
            declared_by: self.owner.clone(),
            scope,
            conditions: Vec::new(),
            build_file: self.path.to_owned(),
            source_digest: self.digest.to_owned(),
            byte_range: range,
            complete: true,
        }
    }

    fn requirement(
        &mut self,
        raw: &str,
        range: Range<usize>,
        kind: Kind,
        scope: DependencyScope,
        conditions: &[DependencyCondition],
    ) {
        if self.stopped() {
            return;
        }
        match Requirement::<VerbatimUrl>::from_str(raw) {
            Ok(requirement) => {
                let mut row = self.row(requirement.name.to_string(), kind, range, scope);
                row.locator = Some(raw.to_owned());
                row.conditions.extend_from_slice(conditions);
                row.conditions.extend(
                    requirement
                        .extras
                        .iter()
                        .map(|extra| condition("requested_extra", extra.as_ref())),
                );
                if let Some(marker) = requirement.marker.contents() {
                    row.conditions
                        .push(condition("marker", &marker.to_string()));
                }
                match requirement.version_or_url {
                    Some(VersionOrUrl::VersionSpecifier(specifier)) => {
                        row.version_requirement = Some(specifier.to_string())
                    }
                    Some(VersionOrUrl::Url(url)) => {
                        row.source = Some(
                            url.given()
                                .map(str::to_owned)
                                .unwrap_or_else(|| url.to_string()),
                        )
                    }
                    None => {}
                }
                self.output.rows.push(row);
            }
            Err(error) => self.gap(
                range,
                Gap::Malformed,
                &format!("invalid PEP 508 requirement {raw:?}: {error}"),
            ),
        }
    }

    fn requirement_array(
        &mut self,
        item: &Item,
        scope: DependencyScope,
        conditions: &[DependencyCondition],
    ) {
        let Some(array) = item.as_array() else {
            self.gap(
                item.span().unwrap_or(0..0),
                Gap::Malformed,
                "dependencies must be an array",
            );
            return;
        };
        for value in array {
            if self.stopped() {
                break;
            }
            let range = value.span().unwrap_or(0..0);
            if let Some(raw) = value.as_str() {
                self.requirement(raw, range, Kind::Declared, scope, conditions);
            } else {
                self.gap(range, Gap::Malformed, "dependency must be a string");
            }
        }
    }

    fn pyproject(&mut self, document: &Item) {
        if let Some(project) = document.get("project") {
            if project.as_table_like().is_none() {
                self.gap(
                    project.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "project must be a table",
                );
            } else {
                self.project_identity(project);
                if let Some(dynamic) = project.get("dynamic") {
                    if let Some(array) = dynamic.as_array() {
                        for value in array {
                            if self.stopped() {
                                break;
                            }
                            self.gap(
                                value.span().unwrap_or(0..0),
                                Gap::Unresolved,
                                &format!("dynamic metadata remains unresolved: {value}"),
                            );
                        }
                    } else {
                        self.gap(
                            dynamic.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "dynamic must be an array",
                        );
                    }
                }
                if let Some(item) = project.get("dependencies")
                    && !dynamic_field(project, "dependencies")
                {
                    self.requirement_array(item, DependencyScope::Runtime, &[]);
                }
                if let Some(item) = project.get("optional-dependencies")
                    && !dynamic_field(project, "optional-dependencies")
                {
                    if let Some(table) = item.as_table_like() {
                        for (extra, dependencies) in table.iter() {
                            match pep508_rs::ExtraName::from_str(extra) {
                                Ok(extra) => self.requirement_array(
                                    dependencies,
                                    DependencyScope::Optional,
                                    &[condition("extra", extra.as_ref())],
                                ),
                                Err(error) => self.gap(
                                    dependencies.span().unwrap_or(0..0),
                                    Gap::Malformed,
                                    &error.to_string(),
                                ),
                            }
                        }
                    } else {
                        self.gap(
                            item.span().unwrap_or(0..0),
                            Gap::Malformed,
                            "optional-dependencies must be a table",
                        );
                    }
                }
            }
        }
        if let Some(groups) = document.get("dependency-groups") {
            self.groups(groups);
        }
        if let Some(poetry) = document.get("tool").and_then(|tool| tool.get("poetry")) {
            self.poetry_declarations(poetry);
        }
        if let Some(uv) = document.get("tool").and_then(|tool| tool.get("uv")) {
            if let Some(dependencies) = uv.get("dev-dependencies") {
                self.requirement_array(
                    dependencies,
                    DependencyScope::FeatureGated,
                    &[condition("group", "dev")],
                );
            }
            self.uv_sources(uv);
        }
    }

    fn project_identity(&mut self, project: &Item) {
        let Some(name) = project.get("name") else {
            self.gap(
                project.span().unwrap_or(0..0),
                Gap::Unresolved,
                "project name is absent",
            );
            return;
        };
        let name = match name
            .as_str()
            .and_then(|raw| PackageName::from_str(raw).ok())
        {
            Some(name) => name.to_string(),
            None => {
                self.gap(
                    name.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid distribution name",
                );
                return;
            }
        };
        let entity = python_project_entity(self.path, &name);
        self.owner = Some(entity.id());
        let mut row = self.row(
            name,
            Kind::Declared,
            project.span().unwrap_or(0..self.source.len()),
            DependencyScope::Unknown,
        );
        row.source = Some(format!(
            "workspace:{}",
            self.path.parent().unwrap_or(Path::new("")).display()
        ));
        row.conditions.push(condition("role", "project"));
        if let Some(version) = project.get("version") {
            match version.as_str().and_then(|raw| Version::from_str(raw).ok()) {
                Some(version) => row.exact_version = Some(version.to_string()),
                None => {
                    row.complete = false;
                    self.gap(
                        version.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "invalid PEP 440 project version",
                    );
                }
            }
        }
        if dynamic_field(project, "version") {
            row.exact_version = None;
            if project.get("version").is_some() {
                row.complete = false;
                self.gap(
                    row.byte_range.clone(),
                    Gap::Conflict,
                    "project version is both static and dynamic",
                );
            }
        }
        if let Some(requires) = project.get("requires-python") {
            match requires
                .as_str()
                .and_then(|raw| VersionSpecifiers::from_str(raw).ok())
            {
                Some(requirement) => row
                    .conditions
                    .push(condition("requires_python", &requirement.to_string())),
                None => {
                    row.complete = false;
                    self.gap(
                        requires.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "invalid requires-python",
                    );
                }
            }
        }
        if !self.stopped() {
            self.output.rows.push(row);
        }
    }

    fn groups(&mut self, groups: &Item) {
        let Some(table) = groups.as_table_like() else {
            self.gap(
                groups.span().unwrap_or(0..0),
                Gap::Malformed,
                "dependency-groups must be a table",
            );
            return;
        };
        if table.len() > self.limits.max_rows {
            self.gap(
                groups.span().unwrap_or(0..0),
                Gap::Limit,
                "dependency group index budget exhausted",
            );
            return;
        }
        // PEP 735 requires normalized comparison and rejects collisions.
        // This bounded index belongs only to this file parse.
        let mut normalized = std::collections::HashMap::new();
        for (group, item) in table.iter() {
            let Ok(name) = PackageName::from_str(group) else {
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Malformed,
                    "invalid dependency group name",
                );
                return;
            };
            if normalized.insert(name, item).is_some() {
                self.gap(
                    item.span().unwrap_or(0..0),
                    Gap::Conflict,
                    "dependency group names collide after normalization",
                );
                return;
            }
        }
        for (group, _) in table.iter() {
            if self.stopped() {
                break;
            }
            let group = PackageName::from_str(group).unwrap().to_string();
            let mut stack = vec![(group.to_owned(), vec![group.to_owned()])];
            let mut work = 0;
            while let Some((name, ancestors)) = stack.pop() {
                work += 1;
                if self.stopped() {
                    break;
                }
                if work > self.limits.max_rows || ancestors.len() > self.limits.max_include_depth {
                    self.gap(
                        groups.span().unwrap_or(0..0),
                        Gap::Limit,
                        "group include budget exhausted",
                    );
                    break;
                }
                let Some(item) = normalized.get(&PackageName::from_str(&name).unwrap()) else {
                    self.gap(
                        groups.span().unwrap_or(0..0),
                        Gap::Missing,
                        &format!("included dependency group {name:?} is missing"),
                    );
                    continue;
                };
                let Some(array) = item.as_array() else {
                    self.gap(
                        item.span().unwrap_or(0..0),
                        Gap::Malformed,
                        "dependency group must be an array",
                    );
                    continue;
                };
                for value in array {
                    if self.stopped() {
                        break;
                    }
                    let range = value.span().unwrap_or(0..0);
                    if let Some(raw) = value.as_str() {
                        self.requirement(
                            raw,
                            range,
                            Kind::Declared,
                            DependencyScope::FeatureGated,
                            &[
                                condition("group", &group),
                                condition("declared_group", &name),
                            ],
                        );
                    } else if let Some(include) = value
                        .as_inline_table()
                        .filter(|table| table.len() == 1)
                        .and_then(|table| table.get("include-group"))
                        .and_then(Value::as_str)
                    {
                        let Ok(include) = PackageName::from_str(include) else {
                            self.gap(range, Gap::Malformed, "invalid included group name");
                            continue;
                        };
                        let include = include.to_string();
                        if ancestors.iter().any(|ancestor| ancestor == &include) {
                            self.gap(
                                range,
                                Gap::Cycle,
                                &format!(
                                    "dependency group include cycle: {ancestors:?} -> {include}"
                                ),
                            );
                        } else {
                            if stack.len().saturating_add(work) >= self.limits.max_rows {
                                self.gap(
                                    range,
                                    Gap::Limit,
                                    "pending group include budget exhausted",
                                );
                                break;
                            }
                            let mut next = ancestors.clone();
                            next.push(include.to_owned());
                            stack.push((include.to_owned(), next));
                        }
                    } else {
                        self.gap(
                            range,
                            Gap::Unsupported,
                            "unsupported dependency group entry",
                        );
                    }
                }
            }
        }
    }
}

fn condition(kind: &str, value: &str) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

fn dynamic_field(project: &Item, field: &str) -> bool {
    project
        .get("dynamic")
        .and_then(Item::as_array)
        .is_some_and(|array| array.iter().any(|value| value.as_str() == Some(field)))
}

/// Build ownership identity for a proven normalized distribution declaration.
/// Source/target configuration support remains incomplete until supplied by
/// the shared build topology provider.
pub fn python_project_entity(path: &Path, name: &str) -> TopologyEntity {
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!(
            "python:{}:{name}",
            path.parent()
                .unwrap_or(Path::new(""))
                .to_string_lossy()
                .replace('\\', "/")
        ),
        owner: None,
        root: path.parent().map(Path::to_owned),
        provenance: vec![TopologyProvenance::new(
            path,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Incomplete,
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::python::packaging::*;

    #[test]
    fn groups_compare_normalized_names_and_reject_collisions() {
        let limits = DependencyFileEvidenceLimits::default();
        let groups = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "groups",
            "[project]\nname='x'\n[dependency-groups]\nDev_Test=[{include-group='base.group'}]\nBase_Group=['foo']\n",
            &limits,
            None,
        );
        assert!(groups.complete(), "{groups:?}");
        assert!(
            groups.rows.iter().any(|row| row.package == "foo"
                && row.conditions.contains(&condition("group", "dev-test")))
        );
        let duplicate = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "duplicates",
            "[dependency-groups]\nBase_Group=['foo']\n'base.group'=['bar']\n",
            &limits,
            None,
        );
        assert!(duplicate.gaps.iter().any(|gap| gap.kind == Gap::Conflict));
        assert!(duplicate.rows.is_empty());
    }

    #[test]
    fn pyproject_preserves_pep_semantics_and_unknown_applicability() {
        let source = r#"[project]
name = "Example__Project"
version = "1!2.0rc1+local.1"
requires-python = ">=3.10,<4"
dependencies = ["Foo__Bar[security]>=1.0rc1; sys_platform == 'win32'", "remote @ https://example.test/a.whl"]
[project.optional-dependencies]
Test_Extra = ["other~=2.1"]
[dependency-groups]
dev = ["pytest", {include-group = "base"}]
base = ["wheel"]
"#;
        let result = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "snapshot",
            source,
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert!(result.complete(), "{result:?}");
        let dependency = result
            .rows
            .iter()
            .find(|row| row.package == "foo-bar")
            .unwrap();
        assert!(dependency.exact_version.is_none());
        assert!(
            dependency
                .conditions
                .iter()
                .any(|item| item.kind == "marker")
        );
        assert!(
            dependency
                .conditions
                .contains(&condition("requested_extra", "security"))
        );
        assert_eq!(
            &source[dependency.byte_range.clone()],
            "\"Foo__Bar[security]>=1.0rc1; sys_platform == 'win32'\""
        );
        assert_eq!(
            result.rows[0].exact_version.as_deref(),
            Some("1!2.0rc1+local.1")
        );
        assert!(
            result
                .rows
                .iter()
                .all(|row| row.declared_by == result.rows[0].declared_by)
        );
    }

    #[test]
    fn dynamic_malformed_and_group_cycles_remain_explicit() {
        let result = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "snapshot",
            "[project]\nname='x'\ndynamic=['version']\ndependencies=['bad >= nope']\n[dependency-groups]\na=[{include-group='b'}]\nb=[{include-group='a'}]\n",
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert!(!result.complete());
        for kind in [Gap::Unresolved, Gap::Malformed, Gap::Cycle] {
            assert!(result.gaps.iter().any(|gap| gap.kind == kind), "{result:?}");
        }
        assert!(result.rows[0].exact_version.is_none());
    }
}

/// A selected requirements root has request or constraint semantics explicitly.
#[derive(Debug, Clone)]
pub struct PythonRequirementsInput {
    pub path: PathBuf,
    pub kind: Kind,
    /// Set only from an established declaring build project, never proximity.
    pub declared_by: Option<String>,
}

/// Includes inherit the caller's snapshot and budgets. `-c` always constrains;
/// `-r` inside a constraints file cannot turn its entries into requests.
pub fn read_python_requirements_evidence(
    project: &dyn Project,
    inputs: &[PythonRequirementsInput],
    limits: &DependencyFileEvidenceLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyFileEvidence {
    use brokk_bifrost_core::path_normalization::NormalizePath;
    let mut output = DependencyFileEvidence::default();
    let selected = &inputs[..inputs.len().min(limits.max_files)];
    if let Some(omitted) = inputs.get(selected.len()) {
        push_gap(
            &mut output,
            &omitted.path,
            0..0,
            Gap::Limit,
            "requirements root budget exhausted",
        );
    }
    let mut stack = selected
        .iter()
        .rev()
        .map(|input| (input.clone(), vec![input.path.clone()]))
        .collect::<Vec<_>>();
    let mut attempts = 0;
    while let Some((input, ancestors)) = stack.pop() {
        if attempts >= limits.max_files
            || output.rows.len().saturating_add(output.gaps.len()) >= limits.max_rows
        {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::Limit,
                "requirements input/evidence budget exhausted",
            );
            break;
        }
        attempts += 1;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::Cancelled,
                "include acquisition cancelled",
            );
            break;
        }
        if !matches!(input.kind, Kind::Declared | Kind::Constraint) {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::Malformed,
                "requirements input must request or constrain",
            );
            continue;
        }
        if !safe_relative_path(&input.path) {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::UnsafePath,
                "unsafe requirements root",
            );
            continue;
        }
        if ancestors.len() > limits.max_include_depth
            || output.files_read >= limits.max_files
            || output.bytes_read >= limits.max_total_bytes
            || output.rows.len() >= limits.max_rows
        {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::Limit,
                "requirements acquisition budget exhausted",
            );
            break;
        }
        if let Err(message) = check_snapshot_path_boundary(project.root(), &input.path) {
            push_gap(&mut output, &input.path, 0..0, Gap::UnsafePath, &message);
            continue;
        }
        let Some(file) = project.file_by_rel_path(&input.path) else {
            push_gap(
                &mut output,
                &input.path,
                0..0,
                Gap::Missing,
                "requirements include is missing",
            );
            continue;
        };
        let cap = limits
            .max_file_bytes
            .min(limits.max_total_bytes - output.bytes_read);
        let snapshot = match project.read_source_snapshot_limited(&file, cap) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                push_gap(
                    &mut output,
                    &input.path,
                    0..0,
                    Gap::Limit,
                    "requirements byte budget exhausted",
                );
                continue;
            }
            Err(error) => {
                push_gap(
                    &mut output,
                    &input.path,
                    0..0,
                    Gap::Missing,
                    &error.to_string(),
                );
                continue;
            }
        };
        output.files_read += 1;
        output.bytes_read += snapshot.source().len();
        let digest = snapshot.oid().to_string();
        let mut reader = Reader {
            path: &input.path,
            digest: &digest,
            source: snapshot.source(),
            limits,
            cancellation,
            output: DependencyFileEvidence::default(),
            owner: input.declared_by.clone(),
            lock_reference_work: 0,
        };
        let mut offset = 0;
        let mut logical = String::new();
        let mut start = 0;
        for physical in snapshot.source().split_inclusive('\n') {
            if output.rows.len()
                + output.gaps.len()
                + reader.output.rows.len()
                + reader.output.gaps.len()
                >= limits.max_rows
                || reader.stopped()
            {
                reader.gap(
                    offset..offset,
                    Gap::Limit,
                    "requirements row budget exhausted",
                );
                break;
            }
            if logical.is_empty() {
                start = offset;
            }
            offset += physical.len();
            let line = physical.trim_end_matches(['\n', '\r']);
            if let Some(continued) = line.strip_suffix('\\') {
                logical.push_str(continued);
                logical.push(' ');
                continue;
            }
            logical.push_str(line);
            let raw = requirement_line_without_comment(&logical).trim();
            let range = start..offset;
            if raw.is_empty() {
                logical.clear();
                continue;
            }
            let include = ["--requirement", "--constraint", "-r", "-c"]
                .into_iter()
                .find_map(|option| {
                    let rest = raw.strip_prefix(option)?;
                    if option.starts_with("--")
                        && !rest
                            .chars()
                            .next()
                            .is_none_or(|ch| ch == '=' || ch.is_whitespace())
                    {
                        return None;
                    }
                    Some((option, rest.strip_prefix('=').unwrap_or(rest).trim()))
                });
            if let Some((option, rest)) = include {
                let Some(arguments) = shlex::split(rest).filter(|args| args.len() == 1) else {
                    reader.gap(range, Gap::Malformed, "include must name one local file");
                    logical.clear();
                    continue;
                };
                let included = Path::new(&arguments[0]);
                let absolute = project
                    .root()
                    .join(input.path.parent().unwrap_or(Path::new("")))
                    .join(included)
                    .normalize();
                let rel = absolute.strip_prefix(project.root()).ok();
                if included.is_absolute() || arguments[0].contains([':', '\\']) {
                    reader.gap(
                        range,
                        Gap::UnsafePath,
                        "requirements include escapes the workspace or names a remote/unsafe path",
                    );
                } else if let Some(rel) = rel {
                    let rel = rel.to_owned();
                    if ancestors.contains(&rel) {
                        reader.gap(
                            range,
                            Gap::Cycle,
                            &format!("requirements include cycle: {ancestors:?} -> {rel:?}"),
                        );
                    } else {
                        if attempts + stack.len() >= limits.max_files {
                            reader.gap(
                                range,
                                Gap::Limit,
                                "requirements pending include budget exhausted",
                            );
                            logical.clear();
                            continue;
                        }
                        let mut next = ancestors.clone();
                        next.push(rel.clone());
                        stack.push((
                            PythonRequirementsInput {
                                path: rel,
                                kind: if input.kind == Kind::Constraint
                                    || matches!(option, "--constraint" | "-c")
                                {
                                    Kind::Constraint
                                } else {
                                    Kind::Declared
                                },
                                declared_by: input.declared_by.clone(),
                            },
                            next,
                        ));
                    }
                } else {
                    reader.gap(
                        range,
                        Gap::UnsafePath,
                        "requirements include escapes the workspace",
                    );
                }
            } else if let Some(editable) = raw
                .strip_prefix("--editable ")
                .or_else(|| raw.strip_prefix("-e "))
            {
                let previous = reader.output.rows.len();
                reader.requirement(
                    editable.trim(),
                    range.clone(),
                    input.kind,
                    DependencyScope::Unknown,
                    &[condition("editable", "true")],
                );
                if let Some(row) = reader.output.rows.get_mut(previous)
                    && row.source.is_none()
                {
                    row.complete = false;
                    reader.gap(
                        range,
                        Gap::Unsupported,
                        "editable requirement needs explicit distribution and source",
                    );
                }
            } else if raw.starts_with('-')
                || (raw.contains(" --") && Requirement::<VerbatimUrl>::from_str(raw).is_err())
            {
                reader.gap(
                    range,
                    Gap::Unsupported,
                    &format!("unsupported requirements option retained: {raw}"),
                );
            } else {
                reader.requirement(raw, range, input.kind, DependencyScope::Unknown, &[]);
            }
            logical.clear();
        }
        if !logical.is_empty() {
            reader.gap(
                start..offset,
                Gap::Malformed,
                "unterminated requirements continuation",
            );
        }
        append_bounded_evidence(&mut output, &mut reader.output, &input.path, limits);
    }
    output
}

// Requirements files have line/comment/continuation syntax rather than a
// tree-sitter grammar. Preserve hashes in URLs and quoted marker operands.
fn requirement_line_without_comment(line: &str) -> &str {
    let mut quote = None;
    let mut previous_whitespace = true;
    for (offset, ch) in line.char_indices() {
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
        }
        if ch == '#' && quote.is_none() && previous_whitespace {
            return &line[..offset];
        }
        previous_whitespace = ch.is_whitespace();
    }
    line
}

/// PEP 440 membership for canonical policy evaluators. Declarations and
/// constraints do not become selected versions merely because they are exact.
pub fn python_evidence_matches_version(
    row: &DependencyEvidence,
    requirement: &str,
) -> Option<bool> {
    if row.ecosystem != "pypi"
        || !row.complete
        || !matches!(row.kind, Kind::Locked | Kind::Installed)
    {
        return None;
    }
    let version = Version::from_str(row.exact_version.as_deref()?).ok()?;
    let requirement = VersionSpecifiers::from_str(requirement).ok()?;
    Some(requirement.contains(&version))
}

/// Version disagreement for two facts with the same explicit project owner.
/// `None` means ownership, selection or version evidence is insufficient.
/// Distinct lock alternatives can disagree without selecting an environment;
/// this comparison never turns that difference into an activation claim.
pub fn python_version_evidence_disagrees(
    left: &DependencyEvidence,
    right: &DependencyEvidence,
    target: Option<&PythonPackagingTarget>,
) -> Option<bool> {
    if left.ecosystem != "pypi"
        || right.ecosystem != "pypi"
        || left.package != right.package
        || left.declared_by.is_none()
        || left.declared_by != right.declared_by
        || python_evidence_applies_to_target(left, target) != Some(true)
        || python_evidence_applies_to_target(right, target) != Some(true)
    {
        return None;
    }
    let exact = |row: &DependencyEvidence| {
        matches!(row.kind, Kind::Locked | Kind::Installed)
            .then(|| {
                row.exact_version
                    .as_deref()
                    .and_then(|raw| Version::from_str(raw).ok())
            })
            .flatten()
    };
    match (exact(left), exact(right)) {
        (Some(left), Some(right)) => Some(left != right),
        (None, Some(version)) if matches!(left.kind, Kind::Declared | Kind::Constraint) => {
            let specifier =
                VersionSpecifiers::from_str(left.version_requirement.as_deref().unwrap_or(""))
                    .ok()?;
            Some(!specifier.contains(&version))
        }
        (Some(version), None) if matches!(right.kind, Kind::Declared | Kind::Constraint) => {
            let specifier =
                VersionSpecifiers::from_str(right.version_requirement.as_deref().unwrap_or(""))
                    .ok()?;
            Some(!specifier.contains(&version))
        }
        _ => None,
    }
}

#[cfg(test)]
mod acquisition_tests {

    use crate::analyzer::python::packaging::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
    use std::collections::{BTreeMap, BTreeSet};

    // A snapshot fake makes a disk fallback fail and allows incremental input
    // changes without an interpreter or filesystem generation leaking in.
    struct SnapshotProject {
        root: PathBuf,
        files: BTreeMap<PathBuf, String>,
    }

    impl SnapshotProject {
        fn new(files: &[(&str, &str)]) -> Self {
            Self {
                root: std::env::temp_dir().join("packaging-snapshot-root"),
                files: files
                    .iter()
                    .map(|(path, source)| (PathBuf::from(path), (*source).to_owned()))
                    .collect(),
            }
        }
    }

    impl Project for SnapshotProject {
        fn root(&self) -> &Path {
            &self.root
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Python])
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            Ok(self
                .files
                .keys()
                .map(|path| ProjectFile::new(&self.root, path))
                .collect())
        }
        fn analyzable_files(&self, _language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.all_files()
        }
        fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
            self.files
                .contains_key(path)
                .then(|| ProjectFile::new(&self.root, path))
        }
        fn read_source(&self, _file: &ProjectFile) -> std::io::Result<String> {
            panic!("packaging must read the selected bounded snapshot")
        }
        fn read_source_snapshot_limited(
            &self,
            file: &ProjectFile,
            limit: usize,
        ) -> std::io::Result<Option<ProjectSourceSnapshot>> {
            Ok(self
                .files
                .get(file.rel_path())
                .filter(|source| source.len() <= limit)
                .map(|source| ProjectSourceSnapshot::disk(source.clone())))
        }
    }

    #[test]
    fn changed_snapshots_equal_fresh_and_unrelated_edits_do_not_rotate_rows() {
        let limits = DependencyFileEvidenceLimits::default();
        let mut project = SnapshotProject::new(&[
            (
                "pyproject.toml",
                "[project]\nname='root'\ndependencies=['foo>=1']\n",
            ),
            ("main.py", "import foo\n"),
        ]);
        let paths = [PathBuf::from("pyproject.toml")];
        let initial = read_python_packaging_evidence(&project, &paths, &limits, None);
        project
            .files
            .insert("main.py".into(), "class foo: pass\n".to_owned());
        assert_eq!(
            initial,
            read_python_packaging_evidence(&project, &paths, &limits, None)
        );
        let edited = "[project]\nname='root'\ndependencies=['foo>=2']\n";
        project.files.insert(paths[0].clone(), edited.to_owned());
        let incremental = read_python_packaging_evidence(&project, &paths, &limits, None);
        let fresh = read_python_packaging_evidence(
            &SnapshotProject::new(&[("pyproject.toml", edited)]),
            &paths,
            &limits,
            None,
        );
        assert_eq!(incremental, fresh);
        assert_ne!(initial.rows[1].id(), incremental.rows[1].id());
        let metadata = parse_python_packaging_file(
            Path::new("env/foo.dist-info/METADATA"),
            "installed",
            "Name: Foo\nVersion: 3.0\n\n",
            &limits,
            None,
        );
        assert_eq!(metadata.rows[0].kind, Kind::Installed);
        assert!(metadata.rows[0].declared_by.is_none());
        assert_ne!(
            metadata.rows[0].exact_version,
            incremental.rows[1].exact_version
        );
    }

    #[test]
    fn unsupported_long_options_do_not_become_includes_or_break_quoted_markers() {
        let project = SnapshotProject::new(&[
            (
                "requirements.txt",
                "--requirement-unknown=hidden.txt\nfoo; os_name == 'a -- b'\n",
            ),
            ("-unknown=hidden.txt", "unexpected\n"),
        ]);
        let result = read_python_requirements_evidence(
            &project,
            &[PythonRequirementsInput {
                path: "requirements.txt".into(),
                kind: Kind::Declared,
                declared_by: None,
            }],
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert_eq!(result.files_read, 1);
        assert!(result.rows.iter().any(|row| row.package == "foo"));
        assert!(result.rows.iter().all(|row| row.package != "unexpected"));
        assert!(result.gaps.iter().any(|gap| gap.kind == Gap::Unsupported
            && gap.message.contains("--requirement-unknown=hidden.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escapes_are_rejected_before_snapshot_read() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("data"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("data"),
            workspace.path().join("pyproject.toml"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("data"),
            workspace.path().join("requirements.txt"),
        )
        .unwrap();
        let mut project = SnapshotProject::new(&[
            ("pyproject.toml", "[project]\nname='wrong'\n"),
            ("requirements.txt", "wrong\n"),
        ]);
        project.root = workspace.path().to_owned();
        let limits = DependencyFileEvidenceLimits::default();
        let result =
            read_python_packaging_evidence(&project, &["pyproject.toml".into()], &limits, None);
        assert_eq!(result.files_read, 0);
        assert_eq!(result.gaps[0].kind, Gap::UnsafePath);
        let result = read_python_requirements_evidence(
            &project,
            &[PythonRequirementsInput {
                path: "requirements.txt".into(),
                kind: Kind::Declared,
                declared_by: None,
            }],
            &limits,
            None,
        );
        assert_eq!(result.files_read, 0);
        assert_eq!(result.gaps[0].kind, Gap::UnsafePath);
    }

    #[test]
    fn constraints_includes_cycles_options_and_limits() {
        let project = SnapshotProject::new(&[
            (
                "requirements.txt",
                "Foo__Bar[security]>=1; sys_platform == 'win32'\n-c constraints.txt\n-r nested/base.txt\n--index-url https://example.test\n",
            ),
            ("constraints.txt", "only-constraint<2\n-r more.txt\n"),
            ("more.txt", "also-constraint==1\n"),
            (
                "nested/base.txt",
                "-r ../requirements.txt\n-r ../../escape.txt\nother @ https://example.test/a.whl#sha256=abc\n",
            ),
        ]);
        let root = PythonRequirementsInput {
            path: "requirements.txt".into(),
            kind: Kind::Declared,
            declared_by: Some("owner".to_owned()),
        };
        let limits = DependencyFileEvidenceLimits::default();
        let result =
            read_python_requirements_evidence(&project, std::slice::from_ref(&root), &limits, None);
        assert!(
            result
                .rows
                .iter()
                .filter(|row| row.package.ends_with("constraint"))
                .all(|row| row.kind == Kind::Constraint)
        );
        assert!(result.rows.iter().any(|row| {
            row.package == "foo-bar"
                && row
                    .conditions
                    .contains(&condition("requested_extra", "security"))
        }));
        assert!(result.rows.iter().any(|row| {
            row.source
                .as_deref()
                .is_some_and(|source| source.ends_with("#sha256=abc"))
        }));
        for kind in [Gap::Cycle, Gap::UnsafePath, Gap::Unsupported] {
            assert!(result.gaps.iter().any(|gap| gap.kind == kind), "{result:?}");
        }
        let constrained = read_python_requirements_evidence(
            &project,
            &[PythonRequirementsInput {
                path: "constraints.txt".into(),
                kind: Kind::Constraint,
                declared_by: None,
            }],
            &limits,
            None,
        );
        assert!(constrained.complete(), "{constrained:?}");
        assert!(
            constrained
                .rows
                .iter()
                .all(|row| row.kind == Kind::Constraint && row.exact_version.is_none())
        );
        assert!(
            constrained
                .rows
                .iter()
                .all(|row| python_evidence_matches_version(row, "<2").is_none())
        );
        let bounded = read_python_requirements_evidence(
            &project,
            &[root],
            &DependencyFileEvidenceLimits {
                max_files: 1,
                ..limits
            },
            None,
        );
        assert!(bounded.gaps.iter().any(|gap| gap.kind == Gap::Limit));
    }

    #[test]
    fn uv_forks_sources_and_explicit_owners() {
        let source = r#"version = 1
revision = 3
requires-python = ">=3.10"
[[package]]
name = "root"
version = "0.1"
source = {editable = "."}
dependencies = [{name = "Foo__Bar", marker = "sys_platform == 'win32'"}]
[[package]]
name = "foo-bar"
version = "1.0rc1"
source = {registry = "https://example.test/simple"}
resolution-markers = ["python_version < '3.12'"]
[[package]]
name = "foo.bar"
version = "2.0"
source = {git = "https://example.test/repo?rev=abc"}
resolution-markers = ["python_version >= '3.12'"]
[[package]]
name = "unrelated"
version = "1.0"
source = {registry = "https://other.test/simple"}
"#;
        let result = parse_python_packaging_file(
            Path::new("uv.lock"),
            "snapshot",
            source,
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert!(result.complete(), "{result:?}");
        let owned = result
            .rows
            .iter()
            .filter(|row| row.package == "foo-bar" && row.declared_by.is_some())
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 2);
        assert_ne!(owned[0].source, owned[1].source);
        assert!(
            owned
                .iter()
                .all(|row| row.conditions.iter().any(|item| item.kind == "marker"))
        );
        assert!(
            result
                .rows
                .iter()
                .filter(|row| row.package == "unrelated")
                .all(|row| row.declared_by.is_none())
        );
        let project = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "manifest",
            "[project]\nname='root'\n",
            &DependencyFileEvidenceLimits::default(),
            None,
        );
        assert_eq!(owned[0].declared_by, project.rows[0].declared_by);
        assert_eq!(
            python_evidence_matches_version(owned[0], ">=1.0rc1,<2"),
            Some(true)
        );
        assert_eq!(
            python_evidence_matches_version(owned[1], ">=1.0rc1,<2"),
            Some(false)
        );
    }

    #[test]
    fn poetry_and_legacy_are_literal_and_keep_conditions() {
        let limits = DependencyFileEvidenceLimits::default();
        let declarations = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "snapshot",
            r#"[tool.poetry]
name = "root"
version = "1.0"
[tool.poetry.dependencies]
python = "^3.10"
foo = {version = "^1.2", optional = true, extras = ["fast"], markers = "sys_platform == 'win32'", source = "internal"}
[tool.poetry.extras]
web = ["foo"]
[tool.poetry.group.dev.dependencies]
pytest = "~8.2"
"#,
            &limits,
            None,
        );
        assert!(declarations.complete(), "{declarations:?}");
        let foo = declarations
            .rows
            .iter()
            .find(|row| row.package == "foo")
            .unwrap();
        assert_eq!(foo.scope, DependencyScope::Optional);
        assert!(foo.conditions.contains(&condition("extra", "web")));
        assert_eq!(foo.version_requirement.as_deref(), Some(">=1.2,<2"));
        let lock = parse_python_packaging_file(
            Path::new("poetry.lock"),
            "lock",
            "[[package]]\nname='Foo'\nversion='1.2.3'\npython-versions='>=3.10'\ngroups=['main']\nmarkers=\"sys_platform == 'win32'\"\n[metadata]\nlock-version='2.1'\n",
            &limits,
            None,
        );
        assert!(lock.complete(), "{lock:?}");
        assert!(lock.rows[0].declared_by.is_none());
        let legacy = parse_python_packaging_file(
            Path::new("setup.py"),
            "legacy",
            "from setuptools import setup\nsetup(name='root', version='1.0', install_requires=['Foo>=1'], extras_require={'web':['bar']})\n",
            &limits,
            None,
        );
        assert!(legacy.complete(), "{legacy:?}");
        assert!(legacy.rows.iter().any(|row| row.package == "foo"));
        assert!(
            legacy
                .rows
                .iter()
                .any(|row| row.package == "bar"
                    && row.conditions.contains(&condition("extra", "web")))
        );
        let dynamic = parse_python_packaging_file(
            Path::new("setup.py"),
            "dynamic",
            "from setuptools import setup\nsetup(name='root', install_requires=get_requirements())\n",
            &limits,
            None,
        );
        assert!(dynamic.gaps.iter().any(|gap| gap.kind == Gap::Unresolved));
        assert!(
            !dynamic
                .rows
                .iter()
                .any(|row| row.package == "get_requirements")
        );
        let cfg = parse_python_packaging_file(
            Path::new("setup.cfg"),
            "cfg",
            "[metadata]\nname=root\nversion=1.0\n[options]\ninstall_requires=\n    Foo>=1\n    bar\n",
            &limits,
            None,
        );
        assert!(cfg.complete(), "{cfg:?}");
        assert_eq!(cfg.rows.len(), 3);
    }

    #[test]
    fn malformed_unsupported_cancelled_and_bounded_are_incomplete() {
        let limits = DependencyFileEvidenceLimits::default();
        for (path, source, expected) in [
            ("uv.lock", "version=2\n", Gap::Unsupported),
            (
                "poetry.lock",
                "[metadata]\nlock-version='99'",
                Gap::Unsupported,
            ),
            ("pyproject.toml", "[project\n", Gap::Malformed),
            ("Pipfile.lock", "{}", Gap::Unsupported),
        ] {
            let result =
                parse_python_packaging_file(Path::new(path), "snapshot", source, &limits, None);
            assert!(!result.complete());
            assert!(result.gaps.iter().any(|gap| gap.kind == expected));
        }
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(
            !parse_python_packaging_file(
                Path::new("pyproject.toml"),
                "snapshot",
                "",
                &limits,
                Some(&cancellation)
            )
            .complete()
        );
        let bounded = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "snapshot",
            "[project]\nname='x'\n",
            &DependencyFileEvidenceLimits {
                max_file_bytes: 1,
                ..limits
            },
            None,
        );
        assert!(bounded.gaps.iter().any(|gap| gap.kind == Gap::Limit));
    }

    #[test]
    fn missing_roots_and_diagnostics_obey_aggregate_budgets() {
        let project = SnapshotProject::new(&[]);
        let paths = (0..100)
            .map(|index| PathBuf::from(format!("missing/{index}.txt")))
            .collect::<Vec<_>>();
        let limits = DependencyFileEvidenceLimits {
            max_files: 2,
            max_rows: 2,
            ..Default::default()
        };
        let result = read_python_packaging_evidence(&project, &paths, &limits, None);
        assert!(result.gaps.len() <= limits.max_rows + 1);
        assert!(result.gaps.iter().any(|gap| gap.kind == Gap::Limit));
        let inputs = paths
            .into_iter()
            .map(|path| PythonRequirementsInput {
                path,
                kind: Kind::Constraint,
                declared_by: None,
            })
            .collect::<Vec<_>>();
        let result = read_python_requirements_evidence(&project, &inputs, &limits, None);
        assert!(result.gaps.len() <= limits.max_rows + 1);
        assert!(result.gaps.iter().any(|gap| gap.kind == Gap::Limit));
        assert!(result.rows.is_empty());
    }

    #[test]
    fn poetry_associations_require_paired_declarations_sources_and_versions() {
        let limits = DependencyFileEvidenceLimits::default();
        let declaration = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "manifest",
            "[project]\nname='root'\ndependencies=['Foo_Bar>=1,<2', 'direct @ https://example.test/pkg.whl']\n",
            &limits,
            None,
        );
        let mut lock = parse_python_packaging_file(
            Path::new("poetry.lock"),
            "lock",
            "[[package]]\nname='foo.bar'\nversion='1.5'\n[[package]]\nname='foo-bar'\nversion='2.0'\n[[package]]\nname='direct'\nversion='1'\n[package.source]\ntype='url'\nurl='https://example.test/pkg.whl'\n[metadata]\nlock-version='2.1'\n",
            &limits,
            None,
        );
        associate_python_poetry_lock(&declaration, &mut lock, &limits, None);
        assert!(lock.complete(), "{lock:?}");
        let owned = lock
            .rows
            .iter()
            .filter(|row| row.declared_by.is_some())
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 2);
        assert!(
            owned
                .iter()
                .all(|row| row.declared_by == declaration.rows[0].declared_by)
        );
        let selected = owned.iter().find(|row| row.package == "foo-bar").unwrap();
        assert_eq!(
            python_evidence_matches_version(selected, "<1.6"),
            Some(true)
        );
        assert_eq!(
            python_evidence_matches_version(selected, "<1.5"),
            Some(false)
        );
        assert!(lock.rows.iter().any(|row| row.exact_version.as_deref() == Some("2.0") && row.declared_by.is_none()));
        let mut wrong_root = parse_python_packaging_file(
            Path::new("other/poetry.lock"),
            "wrong",
            "[[package]]\nname='foo-bar'\nversion='1.5'\n[metadata]\nlock-version='2.1'\n",
            &limits,
            None,
        );
        associate_python_poetry_lock(&declaration, &mut wrong_root, &limits, None);
        assert!(wrong_root.rows.iter().all(|row| row.declared_by.is_none()));
        assert!(
            wrong_root
                .gaps
                .iter()
                .any(|gap| gap.kind == Gap::Unresolved)
        );
        let mut installed = parse_python_packaging_file(
            Path::new("env/METADATA"),
            "installed",
            "Name: Foo__Bar\nVersion: 3\n\n",
            &limits,
            None,
        )
        .rows
        .remove(0);
        assert_eq!(
            python_version_evidence_disagrees(selected, &installed, None),
            None
        );
        // An acquisition caller must establish this enrichment binding.
        installed.declared_by = selected.declared_by.clone();
        assert_eq!(
            python_version_evidence_disagrees(selected, &installed, None),
            Some(true)
        );
        installed.exact_version = Some("1.5.0".to_owned());
        assert_eq!(
            python_version_evidence_disagrees(selected, &installed, None),
            Some(false)
        );
        installed.declared_by = Some("unrelated component".to_owned());
        assert_eq!(
            python_version_evidence_disagrees(selected, &installed, None),
            None
        );
        let configured = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "indices",
            "[tool.poetry]\nname='root'\nversion='1'\n[tool.poetry.dependencies]\nfoo='>=1'\n[[tool.poetry.source]]\nname='private'\nurl='https://private.example.test/simple'\npriority='primary'\n",
            &limits,
            None,
        );
        assert!(
            configured
                .gaps
                .iter()
                .any(|gap| gap.kind == Gap::Unresolved)
        );
        assert!(
            configured
                .rows
                .iter()
                .any(|row| row.conditions.iter().any(|condition| condition.kind
                    == "poetry_sources"
                    && condition
                        .value
                        .contains("https://private.example.test/simple")))
        );
        let mut configured_lock = parse_python_packaging_file(
            Path::new("poetry.lock"),
            "stale-public-index",
            "[[package]]\nname='foo'\nversion='1.5'\n[metadata]\nlock-version='2.1'\n",
            &limits,
            None,
        );
        associate_python_poetry_lock(&configured, &mut configured_lock, &limits, None);
        assert!(
            configured_lock
                .rows
                .iter()
                .all(|row| row.declared_by.is_none())
        );
    }
}

/// Every target value is explicitly supplied. This has no host default.
#[derive(Debug, Clone)]
pub struct PythonPackagingTarget {
    pub environment: pep508_rs::MarkerEnvironment,
    pub extras: Vec<pep508_rs::ExtraName>,
    pub groups: Vec<String>,
}

/// Applicability of a retained condition, not installation or code loading.
/// Unsupported selection syntax stays unknown, even with a target.
pub fn python_evidence_applies_to_target(
    row: &DependencyEvidence,
    target: Option<&PythonPackagingTarget>,
) -> Option<bool> {
    if !row.complete {
        return None;
    }
    let mut unknown = false;
    for entry in &row.conditions {
        match entry.kind.as_str() {
            "marker" => {
                let target = target?;
                let marker = pep508_rs::MarkerTree::from_str(&entry.value).ok()?;
                if !marker.evaluate(&target.environment, &target.extras) {
                    return Some(false);
                }
            }
            "requires_python" => {
                let target = target?;
                if entry.value != "*" {
                    let requirement = VersionSpecifiers::from_str(&entry.value).ok()?;
                    if !requirement.contains(&target.environment.python_full_version().version) {
                        return Some(false);
                    }
                }
            }
            "extra"
            | "source_extra"
            | "group"
            | "source_group"
            | "lock_group"
            | "candidate_resolution_marker"
            | "resolution-markers"
            | "environments"
            | "supported-environments" => {}
            "role"
            | "requested_extra"
            | "declared_group"
            | "association_range"
            | "declaration_range"
            | "declaration_file"
            | "declaration_snapshot"
            | "source_override"
            | "dependencies"
            | "optional-dependencies"
            | "dev-dependencies"
            | "extras" => {}
            "poetry_sources" => {}
            "editable" => {}
            "optional"
                if entry.value == "true"
                    && row
                        .conditions
                        .iter()
                        .any(|condition| condition.kind == "extra") => {}
            _ => unknown = true,
        }
    }
    for kind in [
        "extra",
        "source_extra",
        "group",
        "source_group",
        "lock_group",
        "candidate_resolution_marker",
        "resolution-markers",
        "environments",
        "supported-environments",
    ] {
        let entries = row
            .conditions
            .iter()
            .filter(|entry| entry.kind == kind)
            .collect::<Vec<_>>();
        if entries.is_empty() {
            continue;
        }
        let target = target?;
        let mut applies = false;
        for entry in entries {
            applies |= match kind {
                "extra" | "source_extra" => {
                    let extra = pep508_rs::ExtraName::from_str(&entry.value).ok()?;
                    target.extras.contains(&extra)
                }
                "group" | "lock_group" | "source_group" => {
                    let group = PackageName::from_str(&entry.value).ok()?;
                    let mut selected = false;
                    for supplied in &target.groups {
                        selected |= group == PackageName::from_str(supplied).ok()?;
                    }
                    selected
                }
                _ => pep508_rs::MarkerTree::from_str(&entry.value)
                    .ok()?
                    .evaluate(&target.environment, &target.extras),
            };
        }
        if !applies {
            return Some(false);
        }
    }
    if unknown { None } else { Some(true) }
}

#[cfg(test)]
mod target_tests {

    use crate::analyzer::python::packaging::*;

    #[test]
    fn conditions_use_only_supplied_targets() {
        let rows = parse_python_packaging_file(Path::new("pyproject.toml"), "snapshot",
            "[project]\nname='x'\ndependencies=[\"foo; sys_platform == 'win32'\"]\n[project.optional-dependencies]\nweb=['bar']\n",
            &DependencyFileEvidenceLimits::default(), None).rows;
        let environment =
            pep508_rs::MarkerEnvironment::try_from(pep508_rs::MarkerEnvironmentBuilder {
                implementation_name: "cpython",
                implementation_version: "3.12.0",
                os_name: "nt",
                platform_machine: "AMD64",
                platform_python_implementation: "CPython",
                platform_release: "10",
                platform_system: "Windows",
                platform_version: "10",
                python_full_version: "3.12.0",
                python_version: "3.12",
                sys_platform: "win32",
            })
            .unwrap();
        let mut target = PythonPackagingTarget {
            environment,
            extras: vec![],
            groups: vec![],
        };
        let foo = rows.iter().find(|row| row.package == "foo").unwrap();
        let bar = rows.iter().find(|row| row.package == "bar").unwrap();
        assert_eq!(python_evidence_applies_to_target(foo, None), None);
        assert_eq!(
            python_evidence_applies_to_target(foo, Some(&target)),
            Some(true)
        );
        assert_eq!(
            python_evidence_applies_to_target(bar, Some(&target)),
            Some(false)
        );
        target.extras.push("web".parse().unwrap());
        assert_eq!(
            python_evidence_applies_to_target(bar, Some(&target)),
            Some(true)
        );
        let limits = DependencyFileEvidenceLimits::default();
        let lock = parse_python_packaging_file(
            Path::new("uv.lock"),
            "lock",
            "version=1\n[[package]]\nname='foo'\nversion='1'\nsource={registry='https://example.test/simple'}\nresolution-markers=[\"sys_platform == 'linux'\",\"python_version >= '0' or python_version < '0'\"]\n",
            &limits,
            None,
        );
        assert_eq!(
            python_evidence_applies_to_target(&lock.rows[0], Some(&target)),
            Some(true)
        );
        let malformed = parse_python_packaging_file(
            Path::new("uv.lock"),
            "bad",
            "version=1\nresolution-markers=['invalid marker']\n[[package]]\nname='foo'\nversion='1'\nsource={registry='https://example.test/simple'}\n",
            &limits,
            None,
        );
        assert!(!malformed.complete());
        assert_eq!(
            python_evidence_applies_to_target(&malformed.rows[0], Some(&target)),
            None
        );
        let declaration = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "poetry-manifest",
            "[tool.poetry]\nname='root'\nversion='1'\n[tool.poetry.group.dev.dependencies]\nfoo='^1'\n",
            &limits,
            None,
        );
        let mut poetry = parse_python_packaging_file(
            Path::new("poetry.lock"),
            "poetry-lock",
            "[[package]]\nname='foo'\nversion='1.5'\ngroups=['main','dev']\noptional=false\n[metadata]\nlock-version='2.1'\n",
            &limits,
            None,
        );
        associate_python_poetry_lock(&declaration, &mut poetry, &limits, None);
        let owned = poetry
            .rows
            .iter()
            .find(|row| row.declared_by.is_some())
            .unwrap();
        target.groups = vec!["main".to_owned()];
        assert_eq!(
            python_evidence_applies_to_target(owned, Some(&target)),
            Some(false)
        );
        target.groups = vec!["DEV".to_owned()];
        assert_eq!(
            python_evidence_applies_to_target(owned, Some(&target)),
            Some(true)
        );
        let overridden = parse_python_packaging_file(
            Path::new("pyproject.toml"),
            "source-override",
            "[project]\nname='root'\n[project.optional-dependencies]\nweb=['foo']\ngpu=['foo']\n[tool.uv.sources]\nfoo={path='vendor/foo',extra='gpu'}\n",
            &limits,
            None,
        );
        let source = overridden
            .rows
            .iter()
            .find(|row| {
                row.conditions.contains(&condition("source_override", "uv"))
                    && row.conditions.contains(&condition("extra", "web"))
            })
            .unwrap();
        assert_eq!(
            python_evidence_applies_to_target(source, Some(&target)),
            Some(false)
        );
        target.extras.push("gpu".parse().unwrap());
        assert_eq!(
            python_evidence_applies_to_target(source, Some(&target)),
            Some(true)
        );
    }
}
