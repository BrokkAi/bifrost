//! Files-only Composer and PHP runtime evidence projected into the shared
//! #2442 contract (#9328).
//!
//! A Composer project is a directory holding a `composer.json` or a
//! `composer.lock`, outside any `vendor` directory. Every row of a project
//! names its BuildProject in `declared_by`:
//! - each `composer.json` `require`, `require-dev`, `replace`, `provide` and
//!   `conflict` link is a `declared` `composer` row whose requirement is the
//!   authored constraint, `composer.link` naming the section;
//! - each `composer.lock` `packages` and `packages-dev` entry is a `locked`
//!   row with the version exactly as Composer wrote it (`v1.2.2`,
//!   `dev-main`), its VCS source and dist identities, root aliases and branch
//!   aliases as conditions, and the replace and provide links of a locked
//!   package as `declared` rows naming it in `composer.replaced_by`;
//! - the PHP runtime and the other platform packages (`ext-*`, `lib-*`,
//!   `composer-*-api`) are the `php-toolchain` ecosystem: a platform
//!   requirement is a `constraint`, an exact `config.platform` or
//!   `.php-version` pin is `locked`, and a project with no PHP runtime
//!   evidence has a `php.runtime_evidence=none` constraint. None of these is
//!   the runtime that executes, which `php.runtime_override=unobserved` says.
//!
//! A manifest without a lock, a lock without a manifest, and a file that does
//! not parse are gaps, so a missing lock is never a complete empty answer
//! (#8357).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Component, Path};

use brokk_bifrost_analysis::analyzer::configuration::{
    DocumentRouteStep, DocumentSpans, decode_json_document,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
    VersionComparator, version_bounds_admit,
};
use brokk_bifrost_analysis::analyzer::topology::{
    DependencyScope, TopologyCompleteness, TopologyEntity, TopologyEntityKind, TopologyProvenance,
    TopologyProvenanceKind,
};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
use serde_json::Value;

/// Package rows from `composer.json` and `composer.lock`.
pub const COMPOSER_ECOSYSTEM: &str = "composer";
/// PHP runtime and platform-package rows.
pub const PHP_TOOLCHAIN_ECOSYSTEM: &str = "php-toolchain";

const MANIFEST: &str = "composer.json";
const LOCKFILE: &str = "composer.lock";
const RUNTIME_FILE: &str = ".php-version";
/// Manifest link sections in authored order, with the scope each implies.
const LINKS: [(&str, DependencyScope); 5] = [
    ("require", DependencyScope::Runtime),
    ("require-dev", DependencyScope::Test),
    ("replace", DependencyScope::Unknown),
    ("provide", DependencyScope::Unknown),
    ("conflict", DependencyScope::Unknown),
];

/// Whether `path` is a file this producer reads. An installed package's own
/// manifest under `vendor` describes that package, not the project.
pub(crate) fn is_composer_dependency_input(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == MANIFEST || name == LOCKFILE || name == RUNTIME_FILE)
        && !path
            .components()
            .any(|part| part == Component::Normal("vendor".as_ref()))
}

/// Whether `path` declares or locks a Composer project, so its directory's
/// runtime pins apply to it.
pub(crate) fn is_composer_project_input(path: &Path) -> bool {
    is_composer_dependency_input(path)
        && path
            .file_name()
            .is_some_and(|name| name == MANIFEST || name == LOCKFILE)
}

/// Shared topology identity convention for the Composer project rooted at
/// `directory`, so its manifest and lock name one owner.
pub fn composer_project(directory: &Path, provenance: &Path) -> TopologyEntity {
    let text = directory.to_string_lossy().replace('\\', "/");
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!("composer:{}", if text.is_empty() { "." } else { &text }),
        owner: None,
        root: Some(directory.to_path_buf()),
        provenance: vec![TopologyProvenance::new(
            provenance,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
}

/// Composer's platform package names: the PHP runtime and its variants,
/// HHVM, extensions, system libraries and the Composer APIs.
fn is_platform_package(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "php"
            | "php-64bit"
            | "php-ipv6"
            | "php-zts"
            | "php-debug"
            | "hhvm"
            | "composer"
            | "composer-plugin-api"
            | "composer-runtime-api"
    ) || name.starts_with("ext-")
        || name.starts_with("lib-")
}

fn is_php_runtime(name: &str) -> bool {
    name.eq_ignore_ascii_case("php")
}

struct Input<'a> {
    path: &'a Path,
    source: &'a str,
    digest: String,
}

struct Collector<'a> {
    input: &'a Input<'a>,
    owner: &'a str,
    rows: &'a mut Vec<DependencyEvidence>,
    gaps: &'a mut Vec<DependencyEvidenceGap>,
}

impl Collector<'_> {
    fn gap(&mut self, kind: DependencyEvidenceGapKind, range: Range<usize>, message: String) {
        self.gaps.push(DependencyEvidenceGap {
            kind,
            build_file: self.input.path.to_path_buf(),
            byte_range: range,
            message,
        });
    }

    /// Push a complete row with no requirement, version, source or
    /// condition, for the caller to fill in.
    fn row(
        &mut self,
        ecosystem: &str,
        package: &str,
        kind: DependencyEvidenceKind,
        scope: DependencyScope,
        range: Range<usize>,
    ) -> &mut DependencyEvidence {
        self.rows.push(DependencyEvidence {
            ecosystem: ecosystem.to_owned(),
            package: package.to_owned(),
            kind,
            version_requirement: None,
            exact_version: None,
            source: None,
            locator: None,
            declared_by: Some(self.owner.to_owned()),
            scope,
            conditions: Vec::new(),
            build_file: self.input.path.to_path_buf(),
            source_digest: self.input.digest.clone(),
            byte_range: range,
            complete: true,
        });
        self.rows.last_mut().expect("just pushed")
    }
}

fn condition(kind: &str, value: &str) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

fn span(spans: &DocumentSpans, route: &[DocumentRouteStep]) -> Range<usize> {
    let range = spans
        .get(route)
        .expect("a decoded JSON member has exact parser evidence");
    range.start_byte()..range.end_byte()
}

fn key(name: &str) -> DocumentRouteStep {
    DocumentRouteStep::Key(name.to_owned())
}

/// Acquire every Composer project's package and runtime rows from the
/// selected configuration snapshots. Nothing survives the return but the rows.
pub(crate) fn collect_composer_dependency_evidence(
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let mut result = DependencyFileEvidence::default();
    let inputs = selected
        .iter()
        .filter(|(file, _)| is_composer_dependency_input(file.rel_path()))
        .map(|(file, source)| Input {
            path: file.rel_path(),
            source: source.source(),
            digest: source.oid().to_string(),
        })
        .collect::<Vec<_>>();
    result.files_read = inputs.len();
    result.bytes_read = inputs.iter().map(|input| input.source.len()).sum();
    let mut by_directory = BTreeMap::<&Path, Vec<&Input<'_>>>::new();
    for input in &inputs {
        by_directory
            .entry(input.path.parent().unwrap_or(Path::new("")))
            .or_default()
            .push(input);
    }
    let named = |directory: &Path, name: &str| {
        by_directory.get(directory).and_then(|files| {
            files
                .iter()
                .find(|input| input.path.file_name().is_some_and(|file| file == name))
                .copied()
        })
    };
    let projects = by_directory
        .iter()
        .filter(|(_, files)| {
            files
                .iter()
                .any(|input| is_composer_project_input(input.path))
        })
        .map(|(directory, _)| *directory)
        .collect::<BTreeSet<_>>();
    let mut rows = Vec::new();
    for directory in &projects {
        let manifest = named(directory, MANIFEST);
        let lockfile = named(directory, LOCKFILE);
        let primary = manifest
            .or(lockfile)
            .expect("a project has a manifest or lock");
        let owner = composer_project(directory, primary.path).id();
        let mut runtime = false;
        let mut direct = None;
        if let Some(manifest) = manifest {
            let mut collector = Collector {
                input: manifest,
                owner: &owner,
                rows: &mut rows,
                gaps: &mut result.gaps,
            };
            if let Some((names, declares_runtime)) = manifest_rows(&mut collector) {
                direct = Some(names);
                runtime |= declares_runtime;
            }
            if lockfile.is_none() {
                collector.gap(
                    DependencyEvidenceGapKind::Missing,
                    0..0,
                    "the composer.json has no composer.lock, so its locked package versions are unknown"
                        .to_owned(),
                );
            }
        }
        if let Some(lockfile) = lockfile {
            let mut collector = Collector {
                input: lockfile,
                owner: &owner,
                rows: &mut rows,
                gaps: &mut result.gaps,
            };
            if manifest.is_none() {
                collector.gap(
                    DependencyEvidenceGapKind::Missing,
                    0..0,
                    "the composer.lock has no composer.json, so which packages the project requires directly is unknown"
                        .to_owned(),
                );
            }
            lock_rows(&mut collector, direct.as_ref());
        }
        // phpenv, asdf-php and similar version managers read the nearest
        // file upward.
        let pin = directory
            .ancestors()
            .find_map(|level| named(level, RUNTIME_FILE));
        if let Some(pin) = pin {
            let mut collector = Collector {
                input: pin,
                owner: &owner,
                rows: &mut rows,
                gaps: &mut result.gaps,
            };
            runtime |= runtime_file_row(&mut collector);
        }
        if !runtime {
            Collector {
                input: primary,
                owner: &owner,
                rows: &mut rows,
                gaps: &mut result.gaps,
            }
            .row(
                PHP_TOOLCHAIN_ECOSYSTEM,
                "php",
                DependencyEvidenceKind::Constraint,
                DependencyScope::Unknown,
                0..0,
            )
            .conditions = vec![condition("php.runtime_evidence", "none")];
        }
    }
    if projects.is_empty() {
        result.gaps.push(DependencyEvidenceGap {
            kind: DependencyEvidenceGapKind::Missing,
            build_file: MANIFEST.into(),
            byte_range: 0..0,
            message: "no composer.json or composer.lock was supplied, so the packages a PHP program loads are unknown".to_owned(),
        });
    }
    for row in rows {
        if result.rows.len() >= limits.max_rows {
            result.gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Limit,
                build_file: row.build_file,
                byte_range: row.byte_range,
                message: "Composer dependency evidence row limit".to_owned(),
            });
            break;
        }
        result.rows.push(row);
    }
    result.rows.sort_by_cached_key(DependencyEvidence::id);
    result
}

/// Decode one input as a JSON object, or record why it is not one.
fn json_object(collector: &mut Collector<'_>) -> Option<(Value, DocumentSpans)> {
    // The lock is JSON under a name the configuration parser does not know.
    let parser_path = collector.input.path.with_extension("json");
    match decode_json_document(&parser_path, collector.input.source) {
        Ok((value, spans)) if value.is_object() => Some((value, spans)),
        Ok(_) => {
            collector.gap(
                DependencyEvidenceGapKind::Malformed,
                0..collector.input.source.len(),
                format!("{} is not a JSON object", collector.input.path.display()),
            );
            None
        }
        Err(error) => {
            collector.gap(
                DependencyEvidenceGapKind::Malformed,
                0..collector.input.source.len(),
                format!("{} does not parse: {error}", collector.input.path.display()),
            );
            None
        }
    }
}

/// `composer.json` link and `config.platform` rows. Returns the packages the
/// project requires directly and whether it declares the PHP runtime.
fn manifest_rows(collector: &mut Collector<'_>) -> Option<(BTreeSet<String>, bool)> {
    let (value, spans) = json_object(collector)?;
    let mut direct = BTreeSet::new();
    let mut runtime = false;
    for (link, scope) in LINKS {
        let Some(section) = value.get(link) else {
            continue;
        };
        let Some(section) = section.as_object() else {
            collector.gap(
                DependencyEvidenceGapKind::Malformed,
                span(&spans, &[key(link)]),
                format!("composer.json {link} is not an object"),
            );
            continue;
        };
        for (package, constraint) in section {
            let range = span(&spans, &[key(link), key(package)]);
            let Some(constraint) = constraint.as_str() else {
                collector.gap(
                    DependencyEvidenceGapKind::Malformed,
                    range,
                    format!("composer.json {link} {package:?} has no constraint string"),
                );
                continue;
            };
            let mut conditions = vec![condition("composer.link", link)];
            // `dev-main as 1.x-dev` keeps its authored text as the
            // requirement; the alias is also explicit.
            if let Some((_, alias)) = constraint.split_once(" as ") {
                conditions.push(condition("composer.inline_alias", alias.trim()));
            }
            if matches!(link, "require" | "require-dev") {
                direct.insert(package.to_ascii_lowercase());
            }
            let (ecosystem, kind) = if is_platform_package(package) {
                if is_php_runtime(package) {
                    conditions.push(condition("php.runtime_evidence", "composer_require"));
                    runtime |= link == "require";
                }
                (PHP_TOOLCHAIN_ECOSYSTEM, DependencyEvidenceKind::Constraint)
            } else {
                (COMPOSER_ECOSYSTEM, DependencyEvidenceKind::Declared)
            };
            let row = collector.row(ecosystem, package, kind, scope, range);
            row.version_requirement = Some(constraint.to_owned());
            row.conditions = conditions;
        }
    }
    let platform = value
        .get("config")
        .and_then(|config| config.get("platform"))
        .and_then(Value::as_object);
    for (package, version) in platform.into_iter().flatten() {
        let range = span(&spans, &[key("config"), key("platform"), key(package)]);
        let mut conditions = vec![
            condition("php.runtime_evidence", "composer_platform_config"),
            condition("php.runtime_override", "unobserved"),
        ];
        let (kind, requirement, exact) = match version {
            // `"ext-foo": false` makes Composer treat the package as absent.
            Value::Bool(false) => {
                conditions.push(condition("composer.platform_disabled", "true"));
                (DependencyEvidenceKind::Constraint, None, None)
            }
            Value::String(version) if is_exact_release(version) => {
                (DependencyEvidenceKind::Locked, None, Some(version.as_str()))
            }
            Value::String(version) => (
                DependencyEvidenceKind::Constraint,
                Some(version.as_str()),
                None,
            ),
            _ => {
                collector.gap(
                    DependencyEvidenceGapKind::Malformed,
                    range,
                    format!("composer.json config.platform {package:?} is not a version"),
                );
                continue;
            }
        };
        runtime |= is_php_runtime(package);
        let row = collector.row(
            PHP_TOOLCHAIN_ECOSYSTEM,
            package,
            kind,
            DependencyScope::Unknown,
            range,
        );
        row.version_requirement = requirement.map(str::to_owned);
        row.exact_version = exact.map(str::to_owned);
        row.conditions = conditions;
    }
    Some((direct, runtime))
}

/// A complete `major.minor.patch` release with no stability suffix, the form
/// of a pin rather than a constraint.
fn is_exact_release(text: &str) -> bool {
    let parts = text.split('.').collect::<Vec<_>>();
    (3..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// `composer.lock` `packages` and `packages-dev` rows.
fn lock_rows(collector: &mut Collector<'_>, direct: Option<&BTreeSet<String>>) {
    let Some((value, spans)) = json_object(collector) else {
        return;
    };
    // Root aliases (`dev-main as 1.x-dev`) keyed by package and version.
    let mut aliases = BTreeMap::<(String, String), Vec<String>>::new();
    for alias in value
        .get("aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(package), Some(version), Some(alias)) = (
            alias.get("package").and_then(Value::as_str),
            alias.get("version").and_then(Value::as_str),
            alias.get("alias").and_then(Value::as_str),
        ) {
            aliases
                .entry((package.to_ascii_lowercase(), version.to_owned()))
                .or_default()
                .push(alias.to_owned());
        }
    }
    for (section, scope) in [
        ("packages", DependencyScope::Runtime),
        ("packages-dev", DependencyScope::Test),
    ] {
        let Some(packages) = value.get(section).and_then(Value::as_array) else {
            collector.gap(
                DependencyEvidenceGapKind::Malformed,
                spans
                    .member(&[section])
                    .map_or(0..0, |range| range.start_byte()..range.end_byte()),
                format!("composer.lock has no {section} array"),
            );
            continue;
        };
        for (index, package) in packages.iter().enumerate() {
            let route = [key(section), DocumentRouteStep::Index(index)];
            let range = span(&spans, &route);
            let (Some(name), Some(version)) = (
                package.get("name").and_then(Value::as_str),
                package.get("version").and_then(Value::as_str),
            ) else {
                collector.gap(
                    DependencyEvidenceGapKind::Malformed,
                    range,
                    format!("composer.lock {section}[{index}] has no name and version"),
                );
                continue;
            };
            let mut conditions = Vec::new();
            if let Some(kind) = package.get("type").and_then(Value::as_str) {
                conditions.push(condition("composer.package_type", kind));
            }
            if let Some(direct) = direct {
                let association = if direct.contains(&name.to_ascii_lowercase()) {
                    "direct"
                } else {
                    "transitive"
                };
                conditions.push(condition("composer.lock_association", association));
            }
            let vcs = package.get("source");
            let dist = package.get("dist");
            for (prefix, location) in [("source", vcs), ("dist", dist)] {
                for field in ["type", "reference", "shasum"] {
                    if let Some(value) = location
                        .and_then(|location| location.get(field))
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    {
                        conditions.push(condition(&format!("composer.{prefix}_{field}"), value));
                    }
                }
            }
            for alias in aliases
                .get(&(name.to_ascii_lowercase(), version.to_owned()))
                .into_iter()
                .flatten()
            {
                conditions.push(condition("composer.alias", alias));
            }
            let branch_aliases = package
                .get("extra")
                .and_then(|extra| extra.get("branch-alias"))
                .and_then(Value::as_object);
            for (branch, alias) in branch_aliases.into_iter().flatten() {
                if let Some(alias) = alias.as_str() {
                    conditions.push(condition(
                        "composer.branch_alias",
                        &format!("{branch} as {alias}"),
                    ));
                }
            }
            let url = |location| string_field(location, "url");
            let kind = |location| string_field(location, "type");
            // A path repository's code is the directory, not a release.
            let source = if kind(dist) == Some("path") {
                url(dist).map(|url| format!("path:{url}"))
            } else if let (Some(kind), Some(url)) = (kind(vcs), url(vcs)) {
                Some(format!("{kind}+{url}"))
            } else {
                url(dist).map(str::to_owned)
            };
            let row = collector.row(
                COMPOSER_ECOSYSTEM,
                name,
                DependencyEvidenceKind::Locked,
                scope,
                range,
            );
            row.exact_version = Some(version.to_owned());
            row.source = source;
            row.conditions = conditions;
            // A locked package that replaces or provides another satisfies
            // it without that package being installed.
            for link in ["replace", "provide"] {
                let Some(targets) = package.get(link).and_then(Value::as_object) else {
                    continue;
                };
                for (target, constraint) in targets {
                    let Some(constraint) = constraint.as_str() else {
                        continue;
                    };
                    let mut route = route.to_vec();
                    route.extend([key(link), key(target)]);
                    let range = span(&spans, &route);
                    let (ecosystem, kind) = if is_platform_package(target) {
                        (PHP_TOOLCHAIN_ECOSYSTEM, DependencyEvidenceKind::Constraint)
                    } else {
                        (COMPOSER_ECOSYSTEM, DependencyEvidenceKind::Declared)
                    };
                    let row = collector.row(ecosystem, target, kind, scope, range);
                    row.version_requirement = Some(constraint.to_owned());
                    row.conditions = vec![
                        condition("composer.link", link),
                        condition("composer.replaced_by", name),
                    ];
                }
            }
        }
    }
}

/// A string member of a lock package's `source` or `dist` object.
fn string_field<'a>(location: Option<&'a Value>, name: &str) -> Option<&'a str> {
    location?.get(name)?.as_str()
}

/// A `.php-version` pin. Returns whether it names a version.
fn runtime_file_row(collector: &mut Collector<'_>) -> bool {
    let source = collector.input.source;
    let mut line_start = 0;
    let mut pin = None;
    for line in source.split_inclusive('\n') {
        let content = line.split('#').next().unwrap_or("").trim();
        if !content.is_empty() {
            let leading = line.len() - line.trim_start().len();
            pin = Some((content, line_start + leading));
            break;
        }
        line_start += line.len();
    }
    let Some((text, start)) = pin else {
        collector.gap(
            DependencyEvidenceGapKind::Malformed,
            0..source.len(),
            "the .php-version file names no version".to_owned(),
        );
        return false;
    };
    let exact = is_exact_release(text);
    let row = collector.row(
        PHP_TOOLCHAIN_ECOSYSTEM,
        "php",
        if exact {
            DependencyEvidenceKind::Locked
        } else {
            DependencyEvidenceKind::Constraint
        },
        DependencyScope::Unknown,
        start..start + text.len(),
    );
    if exact {
        row.exact_version = Some(text.to_owned());
    } else {
        row.version_requirement = Some(text.to_owned());
    }
    row.conditions = vec![
        condition("php.runtime_evidence", "php_version_file"),
        condition("php.runtime_override", "unobserved"),
    ];
    true
}

/// Composer's stability levels in version order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stability {
    Dev,
    Alpha,
    Beta,
    ReleaseCandidate,
    Stable,
    Patch,
}

/// A Composer version in `VersionParser::normalize` and `version_compare`
/// order: four numeric parts (missing ones are zero, an optional `v` prefix),
/// then the stability (`dev < alpha < beta < RC < stable < patch`) and its
/// numbers, then a trailing `-dev`, which orders below the same version
/// without it. Branch names (`dev-main`) and branch aliases (`1.x-dev`) are
/// not versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComposerVersion {
    release: [u64; 4],
    stability: Stability,
    stability_numbers: Vec<u64>,
    /// `true` sorts above `false`, so a `-dev` build (`false`) is lower.
    not_dev: bool,
}

/// A version as authored: its numeric parts, and whether a stability
/// modifier followed them.
struct Authored {
    parts: Vec<u64>,
    version: ComposerVersion,
    has_modifier: bool,
}

fn parse_authored(text: &str) -> Result<Authored, String> {
    let invalid = || format!("{text:?} is not a Composer version");
    let body = text
        .strip_prefix(['v', 'V'])
        .unwrap_or(text)
        .to_ascii_lowercase();
    let numeric = body
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(body.len());
    // In `1.0.0.beta1` the last dot separates the modifier.
    let numbers = body[..numeric].trim_end_matches('.');
    let mut rest = &body[numbers.len()..];
    let parts = numbers
        .split('.')
        .map(|part| part.parse::<u64>().map_err(|_| invalid()))
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() || parts.len() > 4 {
        return Err(invalid());
    }
    let mut release = [0; 4];
    release[..parts.len()].copy_from_slice(&parts);
    rest = rest.strip_prefix(['.', '_', '-']).unwrap_or(rest);
    let mut stability = Stability::Stable;
    let mut stability_numbers = Vec::new();
    let mut has_modifier = false;
    const MODIFIERS: [(&str, Stability); 9] = [
        ("stable", Stability::Stable),
        ("alpha", Stability::Alpha),
        ("beta", Stability::Beta),
        ("patch", Stability::Patch),
        ("rc", Stability::ReleaseCandidate),
        ("pl", Stability::Patch),
        ("a", Stability::Alpha),
        ("b", Stability::Beta),
        ("p", Stability::Patch),
    ];
    if let Some((after, level)) = MODIFIERS
        .iter()
        .find_map(|(spelling, level)| rest.strip_prefix(spelling).map(|after| (after, *level)))
    {
        stability = level;
        has_modifier = true;
        rest = after;
        loop {
            let digits = rest.strip_prefix(['.', '-']).unwrap_or(rest);
            let length = digits
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(digits.len());
            if length == 0 {
                break;
            }
            stability_numbers.push(digits[..length].parse().map_err(|_| invalid())?);
            rest = &digits[length..];
        }
    }
    let dev = match rest {
        "" => false,
        "dev" | ".dev" | "-dev" => true,
        _ => return Err(invalid()),
    };
    if dev && !has_modifier {
        stability = Stability::Dev;
    }
    has_modifier |= dev;
    Ok(Authored {
        parts,
        version: ComposerVersion {
            release,
            stability,
            stability_numbers,
            not_dev: !(dev && stability != Stability::Dev),
        },
        has_modifier,
    })
}

impl ComposerVersion {
    pub fn parse(text: &str) -> Result<Self, String> {
        parse_authored(text).map(|authored| authored.version)
    }

    /// The `-dev` floor of a release, the lowest version Composer orders at
    /// or above it.
    fn dev_floor(release: [u64; 4]) -> Self {
        Self {
            release,
            stability: Stability::Dev,
            stability_numbers: Vec::new(),
            not_dev: true,
        }
    }
}

/// `parts` padded to four with part `position` (one-based) incremented by
/// `increment` and every later part zeroed: Composer's
/// `manipulateVersionString`.
fn bumped(parts: &[u64], position: usize, increment: u64) -> [u64; 4] {
    let mut release = [0; 4];
    release[..parts.len()].copy_from_slice(parts);
    release[position - 1] += increment;
    release[position..].fill(0);
    release
}

/// An authored affected-version range in Composer constraint syntax for
/// `composer` or `php-toolchain`, as Composer's `VersionParser` reads it:
/// `||` (or `|`) alternatives of comma- or space-joined constraints, each a
/// comparator (`>=`, `<`, `!=`, ...), caret (`^1.2`), tilde (`~1.2.3`),
/// wildcard (`1.2.*`) or hyphen range (`1.0 - 2.0`). A bound with no
/// stability suffix keeps Composer's `-dev` floors, so `<2.0` excludes
/// `2.0.0-beta1` and `>=1.2` admits `1.2.0-RC1`. Stability flags (`@beta`)
/// only affect resolution and are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerVersionRange {
    ecosystem: &'static str,
    alternatives: Vec<Vec<(VersionComparator, ComposerVersion)>>,
}

impl ComposerVersionRange {
    pub fn parse(ecosystem: &str, text: &str) -> Result<Self, String> {
        let ecosystem = match ecosystem {
            COMPOSER_ECOSYSTEM => COMPOSER_ECOSYSTEM,
            PHP_TOOLCHAIN_ECOSYSTEM => PHP_TOOLCHAIN_ECOSYSTEM,
            _ => unreachable!("{ecosystem} is not a Composer version ecosystem"),
        };
        let alternatives = text
            .split("||")
            .flat_map(|part| part.split('|'))
            .map(parse_conjunction)
            .collect::<Result<_, String>>()?;
        Ok(Self {
            ecosystem,
            alternatives,
        })
    }
}

const COMPARATORS: [(&str, VersionComparator); 8] = [
    (">=", VersionComparator::GreaterOrEqual),
    ("<=", VersionComparator::LessOrEqual),
    ("<>", VersionComparator::NotEqual),
    ("!=", VersionComparator::NotEqual),
    ("==", VersionComparator::Equal),
    (">", VersionComparator::Greater),
    ("<", VersionComparator::Less),
    ("=", VersionComparator::Equal),
];

/// One `||` alternative: constraints joined by commas or spaces. An operator
/// may stand apart from its version (`>= 1.0`), and ` - ` joins a hyphen
/// range.
fn parse_conjunction(text: &str) -> Result<Vec<(VersionComparator, ComposerVersion)>, String> {
    let tokens = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(format!("{text:?} has an empty Composer constraint"));
    }
    let mut bounds = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let mut token = tokens[index].to_owned();
        let bare_operator = COMPARATORS.iter().any(|(spelling, _)| token == *spelling)
            || token == "^"
            || token == "~";
        if bare_operator {
            index += 1;
            let version = tokens
                .get(index)
                .ok_or_else(|| format!("{text:?} has an operator with no version"))?;
            token.push_str(version);
        }
        if tokens.get(index + 1) == Some(&"-") {
            let upper = tokens
                .get(index + 2)
                .ok_or_else(|| format!("{text:?} has a hyphen range with no upper bound"))?;
            hyphen_bounds(&token, upper, &mut bounds)?;
            index += 3;
            continue;
        }
        constraint_bounds(&token, &mut bounds)?;
        index += 1;
    }
    Ok(bounds)
}

fn strip_stability_flag(text: &str) -> &str {
    match text.rsplit_once('@') {
        Some((constraint, flag))
            if ["stable", "rc", "beta", "alpha", "dev"]
                .contains(&flag.to_ascii_lowercase().as_str()) =>
        {
            constraint
        }
        _ => text,
    }
}

/// The lower bound of a caret, tilde or hyphen range: the version itself,
/// lowered to its `-dev` floor when it names no stability.
fn lower_bound(authored: &Authored) -> ComposerVersion {
    if authored.has_modifier {
        authored.version.clone()
    } else {
        ComposerVersion::dev_floor(authored.version.release)
    }
}

fn constraint_bounds(
    text: &str,
    bounds: &mut Vec<(VersionComparator, ComposerVersion)>,
) -> Result<(), String> {
    use VersionComparator::{GreaterOrEqual, Less};
    let text = strip_stability_flag(text);
    if matches!(text, "*" | "x" | "X") {
        return Ok(());
    }
    if let Some(version) = text.strip_prefix('^') {
        let authored = parse_authored(version)?;
        let parts = &authored.parts;
        let position = if parts[0] != 0 || parts.len() == 1 {
            1
        } else if parts[1] != 0 || parts.len() == 2 {
            2
        } else {
            3
        };
        bounds.push((GreaterOrEqual, lower_bound(&authored)));
        bounds.push((Less, ComposerVersion::dev_floor(bumped(parts, position, 1))));
        return Ok(());
    }
    if let Some(version) = text.strip_prefix('~') {
        if version.starts_with('>') {
            return Err(format!(
                "{text:?} uses Ruby's ~>; Composer spells it ~ or >="
            ));
        }
        let authored = parse_authored(version)?;
        let position = authored.parts.len().saturating_sub(1).max(1);
        bounds.push((GreaterOrEqual, lower_bound(&authored)));
        bounds.push((
            Less,
            ComposerVersion::dev_floor(bumped(&authored.parts, position, 1)),
        ));
        return Ok(());
    }
    if let Some(prefix) = ["*", "x", "X"]
        .iter()
        .find_map(|wildcard| text.strip_suffix(wildcard)?.strip_suffix('.'))
    {
        let authored = parse_authored(prefix)?;
        if authored.has_modifier || authored.parts.len() > 3 {
            return Err(format!("{text:?} is not a Composer wildcard"));
        }
        let position = authored.parts.len();
        let low = bumped(&authored.parts, position, 0);
        if low != [0; 4] {
            bounds.push((GreaterOrEqual, ComposerVersion::dev_floor(low)));
        }
        bounds.push((
            Less,
            ComposerVersion::dev_floor(bumped(&authored.parts, position, 1)),
        ));
        return Ok(());
    }
    let (comparator, version) = COMPARATORS
        .iter()
        .find_map(|(spelling, comparator)| {
            text.strip_prefix(spelling).map(|rest| (*comparator, rest))
        })
        .unwrap_or((VersionComparator::Equal, text));
    let authored = parse_authored(version)?;
    let bound = if matches!(comparator, Less | GreaterOrEqual) {
        lower_bound(&authored)
    } else {
        authored.version
    };
    bounds.push((comparator, bound));
    Ok(())
}

fn hyphen_bounds(
    lower: &str,
    upper: &str,
    bounds: &mut Vec<(VersionComparator, ComposerVersion)>,
) -> Result<(), String> {
    let low = parse_authored(lower)?;
    let high = parse_authored(upper)?;
    bounds.push((VersionComparator::GreaterOrEqual, lower_bound(&low)));
    // A complete upper bound is inclusive; a partial one covers every
    // release it names.
    if high.parts.len() >= 3 || high.has_modifier {
        bounds.push((VersionComparator::LessOrEqual, high.version));
    } else {
        bounds.push((
            VersionComparator::Less,
            ComposerVersion::dev_floor(bumped(&high.parts, high.parts.len(), 1)),
        ));
    }
    Ok(())
}

/// Whether one complete locked or installed row of the range's ecosystem has
/// an exact version in `range`. Declarations, platform constraints, branch
/// versions (`dev-main`, `1.x-dev`) and path-repository packages (whose code
/// need not be any release) have no comparable selected version and stay
/// unknown.
pub fn composer_dependency_version_matches(
    row: &DependencyEvidence,
    range: &ComposerVersionRange,
) -> Result<Option<bool>, String> {
    if row.ecosystem != range.ecosystem
        || !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
        || row
            .source
            .as_deref()
            .is_some_and(|source| source.starts_with("path:"))
    {
        return Ok(None);
    }
    let Some(version) = row
        .exact_version
        .as_deref()
        .and_then(|version| ComposerVersion::parse(version).ok())
    else {
        return Ok(None);
    };
    if version.stability == Stability::Dev {
        return Ok(None);
    }
    Ok(Some(version_bounds_admit(&range.alternatives, &version)))
}

#[cfg(test)]
mod tests {
    use crate::analyzer::php::dependency_evidence::*;

    fn version(text: &str) -> ComposerVersion {
        ComposerVersion::parse(text).unwrap()
    }

    fn admits(range: &str, candidate: &str) -> bool {
        version_bounds_admit(
            &ComposerVersionRange::parse(COMPOSER_ECOSYSTEM, range)
                .unwrap()
                .alternatives,
            &version(candidate),
        )
    }

    /// Composer ordering and constraint forms, checked against the answers
    /// `Composer\Semver\Semver::satisfies` gives.
    #[test]
    fn composer_versions_and_constraints_follow_composer_semantics() {
        for (lower, higher) in [
            ("1.0.0-dev", "1.0.0-alpha1"),
            ("1.0.0-alpha1", "1.0.0-beta1"),
            ("1.0.0-beta1", "1.0.0-beta2"),
            ("1.0.0-beta2-dev", "1.0.0-beta2"),
            ("1.0.0-beta2", "1.0.0-RC1"),
            ("1.0.0-RC1", "1.0.0"),
            ("1.0.0", "1.0.0-p1"),
            ("1.9", "1.10"),
        ] {
            assert!(version(lower) < version(higher), "{lower} < {higher}");
        }
        assert_eq!(version("v1.2"), version("1.2.0.0"));
        assert_eq!(version("1.0.0-b2"), version("1.0.0beta2"));
        assert_eq!(version("1.0.0.RC.1"), version("1.0.0-rc1"));
        for invalid in ["", "dev-main", "1.x-dev", "1.2.3.4.5", "1..0", "junk"] {
            assert!(ComposerVersion::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(admits("^1.2", "1.9.9"));
        assert!(!admits("^1.2", "2.0.0-beta1"));
        assert!(admits("^1.2", "1.2.0-RC1"));
        assert!(admits("^0.3", "0.3.9"));
        assert!(!admits("^0.3", "0.4.0"));
        assert!(!admits("^0.0.3", "0.0.4"));
        assert!(admits("~1.2", "1.9"));
        assert!(!admits("~1.2", "2.0"));
        assert!(!admits("~1.2.3", "1.3.0"));
        assert!(admits("1.2.*", "1.2.99"));
        assert!(!admits("1.2.*", "1.3.0-alpha1"));
        assert!(admits("1.0 - 2.0", "2.0.5"));
        assert!(!admits("1.0 - 2.0", "2.1.0"));
        assert!(!admits("1.0.0 - 2.1.0", "2.1.1"));
        assert!(!admits("<2.0", "2.0.0-beta1"));
        assert!(admits("<=2.0", "2.0.0-beta1"));
        assert!(admits(">= 1.0, <1.2 || ^2.1", "2.5"));
        assert!(admits(">=1.0 <1.2 | 3.0", "3.0.0"));
        assert!(admits("!=1.0.1", "1.0.2"));
        assert!(admits("^3.8@RC", "3.8.0-RC1"));
        assert!(admits("*", "0.0.1"));
        for invalid in ["", "<", "~>1.0", ">= x", "1.0 -"] {
            assert!(
                ComposerVersionRange::parse(COMPOSER_ECOSYSTEM, invalid).is_err(),
                "{invalid:?}"
            );
        }
    }
}
