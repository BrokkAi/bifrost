//! Package activation rows for the exact PyPI distributions a workspace pins.

use std::collections::BTreeMap;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_diagnostic;
use brokk_bifrost_analysis::analyzer::dependency_support::dependency_provenance_entry as provenance_entry;
use brokk_bifrost_analysis::analyzer::dependency_support::select_dependency_input_snapshots;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;
use brokk_bifrost_analysis::analyzer::semantic_model::dependency::{
    BoundedDependencyDiagnostics, DependencyPackLimits, ResolvedDependency,
};
use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;
use pep440_rs::Operator;

use crate::analyzer::python::packaging::*;

/// The lock and requirements files whose exact pins activate PyPI packs.
pub const PYTHON_LOCK_ACTIVATION_INPUTS: [&str; 3] = ["uv.lock", "poetry.lock", "requirements.txt"];

/// The only package index whose names are PyPI project names.
const PYPI_SIMPLE_INDEX: &str = "https://pypi.org/simple";

/// Artifact-less `pkg:pypi/<name>` activation rows for the distributions the
/// workspace pins exactly, so an installed or reviewed pack for that
/// distribution activates without an installed environment (#14581).
///
/// Each row names the normalized distribution and its exact version. It reads
/// no wheel and produces nothing: it only selects a compatible pack, as a
/// Bundler lock row does for a gem (#9319). The owner decided that this
/// name-and-version evidence is enough for exact member binding (#14581).
/// The pins that count:
/// - `uv.lock` packages from the pypi.org registry;
/// - `poetry.lock` packages with no explicit source (Poetry's PyPI default);
/// - `requirements.txt` requirements whose only specifier is `==<version>`.
///
/// Fail-closed cases activate nothing: ranges, bare names, wildcard pins and
/// `===`, which also block a pin of the same distribution elsewhere;
/// incomplete rows; versions with an epoch, pre-, post-, dev- or local
/// segment, or more than three release segments, which have no
/// semantic-version coordinate; requirements pins with an environment
/// marker; a distribution a `pyproject.toml` takes from a direct URL or a
/// configured index, which blocks its PyPI pins; and every pin when a requirements root includes another file
/// (`-r`, `-c`), which is not a discovery input and whose index options and
/// constraints apply to every pin, when selection omitted or could not read a
/// file, or when a file has an entry the parser could not interpret
/// (`python.lockfile.incomplete_evidence`). A versionless local uv row (the
/// workspace's own project) is not such an entry. Activation is workspace-wide, so one pin's models
/// would apply to code that loads another distribution of the same name: a
/// distribution pinned at more than one version, or also pinned from git, a
/// URL, a path, another index, or a requirements file with an index option, is
/// reported as `python.lockfile.ambiguous_activation`.
///
/// Returns the rows and whether acquisition was cancelled.
pub fn python_lock_activation_rows(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> (Vec<ResolvedDependency>, bool) {
    let reported = |diagnostics: &BoundedDependencyDiagnostics| {
        diagnostics.diagnostics.len() + diagnostics.suppressed.total()
    };
    let reported_before_selection = reported(diagnostics);
    let (selected, _, cancelled) = select_dependency_input_snapshots(
        project,
        "Python",
        "python",
        |path| {
            is_python_lock_activation_input(path)
                || path.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml")
        },
        limits,
        cancellation,
        diagnostics,
    );
    if cancelled {
        return (Vec::new(), true);
    }
    // Selection reports a file it omitted (a file or byte limit) or could not
    // read. That file could pin another version or source of any distribution,
    // so no retained pin proves its distribution unique.
    if reported(diagnostics) != reported_before_selection {
        return (Vec::new(), false);
    }
    let file_limits = DependencyFileEvidenceLimits::default();
    let mut evidence = DependencyFileEvidence::default();
    let mut requirements = Vec::new();
    // A project manifest's ranges are what its lock resolves, so they neither
    // activate nor block. A direct-URL requirement (`name @ git+...`) installs
    // that distribution from outside PyPI, so it blocks a PyPI pin of the same
    // name elsewhere. A requirement a configured index serves (Poetry's
    // `source_selection`) may also come from outside PyPI, so it blocks too.
    let mut manifest_blockers = Vec::new();
    let mut manifest_gaps = Vec::new();
    for (file, snapshot) in &selected {
        let path = file.rel_path();
        let name = path.file_name().and_then(|name| name.to_str());
        if name == Some("pyproject.toml") {
            let parsed = parse_python_packaging_file(
                path,
                &snapshot.oid().to_string(),
                snapshot.source(),
                &file_limits,
                cancellation,
            );
            // Dynamic metadata (usually the version) is unresolved in most
            // manifests and leaves its pins to the lock. Any other gap (a
            // limit, a malformed or unsupported entry) could hide a blocker.
            manifest_gaps.extend(
                parsed
                    .gaps
                    .into_iter()
                    .filter(|gap| gap.kind != Gap::Unresolved),
            );
            manifest_blockers.extend(parsed.rows.into_iter().filter(|row| {
                row.kind == Kind::Declared
                    && (row.source.is_some()
                        || row
                            .conditions
                            .iter()
                            .any(|condition| condition.kind == "source_selection"))
            }));
            continue;
        }
        if name == Some("requirements.txt") {
            requirements.push(PythonRequirementsInput {
                path: path.to_path_buf(),
                kind: Kind::Declared,
                declared_by: None,
            });
            continue;
        }
        let parsed = parse_python_packaging_file(
            path,
            &snapshot.oid().to_string(),
            snapshot.source(),
            &file_limits,
            cancellation,
        );
        evidence.rows.extend(parsed.rows);
        evidence.gaps.extend(parsed.gaps);
    }
    let parsed =
        read_python_requirements_evidence(project, &requirements, &file_limits, cancellation);
    // An included file, even one that pins nothing, is read beyond the roots.
    let requirements_include = parsed.files_read > requirements.len();
    evidence.rows.extend(parsed.rows);
    evidence.gaps.extend(parsed.gaps);
    if evidence
        .gaps
        .iter()
        .chain(&manifest_gaps)
        .any(|gap| gap.kind == Gap::Cancelled)
    {
        return (Vec::new(), true);
    }
    // Any gap leaves a pin unread or uninterpreted: an omitted row (a limit), an
    // unparsable lock, an editable or URL requirement without a name, or an
    // index option such as `--index-url` that may resolve pins from somewhere
    // other than PyPI, in a lock, requirements or project manifest. Each could
    // select another version or source of any distribution, so no read pin
    // proves its distribution unique.
    // uv records the workspace's own projects as local rows that may have no
    // version (a dynamic or virtual root). Such a row names no distribution
    // anyone installs from an index, so its missing version leaves no pin
    // unread.
    let local_rows = evidence
        .rows
        .iter()
        .filter(|row| {
            row.kind == Kind::Locked && row.source.as_deref().is_some_and(is_local_uv_source)
        })
        .map(|row| (row.build_file.as_path(), &row.byte_range))
        .collect::<Vec<_>>();
    let gaps = evidence
        .gaps
        .iter()
        .filter(|gap| !local_rows.contains(&(gap.build_file.as_path(), &gap.byte_range)))
        .collect::<Vec<_>>();
    // An included file is not a discovery input, so a later change to it would
    // not re-run discovery, and pip applies its index options and constraints
    // to every pin. Once any requirements root includes another file, no pin
    // in the workspace is proven current and unique.
    if requirements_include {
        diagnostics.push(dependency_diagnostic(
            "python.lockfile.incomplete_evidence",
            None,
            "a requirements file includes another file (-r or -c), which is not a discovery input; no pin activates package-scoped semantic models",
        ));
        return (Vec::new(), false);
    }
    if !gaps.is_empty() {
        let gaps = gaps
            .iter()
            .map(|gap| (gap.kind, gap.build_file.as_path(), gap.message.as_str()))
            .collect::<Vec<_>>();
        diagnostics.push(dependency_diagnostic(
            "python.lockfile.incomplete_evidence",
            None,
            format!(
                "the workspace's lock and requirements files have uninterpreted entries, so no pin activates package-scoped semantic models: {gaps:?}"
            ),
        ));
        return (Vec::new(), false);
    }
    // A manifest's ranges neither activate nor block, so a manifest gap can
    // hide only a blocker of some read pin. With no pin there is nothing to
    // withhold, and a workspace whose toolchain another file selects keeps a
    // complete discovery (#12368).
    if !manifest_gaps.is_empty() && evidence.rows.iter().any(|row| exact_pin(row).is_some()) {
        let gaps = manifest_gaps
            .iter()
            .map(|gap| (gap.kind, gap.build_file.as_path(), gap.message.as_str()))
            .collect::<Vec<_>>();
        diagnostics.push(dependency_diagnostic(
            "python.lockfile.incomplete_evidence",
            None,
            format!(
                "a project manifest has uninterpreted entries that could take a pinned distribution from outside PyPI, so no pin activates package-scoped semantic models: {gaps:?}"
            ),
        ));
        return (Vec::new(), false);
    }

    let mut by_distribution = BTreeMap::<&str, BTreeMap<Pin, Vec<&DependencyEvidence>>>::new();
    for row in &manifest_blockers {
        by_distribution
            .entry(row.package.as_str())
            .or_default()
            .entry(Pin::Other)
            .or_default()
            .push(row);
    }
    for row in &evidence.rows {
        // A requirement with an environment marker may not be installed where
        // the code runs.
        let blocks_only = row.kind == Kind::Declared
            && row
                .conditions
                .iter()
                .any(|condition| condition.kind == "marker");
        let pin = match exact_pin(row) {
            Some(Pin::PyPi(_)) if blocks_only => Pin::Other,
            Some(pin) => pin,
            None => continue,
        };
        by_distribution
            .entry(row.package.as_str())
            .or_default()
            .entry(pin)
            .or_default()
            .push(row);
    }
    let mut rows = Vec::new();
    for (distribution, versions) in by_distribution {
        let (version, pins) = match versions.into_iter().collect::<Vec<_>>().as_slice() {
            [(Pin::PyPi(version), pins)] => (version.clone(), pins.clone()),
            // A distribution only some other source supplies is not on PyPI.
            [(Pin::Other, _)] => continue,
            pinned => {
                diagnostics.push(dependency_diagnostic(
                    "python.lockfile.ambiguous_activation",
                    None,
                    format!(
                        "the workspace pins distribution {distribution} as {:?}; no pin activates package-scoped semantic models",
                        pinned.iter().map(|(pin, _)| pin).collect::<Vec<_>>()
                    ),
                ));
                continue;
            }
        };
        let Some(coordinate_version) = semantic_version(&version) else {
            diagnostics.push(dependency_diagnostic(
                "python.lockfile.unsupported_version",
                Some(&pins[0].build_file),
                format!(
                    "distribution {distribution} is pinned at {version}, which has no semantic-version coordinate; it activates no package-scoped semantic models"
                ),
            ));
            continue;
        };
        let first = pins
            .iter()
            .min_by(|left, right| left.build_file.cmp(&right.build_file))
            .expect("a grouped version has a pin");
        let activation = if first.kind == Kind::Locked {
            "exact_lock_row"
        } else {
            "exact_requirement_pin"
        };
        let mut provenance = vec![
            provenance_entry("pypi.name", distribution),
            provenance_entry("pypi.version", &version),
            provenance_entry("python.activation", activation),
            provenance_entry("python.pin_file", first.build_file.display()),
            provenance_entry("python.pin_file_digest", &first.source_digest),
        ];
        provenance.sort_by(|left, right| left.key.cmp(&right.key));
        rows.push(ResolvedDependency {
            id: format!("pypi:pin:{distribution}@{version}"),
            evidence: SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package: Some(CatalogCoordinate {
                    name: format!("pkg:pypi/{distribution}"),
                    version: Some(coordinate_version),
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            },
            provenance,
            artifacts: Vec::new(),
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    (rows, false)
}

/// Whether a uv source identity names a project in the workspace itself.
fn is_local_uv_source(source: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(source)
        .ok()
        .and_then(|source| {
            source.as_object().map(|object| {
                ["virtual", "editable", "directory"]
                    .iter()
                    .any(|key| object.contains_key(*key))
            })
        })
        .unwrap_or(false)
}

pub fn is_python_lock_activation_input(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| PYTHON_LOCK_ACTIVATION_INPUTS.contains(&name))
}

/// What one exact pin selects: a PyPI release, or a distribution from another
/// source (a git, URL, path or other-index lock row, or a direct URL
/// requirement), which blocks activation of the PyPI name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Pin {
    /// Compared as PEP 440 versions, so `==1.4` and a locked `1.4.0` agree.
    PyPi(Version),
    Other,
}

/// What a row says about one distribution: an exact PyPI release, a blocker
/// (another source, or a requirement that leaves the version open), or
/// `None` for a row that says nothing, such as an incomplete row.
fn exact_pin(row: &DependencyEvidence) -> Option<Pin> {
    if row.ecosystem != "pypi" || !row.complete {
        return None;
    }
    match row.kind {
        Kind::Locked => {
            let source = row.source.as_deref()?;
            let from_pypi = source == "registry:pypi"
                || serde_json::from_str::<serde_json::Value>(source)
                    .ok()
                    .and_then(|source| {
                        source
                            .get("registry")
                            .and_then(serde_json::Value::as_str)
                            .map(|registry| registry.trim_end_matches('/') == PYPI_SIMPLE_INDEX)
                    })
                    .unwrap_or(false);
            let version = row
                .exact_version
                .as_deref()
                .and_then(|version| Version::from_str(version).ok());
            Some(match (from_pypi, version) {
                (true, Some(version)) => Pin::PyPi(version),
                _ => Pin::Other,
            })
        }
        Kind::Declared if row.source.is_some() => Some(Pin::Other),
        // A bare name or a range leaves the installed version open, so it
        // blocks a pin of the same distribution elsewhere in the workspace.
        Kind::Declared => Some(
            row.version_requirement
                .as_deref()
                .and_then(|requirement| VersionSpecifiers::from_str(requirement).ok())
                .and_then(|specifiers| match &*specifiers {
                    [specifier] if *specifier.operator() == Operator::Equal => {
                        Some(Pin::PyPi(specifier.version().clone()))
                    }
                    _ => None,
                })
                .unwrap_or(Pin::Other),
        ),
        _ => None,
    }
}

/// The semantic-version coordinate of a plain PEP 440 release with at most
/// three segments; `3.1` is `3.1.0`.
fn semantic_version(version: &Version) -> Option<semver::Version> {
    if version.epoch() != 0
        || version.is_pre()
        || version.is_post()
        || version.is_dev()
        || version.is_local()
    {
        return None;
    }
    let release = version.release();
    if release.is_empty() || release.len() > 3 {
        return None;
    }
    let segment = |index: usize| release.get(index).copied().unwrap_or(0);
    Some(semver::Version::new(segment(0), segment(1), segment(2)))
}
