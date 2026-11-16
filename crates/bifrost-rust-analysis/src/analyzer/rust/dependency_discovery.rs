#[cfg(test)]
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelNamespace;

use std::collections::{BTreeMap, VecDeque};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::dependency_support::cancelled_dependency_evidence_diagnostic;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_diagnostic as diagnostic;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_provenance_entry;

use crate::analyzer::semantic_model::ExternalDiscoveryRead;
use brokk_bifrost_analysis::analyzer::dependency_support::{
    declare_external_discovery_reads_complete, read_external_evidence_file_with_budget,
    refuse_external_discovery_reads, report_external_discovery_read,
};

use brokk_bifrost_analysis::analyzer::dependency_support::require_non_empty_evidence_field;

use brokk_bifrost_analysis::analyzer::dependency_support::resolve_dependency_path as resolve_path;

use crate::analyzer::semantic_model::BoundedDependencyDiagnostics;

use crate::analyzer::semantic_model::CatalogCoordinate;

use crate::analyzer::semantic_model::DependencyArtifactRole;

use crate::analyzer::semantic_model::DependencyDiscoveryOutcome;

use crate::analyzer::semantic_model::DependencyDiscoveryProfile;

use crate::analyzer::semantic_model::DependencyPackDiagnostic;

use crate::analyzer::semantic_model::DependencyPackLimits;

use crate::analyzer::semantic_model::DependencyProvenance;

use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind;

use crate::analyzer::semantic_model::ResolvedDependency;

use crate::analyzer::semantic_model::ResolvedDependencyArtifact;

use crate::analyzer::semantic_model::SemanticModelActivationEvidence;
use crate::analyzer::semantic_model::{
    CargoPackageId, CargoResolveEdge, CargoResolveView, CargoSelectedPackage,
    RustCargoArtifactTuple, RustSelectedCargoGraph,
};

use crate::analyzer::semantic_model::StandardLibraryPackExpectation;
use crate::analyzer::topology::DependencyScope;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::config::RustAnalyzerConfig;

use brokk_bifrost_core::analyzer::config::RustArtifactApproximationClaim;
use brokk_bifrost_core::analyzer::config::RustDependencyApiEvidence;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

mod docsrs_evidence;
pub use docsrs_evidence::{
    DocsRsArtifactInput, DocsRsAuthority, DocsRsBindingOutcome, DocsRsBindingRow,
    bind_docsrs_artifacts,
};

const CARGO_METADATA_FORMAT_VERSION: u32 = 1;
const MINIMUM_LOCKFILE_VERSION: u32 = 3;
const MAXIMUM_LOCKFILE_VERSION: u32 = 4;

pub const RUST_STDLIB_TOOLCHAIN_CHANNEL: &str = "nightly-2026-08-24";
pub const RUST_STDLIB_TOOLCHAIN_NAME: &str = "rust";
pub const RUST_STDLIB_TOOLCHAIN_VERSION: &str = "1.100.0-nightly";
pub const RUST_STDLIB_RUSTC_COMMIT: &str = "fb6531d55";
/// The rustdoc standard-library pack a pinned `rust-toolchain.toml` selects
/// (authored in `BrokkAi/bifrost-packs`).
pub const RUST_STDLIB_PACK_ID: &str = "bifrost.rust-stdlib";

#[derive(Debug, Deserialize)]
struct RustToolchainFile {
    toolchain: RustToolchainSection,
}

#[derive(Debug, Deserialize)]
struct RustToolchainSection {
    channel: String,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    version: u32,
    #[serde(default)]
    packages: Vec<CargoMetadataPackage>,
    resolve: Option<CargoMetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    #[serde(default)]
    targets: Vec<CargoMetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataTarget {
    name: String,
    #[serde(default)]
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataResolve {
    #[serde(default)]
    nodes: Vec<CargoMetadataNode>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNode {
    id: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    deps: Vec<CargoMetadataNodeDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNodeDependency {
    name: String,
    pkg: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CargoLockfile {
    pub(crate) version: u32,
    #[serde(default, rename = "package")]
    pub(crate) packages: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CargoLockPackage {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
    pub(crate) checksum: Option<String>,
    #[serde(default)]
    pub(crate) dependencies: Vec<String>,
}

/// Decode the same lock contract for API ingestion and files-only evidence.
pub(crate) fn decode_cargo_lockfile(
    source: &str,
    path: &Path,
) -> Result<CargoLockfile, DependencyPackDiagnostic> {
    let lockfile: CargoLockfile = toml::from_str(source).map_err(|error| {
        diagnostic(
            "rust.lockfile.invalid_toml",
            Some(path),
            format!("could not decode Cargo.lock: {error}"),
        )
    })?;
    if !(MINIMUM_LOCKFILE_VERSION..=MAXIMUM_LOCKFILE_VERSION).contains(&lockfile.version) {
        return Err(diagnostic(
            "rust.lockfile.unsupported_version",
            Some(path),
            format!(
                "Cargo.lock version {} is unsupported; expected {} through {}",
                lockfile.version, MINIMUM_LOCKFILE_VERSION, MAXIMUM_LOCKFILE_VERSION
            ),
        ));
    }
    for package in &lockfile.packages {
        semver::Version::parse(&package.version).map_err(|error| {
            diagnostic(
                "rust.lockfile.invalid_semver",
                Some(path),
                format!("invalid locked version for {}: {error}", package.name),
            )
        })?;
        if package.name.is_empty() || package.source.as_deref() == Some("") {
            return Err(diagnostic(
                "rust.lockfile.invalid_identity",
                Some(path),
                "empty lock package name or source",
            ));
        }
        for reference in &package.dependencies {
            cargo_lock_reference(reference).map_err(|message| {
                diagnostic(
                    "rust.lockfile.invalid_dependency_reference",
                    Some(path),
                    message,
                )
            })?;
        }
    }
    Ok(lockfile)
}

/// Cargo wire reference grammar: name [version] [(source)]. These are lock
/// coordinates, not Rust source paths or rendered analyzer identities.
pub(crate) fn cargo_lock_reference(
    reference: &str,
) -> Result<(&str, Option<&str>, Option<&str>), &'static str> {
    let (coordinate, source) = match reference.split_once(" (") {
        Some((coordinate, suffix)) => (
            coordinate,
            Some(
                suffix
                    .strip_suffix(')')
                    .filter(|source| !source.is_empty())
                    .ok_or("invalid lock source reference")?,
            ),
        ),
        None => (reference, None),
    };
    let mut parts = coordinate.split_whitespace();
    let name = parts.next().ok_or("empty lock dependency reference")?;
    let version = parts.next();
    if parts.next().is_some() || (source.is_some() && version.is_none()) {
        return Err("invalid lock dependency reference shape");
    }
    if let Some(version) = version {
        semver::Version::parse(version).map_err(|_| "invalid lock dependency version")?;
    }
    Ok((name, version, source))
}

#[derive(Debug, Deserialize)]
struct RustdocVersionEnvelope {
    format_version: u32,
    #[serde(default)]
    crate_version: Option<String>,
    #[serde(default)]
    target: Option<RustdocTargetEnvelope>,
    #[serde(default)]
    external_crates: BTreeMap<String, serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
struct RustdocTargetEnvelope {
    triple: String,
}

#[derive(Debug)]
struct DecodedRustdocArtifact {
    package_id: String,
    crate_name: String,
    enabled_features: Vec<String>,
    toolchain: String,
    path: PathBuf,
    format_version: u32,
    crate_version: Option<String>,
    target: String,
    sha256: String,
    approximation: Option<RustArtifactApproximationClaim>,
    cfgs: Vec<String>,
    has_external_reexports: bool,
}

#[derive(Debug)]
struct DecodedRustDependencyEvidence {
    metadata: CargoMetadata,
    lockfile: CargoLockfile,
    artifacts: Vec<DecodedRustdocArtifact>,
}

/// The resolved half is computed from Cargo/lock and the artifact half is
/// checked against the JSON and its bytes. This is the runtime record, not an
/// assertion supplied by the acquisition host.
#[derive(Debug)]
struct RustResolvedArtifactApproximation {
    package_id: String,
    resolved_version: String,
    resolved_features: Vec<String>,
    resolved_target: String,
    artifact_version: String,
    artifact_features: Vec<String>,
    artifact_cfgs: Vec<String>,
    artifact_toolchain: String,
    artifact_format_version: u32,
    artifact_target: String,
    docsrs_build: bool,
    artifact_sha256: String,
    activation_version_requirement: String,
    direction: &'static str,
    mismatch_kinds: Vec<&'static str>,
    selection_rule_id: String,
    selection_rule_version: u32,
}

impl RustResolvedArtifactApproximation {
    fn pack_record(
        &self,
    ) -> brokk_bifrost_semantic::analyzer::semantic_model::RustArtifactApproximation {
        use brokk_bifrost_semantic::analyzer::semantic_model::RustArtifactMismatchKind;
        brokk_bifrost_semantic::analyzer::semantic_model::RustArtifactApproximation {
            built_from_version: self.artifact_version.clone(),
            built_from_features: self.artifact_features.clone(),
            built_from_cfgs: self.artifact_cfgs.clone(),
            target: self.artifact_target.clone(),
            format_version: self.artifact_format_version,
            toolchain: self.artifact_toolchain.clone(),
            docsrs_build: self.docsrs_build,
            original_sha256: self.artifact_sha256.clone(),
            produced_sha256: self.artifact_sha256.clone(),
            activation_version_requirement: self.activation_version_requirement.clone(),
            mismatch_kinds: self
                .mismatch_kinds
                .iter()
                // Version mismatch belongs to resolved Y, so it cannot be
                // frozen into a pack that may activate for several Y values.
                .filter(|kind| **kind != "version-nearby")
                .map(|kind| match *kind {
                    "feature-superset" => RustArtifactMismatchKind::FeatureSuperset,
                    _ => unreachable!("validated approximation mismatch kind"),
                })
                .collect(),
            selection_rule_id: self.selection_rule_id.clone(),
            selection_rule_version: self.selection_rule_version,
        }
    }
    fn provenance(&self) -> Vec<(&'static str, String)> {
        vec![
            ("rust.approximation.package_id", self.package_id.clone()),
            (
                "rust.approximation.resolved_version",
                self.resolved_version.clone(),
            ),
            (
                "rust.approximation.resolved_features",
                self.resolved_features.join(","),
            ),
            (
                "rust.approximation.resolved_target",
                self.resolved_target.clone(),
            ),
            (
                "rust.approximation.artifact_version",
                self.artifact_version.clone(),
            ),
            (
                "rust.approximation.artifact_features",
                self.artifact_features.join(","),
            ),
            (
                "rust.approximation.artifact_cfgs",
                self.artifact_cfgs.join(","),
            ),
            (
                "rust.approximation.artifact_toolchain",
                self.artifact_toolchain.clone(),
            ),
            (
                "rust.approximation.artifact_format_version",
                self.artifact_format_version.to_string(),
            ),
            (
                "rust.approximation.artifact_target",
                self.artifact_target.clone(),
            ),
            (
                "rust.approximation.docsrs_build",
                self.docsrs_build.to_string(),
            ),
            (
                "rust.approximation.artifact_sha256",
                self.artifact_sha256.clone(),
            ),
            (
                "rust.approximation.activation_version_requirement",
                self.activation_version_requirement.clone(),
            ),
            ("rust.approximation.direction", self.direction.to_owned()),
            (
                "rust.approximation.mismatch_kinds",
                self.mismatch_kinds.join(","),
            ),
            (
                "rust.approximation.selection_rule_id",
                self.selection_rule_id.clone(),
            ),
            (
                "rust.approximation.selection_rule_version",
                self.selection_rule_version.to_string(),
            ),
        ]
    }
}

fn validate_rust_artifact_approximation(
    artifact: &DecodedRustdocArtifact,
    package: &CargoMetadataPackage,
    node: &CargoMetadataNode,
    resolved_version: &semver::Version,
    resolved_target: &str,
) -> Result<Option<RustResolvedArtifactApproximation>, DependencyPackDiagnostic> {
    let mut resolved_features = node.features.clone();
    resolved_features.sort();
    resolved_features.dedup();
    let exact_version = artifact.crate_version.as_deref() == Some(package.version.as_str());
    let exact_features = artifact.enabled_features == resolved_features;
    let Some(claim) = &artifact.approximation else {
        // A narrower exact-version artifact retains the existing partial-pack
        // path: it cannot prove absence for features it never saw. A superset
        // claims full authority and therefore needs an approximation record.
        if exact_version
            && artifact
                .enabled_features
                .iter()
                .all(|feature| resolved_features.contains(feature))
        {
            return Ok(None);
        }
        return Err(diagnostic(
            "rust.rustdoc.approximation_record_required",
            Some(&artifact.path),
            "rustdoc version or feature mismatch requires a checked approximation record",
        ));
    };
    let invalid = |reason: &str| {
        diagnostic(
            "rust.rustdoc.invalid_approximation_record",
            Some(&artifact.path),
            reason,
        )
    };
    let artifact_version = artifact
        .crate_version
        .as_deref()
        .ok_or_else(|| invalid("rustdoc JSON has no crate version"))?;
    if claim.artifact_version != artifact_version
        || claim.artifact_sha256 != artifact.sha256
        || claim.artifact_features != artifact.enabled_features
        || claim.artifact_cfgs != artifact.cfgs
        || claim.selection_rule_id != "cargo-compatible-nearest"
        || claim.selection_rule_version != 1
    {
        return Err(invalid(
            "artifact claim disagrees with observed JSON, digest, features or selection rule",
        ));
    }
    if !resolved_features
        .iter()
        .all(|feature| artifact.enabled_features.contains(feature))
    {
        return Err(invalid(
            "artifact features are narrower than Cargo-resolved features",
        ));
    }
    let built_version = semver::Version::parse(artifact_version)
        .map_err(|_| invalid("artifact crate version is invalid semver"))?;
    if !same_cargo_compatibility_family(&built_version, resolved_version) {
        return Err(invalid(
            "artifact version is outside Cargo compatibility range",
        ));
    }
    validate_approximate_activation_range(
        &built_version,
        resolved_version,
        &claim.activation_version_requirement,
    )
    .map_err(|reason| invalid(&reason))?;
    let direction = match built_version.cmp(resolved_version) {
        std::cmp::Ordering::Less => "older_artifact",
        std::cmp::Ordering::Greater => "newer_artifact",
        std::cmp::Ordering::Equal => "same_version",
    };
    let mut mismatch_kinds = Vec::new();
    if !exact_version {
        mismatch_kinds.push("version-nearby");
    }
    if !exact_features {
        mismatch_kinds.push("feature-superset");
    }
    Ok(Some(RustResolvedArtifactApproximation {
        package_id: package.id.clone(),
        resolved_version: package.version.clone(),
        resolved_features,
        resolved_target: resolved_target.to_owned(),
        artifact_version: artifact_version.to_owned(),
        artifact_features: artifact.enabled_features.clone(),
        artifact_cfgs: claim.artifact_cfgs.clone(),
        artifact_toolchain: artifact.toolchain.clone(),
        artifact_format_version: artifact.format_version,
        artifact_target: artifact.target.clone(),
        docsrs_build: claim.docsrs_build,
        artifact_sha256: artifact.sha256.clone(),
        activation_version_requirement: claim.activation_version_requirement.clone(),
        direction,
        mismatch_kinds,
        selection_rule_id: claim.selection_rule_id.clone(),
        selection_rule_version: claim.selection_rule_version,
    }))
}

fn same_cargo_compatibility_family(left: &semver::Version, right: &semver::Version) -> bool {
    if !left.pre.is_empty() || !right.pre.is_empty() {
        return left == right;
    }
    left.major == right.major
        && (left.major > 0
            || (left.minor == right.minor && (left.minor > 0 || left.patch == right.patch)))
}

fn compatibility_bounds(
    version: &semver::Version,
) -> Result<Option<(semver::Version, semver::Version)>, String> {
    if !version.pre.is_empty() {
        return Ok(None);
    }
    if version.major > 0 {
        let next = version
            .major
            .checked_add(1)
            .ok_or("major version overflow")?;
        Ok(Some((
            semver::Version::new(version.major, 0, 0),
            semver::Version::new(next, 0, 0),
        )))
    } else if version.minor > 0 {
        let next = version
            .minor
            .checked_add(1)
            .ok_or("minor version overflow")?;
        Ok(Some((
            semver::Version::new(0, version.minor, 0),
            semver::Version::new(0, next, 0),
        )))
    } else {
        Ok(None)
    }
}

fn validate_approximate_activation_range(
    built: &semver::Version,
    resolved: &semver::Version,
    requirement: &str,
) -> Result<(), String> {
    let parsed = semver::VersionReq::parse(requirement)
        .map_err(|_| "invalid approximation activation requirement")?;
    if !parsed.matches(built) || !parsed.matches(resolved) {
        return Err(
            "approximation interval does not contain artifact and resolved versions".into(),
        );
    }
    let Some((family_lower, family_upper)) = compatibility_bounds(built)? else {
        return (requirement == format!("={built}") && built == resolved)
            .then_some(())
            .ok_or_else(|| "0.0.z and prerelease artifacts require exact activation".into());
    };
    let (lower, upper) = requirement
        .strip_prefix(">=")
        .and_then(|body| body.split_once(", <"))
        .ok_or("approximation interval must be a canonical disjoint range")?;
    let lower = semver::Version::parse(lower).map_err(|_| "invalid range lower bound")?;
    let upper = semver::Version::parse(upper).map_err(|_| "invalid range upper bound")?;
    if lower < family_lower || lower > *built || upper <= *built || upper > family_upper {
        return Err("approximation interval crosses a breaking boundary or excludes X".into());
    }
    Ok(())
}

/// Build disjoint, canonical activation intervals from the pinned artifact
/// set. The lowest artifact in each compatibility family covers older Y.
pub fn build_disjoint_rustdoc_activation_ranges(
    available: &[semver::Version],
) -> Result<Vec<(semver::Version, String)>, String> {
    let mut versions = available.to_vec();
    versions.sort();
    if versions.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate rustdoc artifact version".into());
    }
    versions
        .iter()
        .enumerate()
        .map(|(index, version)| {
            let Some((family_lower, family_upper)) = compatibility_bounds(version)? else {
                return Ok((version.clone(), format!("={version}")));
            };
            let previous_in_family =
                index > 0 && same_cargo_compatibility_family(&versions[index - 1], version);
            let lower = if previous_in_family {
                version.clone()
            } else {
                family_lower
            };
            let upper = versions
                .get(index + 1)
                .filter(|next| same_cargo_compatibility_family(version, next))
                .cloned()
                .unwrap_or(family_upper);
            Ok((version.clone(), format!(">={lower}, <{upper}")))
        })
        .collect()
}

/// Deterministic offline artifact choice. Exact wins, then the nearest older
/// compatible build, then the nearest newer one. The caller pins the chosen
/// bytes; runtime never queries docs.rs or redoes this search.
pub fn choose_nearest_compatible_rustdoc_version(
    resolved: &semver::Version,
    available: &[semver::Version],
) -> Result<Option<semver::Version>, String> {
    let mut candidates = available
        .iter()
        .filter(|candidate| same_cargo_compatibility_family(candidate, resolved))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort();
    if candidates.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("duplicate compatible rustdoc artifact version".into());
    }
    Ok(candidates
        .iter()
        .rev()
        .find(|candidate| *candidate <= resolved)
        .or_else(|| candidates.first())
        .cloned())
}

pub fn resolve_rust_semantic_pack_dependencies(
    config: &RustAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    resolve_rust_semantic_pack_dependencies_with_configuration(
        config,
        project,
        limits,
        cancellation,
        None,
    )
}

pub(super) fn resolve_rust_semantic_pack_dependencies_with_configuration(
    config: &RustAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    recorded: Option<&brokk_bifrost_rust::cargo_config::RustCargoConfiguration>,
) -> DependencyDiscoveryOutcome {
    RUST_CARGO_ROWS
        .with(|slot| *slot.borrow_mut() = CargoResolveView::from_rows(Vec::new(), Vec::new()));
    let mut dependencies = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut metadata_inputs_considered = 0_usize;
    let mut dependencies_considered = 0_usize;
    let mut evidence_bytes_read = 0_u64;
    let mut cancelled = false;

    for configured in &config.dependency_api_evidence {
        if is_cancelled(cancellation) {
            cancelled = true;
            diagnostics.push(cancelled_diagnostic(None));
            break;
        }
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(2);
        let evidence = evidence_paths_from_root(project.root(), configured);
        if dependencies_considered.saturating_add(evidence.packages.len()) > limits.max_dependencies
        {
            diagnostics.push(diagnostic(
                "limit.dependencies",
                None,
                format!(
                    "Rust dependency discovery exceeds the {} dependency limit",
                    limits.max_dependencies
                ),
            ));
            break;
        }
        dependencies_considered = dependencies_considered.saturating_add(evidence.packages.len());
        match decode_rust_dependency_evidence(
            &evidence,
            limits,
            &mut evidence_bytes_read,
            cancellation,
        ) {
            Ok(decoded) => match resolve_rust_dependency_evidence(&evidence, decoded) {
                Ok(mut resolved) => dependencies.append(&mut resolved),
                Err(diagnostic) => diagnostics.push(diagnostic),
            },
            Err(diagnostic) => {
                cancelled |= diagnostic.code == "artifact.cancelled"
                    || diagnostic.code == "rust.evidence.cancelled";
                diagnostics.push(diagnostic);
            }
        }
    }

    let (lock_outcome, _, _, configuration) =
        super::file_dependency_evidence::acquire_cargo_discovery_rows_with_configuration(
            project,
            limits,
            cancellation,
            recorded,
        );
    if !cancelled {
        let (mut locked, lock_diagnostics, lock_cancelled) =
            super::file_dependency_evidence::cargo_lock_activation_rows_from_outcome(lock_outcome);
        dependencies.append(&mut locked);
        for lock_diagnostic in lock_diagnostics {
            diagnostics.push(lock_diagnostic);
        }
        if lock_cancelled {
            cancelled = true;
            diagnostics.push(cancelled_diagnostic(None));
        }
    }

    let mut stdlib_expectation = None;
    if !cancelled && project.analyzer_languages().contains(&Language::Rust) {
        match resolve_rust_stdlib_dependency_with_configuration(
            project,
            limits,
            &mut evidence_bytes_read,
            cancellation,
            &configuration,
        ) {
            Ok(stdlib) => {
                let mut expectation = StandardLibraryPackExpectation::declared(
                    Language::Rust,
                    RUST_STDLIB_PACK_ID,
                    vec![stdlib.dependency.id.clone()],
                );
                // The version remains exact for target-free packs; only a
                // missing target may use the runtime's approximate fallback.
                expectation.approximate = stdlib.dependency.evidence.target.is_none();
                stdlib_expectation = Some(expectation);
                if stdlib.approximation == Some(RustStdlibApproximation::MixedCompileContexts) {
                    let mut warning = diagnostic(
                        "rust.stdlib.mixed_compile_contexts",
                        None,
                        "MixedCompileContexts: indexed units may require different standard-library targets; target-bound packs can activate only approximately, while target-free strict activation is unchanged",
                    );
                    warning.severity =
                        crate::analyzer::semantic_model::DependencyPackDiagnosticSeverity::Warning;
                    diagnostics.push(warning);
                }
                dependencies.push(stdlib.dependency);
            }
            Err(diagnostic) if diagnostic.code == "rust.toolchain.missing" => {
                stdlib_expectation = Some(StandardLibraryPackExpectation::approximate(
                    Language::Rust,
                    RUST_STDLIB_PACK_ID,
                ));
            }
            Err(diagnostic) => {
                cancelled |= diagnostic.code == "rust.evidence.cancelled";
                // A cancelled read answers nothing about the pack; every other
                // refusal is the exact reason the pack is not selected.
                if !cancelled {
                    stdlib_expectation = Some(StandardLibraryPackExpectation::not_selected(
                        Language::Rust,
                        RUST_STDLIB_PACK_ID,
                        diagnostic.message.clone(),
                    ));
                }
                diagnostics.push(diagnostic);
            }
        }
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    dependencies.dedup();
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    let mut outcome = DependencyDiscoveryOutcome {
        incomplete_reason: None,
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
            informational_evidence: Vec::new(),
        },
        // Approximate models can supply positive declarations, but an unpinned
        // toolchain does not establish an exact, complete dependency boundary.
        complete: diagnostics
            .iter()
            .all(|entry| entry.code == "rust.stdlib.mixed_compile_contexts")
            && !cancelled
            && !stdlib_expectation.as_ref().is_some_and(|expectation| {
                matches!(
                    expectation.selection,
                    crate::analyzer::semantic_model::StandardLibraryPackSelection::Unpinned
                )
            }),
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled,
    };
    if let Some(expectation) = stdlib_expectation {
        outcome.expect_standard_library_pack(expectation);
    }
    let view = RUST_CARGO_ROWS.with(|slot| {
        std::mem::replace(
            &mut *slot.borrow_mut(),
            CargoResolveView::from_rows(Vec::new(), Vec::new()),
        )
    });
    if !view.is_empty() {
        match RustSelectedCargoGraph::from_cargo_resolve(view) {
            Ok(graph) => {
                brokk_bifrost_analysis::analyzer::semantic_model::publish_rust_selected_cargo_graph(
                    graph,
                )
            }
            Err(error) => {
                outcome.complete = false;
                if outcome.diagnostics.len() < limits.max_diagnostics {
                    outcome.diagnostics.push(diagnostic(
                        "rust.metadata.ambiguous_cargo_graph",
                        None,
                        format!("Cargo graph cannot identify selected Rust artifacts: {error:?}"),
                    ));
                } else {
                    outcome.suppressed_diagnostics.errors =
                        outcome.suppressed_diagnostics.errors.saturating_add(1);
                }
            }
        }
    }
    declare_external_discovery_reads_complete();
    outcome
}

thread_local! {
    static RUST_CARGO_ROWS: std::cell::RefCell<CargoResolveView> = std::cell::RefCell::new(CargoResolveView::from_rows(Vec::new(), Vec::new()));
}

#[cfg(test)]
fn resolve_rust_stdlib_dependency(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<RustStdlibResolution, DependencyPackDiagnostic> {
    let acquired = super::cargo_configuration_acquisition::acquire(project, &[], limits);
    resolve_rust_stdlib_dependency_with_configuration(
        project,
        limits,
        evidence_bytes_read,
        cancellation,
        &acquired.configuration,
    )
}

fn resolve_rust_stdlib_dependency_with_configuration(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
    configuration: &brokk_bifrost_rust::cargo_config::RustCargoConfiguration,
) -> Result<RustStdlibResolution, DependencyPackDiagnostic> {
    let path = project.root().join("rust-toolchain.toml");
    match std::fs::metadata(&path) {
        Ok(metadata) if !metadata.is_file() => {
            refuse_external_discovery_reads();
            return Err(diagnostic(
                "rust.toolchain.not_file",
                Some(&path),
                "rust-toolchain.toml is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                absolute_path: path.clone(),
            });
            let legacy_path = project.root().join("rust-toolchain");
            match std::fs::symlink_metadata(&legacy_path) {
                Ok(_) => {
                    refuse_external_discovery_reads();
                    return Err(diagnostic(
                        "rust.toolchain.legacy_pin",
                        Some(&legacy_path),
                        "rust-toolchain declares a pin; exact stdlib discovery requires rust-toolchain.toml",
                    ));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                        absolute_path: legacy_path.clone(),
                    });
                }
                Err(error) => {
                    refuse_external_discovery_reads();
                    return Err(diagnostic(
                        "rust.toolchain.metadata",
                        Some(&legacy_path),
                        format!("could not inspect rust-toolchain: {error}"),
                    ));
                }
            }
            return Err(diagnostic(
                "rust.toolchain.missing",
                Some(&path),
                format!(
                    "Rust standard-library semantics require rust-toolchain.toml pinned to exact channel {RUST_STDLIB_TOOLCHAIN_CHANNEL}"
                ),
            ));
        }
        Err(error) => {
            refuse_external_discovery_reads();
            return Err(diagnostic(
                "rust.toolchain.metadata",
                Some(&path),
                format!("could not inspect rust-toolchain.toml: {error}"),
            ));
        }
    }
    let artifact = read_external_evidence_file_with_budget(
        "Rust",
        &path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    let source = std::str::from_utf8(artifact.bytes()).map_err(|error| {
        diagnostic(
            "rust.toolchain.invalid_utf8",
            Some(&path),
            format!("rust-toolchain.toml is not UTF-8: {error}"),
        )
    })?;
    let file: RustToolchainFile = toml::from_str(source).map_err(|error| {
        diagnostic(
            "rust.toolchain.invalid_toml",
            Some(&path),
            format!("could not decode rust-toolchain.toml: {error}"),
        )
    })?;
    let host = file
        .toolchain
        .channel
        .strip_prefix(RUST_STDLIB_TOOLCHAIN_CHANNEL)
        .and_then(|suffix| suffix.strip_prefix('-'));
    if file.toolchain.channel != RUST_STDLIB_TOOLCHAIN_CHANNEL && host.is_none() {
        return Err(diagnostic(
            "rust.toolchain.stdlib_channel_mismatch",
            Some(&path),
            format!(
                "Rust standard-library pack requires exact channel {}; configured channel {} does not select it",
                RUST_STDLIB_TOOLCHAIN_CHANNEL, file.toolchain.channel
            ),
        ));
    }
    if host.is_some_and(|host| {
        brokk_bifrost_rust::cargo_config::builtin_target_platform(host).is_none()
    }) {
        return Err(diagnostic(
            "rust.toolchain.unknown_host",
            Some(&path),
            format!("toolchain host suffix is not a known target triple: {host:?}"),
        ));
    }
    let activation = rust_stdlib_targets(
        project,
        host,
        limits,
        evidence_bytes_read,
        cancellation,
        configuration,
    )?;
    let version = semver::Version::parse(RUST_STDLIB_TOOLCHAIN_VERSION)
        .expect("pinned Rust toolchain version is valid semver");
    let mut dependency = ResolvedDependency {
        id: format!("rust:stdlib:{RUST_STDLIB_TOOLCHAIN_CHANNEL}"),
        evidence: SemanticModelActivationEvidence {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: RUST_STDLIB_TOOLCHAIN_NAME.to_owned(),
                version: Some(version),
            }),
            target: None,
            configuration: None,
            artifact_sha256: None,
        },
        provenance: vec![
            dependency_provenance_entry(
                "rust.activation_input_scope",
                "workspace toolchain file and in-root Cargo configuration; ambient build overrides unobserved",
            ),
            DependencyProvenance {
                key: "rust.toolchain_channel".to_owned(),
                value: file.toolchain.channel.clone(),
            },
            DependencyProvenance {
                key: "rustc.version".to_owned(),
                value: RUST_STDLIB_TOOLCHAIN_VERSION.to_owned(),
            },
            DependencyProvenance {
                key: "rustc.commit".to_owned(),
                value: RUST_STDLIB_RUSTC_COMMIT.to_owned(),
            },
            DependencyProvenance {
                key: "rustdoc.format_version".to_owned(),
                value: rustdoc_types::FORMAT_VERSION.to_string(),
            },
            DependencyProvenance {
                key: "rust.stdlib.crates".to_owned(),
                value: "core,alloc,std".to_owned(),
            },
        ],
        artifacts: Vec::new(),
        scope: DependencyScope::Unknown,
        declared_by: None,
    };
    let approximation = match activation {
        RustStdlibActivation::Exact { target, source } => {
            dependency.id.push(':');
            dependency.id.push_str(&target);
            dependency.evidence.target = Some(target.clone());
            dependency
                .provenance
                .push(dependency_provenance_entry("rust.build_target", &target));
            dependency.provenance.push(dependency_provenance_entry(
                "rust.build_target_source",
                source,
            ));
            None
        }
        RustStdlibActivation::Approximate(reason) => {
            dependency.provenance.push(dependency_provenance_entry(
                "rust.stdlib_approximation",
                format!("{reason:?}"),
            ));
            Some(reason)
        }
    };
    Ok(RustStdlibResolution {
        dependency,
        approximation,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustHostUnitCensus {
    NoHostUnits,
    HostOrUnknownUnits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RustStdlibApproximation {
    UnknownHost,
    MixedCompileContexts,
    StdlibRebuilt,
    BuildModeUnknown,
}

#[derive(Debug, PartialEq, Eq)]
enum RustStdlibActivation {
    Exact {
        target: String,
        source: &'static str,
    },
    Approximate(RustStdlibApproximation),
}

struct RustStdlibResolution {
    dependency: ResolvedDependency,
    approximation: Option<RustStdlibApproximation>,
}

/// One owner of the workspace-wide exactness decision. Until per-unit
/// attachment exists (#12397), a union of target rows cannot certify any one
/// unit's standard-library identity.
fn rust_stdlib_activation(
    explicit: &[String],
    host: Option<&str>,
    census: RustHostUnitCensus,
) -> RustStdlibActivation {
    match explicit {
        [] => match host {
            Some(host) => RustStdlibActivation::Exact {
                target: host.to_owned(),
                source: "rust.toolchain_host",
            },
            None => RustStdlibActivation::Approximate(RustStdlibApproximation::UnknownHost),
        },
        [target] if host == Some(target.as_str()) || census == RustHostUnitCensus::NoHostUnits => {
            RustStdlibActivation::Exact {
                target: target.clone(),
                source: "cargo.build.target",
            }
        }
        _ => RustStdlibActivation::Approximate(RustStdlibApproximation::MixedCompileContexts),
    }
}

/// Census the entire indexed Rust view, including path and indexed dependency
/// manifests. Unknown/unowned source units and incomplete inventories cannot
/// certify the absence of host compilation. Nothing survives this request.
fn rust_host_unit_census(
    project: &dyn Project,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> RustHostUnitCensus {
    use brokk_bifrost_rust::selected_context::{
        RustCallerTargetKind, RustSelectedManifestMount,
        rust_selected_workspace_profiles_from_paths,
    };
    let unknown = RustHostUnitCensus::HostOrUnknownUnits;
    let Ok(files) = project.all_files_shared() else {
        refuse_external_discovery_reads();
        return unknown;
    };
    let Ok(rust_files) = project.analyzable_files_from(&files, Language::Rust) else {
        refuse_external_discovery_reads();
        return unknown;
    };
    let paths = rust_files
        .iter()
        .map(|file| file.rel_path().to_path_buf())
        .collect::<std::collections::BTreeSet<_>>();
    let all_paths = files
        .iter()
        .map(|file| file.rel_path())
        .collect::<std::collections::BTreeSet<_>>();
    let mut manifests = BTreeMap::new();
    for file in files.iter().filter(|file| {
        file.rel_path()
            .file_name()
            .is_some_and(|name| name == "Cargo.toml")
    }) {
        if manifests.len() >= limits.max_source_files_per_artifact || is_cancelled(cancellation) {
            return unknown;
        }
        let remaining = limits
            .max_total_artifact_bytes
            .saturating_sub(*evidence_bytes_read)
            .min(limits.producer.max_artifact_bytes)
            .min(usize::MAX as u64) as usize;
        if remaining == 0 {
            return unknown;
        }
        let Ok(Some(snapshot)) = project.read_source_snapshot_limited(file, remaining) else {
            return unknown;
        };
        *evidence_bytes_read = evidence_bytes_read.saturating_add(snapshot.source().len() as u64);
        report_external_discovery_read(ExternalDiscoveryRead::file(
            &file.abs_path(),
            snapshot.source().as_bytes(),
        ));
        let Ok(manifest) =
            RustSelectedManifestMount::from_source(file.rel_path(), snapshot.source())
        else {
            return unknown;
        };
        if let Some(build) = manifest
            .facts
            .package
            .as_ref()
            .and_then(|package| package.build_script.as_deref())
        {
            let build = brokk_bifrost_rust::selected_context::normalize_selected_path(
                file.rel_path().parent().unwrap_or(Path::new("")),
                build,
            );
            if build
                .as_ref()
                .is_none_or(|path| all_paths.contains(path.as_path()))
            {
                return unknown;
            }
        }
        // A declared host dependency can itself be indexed even when its
        // build-script caller is omitted. Treat that role as possibly host.
        if manifest.facts.dependencies.iter().any(|dependency| {
            dependency.kind == brokk_bifrost_rust::selected_context::RustCargoDependencyKind::Build
        }) || manifest
            .document()
            .get("package")
            .and_then(|package| package.get("build"))
            .is_some_and(|value| value.as_bool() != Some(false))
        {
            return unknown;
        }
        let library = manifest.document().get("lib");
        if library
            .and_then(|lib| lib.get("proc-macro"))
            .is_some_and(|value| value.as_bool() != Some(false))
            || library
                .and_then(|lib| lib.get("plugin"))
                .is_some_and(|value| value.as_bool() != Some(false))
            || library
                .and_then(|lib| lib.get("crate-type"))
                .is_some_and(|value| {
                    value.as_array().is_none_or(|types| {
                        types.is_empty()
                            || types.iter().any(|kind| {
                                !matches!(
                                    kind.as_str(),
                                    Some("lib" | "rlib" | "dylib" | "cdylib" | "staticlib")
                                )
                            })
                    })
                })
        {
            return unknown;
        }
        manifests.insert(file.rel_path().to_path_buf(), manifest);
    }
    let Ok(inventory) = rust_selected_workspace_profiles_from_paths(&paths, &manifests) else {
        return unknown;
    };
    if !inventory.target_inventory_complete
        || inventory
            .profiles
            .iter()
            .any(|unit| unit.target_kind == RustCallerTargetKind::Build)
    {
        return unknown;
    }
    // Only roots have an established unit kind at this acquisition boundary.
    // Module ownership and detached-file contexts are not available here; an
    // unmapped indexed file therefore counts as possibly host compiled.
    let roots = inventory
        .profiles
        .iter()
        .filter_map(|unit| {
            brokk_bifrost_rust::selected_context::normalize_selected_path(
                unit.manifest_path.parent().unwrap_or(Path::new("")),
                &unit.target_root,
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    if !paths.is_subset(&roots) {
        return unknown;
    }
    RustHostUnitCensus::NoHostUnits
}

/// Use the same acquired/recorded view as package and toolchain evidence.
fn rust_stdlib_targets(
    project: &dyn Project,
    host: Option<&str>,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
    configuration: &brokk_bifrost_rust::cargo_config::RustCargoConfiguration,
) -> Result<RustStdlibActivation, DependencyPackDiagnostic> {
    use brokk_bifrost_rust::cargo_config::{RustStdlibBuildMode, builtin_target_platform};
    let (mut targets, defining) = configuration.configured_build_targets(Path::new(""));
    if !defining.is_empty() && targets.is_empty() {
        return Err(diagnostic(
            "rust.config.invalid_target",
            None,
            "configured build.target does not identify a target",
        ));
    }
    // A custom target JSON path is not a known target triple. Never substitute
    // the analyzer's own build target for unknown toolchain identity.
    if !defining.is_empty()
        && targets
            .iter()
            .any(|target| builtin_target_platform(target).is_none())
    {
        return Err(diagnostic(
            "rust.config.unknown_target",
            None,
            format!("configured build targets are not known triples: {targets:?}"),
        ));
    }
    // Preserve observed invalid-target refusals above and pinned compiler
    // mismatches in the caller. Only target-bound completeness is downgraded;
    // runtime strict-first behavior for target-free packs stays unchanged.
    match configuration.stdlib_build_mode(Path::new("")) {
        RustStdlibBuildMode::BuildStd => {
            return Ok(RustStdlibActivation::Approximate(
                RustStdlibApproximation::StdlibRebuilt,
            ));
        }
        RustStdlibBuildMode::Unknown => {
            return Ok(RustStdlibActivation::Approximate(
                RustStdlibApproximation::BuildModeUnknown,
            ));
        }
        RustStdlibBuildMode::Prebuilt => {}
    }
    targets.sort();
    targets.dedup();
    let effective = |targets: Vec<String>| {
        if targets.is_empty() {
            host.map(str::to_owned).into_iter().collect::<Vec<_>>()
        } else {
            targets
        }
    };
    let selected = effective(targets.clone());
    for owner in configuration.acquired_owner_directories() {
        match configuration.stdlib_build_mode(owner) {
            RustStdlibBuildMode::Unknown => {
                return Ok(RustStdlibActivation::Approximate(
                    RustStdlibApproximation::BuildModeUnknown,
                ));
            }
            RustStdlibBuildMode::BuildStd => {
                return Ok(RustStdlibActivation::Approximate(
                    RustStdlibApproximation::StdlibRebuilt,
                ));
            }
            RustStdlibBuildMode::Prebuilt => {}
        }
        let (mut member_targets, defining) = configuration.configured_build_targets(owner);
        if !defining.is_empty()
            && (member_targets.is_empty()
                || member_targets
                    .iter()
                    .any(|target| builtin_target_platform(target).is_none()))
        {
            return Ok(RustStdlibActivation::Approximate(
                RustStdlibApproximation::BuildModeUnknown,
            ));
        }
        member_targets.sort();
        member_targets.dedup();
        if effective(member_targets) != selected {
            // This matcher publishes one global row. Distinct member invocation
            // contexts cannot borrow the root's target until per-unit attachment.
            return Ok(RustStdlibActivation::Approximate(
                RustStdlibApproximation::MixedCompileContexts,
            ));
        }
    }
    let census = if targets.len() == 1 && host != Some(targets[0].as_str()) {
        rust_host_unit_census(project, limits, evidence_bytes_read, cancellation)
    } else {
        RustHostUnitCensus::HostOrUnknownUnits
    };
    if is_cancelled(cancellation) {
        return Err(cancelled_diagnostic(None));
    }
    Ok(rust_stdlib_activation(&targets, host, census))
}

fn resolve_rust_dependency_evidence(
    evidence: &RustDependencyApiEvidence,
    decoded: DecodedRustDependencyEvidence,
) -> Result<Vec<ResolvedDependency>, DependencyPackDiagnostic> {
    let packages_by_id: HashMap<_, _> = decoded
        .metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    if packages_by_id.len() != decoded.metadata.packages.len() {
        return Err(diagnostic(
            "rust.metadata.duplicate_package_id",
            Some(&evidence.metadata_path),
            "Cargo metadata contains duplicate package IDs",
        ));
    }

    let nodes_by_id: HashMap<_, _> = decoded
        .metadata
        .resolve
        .as_ref()
        .ok_or_else(|| {
            diagnostic(
                "rust.metadata.missing_resolve",
                Some(&evidence.metadata_path),
                "Cargo metadata does not contain a resolved dependency graph",
            )
        })?
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    if nodes_by_id.len() != decoded.metadata.resolve.as_ref().unwrap().nodes.len() {
        return Err(diagnostic(
            "rust.metadata.duplicate_node_id",
            Some(&evidence.metadata_path),
            "Cargo metadata resolve graph contains duplicate node IDs",
        ));
    }

    validate_selected_targets(evidence, &packages_by_id)?;
    let reachable = reachable_package_ids(evidence, &nodes_by_id)?;
    let mut resolved = Vec::with_capacity(decoded.artifacts.len());
    let mut selected = Vec::with_capacity(decoded.artifacts.len());
    for artifact in decoded.artifacts {
        let package = packages_by_id
            .get(artifact.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_package",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo metadata does not contain package {}",
                        artifact.package_id
                    ),
                )
            })?;
        if !reachable.contains(artifact.package_id.as_str()) {
            return Err(diagnostic(
                "rust.metadata.unreachable_package",
                Some(&evidence.metadata_path),
                format!(
                    "package {} is not reachable from the selected Cargo targets",
                    artifact.package_id
                ),
            ));
        }
        let node = nodes_by_id
            .get(artifact.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo metadata resolve graph does not contain package {}",
                        artifact.package_id
                    ),
                )
            })?;
        let lock_package = exact_lock_package(package, &decoded.lockfile, &evidence.lockfile_path)?;
        if !package.targets.iter().any(|target| {
            target.name.replace('-', "_") == artifact.crate_name.replace('-', "_")
                && target
                    .kind
                    .iter()
                    .any(|kind| kind == "lib" || kind == "proc-macro")
        }) {
            return Err(diagnostic(
                "rust.rustdoc.crate_name_mismatch",
                Some(&artifact.path),
                format!(
                    "configured crate name {} is not a library target of Cargo package {}",
                    artifact.crate_name, package.name
                ),
            ));
        }
        let version = semver::Version::parse(&package.version).map_err(|error| {
            diagnostic(
                "rust.metadata.invalid_semver",
                Some(&evidence.metadata_path),
                format!(
                    "Cargo package {} has invalid semantic version: {error}",
                    package.id
                ),
            )
        })?;
        let approximation = validate_rust_artifact_approximation(
            &artifact,
            package,
            node,
            &version,
            &evidence.target,
        )?;

        let selected_roots = evidence
            .selected_targets
            .iter()
            .map(|target| target.package_id.as_str())
            .collect::<HashSet<_>>();
        let aliases =
            incoming_dependency_names(&artifact.package_id, &selected_roots, &nodes_by_id);
        let mut provenance = Vec::new();
        push_provenance(
            &mut provenance,
            "cargo.metadata_format",
            decoded.metadata.version,
        );
        push_provenance(
            &mut provenance,
            "cargo.lockfile_version",
            decoded.lockfile.version,
        );
        push_provenance(
            &mut provenance,
            "cargo.source_kind",
            source_kind(package.source.as_deref()),
        );
        if let Some(source) = &package.source {
            push_provenance(&mut provenance, "cargo.source", source);
        }
        if let Some(checksum) = &lock_package.checksum {
            push_provenance(&mut provenance, "cargo.checksum", checksum);
        }
        push_provenance(&mut provenance, "cargo.crate_name", &artifact.crate_name);
        push_provenance(&mut provenance, "cargo.target", &evidence.target);
        push_provenance(
            &mut provenance,
            "cargo.configuration",
            &evidence.configuration,
        );
        for selected in &evidence.selected_targets {
            push_provenance(
                &mut provenance,
                "cargo.selected_target",
                format!(
                    "{}:{}:{}",
                    stable_package_label(&selected.package_id, &packages_by_id),
                    selected.target_name,
                    selected.target_kind
                ),
            );
        }
        for feature in &artifact.enabled_features {
            push_provenance(&mut provenance, "cargo.feature", feature);
        }
        for feature in &node.features {
            push_provenance(&mut provenance, "cargo.metadata_feature", feature);
        }
        for alias in aliases {
            push_provenance(&mut provenance, "cargo.dependency_name", alias);
        }
        push_provenance(&mut provenance, "rustdoc.toolchain", &artifact.toolchain);
        push_provenance(
            &mut provenance,
            "rustdoc.format_version",
            artifact.format_version,
        );
        push_provenance(&mut provenance, "rustdoc.target", &artifact.target);
        if artifact.has_external_reexports {
            push_provenance(&mut provenance, "rustdoc.external_reexports", "format-61");
        }
        for cfg in &artifact.cfgs {
            push_provenance(&mut provenance, "rustdoc.cfg", cfg);
        }
        if let Some(record) = &approximation {
            for (key, value) in record.provenance() {
                push_provenance(&mut provenance, key, value);
            }
        }
        provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
        provenance.dedup();

        let feature_identity = if artifact.enabled_features.is_empty() {
            "none".to_owned()
        } else {
            artifact.enabled_features.join(",")
        };
        let mut reference_artifact = ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Reference,
            ExternalArtifactKind::RustdocJson,
            artifact.path,
        );
        reference_artifact.rust_artifact_approximation = approximation
            .as_ref()
            .map(RustResolvedArtifactApproximation::pack_record);
        let tuple = RustCargoArtifactTuple {
            version: package.version.clone(),
            resolved_features: node.features.clone(),
            artifact_features: artifact.enabled_features.clone(),
            target: evidence.target.clone(),
            toolchain: artifact.toolchain.clone(),
            format_version: artifact.format_version,
            sha256: artifact.sha256.clone(),
            exact: approximation.is_none(),
        };
        resolved.push(ResolvedDependency {
            id: format!(
                "rust:{}@{}:{}:{}:{}",
                package.name,
                package.version,
                artifact.crate_name,
                evidence.target,
                feature_identity
            ),
            evidence: SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: Some(CatalogCoordinate {
                    name: package.name.clone(),
                    version: Some(version.clone()),
                }),
                module: Some(CatalogCoordinate {
                    name: artifact.crate_name,
                    version: Some(version),
                }),
                toolchain: None,
                target: Some(evidence.target.clone()),
                configuration: Some(evidence.configuration.clone()),
                artifact_sha256: None,
            },
            provenance,
            artifacts: vec![reference_artifact],
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
        selected.push(CargoSelectedPackage {
            evidence: resolved.last().expect("just pushed").evidence.clone(),
            package_id: CargoPackageId(package.id.clone()),
            artifact: tuple,
        });
    }
    let edges = decoded
        .metadata
        .resolve
        .as_ref()
        .expect("resolve checked")
        .nodes
        .iter()
        .filter(|node| reachable.contains(node.id.as_str()))
        .flat_map(|node| {
            node.deps.iter().map(move |dep| CargoResolveEdge {
                source: CargoPackageId(node.id.clone()),
                dependency_name: dep.name.clone(),
                target: CargoPackageId(dep.pkg.clone()),
            })
        })
        .collect::<Vec<_>>();
    let crate_names = decoded
        .metadata
        .packages
        .iter()
        .filter_map(|package| {
            package
                .targets
                .iter()
                .find(|target| {
                    target.kind.iter().any(|kind| {
                        matches!(
                            kind.as_str(),
                            "lib" | "rlib" | "dylib" | "cdylib" | "proc-macro"
                        )
                    })
                })
                .map(|target| (CargoPackageId(package.id.clone()), target.name.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    RUST_CARGO_ROWS.with(|slot| {
        let mut view = slot.borrow_mut();
        view.extend(CargoResolveView::from_rows_with_crate_names(
            selected,
            edges,
            crate_names,
        ));
    });
    Ok(resolved)
}

fn decode_rust_dependency_evidence(
    evidence: &RustDependencyApiEvidence,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<DecodedRustDependencyEvidence, DependencyPackDiagnostic> {
    require_non_empty("target", &evidence.target)?;
    require_non_empty("configuration", &evidence.configuration)?;
    if evidence.selected_targets.is_empty() {
        return Err(diagnostic(
            "rust.evidence.selected_targets",
            None,
            "Rust dependency evidence must select at least one Cargo target",
        ));
    }
    if evidence.packages.is_empty() {
        return Err(diagnostic(
            "rust.evidence.artifacts",
            None,
            "Rust dependency evidence must bind at least one rustdoc JSON artifact",
        ));
    }

    let metadata_artifact = read_external_evidence_file_with_budget(
        "Rust",
        &evidence.metadata_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    let metadata: CargoMetadata =
        serde_json::from_slice(metadata_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.metadata.invalid_json",
                Some(&evidence.metadata_path),
                format!("could not decode Cargo metadata JSON: {error}"),
            )
        })?;
    if metadata.version != CARGO_METADATA_FORMAT_VERSION {
        return Err(diagnostic(
            "rust.metadata.unsupported_version",
            Some(&evidence.metadata_path),
            format!(
                "Cargo metadata format {} is unsupported; expected {}",
                metadata.version, CARGO_METADATA_FORMAT_VERSION
            ),
        ));
    }

    let lockfile_artifact = read_external_evidence_file_with_budget(
        "Rust",
        &evidence.lockfile_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    let lockfile = decode_cargo_lockfile(
        std::str::from_utf8(lockfile_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.lockfile.invalid_utf8",
                Some(&evidence.lockfile_path),
                format!("Cargo.lock is not UTF-8: {error}"),
            )
        })?,
        &evidence.lockfile_path,
    )?;

    let mut artifacts = Vec::with_capacity(evidence.packages.len());
    for binding in &evidence.packages {
        if is_cancelled(cancellation) {
            return Err(cancelled_diagnostic(Some(&binding.rustdoc_json_path)));
        }
        require_non_empty("package_id", &binding.package_id)?;
        require_non_empty("crate_name", &binding.crate_name)?;
        require_non_empty("rustdoc_toolchain", &binding.rustdoc_toolchain)?;
        if binding.rustdoc_format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_expected_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "configured rustdoc format {} is unsupported; this producer accepts {}",
                    binding.rustdoc_format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }

        let artifact = read_external_evidence_file_with_budget(
            "Rust",
            &binding.rustdoc_json_path,
            limits,
            evidence_bytes_read,
            cancellation,
        )?;
        let envelope: RustdocVersionEnvelope =
            serde_json::from_slice(artifact.bytes()).map_err(|error| {
                diagnostic(
                    "rust.rustdoc.invalid_json",
                    Some(&binding.rustdoc_json_path),
                    format!("could not read rustdoc JSON version: {error}"),
                )
            })?;
        if envelope.format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc JSON format {} is unsupported; this producer accepts {}",
                    envelope.format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }
        let artifact_target = envelope.target.ok_or_else(|| {
            diagnostic(
                "rust.rustdoc.missing_target",
                Some(&binding.rustdoc_json_path),
                "rustdoc JSON does not declare its compilation target",
            )
        })?;
        if artifact_target.triple != evidence.target {
            return Err(diagnostic(
                "rust.rustdoc.target_mismatch",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc target {} does not match selected target {}",
                    artifact_target.triple, evidence.target
                ),
            ));
        }

        let mut enabled_features = binding.enabled_features.clone();
        enabled_features.sort();
        enabled_features.dedup();
        // Envelope-only, conservative provenance probe. The producer owns
        // full Rustdoc decoding and exact carrier extraction. A nonempty
        // external-crate table may carry an external Use or inlined item.
        let has_external_reexports = !envelope.external_crates.is_empty();
        artifacts.push(DecodedRustdocArtifact {
            package_id: binding.package_id.clone(),
            crate_name: binding.crate_name.clone(),
            enabled_features,
            toolchain: binding.rustdoc_toolchain.clone(),
            path: binding.rustdoc_json_path.clone(),
            format_version: envelope.format_version,
            crate_version: envelope.crate_version,
            target: artifact_target.triple,
            sha256: artifact.sha256().to_owned(),
            approximation: binding.approximation.clone(),
            cfgs: binding.rustdoc_cfgs.clone(),
            has_external_reexports,
        });
    }

    Ok(DecodedRustDependencyEvidence {
        metadata,
        lockfile,
        artifacts,
    })
}

fn evidence_paths_from_root(
    root: &Path,
    evidence: &RustDependencyApiEvidence,
) -> RustDependencyApiEvidence {
    let mut resolved = evidence.clone();
    resolved.metadata_path = resolve_path(root, &resolved.metadata_path);
    resolved.lockfile_path = resolve_path(root, &resolved.lockfile_path);
    for artifact in &mut resolved.packages {
        artifact.rustdoc_json_path = resolve_path(root, &artifact.rustdoc_json_path);
    }
    resolved
}

fn validate_selected_targets<'a>(
    evidence: &RustDependencyApiEvidence,
    packages_by_id: &HashMap<&'a str, &'a CargoMetadataPackage>,
) -> Result<(), DependencyPackDiagnostic> {
    let mut selected = HashSet::default();
    for target in &evidence.selected_targets {
        let package = packages_by_id
            .get(target.package_id.as_str())
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_selected_package",
                    Some(&evidence.metadata_path),
                    format!(
                        "selected Cargo target package {} is absent from metadata",
                        target.package_id
                    ),
                )
            })?;
        if !selected.insert((
            target.package_id.as_str(),
            target.target_name.as_str(),
            target.target_kind.as_str(),
        )) {
            return Err(diagnostic(
                "rust.evidence.duplicate_selected_target",
                None,
                format!(
                    "Cargo target {}:{}:{} is selected more than once",
                    target.package_id, target.target_name, target.target_kind
                ),
            ));
        }
        if !package.targets.iter().any(|candidate| {
            candidate.name == target.target_name && candidate.kind.contains(&target.target_kind)
        }) {
            return Err(diagnostic(
                "rust.metadata.missing_selected_target",
                Some(&evidence.metadata_path),
                format!(
                    "package {} has no Cargo target named {} of kind {}",
                    target.package_id, target.target_name, target.target_kind
                ),
            ));
        }
    }
    Ok(())
}

fn reachable_package_ids<'a>(
    evidence: &RustDependencyApiEvidence,
    nodes_by_id: &HashMap<&'a str, &'a CargoMetadataNode>,
) -> Result<HashSet<&'a str>, DependencyPackDiagnostic> {
    let mut reachable = HashSet::default();
    let mut pending = VecDeque::new();
    for target in &evidence.selected_targets {
        let id = nodes_by_id
            .get_key_value(target.package_id.as_str())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                diagnostic(
                    "rust.metadata.missing_selected_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "selected Cargo target package {} is absent from the resolve graph",
                        target.package_id
                    ),
                )
            })?;
        pending.push_back(id);
    }
    while let Some(id) = pending.pop_front() {
        if !reachable.insert(id) {
            continue;
        }
        let node = nodes_by_id[id];
        for dependency in &node.deps {
            let Some((dependency_id, _)) = nodes_by_id.get_key_value(dependency.pkg.as_str())
            else {
                return Err(diagnostic(
                    "rust.metadata.missing_dependency_node",
                    Some(&evidence.metadata_path),
                    format!(
                        "Cargo resolve edge {} -> {} has no destination node",
                        id, dependency.pkg
                    ),
                ));
            };
            pending.push_back(*dependency_id);
        }
    }
    Ok(reachable)
}

fn exact_lock_package<'a>(
    package: &CargoMetadataPackage,
    lockfile: &'a CargoLockfile,
    path: &Path,
) -> Result<&'a CargoLockPackage, DependencyPackDiagnostic> {
    let mut matches = lockfile.packages.iter().filter(|candidate| {
        candidate.name == package.name
            && candidate.version == package.version
            && candidate.source == package.source
    });
    let Some(found) = matches.next() else {
        return Err(diagnostic(
            "rust.lockfile.missing_package",
            Some(path),
            format!(
                "Cargo.lock has no exact entry for {} {} from {:?}",
                package.name, package.version, package.source
            ),
        ));
    };
    if matches.next().is_some() {
        return Err(diagnostic(
            "rust.lockfile.ambiguous_package",
            Some(path),
            format!(
                "Cargo.lock has multiple entries for {} {} from {:?}",
                package.name, package.version, package.source
            ),
        ));
    }
    Ok(found)
}

fn incoming_dependency_names(
    package_id: &str,
    selected_roots: &HashSet<&str>,
    nodes_by_id: &HashMap<&str, &CargoMetadataNode>,
) -> Vec<String> {
    let mut names = selected_roots
        .iter()
        .filter_map(|root| nodes_by_id.get(root))
        .flat_map(|node| &node.deps)
        .filter(|dependency| dependency.pkg == package_id)
        .map(|dependency| dependency.name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn stable_package_label(
    package_id: &str,
    packages_by_id: &HashMap<&str, &CargoMetadataPackage>,
) -> String {
    packages_by_id
        .get(package_id)
        .map(|package| format!("{}@{}", package.name, package.version))
        .unwrap_or_else(|| package_id.to_owned())
}

fn source_kind(source: Option<&str>) -> &'static str {
    match source {
        Some(value) if value.starts_with("registry+") => "registry",
        Some(value) if value.starts_with("git+") => "git",
        Some(_) => "other",
        None => "path",
    }
}

fn push_provenance(provenance: &mut Vec<DependencyProvenance>, key: &str, value: impl ToString) {
    provenance.push(dependency_provenance_entry(key, value));
}

fn require_non_empty(field: &str, value: &str) -> Result<(), DependencyPackDiagnostic> {
    require_non_empty_evidence_field("Rust", "rust.evidence.empty_field", field, value)
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    brokk_bifrost_core::cancellation::optional_is_cancelled(cancellation)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    cancelled_dependency_evidence_diagnostic("Rust", "rust.evidence.cancelled", path)
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::IAnalyzer;
    use std::collections::HashMap;
    use std::fs;

    use rustdoc_types::{Crate as RustdocCrate, Id, Target};
    use serde_json::json;
    use tempfile::TempDir;

    use crate::analyzer::rust::dependency_discovery::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::config::RustAnalyzerConfig;

    use brokk_bifrost_core::analyzer::config::RustPackageApiArtifact;

    use brokk_bifrost_core::analyzer::config::RustSelectedTarget;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use crate::analyzer::rust::host_target_triple;

    const PACKAGE_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#widget@1.2.3";

    /// The target a build that names no target compiles for, which the host
    /// rustdoc also emits.
    fn host_target() -> &'static str {
        host_target_triple()
    }

    /// A built-in target that differs from the host target.
    fn non_host_target() -> &'static str {
        if host_target() == "x86_64-unknown-linux-gnu" {
            "aarch64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        }
    }

    #[test]
    fn exact_evidence_decodes_supported_metadata_lockfile_and_rustdoc() {
        let fixture = EvidenceFixture::new();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        assert_eq!(decoded.metadata.version, CARGO_METADATA_FORMAT_VERSION);
        assert_eq!(decoded.metadata.packages.len(), 2);
        assert_eq!(decoded.metadata.packages[1].id, PACKAGE_ID);
        assert_eq!(decoded.metadata.packages[1].name, "widget");
        assert_eq!(decoded.metadata.packages[1].version, "1.2.3");
        assert_eq!(
            decoded.metadata.packages[1].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(decoded.metadata.resolve.as_ref().unwrap().nodes.len(), 2);
        assert_eq!(
            decoded.metadata.resolve.as_ref().unwrap().nodes[1].features,
            ["derive"]
        );
        assert_eq!(decoded.lockfile.version, MAXIMUM_LOCKFILE_VERSION);
        assert_eq!(decoded.lockfile.packages.len(), 1);
        assert_eq!(decoded.lockfile.packages[0].name, "widget");
        assert_eq!(decoded.lockfile.packages[0].version, "1.2.3");
        assert_eq!(
            decoded.lockfile.packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(
            decoded.lockfile.packages[0].checksum.as_deref(),
            Some("abc123")
        );
        assert_eq!(decoded.artifacts.len(), 1);
        assert_eq!(decoded.artifacts[0].package_id, PACKAGE_ID);
        assert_eq!(decoded.artifacts[0].crate_name, "widget");
        assert_eq!(decoded.artifacts[0].enabled_features, ["derive"]);
        assert_eq!(decoded.artifacts[0].toolchain, "nightly-2026-07-14");
        assert_eq!(decoded.artifacts[0].target, host_target());
    }

    #[test]
    fn exact_evidence_resolves_reachable_package_with_normalized_provenance() {
        let fixture = EvidenceFixture::new();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let resolved = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap();

        assert_eq!(resolved.len(), 1);
        let dependency = &resolved[0];
        assert_eq!(dependency.evidence.language, "rust");
        assert_eq!(dependency.evidence.ecosystem, "cargo");
        assert_eq!(dependency.evidence.package.as_ref().unwrap().name, "widget");
        assert_eq!(dependency.evidence.module.as_ref().unwrap().name, "widget");
        assert_eq!(dependency.evidence.target.as_deref(), Some(host_target()));
        assert_eq!(
            dependency.evidence.configuration.as_deref(),
            Some("library")
        );
        assert_eq!(dependency.artifacts.len(), 1);
        assert_eq!(
            dependency.artifacts[0].role,
            DependencyArtifactRole::Reference
        );
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::RustdocJson
        );
        assert!(dependency.provenance.iter().any(|entry| {
            entry.key == "cargo.dependency_name" && entry.value == "renamed_widget"
        }));
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| { entry.key == "cargo.checksum" && entry.value == "abc123" })
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| { entry.key == "cargo.feature" && entry.value == "derive" })
        );
    }

    #[test]
    fn rustdoc_selection_prefers_exact_then_nearest_older_then_newer_within_compatibility() {
        let version = |text| semver::Version::parse(text).unwrap();
        let available = vec![version("0.4.23"), version("0.4.27"), version("0.5.0")];
        assert_eq!(
            choose_nearest_compatible_rustdoc_version(&version("0.4.25"), &available).unwrap(),
            Some(version("0.4.23"))
        );
        assert_eq!(
            choose_nearest_compatible_rustdoc_version(&version("0.4.22"), &available).unwrap(),
            Some(version("0.4.23"))
        );
        assert_eq!(
            choose_nearest_compatible_rustdoc_version(&version("0.4.27"), &available).unwrap(),
            Some(version("0.4.27"))
        );
        assert_eq!(
            choose_nearest_compatible_rustdoc_version(&version("0.6.0"), &available).unwrap(),
            None
        );
        assert!(
            choose_nearest_compatible_rustdoc_version(
                &version("0.4.25"),
                &[version("0.4.23"), version("0.4.23")]
            )
            .is_err()
        );
        assert_eq!(
            build_disjoint_rustdoc_activation_ranges(&available).unwrap(),
            vec![
                (version("0.4.23"), ">=0.4.0, <0.4.27".to_owned()),
                (version("0.4.27"), ">=0.4.27, <0.5.0".to_owned()),
                (version("0.5.0"), ">=0.5.0, <0.6.0".to_owned()),
            ]
        );
    }

    #[test]
    fn rustdoc_version_and_feature_mismatch_need_checked_record() {
        let mut fixture = EvidenceFixture::new();
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.rustdoc_path).unwrap()).unwrap();
        json["crate_version"] = serde_json::Value::String("1.2.2".to_owned());
        fs::write(&fixture.rustdoc_path, serde_json::to_vec(&json).unwrap()).unwrap();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        let digest = decoded.artifacts[0].sha256.clone();
        assert_eq!(
            resolve_rust_dependency_evidence(&fixture.evidence, decoded)
                .unwrap_err()
                .code,
            "rust.rustdoc.approximation_record_required"
        );

        fixture.evidence.packages[0].rustdoc_cfgs = vec!["docsrs".to_owned()];
        fixture.evidence.packages[0].approximation = Some(RustArtifactApproximationClaim {
            artifact_version: "1.2.2".to_owned(),
            artifact_features: vec!["derive".to_owned()],
            artifact_cfgs: vec!["docsrs".to_owned()],
            docsrs_build: true,
            artifact_sha256: digest,
            activation_version_requirement: ">=1.0.0, <2.0.0".to_owned(),
            selection_rule_id: "cargo-compatible-nearest".to_owned(),
            selection_rule_version: 1,
        });
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        let resolved = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap();
        assert!(
            resolved[0]
                .provenance
                .iter()
                .any(|entry| entry.key == "rust.approximation.direction"
                    && entry.value == "older_artifact")
        );
        fixture.evidence.packages[0]
            .approximation
            .as_mut()
            .unwrap()
            .artifact_cfgs = vec!["different".to_owned()];
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        assert_eq!(
            resolve_rust_dependency_evidence(&fixture.evidence, decoded)
                .unwrap_err()
                .code,
            "rust.rustdoc.invalid_approximation_record"
        );
        fixture.evidence.packages[0]
            .approximation
            .as_mut()
            .unwrap()
            .artifact_cfgs = vec!["docsrs".to_owned()];
        fixture.evidence.packages[0]
            .approximation
            .as_mut()
            .unwrap()
            .artifact_sha256 = "wrong".into();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        assert_eq!(
            resolve_rust_dependency_evidence(&fixture.evidence, decoded)
                .unwrap_err()
                .code,
            "rust.rustdoc.invalid_approximation_record"
        );
    }

    #[test]
    fn rustdoc_feature_superset_alone_needs_approximation_record() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0]
            .enabled_features
            .push("serde".to_owned());
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        assert_eq!(
            resolve_rust_dependency_evidence(&fixture.evidence, decoded)
                .unwrap_err()
                .code,
            "rust.rustdoc.approximation_record_required"
        );
    }

    #[test]
    fn narrower_exact_version_artifact_keeps_partial_pack_path() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0].enabled_features.clear();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        let resolved = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(
            resolved[0].artifacts[0]
                .rust_artifact_approximation
                .is_none()
        );
        assert!(
            resolved[0]
                .provenance
                .iter()
                .any(|entry| entry.key == "cargo.metadata_feature" && entry.value == "derive")
        );
    }

    #[test]
    fn exact_package_missing_from_lockfile_is_incomplete() {
        let fixture = EvidenceFixture::new();
        fs::write(&fixture.evidence.lockfile_path, "version = 4\n").unwrap();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.lockfile.missing_package");
    }

    #[test]
    fn artifact_package_must_be_reachable_from_selected_target() {
        let fixture = EvidenceFixture::new();
        fixture.write_metadata(false);
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.metadata.unreachable_package");
    }

    #[test]
    fn configured_crate_name_must_be_a_cargo_library_target() {
        let mut fixture = EvidenceFixture::new();
        fixture.evidence.packages[0].crate_name = "different_crate".to_owned();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();

        let diagnostic = resolve_rust_dependency_evidence(&fixture.evidence, decoded).unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.crate_name_mismatch");
    }

    #[test]
    fn dependency_names_are_scoped_to_selected_workspace_roots() {
        let root = CargoMetadataNode {
            id: "root".to_owned(),
            features: Vec::new(),
            deps: vec![
                CargoMetadataNodeDependency {
                    name: "renamed_widget".to_owned(),
                    pkg: "widget".to_owned(),
                },
                CargoMetadataNodeDependency {
                    name: "foo".to_owned(),
                    pkg: "foo".to_owned(),
                },
            ],
        };
        let transitive = CargoMetadataNode {
            id: "foo".to_owned(),
            features: Vec::new(),
            deps: vec![CargoMetadataNodeDependency {
                name: "internal_widget".to_owned(),
                pkg: "widget".to_owned(),
            }],
        };
        let nodes =
            brokk_bifrost_core::hash::HashMap::from_iter([("root", &root), ("foo", &transitive)]);
        let selected_roots = brokk_bifrost_core::hash::HashSet::from_iter(["root"]);

        assert_eq!(
            incoming_dependency_names("widget", &selected_roots, &nodes),
            ["renamed_widget"]
        );
    }

    #[test]
    fn public_discovery_reports_complete_exact_dependency() {
        let fixture = EvidenceFixture::new();
        fixture.write_exact_toolchain();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        };

        let outcome = resolve_rust_semantic_pack_dependencies(
            &config,
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(outcome.complete, "diagnostics: {:?}", outcome.diagnostics);
        assert!(!outcome.cancelled);
        assert_eq!(outcome.profile.metadata_inputs_considered, 2);
        assert_eq!(outcome.profile.dependencies_resolved, 2);
        assert_eq!(outcome.dependencies.len(), 2);
        assert!(outcome.dependencies.iter().any(|dependency| dependency.id
            == format!("rust:widget@1.2.3:widget:{}:derive", host_target())));
        assert!(
            outcome
                .dependencies
                .iter()
                .any(|dependency| dependency.id.starts_with("rust:stdlib:nightly-2026-08-24"))
        );
    }

    #[test]
    fn cargo_external_reads_track_configured_lock_without_unrelated_source() {
        use crate::analyzer::semantic_model::DependencyDiscoveryEvidence;
        use brokk_bifrost_analysis::analyzer::dependency_support::capture_external_discovery_reads;

        let fixture = EvidenceFixture::new();
        fixture.write_exact_toolchain();
        let external = tempfile::tempdir().unwrap();
        let lock = external.path().join("Cargo.lock");
        fs::copy(&fixture.evidence.lockfile_path, &lock).unwrap();
        let source = fixture._root.path().join("edited.rs");
        fs::write(&source, "fn old() {}\n").unwrap();
        let mut configured = fixture.evidence.clone();
        configured.lockfile_path = lock.clone();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![configured],
        };
        let identity = || {
            let (outcome, reads) = capture_external_discovery_reads(|| {
                resolve_rust_semantic_pack_dependencies(
                    &config,
                    &project,
                    &DependencyPackLimits::default(),
                    None,
                )
            });
            assert!(outcome.complete, "diagnostics: {:?}", outcome.diagnostics);
            let evidence = DependencyDiscoveryEvidence::from_outcome(&outcome)
                .with_external_reads(reads.keys, reads.complete);
            assert!(evidence.carry_eligible_external_reads().is_some());
            evidence.external_read_identity
        };
        let first = identity();
        fs::write(&source, "fn new() {}\n").unwrap();
        assert_eq!(first, identity());
        let mut contents = fs::read(&lock).unwrap();
        contents.extend_from_slice(b"\n# changed\n");
        fs::write(&lock, contents).unwrap();
        assert_ne!(first, identity());
    }

    #[test]
    fn exact_rust_toolchain_toml_emits_stdlib_dependency() {
        let fixture = EvidenceFixture::new();
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            format!(
                "[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}-x86_64-unknown-linux-gnu\"\ncomponents = [\"rust-src\"]\n"
            ),
        )
        .unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(outcome.complete, "diagnostics: {:?}", outcome.diagnostics);
        let dependency = outcome
            .dependencies
            .iter()
            .find(|dependency| dependency.id.starts_with("rust:stdlib:nightly-2026-08-24"))
            .expect("exact pinned Rust nightly should emit stdlib evidence");
        assert_eq!(dependency.evidence.ecosystem, "cargo");
        assert_eq!(dependency.evidence.package, None);
        assert_eq!(dependency.evidence.module, None);
        assert_eq!(
            dependency.evidence.toolchain.as_ref().unwrap().name,
            RUST_STDLIB_TOOLCHAIN_NAME
        );
        assert_eq!(
            dependency
                .evidence
                .toolchain
                .as_ref()
                .unwrap()
                .version
                .as_ref()
                .unwrap()
                .to_string(),
            RUST_STDLIB_TOOLCHAIN_VERSION
        );
        assert!(dependency.artifacts.is_empty());
        assert!(dependency.provenance.iter().any(|entry| {
            entry.key == "rustc.commit" && entry.value == RUST_STDLIB_RUSTC_COMMIT
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12360: target-bound verified stdlib packs could not activate from pinned workspaces"
    )]
    fn stdlib_target_identity_matches_on_one_evidence_row() {
        use crate::analyzer::semantic_model::*;
        use brokk_bifrost_semantic::analyzer::semantic_model::runtime::strict_activation_match;
        let target = "x86_64-unknown-linux-gnu";
        let source = json!({
            "schema_version": 2, "pack_id": "test.target-bound-stdlib", "version": "1.0.0",
            "producer": {"name": "fixture", "version": "1.0.0"},
            "language": "rust", "ecosystem": "cargo",
            "compatibility": {"bifrost": "*", "toolchains": [{"name":"rust", "requirement":"=1.100.0-nightly"}]},
            "provenance": {"source": "test-only"}, "license": "NOASSERTION",
            "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "declarations.stdlib", "activation": [{
                "toolchain": {"name": "rust", "version": "=1.100.0-nightly"}, "targets": [target]
            }], "payload": {"kind": "declaration_facts", "types": [{"id":"stdlib.marker","name":"stdlib.Marker","type_kind":"struct","visibility":"public","locator":{"kind":"artifact","path":"fixture.json","symbol":"stdlib.Marker"}}], "members": [], "relations": []}}]
        });
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let decoded =
            brokk_bifrost_semantic::analyzer::semantic_model::artifact::decode_shard_for_manifest(
                &pack.manifest,
                &pack.shards[0].descriptor,
                &pack.shards[0].bytes,
                &DecodeLimits::default(),
            )
            .unwrap();
        let mut selectors = decoded.activation().to_vec();
        for (suffix, config, expected_target, matches) in [
            ("-x86_64-unknown-linux-gnu", None, Some(target), true),
            (
                "",
                Some("target = \"x86_64-unknown-linux-gnu\""),
                Some(target),
                true,
            ),
            (
                "-x86_64-unknown-linux-gnu",
                Some("target = \"aarch64-unknown-linux-gnu\""),
                Some("aarch64-unknown-linux-gnu"),
                false,
            ),
            (
                "",
                Some("target = [\"x86_64-unknown-linux-gnu\", \"aarch64-unknown-linux-gnu\"]"),
                None,
                false,
            ),
            (
                "-x86_64-unknown-linux-gnu",
                Some("target = \"x86_64-unknown-linux-gnu\"\n[unstable]\nbuild-std=['std']"),
                None,
                false,
            ),
            (
                "-x86_64-unknown-linux-gnu",
                Some("target = \"x86_64-unknown-linux-gnu\"\n[unknown_configuration]\nkey=true"),
                None,
                false,
            ),
        ] {
            let fixture = EvidenceFixture::new();
            fs::write(
                fixture._root.path().join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}{suffix}\"\n"),
            )
            .unwrap();
            if let Some(config) = config {
                fs::create_dir_all(fixture._root.path().join(".cargo")).unwrap();
                fs::write(
                    fixture._root.path().join(".cargo/config.toml"),
                    format!("[build]\n{config}\n"),
                )
                .unwrap();
            }
            let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
            let resolved = resolve_rust_stdlib_dependency(
                &project,
                &DependencyPackLimits::default(),
                &mut 0,
                None,
            )
            .unwrap();
            if config.is_some_and(|config| config.contains("build-std")) {
                assert_eq!(
                    resolved.approximation,
                    Some(RustStdlibApproximation::StdlibRebuilt)
                );
            }
            if config.is_some_and(|config| config.contains("unknown_configuration")) {
                assert_eq!(
                    resolved.approximation,
                    Some(RustStdlibApproximation::BuildModeUnknown)
                );
            }
            let rows = [resolved.dependency];
            assert_eq!(rows[0].evidence.target.as_deref(), expected_target);
            let evidence = rows
                .iter()
                .map(|row| row.evidence.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                strict_activation_match(
                    &pack.manifest,
                    &selectors,
                    &evidence,
                    &semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
                )
                .is_some(),
                matches
            );
            // Packs without target restrictions retain their existing matching.
            let targets = std::mem::take(&mut selectors[0].targets);
            assert!(
                strict_activation_match(
                    &pack.manifest,
                    &selectors,
                    &evidence,
                    &semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
                )
                .is_some()
            );
            selectors[0].targets = targets;
            if expected_target.is_some() {
                let source = if config.is_some() {
                    "cargo.build.target"
                } else {
                    "rust.toolchain_host"
                };
                assert!(
                    rows[0]
                        .provenance
                        .iter()
                        .any(|p| p.key == "rust.build_target_source" && p.value == source)
                );
            }
        }
    }

    #[test]
    fn global_stdlib_target_requires_agreement_across_acquired_member_contexts() {
        let root = tempfile::tempdir().unwrap();
        let put = |path: &str, source: &str| {
            let path = root.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        };
        put("Cargo.toml", "[workspace]\nmembers=['a','b']\n");
        for member in ["a", "b"] {
            put(
                &format!("{member}/Cargo.toml"),
                &format!("[package]\nname='{member}'\nversion='0.1.0'\n"),
            );
            put(&format!("{member}/src/lib.rs"), "pub fn example() {}\n");
        }
        put(
            "rust-toolchain.toml",
            &format!(
                "[toolchain]\nchannel='{RUST_STDLIB_TOOLCHAIN_CHANNEL}-x86_64-unknown-linux-gnu'\n"
            ),
        );
        put(
            ".cargo/config.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let home = root.path().join("test-cargo-home");
        fs::create_dir(&home).unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let selected = ["Cargo.toml", "a/Cargo.toml", "b/Cargo.toml"]
            .into_iter()
            .map(|path| {
                let file = brokk_bifrost_core::analyzer::model::ProjectFile::new(root.path(), path);
                let source = project.read_source_snapshot(&file).unwrap();
                (file, source)
            })
            .collect::<Vec<_>>();
        let resolve = || {
            let acquired = super::super::cargo_configuration_acquisition::acquire_with_home(
                &project,
                &selected,
                &DependencyPackLimits::default(),
                Some(&home),
                Vec::new(),
            );
            resolve_rust_stdlib_dependency_with_configuration(
                &project,
                &DependencyPackLimits::default(),
                &mut 0,
                None,
                &acquired.configuration,
            )
            .unwrap()
        };
        let root_only = resolve();
        assert_eq!(
            root_only.dependency.evidence.target.as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(root_only.approximation, None);
        put(
            "a/.cargo/config.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\n",
        );
        put(
            "b/.cargo/config.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let mixed = resolve();
        assert_eq!(mixed.dependency.evidence.target, None);
        assert_eq!(
            mixed.approximation,
            Some(RustStdlibApproximation::MixedCompileContexts)
        );
        fs::remove_file(root.path().join("a/.cargo/config.toml")).unwrap();
        fs::create_dir(root.path().join("a/.cargo/config.toml")).unwrap();
        let unreadable = resolve();
        assert_eq!(unreadable.dependency.evidence.target, None);
        assert_eq!(
            unreadable.approximation,
            Some(RustStdlibApproximation::BuildModeUnknown)
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12360: plain channels must not claim an exact target identity"
    )]
    fn plain_rust_toolchain_requests_approximate_stdlib() {
        let fixture = EvidenceFixture::new();
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            format!("[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}\"\n"),
        )
        .unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(outcome.complete);
        assert_eq!(outcome.dependencies.len(), 1);
        assert!(outcome.dependencies[0].evidence.target.is_none());
        assert!(outcome.diagnostics.is_empty());
        assert!(
            outcome
                .standard_library_pack_expectations()
                .next()
                .unwrap()
                .approximate
        );
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            format!("[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}-unknown-host\"\n"),
        )
        .unwrap();
        let unknown = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(unknown.dependencies.is_empty());
        assert_eq!(unknown.diagnostics[0].code, "rust.toolchain.unknown_host");
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            format!("[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}\"\n"),
        )
        .unwrap();

        fs::create_dir_all(fixture._root.path().join(".cargo")).unwrap();
        fs::write(
            fixture._root.path().join(".cargo/config.toml"),
            "[build]\ntarget = \"unknown-target\"\n",
        )
        .unwrap();
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(outcome.dependencies.is_empty());
        assert_eq!(outcome.diagnostics[0].code, "rust.config.unknown_target");
        assert!(
            !outcome
                .standard_library_pack_expectations()
                .next()
                .unwrap()
                .approximate
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12364: B review found cross-target stdlib facts globally applied to host units"
    )]
    fn mixed_rust_compile_contexts_withhold_exact_target_bound_activation() {
        let host = "x86_64-unknown-linux-gnu";
        let cross = "aarch64-unknown-linux-gnu";
        for (name, known_host, build_script, proc_macro, target, expected) in [
            ("build-cross", true, true, false, cross, None),
            ("proc-path-dependency", true, false, true, cross, None),
            ("build-same", true, true, false, host, Some(host)),
            ("no-host-units", true, false, false, cross, Some(cross)),
            ("two-targets", true, false, false, "both", None),
            ("unknown-host-build", false, true, false, host, None),
            ("unknown-build-kind", true, false, false, cross, None),
            ("custom-build-script", true, false, false, cross, None),
        ] {
            let root = TempDir::new().unwrap();
            fs::create_dir_all(root.path().join("src")).unwrap();
            fs::create_dir_all(root.path().join(".cargo")).unwrap();
            let mut manifest =
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n".to_string();
            let mut lock = "version=3\n[[package]]\nname='app'\nversion='0.1.0'\n".to_string();
            if name == "unknown-build-kind" {
                fs::write(root.path().join("unowned.rs"), "fn other() {}\n").unwrap();
            }
            if name == "custom-build-script" {
                manifest.push_str("build='builder'\n");
                fs::write(root.path().join("builder"), "fn main() {}\n").unwrap();
            }
            if build_script {
                fs::write(root.path().join("build.rs"), "fn main() {}\n").unwrap();
            }
            if proc_macro {
                manifest.push_str("[dependencies]\nmacros={path='macro'}\n");
                lock.push_str(
                    "dependencies=['macros']\n[[package]]\nname='macros'\nversion='0.1.0'\n",
                );
                fs::create_dir_all(root.path().join("macro/src")).unwrap();
                fs::write(root.path().join("macro/Cargo.toml"), "[package]\nname='macros'\nversion='0.1.0'\nedition='2021'\n[lib]\nproc-macro=true\n").unwrap();
                fs::write(
                    root.path().join("macro/src/lib.rs"),
                    "extern crate proc_macro;\n",
                )
                .unwrap();
            }
            fs::write(root.path().join("Cargo.toml"), manifest).unwrap();
            fs::write(root.path().join("Cargo.lock"), lock).unwrap();
            fs::write(root.path().join("src/lib.rs"), "pub fn local() {}\n").unwrap();
            let suffix = if known_host {
                format!("-{host}")
            } else {
                String::new()
            };
            fs::write(
                root.path().join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel='{RUST_STDLIB_TOOLCHAIN_CHANNEL}{suffix}'\n"),
            )
            .unwrap();
            let value = if target == "both" {
                format!("['{host}', '{cross}']")
            } else {
                format!("'{target}'")
            };
            fs::write(
                root.path().join(".cargo/config.toml"),
                format!("[build]\ntarget={value}\n"),
            )
            .unwrap();
            let project = TestProject::new(root.path().to_path_buf(), Language::Rust);
            let outcome = resolve_rust_semantic_pack_dependencies(
                &RustAnalyzerConfig::default(),
                &project,
                &DependencyPackLimits::default(),
                None,
            );
            let stdlib = outcome
                .dependencies
                .iter()
                .find(|row| row.id.starts_with("rust:stdlib:"))
                .unwrap_or_else(|| panic!("{name}: {outcome:#?}"));
            assert_eq!(
                stdlib.evidence.target.as_deref(),
                expected,
                "{name}: {outcome:#?}"
            );
            assert_eq!(
                outcome
                    .standard_library_pack_expectations()
                    .next()
                    .unwrap()
                    .approximate,
                expected.is_none(),
                "{name}"
            );
            assert_eq!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "rust.stdlib.mixed_compile_contexts"),
                expected.is_none(),
                "{name}: {:?}",
                outcome.diagnostics
            );
        }
    }

    #[test]
    fn missing_rust_toolchain_requests_approximate_stdlib() {
        let fixture = EvidenceFixture::new();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty());
        assert!(outcome.diagnostics.is_empty());
        let expectation = outcome.standard_library_pack_expectations().next().unwrap();
        assert!(expectation.approximate);
        assert_eq!(expectation.pack_id, RUST_STDLIB_PACK_ID);
    }

    #[test]
    fn non_exact_rust_toolchain_is_attributable_and_does_not_emit_stdlib_dependency() {
        let fixture = EvidenceFixture::new();
        fs::write(
            fixture._root.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"nightly\"\n",
        )
        .unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let outcome = resolve_rust_semantic_pack_dependencies(
            &RustAnalyzerConfig::default(),
            &project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(!outcome.complete);
        assert!(outcome.dependencies.is_empty());
        assert_eq!(
            outcome.diagnostics[0].code,
            "rust.toolchain.stdlib_channel_mismatch"
        );
        assert!(
            outcome.diagnostics[0]
                .message
                .contains(RUST_STDLIB_TOOLCHAIN_CHANNEL)
        );
        assert!(
            outcome.diagnostics[0]
                .message
                .contains("configured channel nightly")
        );
    }

    #[test]
    fn public_discovery_enforces_dependency_and_aggregate_byte_limits() {
        let fixture = EvidenceFixture::new();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone()],
        };
        let dependency_limits = DependencyPackLimits {
            max_dependencies: 0,
            ..DependencyPackLimits::default()
        };
        let dependency_outcome =
            resolve_rust_semantic_pack_dependencies(&config, &project, &dependency_limits, None);
        assert_eq!(dependency_outcome.diagnostics[0].code, "limit.dependencies");

        let byte_limits = DependencyPackLimits {
            max_total_artifact_bytes: 1,
            ..DependencyPackLimits::default()
        };
        let byte_outcome =
            resolve_rust_semantic_pack_dependencies(&config, &project, &byte_limits, None);
        assert_eq!(
            byte_outcome.diagnostics[0].code,
            "limit.total_artifact_bytes"
        );
    }

    #[test]
    fn invalid_bundles_still_consume_discovery_budgets() {
        let fixture = EvidenceFixture::new();
        fixture.write_exact_toolchain();
        fs::write(&fixture.evidence.metadata_path, b"not json").unwrap();
        let project = TestProject::new(fixture._root.path().to_path_buf(), Language::Rust);
        let config = RustAnalyzerConfig {
            dependency_api_evidence: vec![fixture.evidence.clone(), fixture.evidence.clone()],
        };
        let limits = DependencyPackLimits {
            max_dependencies: 1,
            ..DependencyPackLimits::default()
        };

        let outcome = resolve_rust_semantic_pack_dependencies(&config, &project, &limits, None);

        assert_eq!(
            outcome
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            ["rust.metadata.invalid_json", "limit.dependencies"]
        );

        let mut bytes_read = 0;
        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut bytes_read,
            None,
        )
        .unwrap_err();
        assert_eq!(diagnostic.code, "rust.metadata.invalid_json");
        assert_eq!(bytes_read, b"not json".len() as u64);
    }

    #[test]
    fn unsupported_rustdoc_version_fails_before_full_decode() {
        let fixture = EvidenceFixture::new();
        fs::write(
            &fixture.rustdoc_path,
            serde_json::to_vec(&json!({ "format_version": rustdoc_types::FORMAT_VERSION + 1 }))
                .unwrap(),
        )
        .unwrap();

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.unsupported_version");
    }

    #[test]
    fn rustdoc_target_must_match_selected_target() {
        let fixture = EvidenceFixture::new();
        fixture.write_rustdoc(non_host_target());

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.target_mismatch");
    }

    #[test]
    fn docsrs_adapter_binds_only_exact_test_built_public_api_evidence() {
        use flate2::{Compression, write::GzEncoder};
        use sha2::{Digest, Sha256};
        use std::process::Command;

        let fixture = EvidenceFixture::new();
        let root = fixture._root.path();
        let source = root.join("lib.rs");
        fs::write(&source, "pub fn clean(input: u8) -> u8 { input }\n").unwrap();
        let rustdoc_dir = root.join("rustdoc");
        fs::create_dir(&rustdoc_dir).unwrap();
        let status = Command::new("rustdoc")
            .env("RUSTC_BOOTSTRAP", "1")
            .args([
                "--edition",
                "2024",
                "--crate-type",
                "lib",
                "--crate-name",
                "widget",
                "--crate-version",
                "1.2.3",
                "--output-format",
                "json",
                "-Z",
                "unstable-options",
                "--target",
                host_target(),
                "-o",
            ])
            .arg(&rustdoc_dir)
            .arg(&source)
            .status()
            .unwrap();
        assert!(status.success());
        let json_path = rustdoc_dir.join("widget.json");
        let json_hash = brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
            &Sha256::digest(fs::read(&json_path).unwrap()).into(),
        );

        let archive_path = root.join("widget-1.2.3.crate");
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, bytes) in [
            (
                "widget-1.2.3/Cargo.toml.orig",
                b"[package]\nname = \"widget\"\nversion = \"1.2.3\"\n[features]\nderive = []\n"
                    .as_slice(),
            ),
            (
                "widget-1.2.3/src/lib.rs",
                b"pub fn clean(input: u8) -> u8 { input }\n".as_slice(),
            ),
            (
                "widget-1.2.3/LICENSE",
                b"SPDX-License-Identifier: MIT\n".as_slice(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, path, bytes).unwrap();
        }
        let archive = tar.into_inner().unwrap().finish().unwrap();
        fs::write(&archive_path, &archive).unwrap();
        let archive_hash = brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
            &Sha256::digest(&archive).into(),
        );
        fs::write(&fixture.evidence.lockfile_path, format!("version = 4\n\n[[package]]\nname = \"widget\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{archive_hash}\"\n")).unwrap();

        let mut evidence = fixture.evidence.clone();
        evidence.packages.clear();
        let input = DocsRsArtifactInput {
            package_id: PACKAGE_ID.into(),
            crate_name: "widget".into(),
            crate_archive_path: archive_path,
            crate_archive_sha256: archive_hash,
            rustdoc_json_path: json_path,
            rustdoc_json_sha256: json_hash,
            docsrs_resolved_features: vec!["derive".into()],
            rustdoc_toolchain: "rustdoc 1.99.1 test fixture".into(),
            rustdoc_format_version: rustdoc_types::FORMAT_VERSION,
            docsrs_url: format!(
                "https://docs.rs/crate/widget/1.2.3/json/{}.gz",
                rustdoc_types::FORMAT_VERSION
            ),
            target: host_target().into(),
            docsrs_cfg: true,
            authority: DocsRsAuthority::Exact,
        };
        let bound = bind_docsrs_artifacts(evidence.clone(), std::slice::from_ref(&input)).unwrap();
        assert_eq!(bound.rows[0].status, "admitted");
        let decoded = decode_rust_dependency_evidence(
            &bound.evidence,
            &DependencyPackLimits::default(),
            &mut 0,
            None,
        )
        .unwrap();
        let resolved = resolve_rust_dependency_evidence(&bound.evidence, decoded).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(
            resolved[0]
                .provenance
                .iter()
                .any(|p| p.key == "rustdoc.cfg" && p.value == "docsrs")
        );
        let catalog = crate::analyzer::semantic_model::SemanticPackCatalog::open_ephemeral(
            crate::analyzer::semantic_model::CatalogOptions::default(),
        )
        .unwrap();
        let prepared = crate::analyzer::semantic_model::prepare_dependency_semantic_packs(
            &catalog,
            &crate::analyzer::rust::RustDependencyPackAdapter,
            &resolved,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(prepared.complete, "{:#?}", prepared.diagnostics);
        assert_eq!(prepared.profile.generated_packs, 1);
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn call() -> u8 { renamed_widget::clean(1) }\n",
        )
        .unwrap();
        let project = std::sync::Arc::new(TestProject::new(root.to_path_buf(), Language::Rust));
        let analyzer = crate::analyzer::rust::RustAnalyzer::new_with_config(
            project,
            crate::analyzer::AnalyzerConfig {
                rust: RustAnalyzerConfig {
                    dependency_api_evidence: vec![bound.evidence.clone()],
                },
                ..Default::default()
            },
        );
        let request = prepared
            .compose_activation_request(
                crate::analyzer::semantic_model::SemanticModelActivationRequest {
                    approximate_standard_libraries: Vec::new(),
                    bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                    evidence: Vec::new(),
                    controls: Vec::new(),
                    limits: Default::default(),
                },
            )
            .unwrap();
        let activation = crate::analyzer::semantic_model::acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &brokk_bifrost_core::CancellationToken::default(),
        );
        assert!(matches!(
            activation,
            crate::analyzer::semantic_model::SemanticModelRuntimeOutcome::Ready { .. }
        ));
        let overlay = analyzer.semantic_model_overlay_read().published().unwrap();
        assert_eq!(
            overlay
                .symbols_named_in_family(
                    "renamed_widget.clean",
                    "rust",
                    SemanticModelNamespace::Unknown
                )
                .records
                .len(),
            1
        );
        let crates = crate::analyzer::rust::crate_identity::RustOverlayCrates::new(Some(&overlay));
        assert!(
            crates
                .referenceable_symbol("renamed_widget.clean")
                .is_some()
        );
        assert!(crates.referenceable_symbol("widget.clean").is_none());
        let duplicate =
            bind_docsrs_artifacts(evidence.clone(), &[input.clone(), input.clone()]).unwrap();
        assert_eq!(duplicate.rows.len(), 2);
        assert_eq!(duplicate.evidence.packages.len(), 1);
        assert!(
            duplicate.rows[1]
                .status
                .contains("duplicate package/crate binding")
        );

        let mut cases = Vec::new();
        let mut wrong_feature = input.clone();
        wrong_feature.docsrs_resolved_features.clear();
        cases.push(wrong_feature);
        let mut wrong_target = input.clone();
        wrong_target.target = non_host_target().into();
        cases.push(wrong_target);
        let mut wrong_format = input.clone();
        wrong_format.rustdoc_format_version += 1;
        cases.push(wrong_format);
        let mut wrong_cfg = input.clone();
        wrong_cfg.docsrs_cfg = false;
        cases.push(wrong_cfg);
        let mut wrong_hash = input.clone();
        wrong_hash.rustdoc_json_sha256 = "0".repeat(64);
        cases.push(wrong_hash);
        let mut wrong_url = input.clone();
        wrong_url.docsrs_url = "https://example.invalid/widget.json".into();
        cases.push(wrong_url);
        let mut wrong_version = input.clone();
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&input.rustdoc_json_path).unwrap()).unwrap();
        document["crate_version"] = json!("1.2.4");
        let wrong_version_bytes = serde_json::to_vec(&document).unwrap();
        wrong_version.rustdoc_json_path = root.join("wrong-version.json");
        fs::write(&wrong_version.rustdoc_json_path, &wrong_version_bytes).unwrap();
        wrong_version.rustdoc_json_sha256 =
            brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
                &Sha256::digest(&wrong_version_bytes).into(),
            );
        cases.push(wrong_version);
        let mut approximate = input.clone();
        approximate.authority = DocsRsAuthority::Approximate {
            resolved_version: "1.2.3".into(),
            built_from_version: "1.2.4".into(),
            mismatch_kinds: vec!["version".into()],
            direction: "newer_artifact".into(),
            selection_rule_id: "nearest-compatible".into(),
            selection_rule_version: 1,
        };
        cases.push(approximate);
        for bad in cases {
            let outcome = bind_docsrs_artifacts(evidence.clone(), &[bad]).unwrap();
            assert!(outcome.evidence.packages.is_empty(), "{:#?}", outcome.rows);
            assert!(
                outcome.rows[0]
                    .status
                    .starts_with("missing_declaration_evidence:")
            );
        }
    }
    struct EvidenceFixture {
        _root: TempDir,
        rustdoc_path: std::path::PathBuf,
        evidence: RustDependencyApiEvidence,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let metadata_path = root.path().join("metadata.json");
            let lockfile_path = root.path().join("Cargo.lock");
            let rustdoc_path = root.path().join("widget.json");
            fs::write(
                &lockfile_path,
                "version = 4\n\n[[package]]\nname = \"widget\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n",
            )
            .unwrap();
            let evidence = RustDependencyApiEvidence {
                metadata_path,
                lockfile_path,
                target: host_target().to_owned(),
                configuration: "library".to_owned(),
                selected_targets: vec![RustSelectedTarget {
                    package_id: "path+file:///workspace#consumer@0.1.0".to_owned(),
                    target_name: "consumer".to_owned(),
                    target_kind: "lib".to_owned(),
                }],
                packages: vec![RustPackageApiArtifact {
                    package_id: PACKAGE_ID.to_owned(),
                    crate_name: "widget".to_owned(),
                    enabled_features: vec!["derive".to_owned()],
                    rustdoc_json_path: rustdoc_path.clone(),
                    rustdoc_toolchain: "nightly-2026-07-14".to_owned(),
                    rustdoc_format_version: rustdoc_types::FORMAT_VERSION,
                    rustdoc_cfgs: Vec::new(),
                    approximation: None,
                }],
            };
            let fixture = Self {
                _root: root,
                rustdoc_path,
                evidence,
            };
            fixture.write_metadata(true);
            fixture.write_rustdoc(host_target());
            fixture
        }

        fn write_exact_toolchain(&self) {
            fs::write(
                self._root.path().join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel = \"{RUST_STDLIB_TOOLCHAIN_CHANNEL}-x86_64-unknown-linux-gnu\"\n"),
            )
            .unwrap();
        }

        fn write_metadata(&self, reachable: bool) {
            let dependencies = if reachable {
                vec![json!({
                    "name": "renamed_widget",
                    "pkg": PACKAGE_ID,
                    "dep_kinds": [{ "kind": null, "target": null }]
                })]
            } else {
                Vec::new()
            };
            fs::write(
                &self.evidence.metadata_path,
                serde_json::to_vec(&json!({
                    "version": CARGO_METADATA_FORMAT_VERSION,
                    "packages": [
                        {
                            "id": "path+file:///workspace#consumer@0.1.0",
                            "name": "consumer",
                            "version": "0.1.0",
                            "source": null,
                            "targets": [{ "name": "consumer", "kind": ["lib"] }]
                        },
                        {
                            "id": PACKAGE_ID,
                            "name": "widget",
                            "version": "1.2.3",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "targets": [{ "name": "widget", "kind": ["lib"] }]
                        }
                    ],
                    "resolve": {
                        "nodes": [
                            {
                                "id": "path+file:///workspace#consumer@0.1.0",
                                "features": [],
                                "deps": dependencies
                            },
                            {
                                "id": PACKAGE_ID,
                                "features": ["derive"],
                                "deps": []
                            }
                        ]
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        }

        fn write_rustdoc(&self, target: &str) {
            let document = RustdocCrate {
                root: Id(0),
                crate_version: Some("1.2.3".to_owned()),
                includes_private: false,
                index: HashMap::new(),
                paths: HashMap::new(),
                external_crates: HashMap::new(),
                target: Target {
                    triple: target.to_owned(),
                    target_features: Vec::new(),
                },
                format_version: rustdoc_types::FORMAT_VERSION,
            };
            fs::write(&self.rustdoc_path, serde_json::to_vec(&document).unwrap()).unwrap();
        }
    }
}
#[test]
fn rustdoc_provenance_probe_does_not_decode_the_item_index() {
    let bytes = br#"{"format_version":61,"target":{"triple":"x86_64-unknown-linux-gnu"},"external_crates":{"1":{"name":"core"}},"index":"not a rustdoc index"}"#;
    let envelope: RustdocVersionEnvelope = serde_json::from_slice(bytes).unwrap();
    assert!(!envelope.external_crates.is_empty());
    assert!(serde_json::from_slice::<rustdoc_types::Crate>(bytes).is_err());
}
