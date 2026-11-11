use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_analysis::analyzer::dependency_support::cancelled_dependency_evidence_diagnostic;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_diagnostic as diagnostic;

use brokk_bifrost_analysis::analyzer::dependency_support::dependency_provenance_entry as provenance_entry;

use brokk_bifrost_analysis::analyzer::dependency_support::{
    declare_external_discovery_reads_complete, read_external_evidence_file_with_budget,
    refuse_external_discovery_reads, report_external_discovery_read,
};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ExternalDiscoveryRead, UnverifiableDiscoveryRead,
};

use brokk_bifrost_analysis::analyzer::dependency_support::require_non_empty_evidence_field;

use brokk_bifrost_analysis::analyzer::dependency_support::resolve_dependency_path as resolve_path;

use brokk_bifrost_core::path_normalization::is_canonical_spelling;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::BoundedDependencyDiagnostics;

use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyArtifactRole;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyDiscoveryOutcome;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyDiscoveryProfile;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnostic;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackLimits;

use brokk_bifrost_analysis::analyzer::semantic_model::producer::ExternalArtifactKind;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependency;

use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependencyArtifact;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

use brokk_bifrost_analysis::analyzer::topology::DependencyScope;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::config::RubyAnalyzerConfig;

use brokk_bifrost_core::analyzer::config::RubyDependencyApiEvidence;

use brokk_bifrost_core::analyzer::config::RubyGemApiArtifact;

use brokk_bifrost_core::hash::HashSet;

use std::collections::BTreeMap;

use brokk_bifrost_analysis::analyzer::dependency_support::select_dependency_input_snapshots;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyEvidence, DependencyEvidenceGapKind, DependencyEvidenceKind,
    DependencyFileEvidenceLimits,
};

use crate::analyzer::ruby::dependency_evidence::{
    GemVersion, RUBYGEMS_ECOSYSTEM, collect_ruby_dependency_evidence,
};

pub fn resolve_ruby_semantic_pack_dependencies(
    config: &RubyAnalyzerConfig,
    project: &dyn Project,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyDiscoveryOutcome {
    let mut dependencies = Vec::new();
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut metadata_inputs_considered = 0_usize;
    let mut evidence_bytes_read = 0_u64;
    let mut cancelled = false;

    for configured in &config.dependency_api_evidence {
        if is_cancelled(cancellation) {
            cancelled = true;
            diagnostics.push(cancelled_diagnostic(None));
            break;
        }
        let evidence = evidence_paths_from_root(project.root(), configured);
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(1);
        if dependencies.len().saturating_add(evidence.gems.len()) > limits.max_dependencies {
            diagnostics.push(diagnostic(
                "limit.dependencies",
                None,
                format!(
                    "Ruby dependency discovery exceeds the {} dependency limit",
                    limits.max_dependencies
                ),
            ));
            break;
        }
        match resolve_evidence(&evidence, limits, &mut evidence_bytes_read, cancellation) {
            Ok(mut resolved) => {
                metadata_inputs_considered =
                    metadata_inputs_considered.saturating_add(resolved.len());
                dependencies.append(&mut resolved);
            }
            Err(error) => {
                cancelled |=
                    error.code == "artifact.cancelled" || error.code == "ruby.evidence.cancelled";
                diagnostics.push(error);
            }
        }
    }

    if !cancelled {
        // A host's configured archive already generates its gem's
        // declarations, so a vendored copy must not add a second owner.
        let configured_archives = dependencies
            .iter()
            .filter_map(|dependency| dependency.evidence.package.as_ref())
            .map(|package| package.name.clone())
            .collect::<HashSet<_>>();
        let (mut locked, lock_cancelled) = bundler_lock_activation_rows(
            project,
            &configured_archives,
            limits,
            &mut evidence_bytes_read,
            cancellation,
            &mut diagnostics,
        );
        metadata_inputs_considered = metadata_inputs_considered.saturating_add(locked.len());
        dependencies.append(&mut locked);
        cancelled = lock_cancelled;
    }

    dependencies.sort_by(|left, right| left.id.cmp(&right.id));
    let before_dedup = dependencies.len();
    dependencies.dedup_by(|left, right| left.id == right.id);
    if dependencies.len() != before_dedup {
        diagnostics.push(diagnostic(
            "ruby.evidence.duplicate_gem",
            None,
            "Ruby dependency evidence contains duplicate gem identities",
        ));
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    declare_external_discovery_reads_complete();
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
            informational_evidence: Vec::new(),
        },
        complete: diagnostics.is_empty() && suppressed_diagnostics.total() == 0 && !cancelled,
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled,
    }
}

/// The only gem server whose coordinates name a published RubyGems release.
const RUBYGEMS_ORG: &str = "https://rubygems.org";

/// Package activation rows for the exact gems the workspace's bundles lock.
///
/// Each `Gemfile.lock` (or `gems.locked`) spec from the rubygems.org `GEM`
/// source becomes one artifact-less `rubygems` row naming the gem and its
/// exact version, owned by the bundle that locks it. Such a row reads no gem
/// archive and produces nothing: it selects only a compatible installed or
/// reviewed workspace pack, so a host activates a gem pack from the lockfile
/// alone (#9319). Fail-closed cases activate nothing:
/// - `GIT` and `PATH` specs, other gem servers, and incomplete lock rows;
/// - a gem that bundles lock at more than one version, because activation is
///   workspace-wide and one version's models would apply to code that loads
///   another. That ambiguity is reported as `ruby.lockfile.ambiguous_activation`.
///
/// A bundle that vendors the gem's `.gem` archive ([`vendored_gem_archive`])
/// gets an artifact row instead, which generates the gem's declarations unless
/// a compatible reviewed pack supersedes them or a host already configured an
/// archive for that gem (#10011). The coordinate version
/// is [`GemVersion::coordinate_version`], so a four-segment `7.0.8.1` matches a
/// pack that requires `=7.0.8`. Acquisition failures and limits are reported,
/// and a vendored archive that cannot be used leaves the bundle's lock row.
///
/// Returns the rows and whether acquisition was cancelled.
fn bundler_lock_activation_rows(
    project: &dyn Project,
    configured_archives: &HashSet<String>,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> (Vec<ResolvedDependency>, bool) {
    let (selected, _, cancelled) = select_dependency_input_snapshots(
        project,
        "Bundler",
        "ruby",
        |path| {
            brokk_bifrost_analysis::analyzer::semantic_model::DependencyResolver::is_discovery_candidate(
                &crate::analyzer::ruby::dependency_packs::RubyDependencyResolver,
                path,
            )
        },
        limits,
        cancellation,
        diagnostics,
    );
    if cancelled {
        return (Vec::new(), true);
    }
    let evidence =
        collect_ruby_dependency_evidence(&selected, &DependencyFileEvidenceLimits::default());
    for gap in &evidence.gaps {
        // A row limit may have omitted lock rows; other gaps are interpretation
        // limits of rows that then activate nothing, and stay on the files-only
        // dependency-evidence surface.
        if gap.kind == DependencyEvidenceGapKind::Limit {
            diagnostics.push(diagnostic(
                "limit.ruby_lock_rows",
                Some(&gap.build_file),
                gap.message.clone(),
            ));
        }
    }
    let mut by_gem = BTreeMap::<&str, BTreeMap<&str, Vec<&DependencyEvidence>>>::new();
    for row in &evidence.rows {
        let condition = |kind: &str| {
            row.conditions
                .iter()
                .find(|condition| condition.kind == kind)
                .map(|condition| condition.value.as_str())
        };
        if row.ecosystem != RUBYGEMS_ECOSYSTEM
            || row.kind != DependencyEvidenceKind::Locked
            || !row.complete
            || condition("bundler.source_kind") != Some("gem")
            || row
                .source
                .as_deref()
                .map(|source| source.trim_end_matches('/'))
                != Some(RUBYGEMS_ORG)
        {
            continue;
        }
        let version = row
            .exact_version
            .as_deref()
            .expect("a complete locked row has an exact version");
        by_gem
            .entry(row.package.as_str())
            .or_default()
            .entry(version)
            .or_default()
            .push(row);
    }
    let checksums = evidence
        .rows
        .iter()
        .filter(|row| {
            row.ecosystem == RUBYGEMS_ECOSYSTEM && row.kind == DependencyEvidenceKind::Checksum
        })
        .filter_map(|row| {
            let condition = |kind: &str| {
                row.conditions
                    .iter()
                    .find(|condition| condition.kind == kind)
                    .map(|condition| condition.value.as_str())
            };
            Some((
                (
                    row.declared_by.as_deref()?,
                    row.package.as_str(),
                    row.exact_version.as_deref()?,
                    condition("bundler.platform"),
                ),
                condition("bundler.checksum")?,
            ))
        })
        .collect::<LockChecksums<'_>>();
    let mut rows = Vec::new();
    for (gem, versions) in by_gem {
        if versions.len() > 1 {
            diagnostics.push(diagnostic(
                "ruby.lockfile.ambiguous_activation",
                None,
                format!(
                    "bundles lock gem {gem} at versions {:?}; no version activates package-scoped semantic models",
                    versions.keys().collect::<Vec<_>>()
                ),
            ));
            continue;
        }
        let (version, locks) = versions
            .into_iter()
            .next()
            .expect("a grouped gem has a version");
        let mut owners = BTreeMap::<&str, Vec<&DependencyEvidence>>::new();
        for lock in locks {
            // Platform variants of one spec are one coordinate per bundle.
            owners
                .entry(
                    lock.declared_by
                        .as_deref()
                        .expect("lock rows name their bundle"),
                )
                .or_default()
                .push(lock);
        }
        let coordinate = CatalogCoordinate {
            name: gem.to_owned(),
            version: Some(
                GemVersion::parse(version)
                    .expect("a complete locked row has a RubyGems version")
                    .coordinate_version(),
            ),
        };
        // Activation is workspace-wide, so one vendored archive per gem
        // generates its declarations; other bundles keep their lock rows.
        let mut vendored_row = configured_archives.contains(gem);
        for (owner, variants) in owners {
            // A vendored row's provenance enters its production key, so it
            // names the gem and archive but not the lockfile's path or bytes.
            let mut provenance = vec![
                provenance_entry("rubygems.name", gem),
                provenance_entry("rubygems.source", RUBYGEMS_ORG),
                provenance_entry("rubygems.version", version),
            ];
            let vendored = if vendored_row {
                None
            } else {
                match vendored_gem_archive(
                    project.root(),
                    owner,
                    gem,
                    version,
                    &variants,
                    &checksums,
                    limits,
                    evidence_bytes_read,
                    cancellation,
                ) {
                    Ok(archive) => archive,
                    Err(error)
                        if error.code == "artifact.cancelled"
                            || error.code == "ruby.evidence.cancelled" =>
                    {
                        diagnostics.push(error);
                        return (Vec::new(), true);
                    }
                    Err(error) => {
                        diagnostics.push(error);
                        None
                    }
                }
            };
            let (id, artifacts) = match vendored {
                Some((layout, artifact)) => {
                    vendored_row = true;
                    provenance.push(provenance_entry("bundler.activation", layout));
                    provenance.push(provenance_entry(
                        "rubygems.archive_sha256",
                        artifact.expected_sha256.as_deref().expect("exact archive"),
                    ));
                    (
                        format!("rubygems:vendored:{owner}:{gem}@{version}"),
                        vec![artifact],
                    )
                }
                None => {
                    provenance.extend([
                        provenance_entry("bundler.activation", "exact_lock_row"),
                        provenance_entry("bundler.lockfile", variants[0].build_file.display()),
                        provenance_entry("bundler.lockfile_digest", &variants[0].source_digest),
                    ]);
                    (format!("rubygems:lock:{owner}:{gem}@{version}"), Vec::new())
                }
            };
            provenance.sort_by(|left, right| left.key.cmp(&right.key));
            rows.push(ResolvedDependency {
                id,
                evidence: SemanticModelActivationEvidence {
                    language: "ruby".to_owned(),
                    ecosystem: RUBYGEMS_ECOSYSTEM.to_owned(),
                    package: Some(coordinate.clone()),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                provenance,
                artifacts,
                scope: DependencyScope::Unknown,
                declared_by: Some(owner.to_owned()),
            });
        }
    }
    (rows, false)
}

/// Bundler `CHECKSUMS` entries by bundle, gem, version and platform.
type LockChecksums<'a> = BTreeMap<(&'a str, &'a str, &'a str, Option<&'a str>), &'a str>;

/// The `.gem` archive a bundle vendors for one locked gem, as an exact
/// declaration artifact, with the layout that held it (#10011).
///
/// `bundle cache` writes `vendor/cache/<gem>-<version>[-<platform>].gem`, and
/// `bundle install --path vendor/bundle` keeps the installed gem's archive in
/// `vendor/bundle/ruby/<abi>/cache/`. Those are probed in that order, the
/// platform-independent file name first, and the first present archive wins.
/// A `CHECKSUMS` entry for that spec must match the archive's digest. Every
/// probe is a discovery read, so vendoring or removing an archive invalidates
/// retained discovery; listing the installed tree's ABI directories is a walk
/// no key reproduces, so a bundle with one is rediscovered each time.
#[allow(clippy::too_many_arguments)]
fn vendored_gem_archive(
    root: &Path,
    owner: &str,
    gem: &str,
    version: &str,
    variants: &[&DependencyEvidence],
    checksums: &LockChecksums<'_>,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<(&'static str, ResolvedDependencyArtifact)>, DependencyPackDiagnostic> {
    let bundle = root.join(
        variants[0]
            .build_file
            .parent()
            .expect("a lockfile path has a parent"),
    );
    let mut names = variants
        .iter()
        .map(|lock| {
            let platform = lock
                .conditions
                .iter()
                .find(|condition| condition.kind == "bundler.platform")
                .map(|condition| condition.value.as_str());
            let name = match platform {
                Some(platform) => format!("{gem}-{version}-{platform}.gem"),
                None => format!("{gem}-{version}.gem"),
            };
            (name, platform)
        })
        .collect::<Vec<_>>();
    names.sort_by_key(|(_, platform)| platform.is_some());
    let mut directories = vec![("vendor_cache_archive", bundle.join("vendor/cache"))];
    let installed = bundle.join("vendor/bundle/ruby");
    match std::fs::read_dir(&installed) {
        Ok(entries) => {
            report_external_discovery_read(ExternalDiscoveryRead::Unverifiable(
                UnverifiableDiscoveryRead::ExternalCacheWalk,
            ));
            let mut abis = entries
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    diagnostic(
                        "ruby.vendored.installed_tree",
                        Some(&installed),
                        format!("could not list the installed gem tree: {error}"),
                    )
                })?;
            abis.sort();
            directories.extend(
                abis.into_iter()
                    .map(|abi| ("vendor_bundle_archive", abi.join("cache"))),
            );
        }
        Err(_) if !installed.exists() => {
            report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                absolute_path: installed,
            });
        }
        Err(error) => {
            return Err(diagnostic(
                "ruby.vendored.installed_tree",
                Some(&installed),
                format!("could not list the installed gem tree: {error}"),
            ));
        }
    }
    for (layout, directory) in directories {
        for (name, platform) in &names {
            let path = directory.join(name);
            if !path.exists() {
                report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                    absolute_path: path,
                });
                continue;
            }
            let archive = read_external_evidence_file_with_budget(
                "Ruby",
                &path,
                limits,
                evidence_bytes_read,
                cancellation,
            )?;
            if let Some(checksum) = checksums.get(&(owner, gem, version, *platform))
                && archive.sha256() != *checksum
            {
                return Err(diagnostic(
                    "ruby.vendored.checksum_mismatch",
                    Some(&path),
                    format!(
                        "vendored gem archive digest {} does not match the Gemfile.lock checksum {checksum}",
                        archive.sha256()
                    ),
                ));
            }
            let canonical = path.canonicalize().map_err(|error| {
                diagnostic(
                    "ruby.vendored.archive",
                    Some(&path),
                    format!("could not canonicalize the vendored gem archive: {error}"),
                )
            })?;
            return Ok(Some((
                layout,
                ResolvedDependencyArtifact::exact_file(
                    DependencyArtifactRole::Declarations,
                    ExternalArtifactKind::RubyGemArchive,
                    canonical,
                    archive.sha256().to_owned(),
                ),
            )));
        }
    }
    Ok(None)
}

fn resolve_evidence(
    evidence: &RubyDependencyApiEvidence,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<ResolvedDependency>, DependencyPackDiagnostic> {
    require_non_empty("ruby_version", &evidence.ruby_version)?;
    require_non_empty("platform", &evidence.platform)?;
    if !is_lower_sha256(&evidence.lockfile_sha256) {
        return Err(diagnostic(
            "ruby.evidence.invalid_lockfile_digest",
            Some(&evidence.lockfile_path),
            "Ruby dependency evidence lockfile digest must be lowercase SHA-256",
        ));
    }
    if evidence.approved_archive_roots.is_empty() {
        return Err(diagnostic(
            "ruby.evidence.missing_archive_roots",
            None,
            "Ruby dependency evidence must declare at least one approved archive root",
        ));
    }

    let lockfile = read_external_evidence_file_with_budget(
        "Ruby",
        &evidence.lockfile_path,
        limits,
        evidence_bytes_read,
        cancellation,
    )?;
    if lockfile.sha256() != evidence.lockfile_sha256 {
        return Err(diagnostic(
            "ruby.evidence.lockfile_digest_mismatch",
            Some(&evidence.lockfile_path),
            format!(
                "Gemfile.lock digest {} does not match configured digest {}",
                lockfile.sha256(),
                evidence.lockfile_sha256
            ),
        ));
    }
    let lockfile_source = std::str::from_utf8(lockfile.bytes()).map_err(|_| {
        diagnostic(
            "ruby.evidence.lockfile_encoding",
            Some(&evidence.lockfile_path),
            "Gemfile.lock must be valid UTF-8",
        )
    })?;
    let parsed_lockfile = rubund::parser::parse_lockfile(lockfile_source);
    if !parsed_lockfile.platforms.iter().any(|platform| {
        *platform == evidence.platform || (*platform == "ruby" && evidence.platform == "ruby")
    }) {
        return Err(diagnostic(
            "ruby.evidence.platform_not_locked",
            Some(&evidence.lockfile_path),
            format!(
                "configured Ruby platform {} is not present in Gemfile.lock",
                evidence.platform
            ),
        ));
    }
    if let Some(locked_ruby) = parsed_lockfile.ruby_version {
        let configured = evidence.ruby_version.as_str();
        let locked = locked_ruby.strip_prefix("ruby ").unwrap_or(locked_ruby);
        if locked != configured
            && !locked
                .strip_prefix(configured)
                .is_some_and(|suffix| suffix.starts_with('p'))
        {
            return Err(diagnostic(
                "ruby.evidence.ruby_version_mismatch",
                Some(&evidence.lockfile_path),
                format!(
                    "configured Ruby version {} does not match locked Ruby version {}",
                    evidence.ruby_version, locked_ruby
                ),
            ));
        }
    }

    let approved_roots = evidence
        .approved_archive_roots
        .iter()
        .map(|root| {
            root.canonicalize().map_err(|error| {
                diagnostic(
                    "ruby.evidence.archive_root",
                    Some(root),
                    format!("could not canonicalize approved Ruby archive root: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if approved_roots
        .iter()
        .zip(&evidence.approved_archive_roots)
        .any(|(canonical, configured)| !is_canonical_spelling(configured, canonical))
    {
        refuse_external_discovery_reads();
    }
    if approved_roots.iter().any(|root| !root.is_dir()) {
        return Err(diagnostic(
            "ruby.evidence.archive_root_not_directory",
            None,
            "approved Ruby archive roots must be directories",
        ));
    }

    let mut identities = HashSet::default();
    let mut resolved = Vec::with_capacity(evidence.gems.len());
    for gem in &evidence.gems {
        if is_cancelled(cancellation) {
            return Err(cancelled_diagnostic(Some(&gem.gem_archive_path)));
        }
        validate_gem_fields(gem)?;
        validate_locked_gem(
            &parsed_lockfile,
            gem,
            &evidence.platform,
            &evidence.lockfile_path,
        )?;
        let identity = (gem.name.as_str(), gem.version.as_str(), gem.source.as_str());
        if !identities.insert(identity) {
            return Err(diagnostic(
                "ruby.evidence.duplicate_gem",
                Some(&gem.gem_archive_path),
                format!(
                    "Ruby dependency evidence repeats {} {} from {}",
                    gem.name, gem.version, gem.source
                ),
            ));
        }

        let canonical_archive = gem.gem_archive_path.canonicalize().map_err(|error| {
            diagnostic(
                "ruby.evidence.gem_archive",
                Some(&gem.gem_archive_path),
                format!("could not canonicalize exact gem archive: {error}"),
            )
        })?;
        if !is_canonical_spelling(&gem.gem_archive_path, &canonical_archive) {
            refuse_external_discovery_reads();
        }
        if !canonical_archive.is_file() {
            return Err(diagnostic(
                "ruby.evidence.gem_archive_not_file",
                Some(&canonical_archive),
                "exact gem archive path is not a regular file",
            ));
        }
        if !approved_roots
            .iter()
            .any(|root| canonical_archive.starts_with(root))
        {
            return Err(diagnostic(
                "ruby.evidence.gem_archive_outside_roots",
                Some(&canonical_archive),
                "exact gem archive is outside every approved archive root",
            ));
        }

        let archive = read_external_evidence_file_with_budget(
            "Ruby",
            &canonical_archive,
            limits,
            evidence_bytes_read,
            cancellation,
        )?;
        if let Some(checksum) = &gem.checksum
            && archive.sha256() != checksum
        {
            return Err(diagnostic(
                "ruby.evidence.gem_checksum_mismatch",
                Some(&canonical_archive),
                format!(
                    "gem archive digest {} does not match configured checksum {}",
                    archive.sha256(),
                    checksum
                ),
            ));
        }

        let parsed_version = GemVersion::parse(&gem.version)
            .ok()
            .map(|version| version.coordinate_version());
        let mut provenance = Vec::with_capacity(8);
        if let Some(checksum) = &gem.checksum {
            provenance.push(provenance_entry("bundler.checksum", checksum));
        }
        provenance.extend([
            provenance_entry("bundler.lockfile_sha256", &evidence.lockfile_sha256),
            provenance_entry("ruby.platform", &evidence.platform),
            provenance_entry("ruby.version", &evidence.ruby_version),
            provenance_entry("rubygems.archive_sha256", archive.sha256()),
            provenance_entry("rubygems.name", &gem.name),
            provenance_entry("rubygems.source", &gem.source),
            provenance_entry("rubygems.version", &gem.version),
        ]);

        resolved.push(ResolvedDependency {
            id: format!(
                "rubygems:{}@{}:{}:{}:{}:{}:{}",
                gem.name,
                gem.version,
                evidence.platform,
                evidence.ruby_version,
                gem.source,
                evidence.lockfile_sha256,
                archive.sha256()
            ),
            evidence: SemanticModelActivationEvidence {
                language: "ruby".to_owned(),
                ecosystem: "rubygems".to_owned(),
                package: Some(CatalogCoordinate {
                    name: gem.name.clone(),
                    version: parsed_version,
                }),
                module: None,
                toolchain: None,
                target: Some(evidence.platform.clone()),
                configuration: Some(evidence.ruby_version.clone()),
                artifact_sha256: None,
            },
            provenance,
            artifacts: vec![ResolvedDependencyArtifact::exact_file(
                DependencyArtifactRole::Declarations,
                ExternalArtifactKind::RubyGemArchive,
                canonical_archive,
                archive.sha256().to_owned(),
            )],
            scope: DependencyScope::Unknown,
            declared_by: None,
        });
    }
    Ok(resolved)
}

fn validate_locked_gem(
    lockfile: &rubund::parser::Lockfile<'_>,
    gem: &RubyGemApiArtifact,
    platform: &str,
    lockfile_path: &Path,
) -> Result<(), DependencyPackDiagnostic> {
    let Some(spec) = lockfile.specs.iter().find(|spec| {
        spec.name == gem.name
            && (spec.version == gem.version
                || spec.version == format!("{}-{platform}", gem.version))
    }) else {
        return Err(diagnostic(
            "ruby.evidence.gem_not_locked",
            Some(lockfile_path),
            format!(
                "configured gem {} {} is not an exact Gemfile.lock spec",
                gem.name, gem.version
            ),
        ));
    };
    let Some(source) = lockfile.sources.get(spec.source_index) else {
        return Err(diagnostic(
            "ruby.evidence.gem_source_missing",
            Some(lockfile_path),
            format!(
                "Gemfile.lock has no source for {} {}",
                gem.name, gem.version
            ),
        ));
    };
    let locked_source = match source.type_ {
        rubund::parser::SourceType::Gem => source.remote,
        rubund::parser::SourceType::Git => source.remote,
        rubund::parser::SourceType::Path => source.path.unwrap_or(source.remote),
    };
    if locked_source.trim_end_matches('/') != gem.source.trim_end_matches('/') {
        return Err(diagnostic(
            "ruby.evidence.gem_source_mismatch",
            Some(lockfile_path),
            format!(
                "configured source {} does not match locked source {} for {} {}",
                gem.source, locked_source, gem.name, gem.version
            ),
        ));
    }
    if let Some((_, _, locked_checksum)) = lockfile
        .checksums
        .iter()
        .find(|(name, version, _)| *name == gem.name && *version == spec.version)
        && gem.checksum.as_deref() != Some(*locked_checksum)
    {
        return Err(diagnostic(
            "ruby.evidence.locked_checksum_mismatch",
            Some(lockfile_path),
            format!(
                "configured checksum does not match Gemfile.lock checksum for {} {}",
                gem.name, gem.version
            ),
        ));
    }
    Ok(())
}

fn evidence_paths_from_root(
    root: &Path,
    evidence: &RubyDependencyApiEvidence,
) -> RubyDependencyApiEvidence {
    let mut resolved = evidence.clone();
    resolved.lockfile_path = resolve_path(root, &resolved.lockfile_path);
    for archive_root in &mut resolved.approved_archive_roots {
        *archive_root = resolve_path(root, archive_root);
    }
    for gem in &mut resolved.gems {
        gem.gem_archive_path = resolve_path(root, &gem.gem_archive_path);
    }
    resolved
}

fn validate_gem_fields(gem: &RubyGemApiArtifact) -> Result<(), DependencyPackDiagnostic> {
    require_non_empty("gem.name", &gem.name)?;
    require_non_empty("gem.version", &gem.version)?;
    require_non_empty("gem.source", &gem.source)?;
    if let Some(checksum) = &gem.checksum
        && !is_lower_sha256(checksum)
    {
        return Err(diagnostic(
            "ruby.evidence.invalid_gem_checksum",
            Some(&gem.gem_archive_path),
            "Ruby gem checksum must be lowercase SHA-256",
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), DependencyPackDiagnostic> {
    require_non_empty_evidence_field("Ruby", "ruby.evidence.empty_field", field, value)
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    brokk_bifrost_core::cancellation::optional_is_cancelled(cancellation)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    cancelled_dependency_evidence_diagnostic("Ruby", "ruby.evidence.cancelled", path)
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::dependency_support::capture_external_discovery_reads;
    use brokk_bifrost_test_macros::hardwon;
    use std::fs;

    use tempfile::TempDir;

    use crate::analyzer::ruby::dependency_discovery::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::canonical::sha256_hex;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::TestProject;

    const LOCKFILE: &[u8] = b"GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3.pre)\n\nPLATFORMS\n  arm64-darwin\n\nDEPENDENCIES\n  widget\n\nRUBY VERSION\n   ruby 3.4.1p0\n";

    #[test]
    #[hardwon(
        "#10377: on Windows a verbatim canonical path never equaled the configured one, refusing every Ruby discovery carry"
    )]
    fn external_archive_change_invalidates_ruby_discovery_reads() {
        let fixture = EvidenceFixture::new();
        let discover = || {
            resolve_ruby_semantic_pack_dependencies(
                &fixture.config,
                &fixture.project,
                &DependencyPackLimits::default(),
                None,
            )
        };
        let (outcome, reads) = capture_external_discovery_reads(discover);
        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert!(reads.complete);
        assert_eq!(reads.keys.len(), 2);
        assert!(reads.keys.iter().all(|key| key.still_matches()));
        fs::write(&fixture.archive, b"changed gem bytes").unwrap();
        assert!(reads.keys.iter().any(|key| !key.still_matches()));
    }

    #[test]
    fn exact_evidence_binds_lockfile_coordinate_platform_and_archive() {
        let fixture = EvidenceFixture::new();
        let outcome = resolve_ruby_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &DependencyPackLimits::default(),
            None,
        );

        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert_eq!(outcome.dependencies.len(), 2);
        let dependency = outcome
            .dependencies
            .iter()
            .find(|dependency| !dependency.artifacts.is_empty())
            .expect("the configured archive-backed gem remains present");
        assert_eq!(
            outcome
                .dependencies
                .iter()
                .filter(|dependency| dependency.artifacts.is_empty())
                .count(),
            1,
            "the exact Gemfile.lock spec contributes its activation row"
        );
        assert_eq!(dependency.evidence.language, "ruby");
        assert_eq!(dependency.evidence.ecosystem, "rubygems");
        assert_eq!(dependency.evidence.target.as_deref(), Some("arm64-darwin"));
        assert_eq!(dependency.evidence.configuration.as_deref(), Some("3.4.1"));
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::RubyGemArchive
        );
        assert_eq!(
            dependency.artifacts[0].path(),
            fixture.archive.canonicalize().unwrap()
        );
        let archive_digest = sha256_hex(b"exact gem bytes");
        assert_eq!(
            dependency.artifacts[0].expected_sha256.as_deref(),
            Some(archive_digest.as_str())
        );
        assert!(
            dependency
                .provenance
                .iter()
                .any(|entry| { entry.key == "rubygems.version" && entry.value == "1.2.3.pre" })
        );
        assert_eq!(
            dependency.evidence.package.as_ref().unwrap().version,
            Some(semver::Version::parse("1.2.3-pre").unwrap()),
            "a RubyGems prerelease maps to the semver coordinate (#10011)"
        );
    }

    #[test]
    fn discovery_rejects_digest_mismatch_and_archive_outside_approved_roots() {
        let mut fixture = EvidenceFixture::new();
        fixture.config.dependency_api_evidence[0].lockfile_sha256 = "0".repeat(64);
        let mismatch = resolve_ruby_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &DependencyPackLimits::default(),
            None,
        );
        assert_eq!(
            mismatch.diagnostics[0].code,
            "ruby.evidence.lockfile_digest_mismatch"
        );

        let outside = fixture.temp.path().join("outside.gem");
        fs::write(&outside, b"outside").unwrap();
        let evidence = &mut fixture.config.dependency_api_evidence[0];
        evidence.lockfile_sha256 = sha256_hex(LOCKFILE);
        evidence.gems[0].gem_archive_path = outside;
        evidence.gems[0].checksum = Some(sha256_hex(b"outside"));
        let outside = resolve_ruby_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &DependencyPackLimits::default(),
            None,
        );
        assert_eq!(
            outside.diagnostics[0].code,
            "ruby.evidence.gem_archive_outside_roots"
        );
    }

    #[test]
    fn discovery_rejects_configured_gem_absent_from_exact_lockfile() {
        let mut fixture = EvidenceFixture::new();
        fixture.config.dependency_api_evidence[0].gems[0].version = "9.9.9".to_owned();

        let outcome = resolve_ruby_semantic_pack_dependencies(
            &fixture.config,
            &fixture.project,
            &DependencyPackLimits::default(),
            None,
        );

        assert_eq!(outcome.diagnostics[0].code, "ruby.evidence.gem_not_locked");
    }

    #[test]
    fn native_locked_version_matches_separate_version_and_platform_evidence() {
        let source = "GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3-arm64-darwin)\n\nPLATFORMS\n  arm64-darwin\n\nCHECKSUMS\n  widget (1.2.3) sha256=generic\n  widget (1.2.3-arm64-darwin) sha256=native\n";
        let lockfile = rubund::parser::parse_lockfile(source);
        let gem = RubyGemApiArtifact {
            name: "widget".to_owned(),
            version: "1.2.3".to_owned(),
            source: "https://rubygems.org/".to_owned(),
            checksum: Some("native".to_owned()),
            gem_archive_path: PathBuf::from("widget.gem"),
        };

        validate_locked_gem(&lockfile, &gem, "arm64-darwin", Path::new("Gemfile.lock")).unwrap();
    }

    struct EvidenceFixture {
        temp: TempDir,
        project: TestProject,
        config: RubyAnalyzerConfig,
        archive: PathBuf,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            // The reader refuses evidence keyed by a non-canonical path; on
            // macOS the temp root is `/var/...`, a symlink to `/private/var/...`.
            let root = temp.path().canonicalize().unwrap().join("project");
            let archives = root.join("vendor/cache");
            fs::create_dir_all(&archives).unwrap();
            fs::write(root.join("Gemfile.lock"), LOCKFILE).unwrap();
            let archive = archives.join("widget-1.2.3.pre.gem");
            fs::write(&archive, b"exact gem bytes").unwrap();
            let project = TestProject::new(&root, Language::Ruby);
            let config = RubyAnalyzerConfig {
                dependency_api_evidence: vec![RubyDependencyApiEvidence {
                    lockfile_path: PathBuf::from("Gemfile.lock"),
                    lockfile_sha256: sha256_hex(LOCKFILE),
                    ruby_version: "3.4.1".to_owned(),
                    platform: "arm64-darwin".to_owned(),
                    approved_archive_roots: vec![PathBuf::from("vendor/cache")],
                    gems: vec![RubyGemApiArtifact {
                        name: "widget".to_owned(),
                        version: "1.2.3.pre".to_owned(),
                        source: "https://rubygems.org/".to_owned(),
                        checksum: Some(sha256_hex(b"exact gem bytes")),
                        gem_archive_path: PathBuf::from("vendor/cache/widget-1.2.3.pre.gem"),
                    }],
                }],
            };
            Self {
                temp,
                project,
                config,
                archive,
            }
        }
    }
}
