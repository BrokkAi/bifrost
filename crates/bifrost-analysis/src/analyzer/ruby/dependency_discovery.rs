use std::path::{Path, PathBuf};

use semver::Version;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::is_lower_sha256;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedDependencyDiagnostics, CatalogCoordinate,
    DependencyArtifactRole, DependencyDiscoveryOutcome, DependencyDiscoveryProfile,
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    DependencyProvenance, ExternalArtifactKind, ProducerDiagnostic, ProducerDiagnosticSeverity,
    ResolvedDependency, ResolvedDependencyArtifact, SemanticModelActivationEvidence,
    read_exact_artifact_while,
};
use crate::analyzer::{Project, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyGemApiArtifact};
use crate::hash::HashSet;

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
    DependencyDiscoveryOutcome {
        profile: DependencyDiscoveryProfile {
            metadata_inputs_considered,
            dependencies_resolved: dependencies.len(),
        },
        complete: diagnostics.is_empty() && suppressed_diagnostics == 0 && !cancelled,
        dependencies,
        diagnostics,
        suppressed_diagnostics,
        cancelled,
    }
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

    let lockfile = read_evidence_file_with_budget(
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
        validate_locked_gem(&parsed_lockfile, gem, &evidence.lockfile_path)?;
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

        let archive = read_evidence_file_with_budget(
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

        let parsed_version = Version::parse(&gem.version).ok();
        let mut provenance = vec![
            provenance_entry("bundler.lockfile_sha256", &evidence.lockfile_sha256),
            provenance_entry("ruby.version", &evidence.ruby_version),
            provenance_entry("ruby.platform", &evidence.platform),
            provenance_entry("rubygems.name", &gem.name),
            provenance_entry("rubygems.version", &gem.version),
            provenance_entry("rubygems.source", &gem.source),
            provenance_entry("rubygems.archive_sha256", archive.sha256()),
        ];
        if let Some(checksum) = &gem.checksum {
            provenance.push(provenance_entry("bundler.checksum", checksum));
        }
        provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));

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
        });
    }
    Ok(resolved)
}

fn validate_locked_gem(
    lockfile: &rubund::parser::Lockfile<'_>,
    gem: &RubyGemApiArtifact,
    lockfile_path: &Path,
) -> Result<(), DependencyPackDiagnostic> {
    let Some(spec) = lockfile
        .specs
        .iter()
        .find(|spec| spec.name == gem.name && spec.version == gem.version)
    else {
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
        .find(|(name, version, _)| *name == gem.name && *version == gem.version)
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

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
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

fn read_evidence_file_with_budget(
    path: &Path,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::analyzer::semantic_model::ExactArtifact, DependencyPackDiagnostic> {
    let remaining = limits
        .max_total_artifact_bytes
        .saturating_sub(*evidence_bytes_read);
    if remaining == 0 {
        return Err(diagnostic(
            "limit.total_artifact_bytes",
            Some(path),
            format!(
                "Ruby dependency evidence exceeds the {} byte aggregate limit",
                limits.max_total_artifact_bytes
            ),
        ));
    }
    let producer_limits = ArtifactProducerLimits {
        max_artifact_bytes: limits.producer.max_artifact_bytes.min(remaining),
        ..limits.producer
    };
    let artifact = read_exact_artifact_while(path, &producer_limits, || is_cancelled(cancellation))
        .map_err(|producer| producer_diagnostic(path, producer))?;
    *evidence_bytes_read = evidence_bytes_read.saturating_add(artifact.bytes().len() as u64);
    Ok(artifact)
}

fn provenance_entry(key: &str, value: impl ToString) -> DependencyProvenance {
    DependencyProvenance {
        key: key.to_owned(),
        value: value.to_string(),
    }
}

fn producer_diagnostic(path: &Path, producer: ProducerDiagnostic) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: match producer.severity {
            ProducerDiagnosticSeverity::Warning => DependencyPackDiagnosticSeverity::Warning,
            ProducerDiagnosticSeverity::Error => DependencyPackDiagnosticSeverity::Error,
        },
        code: producer.code,
        dependency_id: None,
        location: Some(path.to_string_lossy().into_owned()),
        message: producer.message,
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), DependencyPackDiagnostic> {
    if value.trim().is_empty() {
        return Err(diagnostic(
            "ruby.evidence.empty_field",
            None,
            format!("Ruby dependency evidence field {field} must not be empty"),
        ));
    }
    Ok(())
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    diagnostic(
        "ruby.evidence.cancelled",
        path,
        "Ruby dependency evidence decoding was cancelled",
    )
}

fn diagnostic(
    code: &str,
    path: Option<&Path>,
    message: impl Into<String>,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: code.to_owned(),
        dependency_id: None,
        location: path.map(|value| value.to_string_lossy().into_owned()),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
    use crate::analyzer::{Language, TestProject};

    const LOCKFILE: &[u8] = b"GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3.pre)\n\nPLATFORMS\n  arm64-darwin\n\nDEPENDENCIES\n  widget\n";

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
        assert_eq!(outcome.dependencies.len(), 1);
        let dependency = &outcome.dependencies[0];
        assert_eq!(dependency.evidence.language, "ruby");
        assert_eq!(dependency.evidence.ecosystem, "rubygems");
        assert_eq!(dependency.evidence.target.as_deref(), Some("arm64-darwin"));
        assert_eq!(dependency.evidence.configuration.as_deref(), Some("3.4.1"));
        assert_eq!(
            dependency.artifacts[0].kind,
            ExternalArtifactKind::RubyGemArchive
        );
        assert_eq!(
            dependency.artifacts[0].path,
            fixture.archive.canonicalize().unwrap()
        );
        let archive_digest = digest(b"exact gem bytes");
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
        assert_eq!(dependency.evidence.package.as_ref().unwrap().version, None);
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
        evidence.lockfile_sha256 = digest(LOCKFILE);
        evidence.gems[0].gem_archive_path = outside;
        evidence.gems[0].checksum = Some(digest(b"outside"));
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

    struct EvidenceFixture {
        temp: TempDir,
        project: TestProject,
        config: RubyAnalyzerConfig,
        archive: PathBuf,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("project");
            let archives = root.join("vendor/cache");
            fs::create_dir_all(&archives).unwrap();
            fs::write(root.join("Gemfile.lock"), LOCKFILE).unwrap();
            let archive = archives.join("widget-1.2.3.pre.gem");
            fs::write(&archive, b"exact gem bytes").unwrap();
            let project = TestProject::new(&root, Language::Ruby);
            let config = RubyAnalyzerConfig {
                dependency_api_evidence: vec![RubyDependencyApiEvidence {
                    lockfile_path: PathBuf::from("Gemfile.lock"),
                    lockfile_sha256: digest(LOCKFILE),
                    ruby_version: "3.4.1".to_owned(),
                    platform: "arm64-darwin".to_owned(),
                    approved_archive_roots: vec![PathBuf::from("vendor/cache")],
                    gems: vec![RubyGemApiArtifact {
                        name: "widget".to_owned(),
                        version: "1.2.3.pre".to_owned(),
                        source: "https://rubygems.org/".to_owned(),
                        checksum: Some(digest(b"exact gem bytes")),
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

    fn digest(bytes: &[u8]) -> String {
        lower_hex_string(&sha256_bytes(bytes))
    }
}
