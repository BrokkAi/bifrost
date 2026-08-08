//! Offline measurement harness for the semantic-diagnostic rollout artifact
//! (#1628).
//!
//! [`semantic_diagnostic_rollout`](super::semantic_diagnostic_rollout) defines
//! the artifact, its aggregation, and its validation. This module produces one
//! against a pinned fixture workspace by doing exactly what the LSP host does:
//! activate dependency packs once, off the request path, then serve per-file
//! diagnostic requests that only read the published proof.
//!
//! Cold and warm stay separate series. Cold is a fresh ephemeral catalog and a
//! first read of each file; warm re-reads the same files against the same
//! published proof; the refresh series re-activates a fresh analyzer
//! generation against the now-populated catalog, which is what a host does
//! after a workspace update drops the published proof.
//!
//! The harness deliberately sets no latency threshold. It produces the numbers
//! a team reviews before deciding whether unrecognized-symbol diagnostics may
//! default to on.
//!
//! Nothing here downloads, and nothing runs a package manager: it measures the
//! same file-reading discovery the host performs.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
};
use crate::benchmark::semantic_diagnostic_rollout::{
    ActivePackIdentity, HashedRolloutConfiguration, PinnedRolloutInput,
    SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION, SemanticDiagnosticActivationSample,
    SemanticDiagnosticCacheState, SemanticDiagnosticPhase, SemanticDiagnosticRolloutAggregate,
    SemanticDiagnosticRolloutArtifact, SemanticDiagnosticRolloutIdentity, SemanticDiagnosticSample,
    aggregate_semantic_diagnostic_rollout, render_semantic_diagnostic_rollout_markdown,
};
use crate::{
    AnalyzerConfig, CancellationToken, DependencyPackEcosystem, DependencyPackWorkspaceContext,
    FilesystemProject, Project, ProjectFile, WorkspaceAnalyzer,
};

/// Identifier of the cold activation every cold and warm diagnostic sample
/// refers to.
const COLD_ACTIVATION: &str = "activation.cold";
/// Identifier of the re-activation the refresh diagnostic samples refer to.
const WARM_ACTIVATION: &str = "activation.warm";

/// One pinned rollout measurement.
///
/// The Bifrost revision is supplied rather than read from git so the
/// measurement itself stays deterministic and free of subprocesses; the caller
/// that knows how it checked out the tree records what it pinned.
#[derive(Debug, Clone)]
pub struct SemanticDiagnosticRolloutRequest {
    pub bifrost_revision: String,
    pub bifrost_dirty: bool,
    /// Stable name of the fixture workspace, e.g. `tests/fixtures/testcode-py`.
    pub fixture_id: String,
    /// The fixture's pinned revision. For an in-repo fixture this is the
    /// Bifrost revision that contains it.
    pub fixture_revision: String,
    pub fixture_root: PathBuf,
    /// Stable name of the measured configuration. Its hash is derived.
    pub configuration_id: String,
    /// Cap on the files measured per phase. `None` measures every analyzable
    /// file of every selected ecosystem's languages.
    pub max_files: Option<usize>,
}

/// Measure one rollout artifact against `request`'s fixture.
pub fn measure_semantic_diagnostic_rollout(
    request: &SemanticDiagnosticRolloutRequest,
) -> Result<SemanticDiagnosticRolloutArtifact, String> {
    let root = request.fixture_root.canonicalize().map_err(|error| {
        format!(
            "fixture root {:?} is unusable: {error}",
            request.fixture_root
        )
    })?;
    let config = AnalyzerConfig::default();
    let project: Arc<dyn Project> = Arc::new(
        FilesystemProject::new(root.clone())
            .map_err(|error| format!("failed to open fixture {root:?}: {error}"))?,
    );
    let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), config.clone());
    let ecosystems = ecosystems_for_workspace(&workspace);
    if ecosystems.is_empty() {
        return Err(format!(
            "fixture {root:?} holds no language that maps to a dependency-pack ecosystem"
        ));
    }
    let files = measured_files(project.as_ref(), &ecosystems, request.max_files)?;
    if files.is_empty() {
        return Err(format!(
            "fixture {root:?} holds no analyzable file to measure"
        ));
    }

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .map_err(|error| format!("failed to open the measurement catalog: {error}"))?;
    let activation = activation_request();
    let cancellation = CancellationToken::default();
    let context = DependencyPackWorkspaceContext {
        catalog: &catalog,
        persistence: None,
        activation: &activation,
        limits: DependencyPackLimits::default(),
        cancellation: &cancellation,
    };

    let started = Instant::now();
    let cold_outcome = workspace.activate_dependency_packs(&config, &ecosystems, context);
    let cold_activation = SemanticDiagnosticActivationSample::from_dependency_pack_outcome(
        COLD_ACTIVATION,
        SemanticDiagnosticCacheState::Cold,
        elapsed_nanos(started),
        &cold_outcome,
    );
    let active_packs = active_packs(&cold_outcome.runtime);

    let mut diagnostic_samples = measure_files(
        &workspace,
        project.as_ref(),
        &catalog,
        &files,
        COLD_ACTIVATION,
        SemanticDiagnosticPhase::ColdDiagnostic,
        SemanticDiagnosticCacheState::Cold,
    )?;
    diagnostic_samples.extend(measure_files(
        &workspace,
        project.as_ref(),
        &catalog,
        &files,
        COLD_ACTIVATION,
        SemanticDiagnosticPhase::WarmDiagnostic,
        SemanticDiagnosticCacheState::Warm,
    )?);

    // A fresh analyzer generation starts with no published proof, exactly as
    // one does in a host after a workspace update. Re-activating it against the
    // now-populated catalog is the refresh a host pays repeatedly, so it is
    // measured separately from the cold first activation.
    let refreshed = WorkspaceAnalyzer::build(Arc::clone(&project), config.clone());
    let started = Instant::now();
    let warm_outcome = refreshed.activate_dependency_packs(&config, &ecosystems, context);
    let warm_activation = SemanticDiagnosticActivationSample::from_dependency_pack_outcome(
        WARM_ACTIVATION,
        SemanticDiagnosticCacheState::Warm,
        elapsed_nanos(started),
        &warm_outcome,
    );
    if warm_activation.diagnostic_refresh_required {
        diagnostic_samples.extend(measure_files(
            &refreshed,
            project.as_ref(),
            &catalog,
            &files,
            WARM_ACTIVATION,
            SemanticDiagnosticPhase::RefreshDiagnostic,
            SemanticDiagnosticCacheState::Warm,
        )?);
    }

    Ok(SemanticDiagnosticRolloutArtifact {
        schema_version: SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION,
        generated_at: chrono::Utc::now().to_rfc3339(),
        identity: SemanticDiagnosticRolloutIdentity {
            bifrost_revision: request.bifrost_revision.clone(),
            bifrost_dirty: request.bifrost_dirty,
            bifrost_tree_sha256: None,
            fixture: PinnedRolloutInput {
                id: request.fixture_id.clone(),
                revision: request.fixture_revision.clone(),
            },
            configuration: HashedRolloutConfiguration {
                id: request.configuration_id.clone(),
                sha256: configuration_sha256(&ecosystems, &files, request.max_files),
            },
            active_packs,
        },
        release_bundle: None,
        activation_samples: vec![cold_activation, warm_activation],
        diagnostic_samples,
    })
}

/// Measure, aggregate, validate, and render one rollout in the order the
/// runbook prescribes. The aggregate is returned with its markdown so a caller
/// can record both.
pub fn report_semantic_diagnostic_rollout(
    request: &SemanticDiagnosticRolloutRequest,
) -> Result<(SemanticDiagnosticRolloutAggregate, String), String> {
    let artifact = measure_semantic_diagnostic_rollout(request)?;
    let aggregate = aggregate_semantic_diagnostic_rollout(std::slice::from_ref(&artifact))
        .map_err(|error| format!("rollout artifact is invalid: {error}"))?;
    let markdown = render_semantic_diagnostic_rollout_markdown(&aggregate);
    Ok((aggregate, markdown))
}

/// The ecosystems whose languages the workspace analyzes. Same selection rule
/// as the LSP host, so the harness measures the work a session performs.
fn ecosystems_for_workspace(workspace: &WorkspaceAnalyzer) -> Vec<DependencyPackEcosystem> {
    let languages = workspace.analyzer().languages();
    DependencyPackEcosystem::ALL
        .into_iter()
        .filter(|ecosystem| {
            ecosystem
                .languages()
                .iter()
                .any(|language| languages.contains(language))
        })
        .collect()
}

fn measured_files(
    project: &dyn Project,
    ecosystems: &[DependencyPackEcosystem],
    max_files: Option<usize>,
) -> Result<Vec<ProjectFile>, String> {
    let mut files = BTreeSet::new();
    for ecosystem in ecosystems {
        for language in ecosystem.languages() {
            files.extend(
                project
                    .analyzable_files(*language)
                    .map_err(|error| format!("failed to list {language:?} files: {error}"))?,
            );
        }
    }
    let mut files = files.into_iter().collect::<Vec<_>>();
    if let Some(max_files) = max_files {
        files.truncate(max_files);
    }
    Ok(files)
}

fn measure_files(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    catalog: &SemanticPackCatalog,
    files: &[ProjectFile],
    activation_sample_id: &str,
    phase: SemanticDiagnosticPhase,
    cache_state: SemanticDiagnosticCacheState,
) -> Result<Vec<SemanticDiagnosticSample>, String> {
    let mut samples = Vec::with_capacity(files.len());
    for file in files {
        let content = project
            .read_source(file)
            .map_err(|error| format!("failed to read {:?}: {error}", file.rel_path()))?;
        let sql_before = catalog.sql_statement_count();
        let started = Instant::now();
        let report = workspace.analyzer().semantic_diagnostics(file, &content);
        let elapsed = elapsed_nanos(started);
        let catalog_sql_statements = catalog.sql_statement_count().saturating_sub(sql_before);
        samples.push(SemanticDiagnosticSample::from_report(
            activation_sample_id,
            phase,
            cache_state,
            file_id(file),
            elapsed,
            catalog_sql_statements,
            &report,
        ));
    }
    Ok(samples)
}

/// Workspace-relative identity of a measured file. Slashes are normalized here,
/// at the artifact boundary, so the same fixture produces the same file ids on
/// every operating system.
fn file_id(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("package version must be semver"),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn active_packs(runtime: &Option<SemanticModelRuntimeOutcome>) -> Vec<ActivePackIdentity> {
    let Some(SemanticModelRuntimeOutcome::Ready { active, .. }) = runtime else {
        return Vec::new();
    };
    let mut packs = active
        .shards()
        .iter()
        .map(|shard| ActivePackIdentity {
            pack_id: shard.manifest.pack_id.clone(),
            pack_version: shard.manifest.version.clone(),
            manifest_sha256: shard.manifest.content_sha256.clone(),
        })
        .collect::<Vec<_>>();
    // One pack contributes one identity however many shards it activates.
    packs.sort();
    packs.dedup();
    packs
}

/// Hash of everything the measurement depends on besides the fixture content
/// and the Bifrost revision, both of which the identity pins separately.
fn configuration_sha256(
    ecosystems: &[DependencyPackEcosystem],
    files: &[ProjectFile],
    max_files: Option<usize>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION.to_le_bytes());
    hasher.update(format!("{ecosystems:?}").as_bytes());
    hasher.update(format!("{:?}", AnalyzerConfig::default()).as_bytes());
    hasher.update(format!("{:?}", DependencyPackLimits::default()).as_bytes());
    hasher.update(format!("{:?}", SemanticModelRuntimeLimits::default()).as_bytes());
    hasher.update(format!("{max_files:?}").as_bytes());
    for file in files {
        hasher.update(file_id(file).as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::semantic_diagnostic_rollout::SemanticDiagnosticCacheState;

    fn fixture_request(id: &str, root: &str) -> SemanticDiagnosticRolloutRequest {
        SemanticDiagnosticRolloutRequest {
            bifrost_revision: "0000000000000000000000000000000000000000".to_owned(),
            bifrost_dirty: false,
            fixture_id: id.to_owned(),
            fixture_revision: "in-repo".to_owned(),
            fixture_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(root),
            configuration_id: "default-analyzer-config".to_owned(),
            max_files: Some(8),
        }
    }

    #[test]
    fn a_pinned_fixture_produces_a_valid_rollout_artifact() {
        let request = fixture_request("tests/fixtures/testcode-py", "tests/fixtures/testcode-py");
        let (aggregate, markdown) = report_semantic_diagnostic_rollout(&request).unwrap();

        assert_eq!(
            aggregate.schema_version,
            SEMANTIC_DIAGNOSTIC_ROLLOUT_SCHEMA_VERSION
        );
        assert_eq!(aggregate.identity.fixture.id, "tests/fixtures/testcode-py");
        assert!(markdown.contains("# Semantic diagnostic rollout"));
        assert!(markdown.contains("## Activation"));
    }

    #[test]
    fn cold_and_warm_series_stay_separate() {
        let request = fixture_request("tests/fixtures/testcode-go", "tests/fixtures/testcode-go");
        let artifact = measure_semantic_diagnostic_rollout(&request).unwrap();

        let cold = artifact
            .diagnostic_samples
            .iter()
            .filter(|sample| sample.phase == SemanticDiagnosticPhase::ColdDiagnostic)
            .count();
        let warm = artifact
            .diagnostic_samples
            .iter()
            .filter(|sample| sample.phase == SemanticDiagnosticPhase::WarmDiagnostic)
            .count();
        assert!(
            cold > 0 && cold == warm,
            "{:#?}",
            artifact.diagnostic_samples
        );
        assert!(
            artifact
                .diagnostic_samples
                .iter()
                .all(|sample| match sample.phase {
                    SemanticDiagnosticPhase::ColdDiagnostic =>
                        sample.cache_state == SemanticDiagnosticCacheState::Cold,
                    _ => sample.cache_state == SemanticDiagnosticCacheState::Warm,
                }),
            "each phase must keep its own cache state: {:#?}",
            artifact.diagnostic_samples
        );

        let aggregate =
            aggregate_semantic_diagnostic_rollout(std::slice::from_ref(&artifact)).unwrap();
        let cold_series = aggregate
            .diagnostics
            .iter()
            .filter(|series| series.cache_state == SemanticDiagnosticCacheState::Cold)
            .count();
        assert_eq!(cold_series, 1, "{:#?}", aggregate.diagnostics);
        assert_eq!(
            aggregate.activation.len(),
            2,
            "cold and warm activation stay separate: {:#?}",
            aggregate.activation
        );
    }

    #[test]
    fn a_fixture_without_a_pack_ecosystem_is_reported_rather_than_measured() {
        let request = fixture_request("tests/fixtures/testcode-cpp", "tests/fixtures/testcode-cpp");
        let error = measure_semantic_diagnostic_rollout(&request).unwrap_err();
        assert!(
            error.contains("no language that maps to a dependency-pack ecosystem"),
            "{error}"
        );
    }
}
