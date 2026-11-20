use crate::CancellationToken;
use crate::analyzer::DependencyPackEcosystem;
use crate::analyzer::semantic_model::{
    CatalogCandidate, CatalogError, CatalogPackSourceKind, Completeness, GeneratedProductionKey,
    PackExtractionAccounting, Producer, SemanticPackCatalog,
    producer::{
        read_exact_artifact_while, read_exact_source_set_seekable_while,
        read_exact_source_set_while,
    },
};
use crate::hash::{HashSet, set_with_capacity};
pub use brokk_bifrost_semantic::analyzer::semantic_model::dependency::*;
use std::sync::{OnceLock, RwLock};
pub(crate) type CandidateSelection<T> = (Vec<T>, Vec<(String, CatalogError)>);

/// Reads for provider selection; pinned implementations use the reader's borrowed connection.
pub(crate) trait DependencyProviderReads {
    fn provider_candidates(
        &self,
        query: &super::SemanticPackSelectorQuery,
    ) -> Result<CandidateSelection<CatalogCandidate>, CatalogError>;
    fn provider_extraction(
        &self,
        digest: &str,
    ) -> Result<Option<PackExtractionAccounting>, CatalogError>;
}

/// One ecosystem's dependency resolver.
///
/// Before this, the nine resolvers were free functions behind a hard-coded
/// `match` in `WorkspaceAnalyzer::activate_dependency_packs`, each with its own
/// signature, its own private caps, and its own relationship to the pack
/// adapter that consumes it. The trait makes the four things a caller needs --
/// which adapter pairs with it, which files invalidate it, what it is allowed
/// to spend, and how to run it -- one uniform surface, so activation dispatches
/// through a registry instead of restating the pairing.
///
/// Implementations live with the ecosystem they know about; the registry that
/// names them is `DependencyPackEcosystem::resolver`.
pub trait DependencyResolver: Send + Sync {
    /// Select paths that this resolver's discovery enumeration could read.
    /// The enumeration must use this same predicate for candidate selection.
    fn is_discovery_candidate(&self, _rel_path: &std::path::Path) -> bool {
        true
    }

    /// Select membership changes that can affect discovery, including paths
    /// whose existence is observed without reading their contents. Kept
    /// separate from content candidates so an inventory census does not widen
    /// bounded file acquisition.
    fn is_discovery_membership_candidate(&self, rel_path: &std::path::Path) -> bool {
        self.is_discovery_candidate(rel_path)
    }

    /// Whether a discovery diagnostic of this kind is a function of the reads
    /// the discovery recorded (project reads and verifiable external reads),
    /// so that a discovery reporting it can carry across requests. This is an
    /// allow-list: the default vouches for nothing, so a new kind refuses
    /// until a reviewer has shown that its producer records every input it
    /// consults, and that a failed or transient read refuses the discovery.
    fn diagnostic_follows_recorded_reads(&self, _code: &str) -> bool {
        false
    }

    /// The pack adapter that produces semantic packs from what this resolver
    /// resolves. Pairing them here is what removes the chance of activating an
    /// ecosystem's dependencies through another's adapter.
    fn adapter(&self) -> &'static dyn DependencyPackAdapter;

    /// Base names of the files whose change can invalidate this resolver's
    /// answer.
    fn dependency_inputs(&self) -> &'static [&'static str];

    /// The bounds this resolver runs under for the given configuration. The
    /// subprocess policy depends on configuration for the two ecosystems that
    /// have a build-tool mode at all.
    fn bounds(&self, config: &crate::analyzer::AnalyzerConfig) -> DependencyResolverBounds;

    /// Widen the shared pack limits where this ecosystem's artifact shape
    /// needs it. Called once per activation, before `resolve`, so the same
    /// limits govern discovery and preparation.
    fn adjust_limits(
        &self,
        _config: &crate::analyzer::AnalyzerConfig,
        _limits: &mut DependencyPackLimits,
    ) {
    }

    /// Prepare the dependencies this resolver discovered. Most ecosystems
    /// produce the complete exact dependency surface. A resolver may instead
    /// select only compatible installed packs when its configured discovery
    /// mode deliberately supplied coordinate evidence without source
    /// artifacts.
    fn prepare(
        &self,
        _config: &crate::analyzer::AnalyzerConfig,
        catalog: &SemanticPackCatalog,
        dependencies: &[ResolvedDependency],
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackPreparationOutcome {
        prepare_dependency_semantic_packs(
            catalog,
            self.adapter(),
            dependencies,
            limits,
            cancellation,
        )
    }

    /// Discover this ecosystem's exact local dependencies. `digests` is the
    /// workspace store's budget-charged content-digest region; an ecosystem
    /// that binds artifact content during discovery (the JDK) streams its
    /// digests through it, and the others ignore it. `verifications` is the
    /// store-owned holder shared by activation and request-time toolchain checks.
    fn resolve(
        &self,
        config: &crate::analyzer::AnalyzerConfig,
        project: &dyn crate::analyzer::Project,
        digests: &brokk_bifrost_core::content_digest::ContentDigestCache,
        verifications: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyDiscoveryOutcome;
}

pub(crate) fn register_reused_exact_go_source(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    manifest_digest: &str,
    source: Option<&PreparedExactGoSource<'_>>,
) -> Result<(), CatalogError> {
    if dependency.evidence.language != "go" {
        return Ok(());
    }
    let source = source.ok_or_else(|| {
        CatalogError::Integrity(
            "Go exact source preparation did not produce a selected source set".to_owned(),
        )
    })?;
    catalog.register_exact_go_source(manifest_digest, source.artifact, &source.packages)
}

pub(crate) fn register_exact_source_for_reused_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    source: Option<&PreparedExactGoSource<'_>>,
    manifest_digest: &str,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> bool {
    match register_reused_exact_go_source(catalog, dependency, manifest_digest, source) {
        Ok(()) => true,
        Err(error) => {
            diagnostics.catalog(Some(&dependency.id), "go.source_registration", error);
            false
        }
    }
}

/// A process-wide, host-installed attempt to acquire one semantic pack. The
/// callback may install bytes into `catalog`, but cannot hand a pack directly
/// to preparation. Preparation always re-reads the catalog after this hook,
/// which keeps catalog verification authoritative.
pub type SemanticPackAcquisitionHook =
    fn(&SemanticPackCatalog, &AcquisitionRequest<'_>) -> Result<(), String>;

pub(crate) static SEMANTIC_PACK_ACQUISITION_HOOK: OnceLock<
    RwLock<Option<SemanticPackAcquisitionHook>>,
> = OnceLock::new();

pub(crate) fn acquisition_hook_slot() -> &'static RwLock<Option<SemanticPackAcquisitionHook>> {
    let is_capturing = crate::analyzer::i_analyzer::has_read_attribution_ledgers();
    debug_assert!(
        !is_capturing,
        "pack acquisition is host setup before captured reads"
    );

    SEMANTIC_PACK_ACQUISITION_HOOK.get_or_init(|| RwLock::new(None))
}

/// Install or clear the process-wide semantic-pack acquisition hook.
///
/// The previous hook is returned so a caller that temporarily owns process
/// configuration, such as a test harness, can restore it exactly.
pub fn set_semantic_pack_acquisition_hook(
    hook: Option<SemanticPackAcquisitionHook>,
) -> Option<SemanticPackAcquisitionHook> {
    let mut slot = acquisition_hook_slot()
        .write()
        .expect("semantic-pack acquisition hook mutex poisoned");
    std::mem::replace(&mut *slot, hook)
}

pub(crate) fn semantic_pack_acquisition_hook() -> Option<SemanticPackAcquisitionHook> {
    *acquisition_hook_slot()
        .read()
        .expect("semantic-pack acquisition hook mutex poisoned")
}

// Keep full preparation and the installed stage on the same curated route.
fn selects_curated_dependency_pack(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
) -> Result<bool, CatalogError> {
    if adapter.installed_packs_only(dependency) {
        return Ok(true);
    }
    if !adapter.reviewed_pack_supersedes_production(dependency) {
        return Ok(false);
    }
    Ok(compatible_curated_installed_pack(catalog, dependency)?.is_some())
}

/// Activate a selected installed pack. This is the only place preparation adds
/// an installed pack to its evidence and its activated list, and it takes no
/// failure list: a pack that is installed and activated is never a preparation
/// failure (f728c64932), so "quarantined and still activated" cannot be written.
///
/// A pack whose extraction accounting is not certified is activated all the
/// same, and its coverage is partial. `dependency_gaps` derives that as a
/// deterministic `PartialCoverage` gap from the active shard's manifest
/// completeness, which is replayable through `ReadKey::Models` and
/// deduplicated with the shard's own gap. `pack_is_activation_ready` is true
/// for every complete manifest, so uncertified accounting always means a
/// partial one and that derivation covers it.
fn activate_installed_pack(
    installed: PreparedInstalledDependencyPack,
    evidence: &mut Vec<crate::analyzer::semantic_model::runtime::SemanticModelActivationEvidence>,
    installed_packs: &mut Vec<PreparedInstalledDependencyPack>,
    profile: &mut DependencyPackPreparationProfile,
) {
    debug_assert!(
        installed.activation_ready || installed.completeness != Completeness::Complete,
        "uncertified accounting on a complete pack would carry no partial-coverage gap: {installed:?}"
    );
    evidence.push(installed.evidence.clone());
    installed_packs.push(installed);
    profile.installed_packs += 1;
}

/// Prepare one ecosystem's discovered dependencies.
///
/// A row the adapter marks [`DependencyPackAdapter::installed_packs_only`],
/// such as an exact lockfile coordinate with no artifact to produce from,
/// selects only compatible installed or reviewed workspace packs through
/// [`prepare_compatible_installed_semantic_packs`], as curated Go module
/// evidence does: such a package without a pack is not a failure, because
/// most locked packages have no model. So does a producible row the adapter
/// marks [`DependencyPackAdapter::reviewed_pack_supersedes_production`] when
/// such a pack exists for its coordinate; a failed lookup routes it there too,
/// so the installed route reports the failure instead of generating a second
/// owner of the reviewed symbols. Every other row is produced or acquired.
pub fn prepare_dependency_semantic_packs(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyPackPreparationOutcome {
    // Diagnose obsolete metadata before routing or cache hits can hide it.
    // This is an indexed dependency-coordinate read, not an artifact read.
    let mut revision_diagnostics = BoundedDependencyDiagnostics::new(limits);
    for dependency in dependencies.iter().take(limits.max_dependencies) {
        if is_cancelled(cancellation) {
            break;
        }
        if let Err(error) =
            record_obsolete_dependency_candidates(catalog, dependency, &mut revision_diagnostics)
        {
            revision_diagnostics.warning("catalog.revision_probe", Some(&dependency.id), format!("preliminary producer revision lookup failed; full preparation will retry: {error}"));
        }
    }
    let finish = |mut outcome: DependencyPackPreparationOutcome| {
        // Preserve the request cap and error priority when adding probe warnings.
        let mut combined = revision_diagnostics;
        for diagnostic in outcome.diagnostics.drain(..) {
            combined.push(diagnostic);
        }
        let (diagnostics, suppressed) = combined.finish();
        outcome.diagnostics = diagnostics;
        outcome.suppressed_diagnostics += suppressed;
        outcome
    };
    let routes = dependencies
        .iter()
        // A failed lookup takes the curated route so that full preparation
        // reports it there, instead of producing a second symbol owner.
        .map(|dependency| {
            selects_curated_dependency_pack(catalog, adapter, dependency).unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if !routes.contains(&true) {
        return finish(prepare_produced_dependency_semantic_packs(
            catalog,
            adapter,
            dependencies,
            limits,
            cancellation,
        ));
    }
    let (mut locked, mut produced) = (Vec::new(), Vec::new());
    for (dependency, installed) in dependencies.iter().zip(routes) {
        if installed {
            locked.push(dependency.clone());
        } else {
            produced.push(dependency.clone());
        }
    }
    let mut outcome = prepare_produced_dependency_semantic_packs(
        catalog,
        adapter,
        &produced,
        limits,
        cancellation,
    );
    if outcome.cancelled {
        return finish(outcome);
    }
    let installed =
        prepare_compatible_installed_semantic_packs(catalog, &locked, limits, cancellation);
    outcome.failures.extend(installed.failures);
    outcome.installed_packs.extend(installed.installed_packs);
    outcome.evidence.extend(installed.evidence);
    outcome.diagnostics.extend(installed.diagnostics);
    outcome.suppressed_diagnostics += installed.suppressed_diagnostics;
    outcome.complete &= installed.complete;
    outcome.cancelled = installed.cancelled;
    outcome.profile.dependencies_considered += installed.profile.dependencies_considered;
    outcome.profile.installed_packs += installed.profile.installed_packs;
    finish(outcome)
}

fn record_dependency_candidate_findings(
    catalog: &SemanticPackCatalog,
    dependency_id: &str,
    findings: Vec<(String, CatalogError)>,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> Result<(), CatalogError> {
    for (_, finding) in &findings {
        if matches!(finding, CatalogError::StaleGeneratedSelector { .. }) {
            diagnostics.warning(
                "StaleGeneratedSelector",
                Some(dependency_id),
                finding.to_string(),
            );
        }
    }
    catalog.apply_candidate_findings(findings)
}

fn record_obsolete_dependency_candidates(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> Result<(), CatalogError> {
    let Some(query) = installed_pack_query(dependency) else {
        return Ok(());
    };
    let (_, findings) = catalog.provider_candidates(&query)?;
    record_dependency_candidate_findings(catalog, &dependency.id, findings, diagnostics)
}

fn catalog_diagnostics(
    catalog: &SemanticPackCatalog,
    limits: &DependencyPackLimits,
) -> BoundedDependencyDiagnostics {
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    match catalog.upgrade_diagnostics() {
        Ok(warnings) => {
            for warning in warnings {
                diagnostics.warning(warning.code, None, warning.message);
            }
        }
        Err(error) => {
            diagnostics.warning("catalog.default_upgrade_report", None, error.to_string())
        }
    }
    diagnostics
}

fn prepare_produced_dependency_semantic_packs(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyPackPreparationOutcome {
    let mut diagnostics = catalog_diagnostics(catalog, limits);
    let mut failures = Vec::new();
    let mut packs = Vec::new();
    let mut installed_packs = Vec::new();
    let mut evidence = Vec::new();
    let mut profile = DependencyPackPreparationProfile::default();
    let mut cancelled = false;

    let dependency_limit = dependencies.len().min(limits.max_dependencies);
    if dependencies.len() > dependency_limit {
        diagnostics.error(
            "limit.dependencies",
            None,
            None,
            format!(
                "dependency count exceeds configured limit {}",
                limits.max_dependencies
            ),
        );
    }

    for dependency in &dependencies[..dependency_limit] {
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        profile.dependencies_considered += 1;
        let rejected = || DependencyPreparationFailure {
            dependency_id: dependency.id.clone(),
            cause: DependencyPreparationFailureCause::Rejected,
        };
        if dependency.id.is_empty() {
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            failures.push(rejected());
            continue;
        }
        if dependency.artifacts.is_empty() || !adapter.can_produce(dependency) {
            match resolve_declared_dependency_pack(
                catalog,
                dependency,
                cancellation,
                &mut diagnostics,
                &mut failures,
            ) {
                Ok(Some(installed)) => activate_installed_pack(
                    installed,
                    &mut evidence,
                    &mut installed_packs,
                    &mut profile,
                ),
                Ok(None) => {}
                Err(DeclaredPackCancelled) => {
                    cancelled = true;
                    break;
                }
            }
            continue;
        }
        if !dependency.evidence.verified_raw_artifacts.is_empty()
            || dependency.evidence.production_input_digest.is_some()
        {
            diagnostics.error(
                "dependency.artifact_evidence",
                Some(&dependency.id),
                None,
                "resolved dependency artifact digest must be supplied by preparation",
            );
            failures.push(rejected());
            continue;
        }
        if dependency
            .provenance
            .iter()
            .any(|entry| entry.key.is_empty() || entry.value.is_empty())
        {
            diagnostics.error(
                "dependency.provenance",
                Some(&dependency.id),
                None,
                "dependency provenance keys and values must not be empty",
            );
            failures.push(rejected());
            continue;
        }
        if dependency.artifacts.len() > limits.max_artifacts_per_dependency {
            diagnostics.error(
                "limit.artifacts_per_dependency",
                Some(&dependency.id),
                None,
                format!(
                    "dependency artifact count exceeds configured limit {}",
                    limits.max_artifacts_per_dependency
                ),
            );
            failures.push(rejected());
            continue;
        }

        let source_identity = dependency_source_identity(adapter, dependency, limits);
        if let Some(identity) = source_identity.as_ref() {
            let reusable = {
                let _scope = crate::profiling::scope("semantic_pack.lookup_source_identity");
                reusable_generated_pack_by_source_identity(
                    catalog,
                    &adapter.producer(),
                    adapter.production_schema_version(),
                    identity,
                    dependency,
                )
            };
            match reusable {
                Ok(Some(prepared)) => {
                    remember_dependency_source_identity(
                        catalog,
                        source_identity.as_ref(),
                        &prepared.production.key,
                        &dependency.id,
                        &mut diagnostics,
                    );
                    record_reused_generated_pack(
                        prepared,
                        dependency,
                        &mut diagnostics,
                        &mut evidence,
                        &mut packs,
                        &mut profile,
                    );
                    continue;
                }
                Ok(None) => {}
                Err(error) => diagnostics.warning(
                    "catalog.source_identity",
                    Some(&dependency.id),
                    format!(
                        "could not consult the read-free dependency identity, so its artifacts will be read: {error}"
                    ),
                ),
            }
        }

        if source_identity.is_none() && adapter.reuses_productions_by_pinned_key() {
            let reusable = {
                let _scope = crate::profiling::scope("semantic_pack.lookup_pinned_key");
                pinned_generated_production_key(adapter, dependency, limits).and_then(|key| {
                    key.map(|key| {
                        reusable_generated_pack(catalog, &key, dependency, key.input_digest(), None)
                    })
                    .transpose()
                    .map(Option::flatten)
                })
            };
            match reusable {
                Ok(Some(prepared)) => {
                    record_reused_generated_pack(
                        prepared,
                        dependency,
                        &mut diagnostics,
                        &mut evidence,
                        &mut packs,
                        &mut profile,
                    );
                    continue;
                }
                Ok(None) => {}
                Err(error) => diagnostics.warning(
                    "catalog.pinned_key",
                    Some(&dependency.id),
                    format!(
                        "could not consult the catalog under the pinned production key, so its artifacts will be read: {error}"
                    ),
                ),
            }
        }

        let artifact_read_scope = crate::profiling::scope("semantic_pack.read_exact_artifacts");
        let mut exact_artifacts = Vec::with_capacity(dependency.artifacts.len());
        for artifact in &dependency.artifacts {
            if is_cancelled(cancellation) {
                cancelled = true;
                break;
            }
            let remaining = limits
                .max_total_artifact_bytes
                .saturating_sub(profile.artifact_bytes_read);
            if remaining == 0 {
                diagnostics.error(
                    "limit.total_artifact_bytes",
                    Some(&dependency.id),
                    Some(artifact.path()),
                    format!(
                        "dependency artifacts exceed configured total of {} bytes",
                        limits.max_total_artifact_bytes
                    ),
                );
                break;
            }
            let mut artifact_limits = limits.producer;
            artifact_limits.max_artifact_bytes = artifact_limits.max_artifact_bytes.min(remaining);
            if artifact.expected_sha256.is_some()
                && !artifact
                    .path()
                    .canonicalize()
                    .is_ok_and(|path| path == artifact.path())
            {
                diagnostics.error(
                    "artifact.path_changed",
                    Some(&dependency.id),
                    Some(artifact.path()),
                    "dependency artifact path no longer resolves to the approved canonical file",
                );
                break;
            }
            let exact = match &artifact.input {
                ResolvedDependencyArtifactInput::File(path) => {
                    read_exact_artifact_while(path, &artifact_limits, || is_cancelled(cancellation))
                }
                ResolvedDependencyArtifactInput::SourceSet {
                    root,
                    relative_paths,
                } if artifact.kind
                    == crate::analyzer::semantic_model::ExternalArtifactKind::JdkJmodSet =>
                {
                    // JMODs can carry large native libraries that still belong
                    // to exact identity. Capture only this source set on disk;
                    // ordinary producers materialize bytes under their 256 MiB
                    // limit, while JMODs use the acquisition-total bound.
                    read_exact_source_set_seekable_while(
                        root,
                        relative_paths,
                        limits.max_source_files_per_artifact.min(512),
                        limits.max_source_path_depth,
                        remaining,
                        &artifact_limits,
                        || is_cancelled(cancellation),
                    )
                }
                ResolvedDependencyArtifactInput::SourceSet {
                    root,
                    relative_paths,
                } => read_exact_source_set_while(
                    root,
                    relative_paths,
                    limits.max_source_files_per_artifact,
                    limits.max_source_path_depth,
                    &artifact_limits,
                    || is_cancelled(cancellation),
                ),
            };
            match exact {
                Ok(exact) => {
                    if artifact
                        .expected_sha256
                        .as_deref()
                        .is_some_and(|expected| expected != exact.sha256())
                    {
                        diagnostics.error(
                            "artifact.digest_changed",
                            Some(&dependency.id),
                            Some(artifact.path()),
                            "dependency artifact digest changed after discovery",
                        );
                        break;
                    }
                    profile.artifacts_read += 1;
                    profile.artifact_bytes_read =
                        profile.artifact_bytes_read.saturating_add(exact.raw_len());
                    exact_artifacts.push(ExactDependencyArtifact {
                        role: artifact.role,
                        kind: artifact.kind,
                        module: artifact.module.clone(),
                        artifact: exact,
                    });
                }
                Err(diagnostic) => {
                    cancelled |= diagnostic.code == "artifact.cancelled";
                    diagnostics.producer(Some(&dependency.id), diagnostic);
                    break;
                }
            }
        }
        drop(artifact_read_scope);
        if cancelled {
            break;
        }
        if exact_artifacts.len() != dependency.artifacts.len() {
            failures.push(DependencyPreparationFailure {
                dependency_id: dependency.id.clone(),
                cause: DependencyPreparationFailureCause::Rejected,
            });
            continue;
        }
        let exact_go_source = match prepared_exact_go_source(dependency, &exact_artifacts) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "go.source_registration", error);
                failures.push(rejected());
                continue;
            }
        };
        let key = match generated_production_key(adapter, dependency, &exact_artifacts, limits) {
            Ok(key) => key,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "production.identity", error);
                failures.push(rejected());
                continue;
            }
        };
        let input_digest = key.input_digest().to_owned();
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        let reusable = {
            let _scope = crate::profiling::scope("semantic_pack.lookup_generated");
            reusable_generated_pack(
                catalog,
                &key,
                dependency,
                &input_digest,
                exact_go_source
                    .as_ref()
                    .map(|source| source.artifact.sha256()),
            )
        };
        match reusable {
            Ok(Some(prepared)) => {
                if !register_exact_source_for_reused_pack(
                    catalog,
                    dependency,
                    exact_go_source.as_ref(),
                    &prepared.production.manifest_digest,
                    &mut diagnostics,
                ) {
                    failures.push(rejected());
                    continue;
                }
                remember_dependency_source_identity(
                    catalog,
                    source_identity.as_ref(),
                    &prepared.production.key,
                    &dependency.id,
                    &mut diagnostics,
                );
                record_reused_generated_pack(
                    prepared,
                    dependency,
                    &mut diagnostics,
                    &mut evidence,
                    &mut packs,
                    &mut profile,
                );
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                failures.push(rejected());
                continue;
            }
        }

        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        let production_lock = match catalog.generated_production_lock(&key) {
            Ok(lock) => lock,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "production.lock", error);
                failures.push(rejected());
                continue;
            }
        };
        let lock_acquired = loop {
            if is_cancelled(cancellation) {
                cancelled = true;
                break false;
            }
            match production_lock.try_acquire() {
                Ok(true) => break true,
                Ok(false) => std::thread::sleep(GENERATED_PRODUCTION_LOCK_RETRY),
                Err(error) => {
                    diagnostics.catalog(Some(&dependency.id), "production.lock", error);
                    failures.push(rejected());
                    break false;
                }
            }
        };
        if !lock_acquired {
            if cancelled {
                break;
            }
            continue;
        }

        // Another process may have completed this exact production while this
        // process waited for the key-specific lock.
        let reusable = {
            let _scope = crate::profiling::scope("semantic_pack.lookup_generated_after_lock");
            reusable_generated_pack(
                catalog,
                &key,
                dependency,
                &input_digest,
                exact_go_source
                    .as_ref()
                    .map(|source| source.artifact.sha256()),
            )
        };
        match reusable {
            Ok(Some(prepared)) => {
                if !register_exact_source_for_reused_pack(
                    catalog,
                    dependency,
                    exact_go_source.as_ref(),
                    &prepared.production.manifest_digest,
                    &mut diagnostics,
                ) {
                    failures.push(rejected());
                    continue;
                }
                remember_dependency_source_identity(
                    catalog,
                    source_identity.as_ref(),
                    &prepared.production.key,
                    &dependency.id,
                    &mut diagnostics,
                );
                record_reused_generated_pack(
                    prepared,
                    dependency,
                    &mut diagnostics,
                    &mut evidence,
                    &mut packs,
                    &mut profile,
                );
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                failures.push(rejected());
                continue;
            }
        }

        if let Some(acquire) = semantic_pack_acquisition_hook() {
            if is_cancelled(cancellation) {
                cancelled = true;
                break;
            }
            let acquisition = {
                let _scope = crate::profiling::scope("semantic_pack.acquire_generated");
                acquire(catalog, &AcquisitionRequest::GeneratedProduction(&key))
            };
            if let Err(error) = acquisition {
                diagnostics.warning(
                    "production.acquire",
                    Some(&dependency.id),
                    format!("could not acquire exact generated production: {error}"),
                );
            }
            // The provider can only attempt installation. Re-read through the
            // ordinary verified catalog path before falling back to production.
            let reusable = {
                let _scope =
                    crate::profiling::scope("semantic_pack.lookup_generated_after_acquire");
                reusable_generated_pack(
                    catalog,
                    &key,
                    dependency,
                    &input_digest,
                    exact_go_source
                        .as_ref()
                        .map(|source| source.artifact.sha256()),
                )
            };
            match reusable {
                Ok(Some(prepared)) => {
                    if !register_exact_source_for_reused_pack(
                        catalog,
                        dependency,
                        exact_go_source.as_ref(),
                        &prepared.production.manifest_digest,
                        &mut diagnostics,
                    ) {
                        failures.push(rejected());
                        continue;
                    }
                    remember_dependency_source_identity(
                        catalog,
                        source_identity.as_ref(),
                        &prepared.production.key,
                        &dependency.id,
                        &mut diagnostics,
                    );
                    record_reused_generated_pack(
                        prepared,
                        dependency,
                        &mut diagnostics,
                        &mut evidence,
                        &mut packs,
                        &mut profile,
                    );
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                    failures.push(rejected());
                    continue;
                }
            }
        }

        let production = match compile_exact_dependency_production(
            adapter,
            dependency,
            &exact_artifacts,
            limits,
            cancellation,
        ) {
            Ok(production) => production,
            Err(failure) => {
                let was_cancelled = is_cancelled(cancellation)
                    || matches!(&failure, DependencyProductionFailure::Cancelled { .. });
                match failure {
                    DependencyProductionFailure::NoPack {
                        diagnostics: producer_diagnostics,
                        suppressed_diagnostics,
                    }
                    | DependencyProductionFailure::Cancelled {
                        diagnostics: producer_diagnostics,
                        suppressed_diagnostics,
                    } => {
                        diagnostics.suppressed += suppressed_diagnostics;
                        for diagnostic in producer_diagnostics {
                            diagnostics.producer(Some(&dependency.id), diagnostic);
                        }
                    }
                    DependencyProductionFailure::InvalidOutput {
                        code,
                        message,
                        diagnostics: producer_diagnostics,
                        suppressed_diagnostics,
                    } => {
                        diagnostics.suppressed += suppressed_diagnostics;
                        for diagnostic in producer_diagnostics {
                            diagnostics.producer(Some(&dependency.id), diagnostic);
                        }
                        diagnostics.error(&code, Some(&dependency.id), None, message);
                    }
                    DependencyProductionFailure::Compilation {
                        diagnostics: compiler_diagnostics,
                        producer_diagnostics,
                        suppressed_diagnostics,
                    } => {
                        diagnostics.suppressed += suppressed_diagnostics;
                        for diagnostic in producer_diagnostics {
                            diagnostics.producer(Some(&dependency.id), diagnostic);
                        }
                        for diagnostic in compiler_diagnostics {
                            diagnostics.error_location(
                                &diagnostic.code,
                                Some(&dependency.id),
                                Some(diagnostic.path),
                                diagnostic.message,
                            );
                        }
                    }
                }
                if was_cancelled {
                    cancelled = true;
                    break;
                }
                failures.push(DependencyPreparationFailure {
                    dependency_id: dependency.id.clone(),
                    cause: DependencyPreparationFailureCause::ProducerFailed,
                });
                continue;
            }
        };
        diagnostics.suppressed += production.suppressed_diagnostics;
        let production_has_diagnostics = !production.diagnostics.is_empty();
        for diagnostic in production.diagnostics.iter().cloned() {
            diagnostics.producer(Some(&dependency.id), diagnostic);
        }
        if production.completeness != Completeness::Complete && !production_has_diagnostics {
            diagnostics.error(
                "production.partial",
                Some(&dependency.id),
                None,
                "dependency producer returned partial semantic coverage",
            );
        }
        let install = {
            let _scope = crate::profiling::scope_with(|| {
                format!("semantic_pack.install[{}]", dependency.id)
            });
            match exact_go_source.as_ref() {
                Some(source) => catalog.install_generated_with_exact_go_source(
                    &production.key,
                    &production.compiled,
                    source.artifact,
                    &source.packages,
                    &verified_raw_slots(&exact_artifacts),
                ),
                None => catalog.install_generated(
                    &production.key,
                    &production.compiled,
                    &verified_raw_slots(&exact_artifacts),
                ),
            }
        };
        match install {
            Ok(installed) => {
                // Partial coverage belongs to the installed pack, not the set of
                // dependencies that could not prepare any usable pack.
                // The exact read has just proven this production for this
                // dependency, so this process also leaves behind the read-free
                // mapping that lets a later process find it without reading.
                remember_dependency_source_identity(
                    catalog,
                    source_identity.as_ref(),
                    &production.key,
                    &dependency.id,
                    &mut diagnostics,
                );
                let activation_evidence = activation_evidence(
                    dependency,
                    production.key.input_digest(),
                    &exact_artifacts,
                );
                evidence.push(activation_evidence.clone());
                packs.push(PreparedDependencyPack {
                    dependency_id: dependency.id.clone(),
                    production: installed.production,
                    status: DependencyPackPreparationStatus::Generated,
                    completeness: production.completeness,
                    evidence: activation_evidence,
                });
                profile.generated_packs += 1;
            }
            Err(error) => {
                failures.push(DependencyPreparationFailure {
                    dependency_id: dependency.id.clone(),
                    cause: DependencyPreparationFailureCause::Rejected,
                });
                diagnostics.catalog(Some(&dependency.id), "catalog.install", error);
            }
        }
    }

    if cancelled {
        diagnostics.error(
            "preparation.cancelled",
            None,
            None,
            "dependency semantic-pack preparation was cancelled",
        );
    }
    // The `complete` conjunction below refuses silently through its count-
    // mismatch arm when a dependency produced neither a generated pack nor an
    // installed pack (for example, a truncated tail past `max_dependencies`).
    // Name every such dependency before that arm folds it into a bare bool.
    let accounted_dependencies: HashSet<&str> = packs
        .iter()
        .map(|pack| pack.dependency_id.as_str())
        .chain(
            installed_packs
                .iter()
                .map(|pack| pack.dependency_id.as_str()),
        )
        .collect();
    let mut unserved_assumed = 0usize;
    for dependency in dependencies {
        if accounted_dependencies.contains(dependency.id.as_str()) {
            continue;
        }
        if dependency.is_assumed() {
            unserved_assumed += 1;
        } else {
            diagnostics.warning(
                "preparation.unaccounted-dependency",
                Some(&dependency.id),
                "dependency preparation produced neither a generated pack nor an installed pack",
            );
        }
    }
    let complete = !cancelled
        && failures.is_empty()
        && dependencies.len() <= limits.max_dependencies
        && packs
            .len()
            .saturating_add(installed_packs.len())
            .saturating_add(unserved_assumed)
            == dependencies.len()
        && packs
            .iter()
            .all(|pack| pack.completeness == Completeness::Complete)
        && installed_packs.iter().all(|pack| pack.activation_ready)
        && !diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DependencyPackDiagnosticSeverity::Error);
    crate::profiling::note_with(|| format!("semantic_pack.preparation_profile {profile:?}"));
    DependencyPackPreparationOutcome {
        failures,
        packs,
        installed_packs,
        evidence,
        diagnostics: diagnostics.diagnostics,
        suppressed_diagnostics: diagnostics.suppressed,
        complete,
        cancelled,
        profile,
    }
}

/// Select compatible trusted catalog packs for exact dependency coordinates
/// without reading dependency artifacts or producing generated packs.
///
/// This is the bounded preparation half of evidence-only discovery. A
/// dependency that has no compatible installed pack is an intentional no-op:
/// the mode asks which reviewed packs the catalog can serve, not for a complete
/// generated model of every dependency in the build. An activation-ready local
/// installation is trusted; a reviewed partial subset is trusted only from a
/// Bifrost-shipped source. Any untrusted matching local installation refuses
/// the dependency's evidence so it cannot piggyback when runtime queries the
/// coordinate again. Exact-version near misses remain visible as warnings,
/// while catalog failures make the preparation incomplete.
pub fn prepare_compatible_installed_semantic_packs(
    catalog: &SemanticPackCatalog,
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyPackPreparationOutcome {
    let mut diagnostics = catalog_diagnostics(catalog, limits);
    let mut failures = Vec::new();
    let mut installed_packs = Vec::new();
    let mut evidence = Vec::new();
    let mut profile = DependencyPackPreparationProfile::default();
    let mut cancelled = false;
    let mut failed = false;

    let dependency_limit = dependencies.len().min(limits.max_dependencies);
    if dependencies.len() > dependency_limit {
        failed = true;
        diagnostics.error(
            "limit.dependencies",
            None,
            None,
            format!(
                "dependency count exceeds configured limit {}",
                limits.max_dependencies
            ),
        );
    }

    for dependency in &dependencies[..dependency_limit] {
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        profile.dependencies_considered += 1;
        let rejected = || DependencyPreparationFailure {
            dependency_id: dependency.id.clone(),
            cause: DependencyPreparationFailureCause::Rejected,
        };
        if dependency.id.is_empty() {
            failed = true;
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            failures.push(rejected());
            continue;
        }
        if let Err(error) =
            record_obsolete_dependency_candidates(catalog, dependency, &mut diagnostics)
        {
            diagnostics.warning("catalog.revision_probe", Some(&dependency.id), format!("preliminary producer revision lookup failed; installed selection will retry: {error}"));
        }
        match compatible_curated_installed_pack(catalog, dependency) {
            Ok(Some(installed)) => activate_installed_pack(
                installed,
                &mut evidence,
                &mut installed_packs,
                &mut profile,
            ),
            Ok(None) => match installed_pack_query(dependency)
                .map(|query| catalog.version_near_misses(&query))
            {
                Some(Ok(near_misses)) => {
                    for near_miss in near_misses {
                        diagnostics.warning(
                            "dependency.pack_version_mismatch",
                            Some(&dependency.id),
                            near_miss.describe(),
                        );
                    }
                }
                Some(Err(error)) => {
                    failed = true;
                    failures.push(rejected());
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                }
                None => {}
            },
            Err(error) => {
                failed = true;
                failures.push(rejected());
                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            }
        }
    }

    if cancelled {
        failed = true;
        diagnostics.error(
            "preparation.cancelled",
            None,
            None,
            "dependency semantic-pack preparation was cancelled",
        );
    }
    // Curated evidence does not claim a complete model of each dependency.
    // Reviewed partial packs (for example, a declaration subset paired with a
    // complete behavior pack) are therefore useful compatible selections in
    // this mode even though full dependency production would refuse them.
    let complete = !failed && dependencies.len() <= limits.max_dependencies;
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    DependencyPackPreparationOutcome {
        failures,
        packs: Vec::new(),
        installed_packs,
        evidence,
        diagnostics,
        suppressed_diagnostics,
        complete,
        cancelled,
        profile,
    }
}

/// One dependency whose exact pack the installed-pack stage could not settle
/// from the catalog: acquisition (fetch, verification, extraction, or
/// generation from a local toolchain) remains for the full activation stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDependencyPackAcquisition {
    pub ecosystem: DependencyPackEcosystem,
    pub dependency_id: String,
}

/// The installed-pack stage of dependency preparation: resolve every
/// dependency against the packs already installed in this catalog without
/// reading dependency artifacts and without fetching, verifying, extracting,
/// or generating anything (issue #3401, the #3372 family).
///
/// A dependency the adapter cannot produce -- one that carries no artifact, or
/// one the adapter refuses -- resolves through the same local installed-pack
/// check the full stage's declared route runs, so an installed hit there is
/// final: the full stage would reach the same answer. A producible dependency
/// is always pending, because the full stage prefers exact production from the
/// local artifacts; an installed hit still serves the interim answer, but only
/// under the curated trust rule, so an untrusted local partial cannot decide
/// an answer the final activation would refuse.
/// The exception is a row whose adapter lets a reviewed pack supersede
/// production: the full stage selects that same pack, so the hit is final.
///
/// A dependency no installed pack settles is reported in `pending` rather than
/// diagnosed: nothing about it has failed, its acquisition simply has not run.
/// Catalog lookup failures are diagnosed and also leave the dependency
/// pending, so the full stage re-attempts and reports through its own outcome.
pub fn prepare_installed_dependency_packs(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> InstalledDependencyPackPreparation {
    let mut diagnostics = catalog_diagnostics(catalog, limits);
    let mut failures = Vec::new();
    let mut installed_packs = Vec::new();
    let mut evidence = Vec::new();
    let mut profile = DependencyPackPreparationProfile::default();
    let mut pending = Vec::new();
    let mut required_pending = false;
    let mut cancelled = false;
    let mut failed = false;

    let dependency_limit = dependencies.len().min(limits.max_dependencies);
    if dependencies.len() > dependency_limit {
        failed = true;
        diagnostics.error(
            "limit.dependencies",
            None,
            None,
            format!(
                "dependency count exceeds configured limit {}",
                limits.max_dependencies
            ),
        );
    }

    for dependency in &dependencies[..dependency_limit] {
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        profile.dependencies_considered += 1;
        let rejected = || DependencyPreparationFailure {
            dependency_id: dependency.id.clone(),
            cause: DependencyPreparationFailureCause::Rejected,
        };
        if dependency.id.is_empty() {
            failed = true;
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            failures.push(rejected());
            continue;
        }
        let mut settled = false;
        match selected_dependency_provider(catalog, adapter, dependency, limits).and_then(
            |choice| {
                record_dependency_candidate_findings(
                    catalog,
                    &dependency.id,
                    choice.findings,
                    &mut diagnostics,
                )?;
                for warning in &choice.warnings {
                    diagnostics.warning(
                        "installed.not-activation-ready",
                        Some(&dependency.id),
                        warning.clone(),
                    );
                }
                if choice.installed.is_some()
                    && !choice.has_complete_candidate
                    && (dependency.artifacts.is_empty() || !adapter.can_produce(dependency))
                    && let Some(query) = installed_pack_query(dependency)
                {
                    for near_miss in catalog.version_near_misses(&query)? {
                        diagnostics.warning(
                            "dependency.pack_version_mismatch",
                            Some(&dependency.id),
                            near_miss.describe(),
                        );
                    }
                }
                Ok((choice.installed, choice.settled))
            },
        ) {
            Ok((installed, is_settled)) => {
                settled = is_settled;
                if let Some(installed) = installed {
                    if is_settled && !installed.activation_ready {
                        // The pack is activated below either way. A curated
                        // selection is trusted without certified accounting;
                        // any other uncertified pack leaves the preparation
                        // incomplete, as its partial coverage does at the
                        // activation stage. It is never a failure record.
                        match selects_curated_dependency_pack(catalog, adapter, dependency) {
                            Ok(true) => {}
                            Ok(false) => failed = true,
                            Err(error) => {
                                failed = true;
                                settled = false;
                                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                            }
                        }
                    }
                    activate_installed_pack(
                        installed,
                        &mut evidence,
                        &mut installed_packs,
                        &mut profile,
                    );
                }
            }
            Err(error) => {
                failed = true;
                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            }
        }
        if !settled {
            // An assumed dependency still waits for acquisition, but its
            // absence does not make the preparation incomplete.
            required_pending |= !dependency.is_assumed();
            pending.push(dependency.id.clone());
        }
    }

    if cancelled {
        failed = true;
        diagnostics.error(
            "preparation.cancelled",
            None,
            None,
            "dependency semantic-pack preparation was cancelled",
        );
    }
    let complete = !failed && !cancelled && !required_pending && failures.is_empty();
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    InstalledDependencyPackPreparation {
        outcome: DependencyPackPreparationOutcome {
            failures,
            packs: Vec::new(),
            installed_packs,
            evidence,
            diagnostics,
            suppressed_diagnostics,
            complete,
            cancelled,
            profile,
        },
        pending,
    }
}

pub(crate) fn reusable_generated_pack(
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
    dependency: &ResolvedDependency,
    _input_digest: &str,
    _exact_source_sha256: Option<&str>,
) -> Result<Option<PreparedDependencyPack>, CatalogError> {
    let Some(production) = catalog.generated_production(key)? else {
        return Ok(None);
    };
    let Some(slots) = catalog.generated_input_slots(&production.key)? else {
        return Ok(None);
    };
    let mut evidence = dependency.evidence.clone();
    evidence.verified_raw_artifacts = slots;
    evidence.production_input_digest = Some(production.key.input_digest().to_owned());
    Ok(Some(PreparedDependencyPack {
        dependency_id: dependency.id.clone(),
        completeness: production.completeness,
        production,
        status: DependencyPackPreparationStatus::Reused,
        evidence,
    }))
}

/// The generated production a read-free dependency identity was learned under,
/// or `None` when this catalog has not learned that identity.
///
/// The identity names a candidate; the production itself still comes from the
/// fully verified key lookup, so a row that outlives its pack, or one recorded
/// at another cache epoch, reads as an ordinary miss.
pub(crate) fn reusable_generated_pack_by_source_identity(
    catalog: &SemanticPackCatalog,
    producer: &Producer,
    schema_version: u32,
    identity: &DependencySourceIdentity,
    dependency: &ResolvedDependency,
) -> Result<Option<PreparedDependencyPack>, CatalogError> {
    let Some(production) = catalog.generated_production_by_source_identity(
        identity.as_str(),
        producer,
        schema_version,
    )?
    else {
        return Ok(None);
    };
    let Some(slots) = catalog.generated_input_slots(&production.key)? else {
        return Ok(None);
    };
    let mut evidence = dependency.evidence.clone();
    evidence.verified_raw_artifacts = slots;
    evidence.production_input_digest = Some(production.key.input_digest().to_owned());
    Ok(Some(PreparedDependencyPack {
        dependency_id: dependency.id.clone(),
        completeness: production.completeness,
        production,
        status: DependencyPackPreparationStatus::Reused,
        evidence,
    }))
}

/// Record the read-free identity under which `key`'s production was observed.
///
/// The mapping is a pure accelerator: it only lets a later process skip the
/// read that would otherwise recompute the same key. A read-only catalog, or a
/// failure to write the row, therefore costs a diagnostic and not a missed
/// pack, and preparation carries on with the read it has already done.
pub(crate) fn remember_dependency_source_identity(
    catalog: &SemanticPackCatalog,
    identity: Option<&DependencySourceIdentity>,
    key: &GeneratedProductionKey,
    dependency_id: &str,
    diagnostics: &mut BoundedDependencyDiagnostics,
) {
    let Some(identity) = identity else {
        return;
    };
    if !catalog.is_writable() {
        return;
    }
    if let Err(error) = catalog.install_generated_source_identity(identity.as_str(), key) {
        diagnostics.warning(
            "catalog.source_identity",
            Some(dependency_id),
            format!(
                "could not record the read-free dependency identity, so a later process will read its artifacts again: {error}"
            ),
        );
    }
}

/// Resolve one dependency that preparation cannot produce locally, either
/// because it carries no artifact or because the adapter refuses it.
///
/// A declared toolchain dependency, such as the CPython version a
/// `pyproject.toml` requires or the PHP version a `composer.json` requires, is
/// the shape that has no artifact at all: nothing about it can form a
/// generated-production key, so the exact-production acquisition route can
/// never reach it (#2957). The acquisition hook is therefore offered the
/// evidence-only selector query instead, and, exactly as on the generated
/// route, the provider can only attempt installation: the catalog is re-read
/// through the ordinary verified path afterwards.
pub(crate) fn resolve_declared_dependency_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedDependencyDiagnostics,
    failures: &mut Vec<DependencyPreparationFailure>,
) -> Result<Option<PreparedInstalledDependencyPack>, DeclaredPackCancelled> {
    let rejected = || DependencyPreparationFailure {
        dependency_id: dependency.id.clone(),
        cause: DependencyPreparationFailureCause::Rejected,
    };
    match compatible_installed_pack(catalog, dependency, diagnostics) {
        Ok(Some(installed)) => return Ok(Some(installed)),
        Ok(None) => {}
        Err(error) => {
            failures.push(rejected());
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            return Ok(None);
        }
    }

    // An assumed dependency is the engine's guess, not the workspace's
    // statement, so no pack serving it is no defect to report: the pack is
    // offered to the acquisition hook and otherwise simply not selected.
    let assumed = dependency.is_assumed();
    let unavailable = |diagnostics: &mut BoundedDependencyDiagnostics,
                       failures: &mut Vec<DependencyPreparationFailure>| {
        if !assumed {
            failures.push(DependencyPreparationFailure {
                dependency_id: dependency.id.clone(),
                cause: DependencyPreparationFailureCause::PackUnavailable,
            });
            diagnostics.error(
                "dependency.pack_unavailable",
                Some(&dependency.id),
                None,
                PACK_UNAVAILABLE_MESSAGE,
            );
        }
    };

    // No usable pack. Distinguish "a pack exists for another version of this
    // exact coordinate" from "no pack at all": the near miss names the
    // installed and required versions so a version mismatch is attributable,
    // never silent (#1884). A near miss is also not an acquisition case: the
    // release bundle already supplied a pack for this coordinate, and the
    // version the workspace declares is what does not match.
    let Some(query) = installed_pack_query(dependency) else {
        unavailable(diagnostics, failures);
        return Ok(None);
    };
    let near_misses = match catalog.version_near_misses(&query) {
        Ok(near_misses) => near_misses,
        Err(error) => {
            failures.push(rejected());
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            return Ok(None);
        }
    };
    if !near_misses.is_empty() && !assumed {
        failures.push(DependencyPreparationFailure {
            dependency_id: dependency.id.clone(),
            cause: DependencyPreparationFailureCause::Rejected,
        });
        for near_miss in near_misses {
            diagnostics.error(
                "dependency.pack_version_mismatch",
                Some(&dependency.id),
                None,
                near_miss.describe(),
            );
        }
        return Ok(None);
    }

    let Some(acquire) = semantic_pack_acquisition_hook() else {
        unavailable(diagnostics, failures);
        return Ok(None);
    };
    if is_cancelled(cancellation) {
        return Err(DeclaredPackCancelled);
    }
    let acquisition = {
        let _scope = crate::profiling::scope("semantic_pack.acquire_declared");
        acquire(catalog, &AcquisitionRequest::DeclaredPack(&query))
    };
    if let Err(error) = acquisition {
        diagnostics.warning(
            "dependency.acquire",
            Some(&dependency.id),
            format!("could not acquire declared dependency semantic pack: {error}"),
        );
    }
    if is_cancelled(cancellation) {
        return Err(DeclaredPackCancelled);
    }
    match compatible_installed_pack(catalog, dependency, diagnostics) {
        Ok(Some(installed)) => Ok(Some(installed)),
        Ok(None) => {
            unavailable(diagnostics, failures);
            Ok(None)
        }
        Err(error) => {
            failures.push(rejected());
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            Ok(None)
        }
    }
}

/// All compatible manifests are kept in ascending digest order, deduplicated.
/// Curated providers may be retained without settling a producible dependency.
/// Findings are data: only the live acquisition caller applies their actions.
pub(crate) fn selected_dependency_provider(
    reads: &impl DependencyProviderReads,
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    limits: &DependencyPackLimits,
) -> Result<DependencyProviderChoice, CatalogError> {
    let (mut candidates, findings) = installed_candidates(reads, dependency)?;
    let producible = !dependency.artifacts.is_empty() && adapter.can_produce(dependency);
    if producible {
        retain_curated_candidates(&mut candidates);
    } else {
        retain_installed_candidates(&mut candidates);
    }
    let warnings = if producible {
        Vec::new()
    } else {
        candidates
            .iter()
            .filter(|candidate| !candidate.activation_ready)
            .map(|candidate| candidate.not_activation_ready.clone())
            .collect()
    };
    let has_complete_candidate = candidates
        .iter()
        .any(|candidate| candidate.completeness == Completeness::Complete);
    let installed = prepared_installed_pack(dependency, &candidates);
    let settled = installed.is_some()
        && (!producible || adapter.reviewed_pack_supersedes_production(dependency));
    let production = if settled || !producible {
        None
    } else {
        pinned_generated_production_key(adapter, dependency, limits)?
    };
    Ok(DependencyProviderChoice {
        installed,
        settled,
        production,
        findings,
        warnings,
        has_complete_candidate,
    })
}

pub struct DependencyProviderChoice {
    pub installed: Option<PreparedInstalledDependencyPack>,
    pub settled: bool,
    /// Exact production key for an unsettled, producible dependency when its
    /// artifacts are pinned. Otherwise the request retains its existing
    /// source-identity or missing-production expectation when `settled` is false.
    pub production: Option<GeneratedProductionKey>,
    pub findings: Vec<(String, CatalogError)>,
    warnings: Vec<String>,
    has_complete_candidate: bool,
}

pub(crate) fn compatible_installed_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> Result<Option<PreparedInstalledDependencyPack>, CatalogError> {
    let Some((installed, not_activation_ready, has_complete_candidate)) =
        compatible_installed_pack_evaluation(catalog, dependency)?
    else {
        return Ok(None);
    };
    for message in not_activation_ready {
        diagnostics.warning(
            "installed.not-activation-ready",
            Some(&dependency.id),
            message,
        );
    }
    if !has_complete_candidate && let Some(query) = installed_pack_query(dependency) {
        for near_miss in catalog.version_near_misses(&query)? {
            diagnostics.warning(
                "dependency.pack_version_mismatch",
                Some(&dependency.id),
                near_miss.describe(),
            );
        }
    }
    Ok(Some(installed))
}

pub(crate) fn compatible_installed_pack_evaluation(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Option<(PreparedInstalledDependencyPack, Vec<String>, bool)>, CatalogError> {
    let mut candidates = compatible_installed_pack_candidates(catalog, dependency)?;
    // This route acquires a pack when no installation serves the coordinate.
    // A reviewed workspace model is not an installation, so it neither stands
    // in for that acquisition nor answers as the coordinate's pack here.
    retain_installed_candidates(&mut candidates);
    let has_complete_candidate = candidates
        .iter()
        .any(|candidate| candidate.completeness == Completeness::Complete);
    let not_activation_ready = candidates
        .iter()
        .filter(|candidate| !candidate.activation_ready)
        .map(|candidate| candidate.not_activation_ready.clone())
        .collect();
    Ok(prepared_installed_pack(dependency, &candidates)
        .map(|installed| (installed, not_activation_ready, has_complete_candidate)))
}

/// Curated partial declaration subsets are trusted only when Bifrost shipped
/// them or the repository checked them in as reviewed workspace models (whose
/// presence is the opt-in, and whose review gate still applies at activation).
/// A locally installed partial pack still needs the ordinary extraction
/// accounting that makes it activation-ready; curated evidence must not turn
/// an arbitrary partial installation into trusted semantics.
pub(crate) fn compatible_curated_installed_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Option<PreparedInstalledDependencyPack>, CatalogError> {
    let mut candidates = compatible_installed_pack_candidates(catalog, dependency)?;
    retain_curated_candidates(&mut candidates);
    Ok(prepared_installed_pack(dependency, &candidates))
}

fn retain_installed_candidates(candidates: &mut Vec<InstalledPackCandidateEvaluation>) {
    candidates
        .retain(|candidate| candidate.source_kind != CatalogPackSourceKind::EphemeralWorkspace);
}

fn retain_curated_candidates(candidates: &mut Vec<InstalledPackCandidateEvaluation>) {
    if candidates.iter().any(|candidate| {
        !candidate.activation_ready && candidate.source_kind == CatalogPackSourceKind::Installed
    }) {
        candidates.clear();
        return;
    }
    candidates.retain(|candidate| {
        candidate.activation_ready
            || matches!(
                candidate.source_kind,
                CatalogPackSourceKind::PreShipped
                    | CatalogPackSourceKind::Embedded
                    | CatalogPackSourceKind::EphemeralWorkspace
            )
    });
}

#[derive(Debug)]
pub(crate) struct InstalledPackCandidateEvaluation {
    manifest_digest: String,
    completeness: Completeness,
    gaps: usize,
    activation_ready: bool,
    source_kind: CatalogPackSourceKind,
    not_activation_ready: String,
}

pub(crate) fn compatible_installed_pack_candidates(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Vec<InstalledPackCandidateEvaluation>, CatalogError> {
    let (candidates, findings) = installed_candidates(catalog, dependency)?;
    catalog.apply_candidate_findings(findings)?;
    Ok(candidates)
}

fn installed_candidates(
    reads: &impl DependencyProviderReads,
    dependency: &ResolvedDependency,
) -> Result<CandidateSelection<InstalledPackCandidateEvaluation>, CatalogError> {
    let Some(query) = installed_pack_query(dependency) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut candidates = Vec::new();
    let mut accounted_manifests: HashSet<String> = set_with_capacity(4);
    let (selected, findings) = reads.provider_candidates(&query)?;
    for candidate in selected {
        if !matches!(
            candidate.source_kind(),
            CatalogPackSourceKind::Installed
                | CatalogPackSourceKind::PreShipped
                | CatalogPackSourceKind::Embedded
                | CatalogPackSourceKind::EphemeralWorkspace
        ) {
            continue;
        }
        if accounted_manifests.insert(candidate.manifest_digest().to_owned()) {
            let extraction = reads.provider_extraction(candidate.manifest_digest())?;
            let candidate_ready = crate::analyzer::semantic_model::pack_is_activation_ready(
                candidate.completeness(),
                extraction.as_ref(),
            );
            candidates.push(InstalledPackCandidateEvaluation {
                manifest_digest: candidate.manifest_digest().to_owned(),
                completeness: candidate.completeness(),
                gaps: extraction
                    .as_ref()
                    .map_or(0, |accounting| accounting.gaps.len()),
                activation_ready: candidate_ready,
                source_kind: candidate.source_kind(),
                not_activation_ready: if candidate_ready {
                    String::new()
                } else {
                    describe_not_activation_ready(&candidate, extraction.as_ref())
                },
            });
        }
    }
    Ok((candidates, findings))
}

pub(crate) fn prepared_installed_pack(
    dependency: &ResolvedDependency,
    candidates: &[InstalledPackCandidateEvaluation],
) -> Option<PreparedInstalledDependencyPack> {
    if candidates.is_empty() {
        return None;
    }
    let mut manifest_digests = candidates
        .iter()
        .map(|candidate| candidate.manifest_digest.clone())
        .collect::<Vec<_>>();
    manifest_digests.sort();
    manifest_digests.dedup();
    Some(PreparedInstalledDependencyPack {
        dependency_id: dependency.id.clone(),
        manifest_digests,
        completeness: if candidates
            .iter()
            .all(|candidate| candidate.completeness == Completeness::Complete)
        {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        gaps: candidates.iter().map(|candidate| candidate.gaps).sum(),
        activation_ready: candidates
            .iter()
            .all(|candidate| candidate.activation_ready),
        evidence: dependency.evidence.clone(),
    })
}

/// Explain why one installed candidate is not activation-ready. This is only
/// called when `pack_is_activation_ready` returned false, which requires
/// `completeness != Complete`, so the accounting breakdown is the only
/// variable part.
pub(crate) fn describe_not_activation_ready(
    candidate: &CatalogCandidate,
    extraction: Option<&PackExtractionAccounting>,
) -> String {
    let reason = match extraction {
        None => "no extraction accounting".to_owned(),
        Some(accounting) if accounting.suppressed_reject_count != 0 => format!(
            "suppressed rejects {} != 0",
            accounting.suppressed_reject_count
        ),
        Some(accounting) if accounting.error_reject_count != 0 => {
            format!("error rejects {} != 0", accounting.error_reject_count)
        }
        Some(accounting) => format!(
            "accounted rejects {} (declaration gaps {}, source entries {}) != reject count {}",
            accounting.gaps.len() + accounting.source_entries.len(),
            accounting.gaps.len(),
            accounting.source_entries.len(),
            accounting.reject_count
        ),
    };
    format!(
        "installed pack source {} manifest {} completeness {:?} is not activation-ready: {reason}",
        candidate.source_id(),
        candidate.manifest_digest(),
        candidate.completeness(),
    )
}

pub fn prepare_discovered_dependency_semantic_packs(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    discovery: DependencyDiscoveryOutcome,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyPackPreparationOutcome {
    let mut outcome = prepare_dependency_semantic_packs(
        catalog,
        adapter,
        &discovery.dependencies,
        limits,
        cancellation,
    );
    // Merge through the bounded collector rather than truncating the joined
    // list. Discovery diagnostics arrive first, so a plain truncation drops
    // the preparation errors that decided the outcome.
    let mut merged = BoundedDependencyDiagnostics::new(limits);
    for diagnostic in discovery
        .diagnostics
        .into_iter()
        .chain(outcome.diagnostics.drain(..))
    {
        merged.push(diagnostic);
    }
    let (diagnostics, merge_suppressed) = merged.finish();
    outcome.suppressed_diagnostics += merge_suppressed;
    outcome.suppressed_diagnostics += discovery.suppressed_diagnostics;
    outcome.complete &= discovery.complete;
    outcome.cancelled |= discovery.cancelled;
    outcome.diagnostics = diagnostics;
    outcome
}

#[cfg(test)]
pub(crate) mod declared_pack_acquisition_tests {
    use super::test_support::*;

    use brokk_bifrost_analysis::analyzer::semantic_model::model::Completeness;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnosticSeverity;

    use brokk_bifrost_analysis::analyzer::semantic::topology::DependencyScope;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependency;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use brokk_bifrost_analysis::analyzer::semantic_model::dependency::set_semantic_pack_acquisition_hook;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

    use semver::Version;

    /// The exact shape `declared_python_stdlib_dependency` produces for a
    /// `pyproject.toml` that states `requires-python = ">=3.10"`: a toolchain
    /// coordinate and no artifact at all, so no generated-production key can
    /// ever be formed for it (#2957).
    fn declared_python_dependency() -> ResolvedDependency {
        ResolvedDependency {
            id: "python:stdlib:declared:cpython:3.10.0".to_owned(),
            evidence: SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
                package: None,
                module: None,
                toolchain: Some(CatalogCoordinate {
                    name: "cpython".to_owned(),
                    version: Some(Version::new(3, 10, 0)),
                }),
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            },
            provenance: Vec::new(),
            artifacts: Vec::new(),
            scope: DependencyScope::Unknown,
            declared_by: None,
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: early terminal rejections vanished when diagnostics were suppressed"
    )]
    fn terminal_records_survive_suppression_but_exclude_unattempted_work() {
        use super::*;
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut dependency = declared_python_dependency();
        dependency.artifacts.push(ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Sources,
            crate::analyzer::semantic_model::ExternalArtifactKind::PythonSource,
            root.path().join("not-read.py"),
        ));
        let mut limits = DependencyPackLimits {
            max_artifacts_per_dependency: 0,
            max_diagnostics: 0,
            ..Default::default()
        };
        let live = CancellationToken::default();
        for invalid_provenance in [false, true] {
            if invalid_provenance {
                limits.max_artifacts_per_dependency = 1;
                dependency.provenance.push(DependencyProvenance {
                    key: String::new(),
                    value: "invalid".into(),
                });
            }
            let outcome = prepare_dependency_semantic_packs(
                &catalog,
                &NeverProducingAdapter,
                std::slice::from_ref(&dependency),
                &limits,
                Some(&live),
            );
            assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
            assert_eq!(
                outcome.failures,
                vec![DependencyPreparationFailure {
                    dependency_id: dependency.id.clone(),
                    cause: DependencyPreparationFailureCause::Rejected,
                }]
            );
        }
        limits.max_dependencies = 0;
        let unattempted = prepare_dependency_semantic_packs(
            &catalog,
            &NeverProducingAdapter,
            std::slice::from_ref(&dependency),
            &limits,
            Some(&live),
        );
        assert!(unattempted.failures.is_empty(), "{unattempted:#?}");
        limits.max_dependencies = 1;
        live.cancel();
        let cancelled = prepare_dependency_semantic_packs(
            &catalog,
            &NeverProducingAdapter,
            &[dependency],
            &limits,
            Some(&live),
        );
        assert!(cancelled.cancelled);
        assert!(cancelled.failures.is_empty(), "{cancelled:#?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: cancellation inside a NoPack producer was recorded as terminal failure"
    )]
    fn cancelled_no_pack_producer_records_no_failure() {
        use super::*;
        struct CancellingProducer;
        impl DependencyPackAdapter for CancellingProducer {
            fn adapter_name(&self) -> &str {
                "cancelled-fixture"
            }
            fn adapter_version(&self) -> &str {
                "1"
            }
            fn producer(&self) -> Producer {
                NeverProducingAdapter.producer()
            }
            fn produce(
                &self,
                _: &ResolvedDependency,
                _: &[ExactDependencyArtifact],
                _: &crate::analyzer::semantic_model::producer::ArtifactProducerLimits,
                cancellation: Option<&CancellationToken>,
            ) -> DependencyPackProduction {
                if let Some(cancellation) = cancellation {
                    cancellation.cancel();
                }
                DependencyPackProduction {
                    pack: None,
                    diagnostics: Vec::new(),
                    suppressed_diagnostics: Default::default(),
                }
            }
        }
        let _fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("types.pyi");
        std::fs::write(&path, "class NoneType: ...\n").unwrap();
        let mut dependency = declared_python_dependency();
        dependency.artifacts.push(ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Declarations,
            crate::analyzer::semantic_model::ExternalArtifactKind::PythonSource,
            path,
        ));
        let terminal = prepare_dependency_semantic_packs(
            &catalog,
            &CancellingProducer,
            std::slice::from_ref(&dependency),
            &Default::default(),
            None,
        );
        assert!(!terminal.complete, "{terminal:#?}");
        assert!(!terminal.cancelled, "{terminal:#?}");
        assert!(terminal.packs.is_empty(), "{terminal:#?}");
        assert_eq!(
            terminal.failures,
            vec![super::DependencyPreparationFailure {
                dependency_id: dependency.id.clone(),
                cause: super::DependencyPreparationFailureCause::ProducerFailed,
            }]
        );
        let cancellation = CancellationToken::default();
        let outcome = prepare_dependency_semantic_packs(
            &catalog,
            &CancellingProducer,
            &[dependency],
            &Default::default(),
            Some(&cancellation),
        );
        assert!(
            cancellation.is_cancelled(),
            "producer must have been invoked"
        );
        assert!(outcome.cancelled, "{outcome:#?}");
        assert!(!outcome.complete, "{outcome:#?}");
        assert!(outcome.failures.is_empty(), "{outcome:#?}");
        assert!(outcome.packs.is_empty(), "{outcome:#?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "68cfca6ab74a+f728c64932b3: an unusable installed pack had no terminal preparation record, and then an activated uncertified pack was also recorded as quarantined"
    )]
    fn uncertified_installed_pack_is_active_and_not_a_failure() {
        let fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let partial = CPYTHON_PACK.replacen(
            "\"completeness\": \"complete\"",
            "\"completeness\": \"partial\"",
            1,
        );
        install_fixture_pack(&catalog, &compiled_pack(&partial)).unwrap();
        let outcome = prepare(&catalog, declared_python_dependency());
        assert!(fixture.requests().is_empty());
        // The pack is installed and activated, so it is not a failure. Its
        // uncertified accounting still leaves the preparation incomplete.
        assert!(!outcome.installed_packs[0].activation_ready);
        assert_eq!(
            outcome.installed_packs[0].completeness,
            Completeness::Partial
        );
        assert_eq!(outcome.evidence.len(), 1, "{outcome:#?}");
        assert!(outcome.failures.is_empty(), "{outcome:#?}");
        assert!(!outcome.complete, "{outcome:#?}");
        let installed_only = super::prepare_installed_dependency_packs(
            &catalog,
            &NeverProducingAdapter,
            &[declared_python_dependency()],
            &Default::default(),
            None,
        );
        assert!(installed_only.pending.is_empty(), "{installed_only:#?}");
        assert!(!installed_only.outcome.complete, "{installed_only:#?}");
        assert!(
            installed_only.outcome.failures.is_empty(),
            "{installed_only:#?}"
        );
        assert_eq!(installed_only.outcome.evidence, outcome.evidence);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "cbc09cd693b2: usable partial packs were incorrectly classified as preparation failures"
    )]
    fn partial_generated_and_reused_packs_have_no_preparation_failure() {
        use super::*;
        struct PartialProducer;
        impl DependencyPackAdapter for PartialProducer {
            fn adapter_name(&self) -> &str {
                "partial-fixture"
            }
            fn adapter_version(&self) -> &str {
                "1"
            }
            fn production_schema_version(&self) -> u32 {
                crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            }
            fn producer(&self) -> Producer {
                Producer {
                    name: "bifrost-fixture".into(),
                    version: "1.0.0".into(),
                }
                .with_dependency_revision()
            }
            fn produce(
                &self,
                _: &ResolvedDependency,
                _: &[ExactDependencyArtifact],
                _: &crate::analyzer::semantic_model::producer::ArtifactProducerLimits,
                _: Option<&CancellationToken>,
            ) -> DependencyPackProduction {
                let mut pack: crate::analyzer::semantic_model::AuthoredSemanticModelPack =
                    serde_json::from_str(CPYTHON_PACK).unwrap();
                pack.schema_version =
                    crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION;
                pack.compatibility.bifrost = None;
                pack.producer = self.producer();
                pack.completeness = Completeness::Partial;
                DependencyPackProduction {
                    pack: Some(pack),
                    diagnostics: Vec::new(),
                    suppressed_diagnostics: Default::default(),
                }
            }
        }
        let _fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("types.pyi");
        std::fs::write(&path, "class NoneType: ...\n").unwrap();
        let mut dependency = declared_python_dependency();
        dependency.artifacts.push(ResolvedDependencyArtifact::file(
            DependencyArtifactRole::Declarations,
            crate::analyzer::semantic_model::ExternalArtifactKind::PythonSource,
            path,
        ));
        let limits = DependencyPackLimits {
            max_diagnostics: 0,
            ..Default::default()
        };
        for status in [
            DependencyPackPreparationStatus::Generated,
            DependencyPackPreparationStatus::Reused,
        ] {
            let outcome = prepare_dependency_semantic_packs(
                &catalog,
                &PartialProducer,
                std::slice::from_ref(&dependency),
                &limits,
                None,
            );
            assert!(!outcome.complete, "{outcome:#?}");
            assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
            assert_eq!(outcome.packs.len(), 1, "{outcome:#?}");
            assert_eq!(outcome.packs[0].status, status);
            assert!(outcome.failures.is_empty(), "{outcome:#?}");
            assert_eq!(outcome.packs[0].completeness, Completeness::Partial);
            // Read back the installed manifest, rather than the producer's
            // transient completeness: dependency gaps rely on this content.
            let inventory = catalog.inventory_bounded(1).unwrap();
            assert!(inventory.complete);
            assert_eq!(inventory.packs.len(), 1);
            assert_eq!(inventory.packs[0].completeness, Completeness::Partial);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: installed preparation quarantined accepted trusted partial packs"
    )]
    fn trusted_partial_packs_agree_between_preparation_stages() {
        use super::*;
        struct CuratedAdapter;
        impl DependencyPackAdapter for CuratedAdapter {
            fn adapter_name(&self) -> &str {
                "curated-fixture"
            }
            fn adapter_version(&self) -> &str {
                "1"
            }
            fn producer(&self) -> Producer {
                NeverProducingAdapter.producer()
            }
            fn installed_packs_only(&self, dependency: &ResolvedDependency) -> bool {
                dependency.artifacts.is_empty()
            }
            fn reviewed_pack_supersedes_production(&self, _: &ResolvedDependency) -> bool {
                true
            }
            fn produce(
                &self,
                _: &ResolvedDependency,
                _: &[ExactDependencyArtifact],
                _: &crate::analyzer::semantic_model::producer::ArtifactProducerLimits,
                _: Option<&CancellationToken>,
            ) -> DependencyPackProduction {
                unimplemented!("the curated provider settles this dependency")
            }
        }
        let _fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let partial = CPYTHON_PACK.replacen(
            "\"completeness\": \"complete\"",
            "\"completeness\": \"partial\"",
            1,
        );
        install_fixture_pack(&catalog, &compiled_pack(&partial)).unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut dependency = declared_python_dependency();
        for artifacts in [
            Vec::new(),
            vec![ResolvedDependencyArtifact::file(
                DependencyArtifactRole::Declarations,
                crate::analyzer::semantic_model::ExternalArtifactKind::PythonSource,
                root.path().join("not-read.pyi"),
            )],
        ] {
            dependency.artifacts = artifacts;
            let full = prepare_dependency_semantic_packs(
                &catalog,
                &CuratedAdapter,
                std::slice::from_ref(&dependency),
                &Default::default(),
                None,
            );
            let preliminary = prepare_installed_dependency_packs(
                &catalog,
                &CuratedAdapter,
                std::slice::from_ref(&dependency),
                &Default::default(),
                None,
            );
            assert!(full.complete, "{full:#?}");
            assert!(preliminary.outcome.complete, "{preliminary:#?}");
            assert!(full.failures.is_empty(), "{full:#?}");
            assert!(preliminary.outcome.failures.is_empty(), "{preliminary:#?}");
            assert!(preliminary.pending.is_empty(), "{preliminary:#?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: retryable installed-stage catalog errors were recorded as terminal"
    )]
    fn preliminary_lookup_error_remains_pending_until_full_preparation_retries() {
        use super::*;
        let _fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        install_fixture_pack(&catalog, &compiled_pack(CPYTHON_PACK)).unwrap();
        catalog
            .connection
            .lock()
            .unwrap()
            .execute_batch("ALTER TABLE catalog_packs RENAME TO temporarily_unavailable_packs")
            .unwrap();
        let dependency = declared_python_dependency();
        let preliminary = prepare_installed_dependency_packs(
            &catalog,
            &NeverProducingAdapter,
            std::slice::from_ref(&dependency),
            &Default::default(),
            None,
        );
        assert!(!preliminary.outcome.complete, "{preliminary:#?}");
        assert!(
            !preliminary.outcome.diagnostics.is_empty(),
            "{preliminary:#?}"
        );
        assert!(preliminary.outcome.failures.is_empty(), "{preliminary:#?}");
        assert_eq!(preliminary.pending, vec![dependency.id.clone()]);
        catalog
            .connection
            .lock()
            .unwrap()
            .execute_batch("ALTER TABLE temporarily_unavailable_packs RENAME TO catalog_packs")
            .unwrap();
        let full = prepare(&catalog, dependency);
        assert!(full.complete, "{full:#?}");
        assert!(full.failures.is_empty(), "{full:#?}");
    }

    // Independent SHA-256 of the v1 source-set frame for api.go and GO_SOURCE,
    // calculated with Python hashlib rather than the producer's hashing helper.

    #[test]
    fn artifact_less_dependency_without_an_installed_pack_reaches_the_hook_once() {
        let fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        assert_eq!(fixture.requests(), vec!["declared:python:cpython@3.10.0"]);
        assert_eq!(outcome.installed_packs.len(), 0);
        assert_eq!(
            outcome.failures,
            vec![super::DependencyPreparationFailure {
                dependency_id: declared_python_dependency().id,
                cause: super::DependencyPreparationFailureCause::PackUnavailable,
            }]
        );
        assert_eq!(
            brokk_bifrost_analysis::analyzer::semantic_model::dependency::diagnostic_codes(
                &outcome.diagnostics
            ),
            vec![
                "dependency.pack_unavailable",
                "preparation.unaccounted-dependency"
            ]
        );
    }

    #[test]
    fn an_installed_compatible_pack_never_reaches_the_hook() {
        let fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        install_fixture_pack(&catalog, &compiled_pack(CPYTHON_PACK)).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        assert!(fixture.requests().is_empty());
        assert_eq!(outcome.installed_packs.len(), 1);
        assert!(outcome.failures.is_empty(), "{outcome:#?}");
        assert!(outcome.diagnostics.is_empty(), "{:#?}", outcome.diagnostics);
    }

    #[test]
    fn a_version_near_miss_never_reaches_the_hook() {
        let fixture = HookFixture::install(HookBehavior::RecordOnly);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let narrowed = CPYTHON_PACK.replace(">=3.10.0, <3.15.0", "=3.13.0");
        install_fixture_pack(&catalog, &compiled_pack(&narrowed)).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        assert!(fixture.requests().is_empty());
        assert_eq!(outcome.installed_packs.len(), 0);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::semantic_model::dependency::diagnostic_codes(
                &outcome.diagnostics
            ),
            vec![
                "dependency.pack_version_mismatch",
                "preparation.unaccounted-dependency"
            ]
        );
    }

    #[test]
    fn a_hook_that_installs_the_pack_yields_an_installed_dependency_pack() {
        let fixture = HookFixture::install(HookBehavior::Install);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        assert_eq!(fixture.requests(), vec!["declared:python:cpython@3.10.0"]);
        assert!(outcome.diagnostics.is_empty(), "{:#?}", outcome.diagnostics);
        assert_eq!(outcome.profile.installed_packs, 1);
        assert_eq!(outcome.installed_packs.len(), 1);
        let installed = &outcome.installed_packs[0];
        assert!(installed.activation_ready);
        assert_eq!(installed.completeness, Completeness::Complete);
        assert_eq!(
            installed.evidence,
            declared_python_dependency().evidence,
            "the installed pack carries the declared dependency's activation evidence"
        );
        assert_eq!(
            outcome.evidence,
            vec![declared_python_dependency().evidence]
        );
    }

    #[test]
    fn a_failed_acquisition_warns_and_leaves_the_dependency_unavailable() {
        let fixture = HookFixture::install(HookBehavior::Fail);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        assert_eq!(fixture.requests(), vec!["declared:python:cpython@3.10.0"]);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::semantic_model::dependency::diagnostic_codes(
                &outcome.diagnostics
            ),
            vec![
                "dependency.acquire",
                "dependency.pack_unavailable",
                "preparation.unaccounted-dependency"
            ]
        );
        assert_eq!(
            outcome.diagnostics[0].severity,
            DependencyPackDiagnosticSeverity::Warning
        );
        assert_eq!(outcome.installed_packs.len(), 0);
    }

    #[test]
    fn a_disabled_hook_is_not_a_warning() {
        let _guard = HOOK_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = set_semantic_pack_acquisition_hook(None);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let outcome = prepare(&catalog, declared_python_dependency());

        set_semantic_pack_acquisition_hook(previous);
        // The unaccounted-dependency warning is the ordinary tail accounting
        // for a dependency that produced no pack. A disabled hook adds nothing
        // of its own: no acquisition attempt was made, so nothing failed.
        assert_eq!(
            brokk_bifrost_analysis::analyzer::semantic_model::dependency::diagnostic_codes(
                &outcome.diagnostics
            ),
            vec![
                "dependency.pack_unavailable",
                "preparation.unaccounted-dependency"
            ]
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

/// Whether project enumeration membership is unchanged across an update.
/// Overlay-set changes belong in `added` and `removed`. M2 may disregard a
/// changed Inventory or Listing read only when this returns true; every other
/// recorded read key still needs exact verification.
pub fn discovery_membership_unchanged(
    resolver: &dyn DependencyResolver,
    added: &[std::path::PathBuf],
    removed: &[std::path::PathBuf],
    old_ignore_rules: &[u8; 32],
    new_ignore_rules: &[u8; 32],
) -> bool {
    old_ignore_rules == new_ignore_rules
        && added
            .iter()
            .chain(removed)
            .all(|path| !resolver.is_discovery_membership_candidate(path))
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::semantic_model::{
        DependencyDiscoveryOutcome, DependencyPackAdapter, DependencyPackLimits,
        DependencyResolverBounds,
    };

    struct DefaultCandidateResolver;
    impl DependencyResolver for DefaultCandidateResolver {
        fn adapter(&self) -> &'static dyn DependencyPackAdapter {
            unimplemented!()
        }
        fn dependency_inputs(&self) -> &'static [&'static str] {
            &[]
        }
        fn bounds(&self, _: &crate::analyzer::AnalyzerConfig) -> DependencyResolverBounds {
            unimplemented!()
        }
        fn resolve(
            &self,
            _: &crate::analyzer::AnalyzerConfig,
            _: &dyn crate::analyzer::Project,
            _: &brokk_bifrost_core::content_digest::ContentDigestCache,
            _: &brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications,
            _: &DependencyPackLimits,
            _: Option<&CancellationToken>,
        ) -> DependencyDiscoveryOutcome {
            unimplemented!()
        }
    }

    #[test]
    fn default_candidate_hook_rejects_added_paths() {
        let digest = [0; 32];
        assert!(!discovery_membership_unchanged(
            &DefaultCandidateResolver,
            &[std::path::PathBuf::from("src/new.rs")],
            &[],
            &digest,
            &digest,
        ));
    }
}

#[derive(Debug, Clone)]
pub struct CapturedDependencyDiscovery {
    pub outcome: DependencyDiscoveryOutcome,
    pub(crate) rust_cargo_graph: Option<super::RustSelectedCargoGraph>,
    pub project_read_keys: std::sync::Arc<[crate::analyzer::read_ledger::ReadKey]>,
    pub project_read_identity: crate::analyzer::semantic::ids::StableDigest,
    pub external_reads: crate::analyzer::dependency_support::ExternalDiscoveryReads,
}

thread_local! {
    static RUST_CARGO_GRAPH_CAPTURE: std::cell::RefCell<Option<super::RustSelectedCargoGraph>> = const { std::cell::RefCell::new(None) };
}

/// Called only by the Rust dependency discoverer while discovery is captured.
pub fn publish_rust_selected_cargo_graph(graph: super::RustSelectedCargoGraph) {
    RUST_CARGO_GRAPH_CAPTURE.with(|slot| *slot.borrow_mut() = Some(graph));
}

pub fn capture_dependency_discovery(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    discover: impl FnOnce() -> DependencyDiscoveryOutcome,
) -> CapturedDependencyDiscovery {
    RUST_CARGO_GRAPH_CAPTURE.with(|slot| *slot.borrow_mut() = None);
    let ((outcome, mut external_reads), project_reads) =
        brokk_bifrost_core::analyzer::project_reads::with_project_read_suppression(false, || {
            crate::analyzer::i_analyzer::capture_with_read_ledger_scope(analyzer, None, || {
                crate::analyzer::dependency_support::capture_external_discovery_reads(discover)
            })
        });
    let rust_cargo_graph = RUST_CARGO_GRAPH_CAPTURE.with(|slot| slot.borrow_mut().take());
    // A project read that failed, an execution dependence or a refused reuse
    // leaves no key (#13517): the discovery's diagnostics or results then
    // stand for something the recorded reads cannot reproduce, so the capture
    // must not be carried.
    if !project_reads.is_bounded() {
        external_reads.refuse_unbounded_project_reads();
    }
    CapturedDependencyDiscovery {
        outcome,
        rust_cargo_graph,
        project_read_keys: project_reads.canonical_keys(),
        project_read_identity: project_reads.digest().digest(),
        external_reads,
    }
}
