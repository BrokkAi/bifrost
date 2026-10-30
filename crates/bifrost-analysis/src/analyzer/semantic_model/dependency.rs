use crate::CancellationToken;
use crate::analyzer::DependencyPackEcosystem;
use crate::analyzer::semantic_model::{
    CatalogCandidate, CatalogError, CatalogPackSourceKind, Completeness, GeneratedProductionKey,
    PackExtractionAccounting, Producer, SemanticPackCatalog,
    producer::{read_exact_artifact_while, read_exact_source_set_while},
};
use crate::hash::{HashSet, set_with_capacity};
pub use brokk_bifrost_semantic::analyzer::semantic_model::dependency::*;
use std::sync::{OnceLock, RwLock};
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

    /// Discover this ecosystem's exact local dependencies.
    fn resolve(
        &self,
        config: &crate::analyzer::AnalyzerConfig,
        project: &dyn crate::analyzer::Project,
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

pub fn prepare_dependency_semantic_packs(
    catalog: &SemanticPackCatalog,
    adapter: &dyn DependencyPackAdapter,
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> DependencyPackPreparationOutcome {
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
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
        if dependency.id.is_empty() {
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            continue;
        }
        if dependency.artifacts.is_empty() || !adapter.can_produce(dependency) {
            match resolve_declared_dependency_pack(
                catalog,
                dependency,
                cancellation,
                &mut diagnostics,
            ) {
                Ok(Some(installed)) => {
                    evidence.push(installed.evidence.clone());
                    installed_packs.push(installed);
                    profile.installed_packs += 1;
                }
                Ok(None) => {}
                Err(DeclaredPackCancelled) => {
                    cancelled = true;
                    break;
                }
            }
            continue;
        }
        if dependency.evidence.artifact_sha256.is_some() {
            diagnostics.error(
                "dependency.artifact_evidence",
                Some(&dependency.id),
                None,
                "resolved dependency artifact digest must be supplied by preparation",
            );
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
            continue;
        }

        let source_identity = dependency_source_identity(adapter, dependency, limits);
        if let Some(identity) = source_identity.as_ref() {
            let reusable = {
                let _scope = crate::profiling::scope("semantic_pack.lookup_source_identity");
                reusable_generated_pack_by_source_identity(
                    catalog,
                    &adapter.producer(),
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
                && !matches!(&artifact.input, ResolvedDependencyArtifactInput::File(_))
            {
                diagnostics.error(
                    "artifact.digest_binding_unsupported",
                    Some(&dependency.id),
                    Some(artifact.path()),
                    "dependency artifact digest binding requires an exact file input",
                );
                break;
            }
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
                    profile.artifact_bytes_read = profile
                        .artifact_bytes_read
                        .saturating_add(exact.bytes().len() as u64);
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
            continue;
        }
        let exact_go_source = match prepared_exact_go_source(dependency, &exact_artifacts) {
            Ok(source) => source,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "go.source_registration", error);
                continue;
            }
        };
        let key = match generated_production_key(adapter, dependency, &exact_artifacts, limits) {
            Ok(key) => key,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "production.identity", error);
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
                let was_cancelled =
                    matches!(&failure, DependencyProductionFailure::Cancelled { .. });
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
                continue;
            }
        };
        diagnostics.suppressed += production.suppressed_diagnostics;
        let production_has_diagnostics = !production.diagnostics.is_empty();
        for diagnostic in production.diagnostics.iter().cloned() {
            diagnostics.producer(Some(&dependency.id), diagnostic);
        }
        if production.completeness == Completeness::Partial && !production_has_diagnostics {
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
                ),
                None => catalog.install_generated(&production.key, &production.compiled),
            }
        };
        match install {
            Ok(installed) => {
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
                let activation_digest = exact_go_source
                    .as_ref()
                    .map(|source| source.artifact.sha256())
                    .unwrap_or_else(|| production.key.input_digest());
                let activation_evidence = activation_evidence(dependency, activation_digest);
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
            Err(error) => diagnostics.catalog(Some(&dependency.id), "catalog.install", error),
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
    for dependency in dependencies {
        if !accounted_dependencies.contains(dependency.id.as_str()) {
            diagnostics.warning(
                "preparation.unaccounted-dependency",
                Some(&dependency.id),
                "dependency preparation produced neither a generated pack nor an installed pack",
            );
        }
    }
    let complete = !cancelled
        && dependencies.len() <= limits.max_dependencies
        && packs.len().saturating_add(installed_packs.len()) == dependencies.len()
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
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
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
        if dependency.id.is_empty() {
            failed = true;
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            continue;
        }
        match compatible_curated_installed_pack(catalog, dependency) {
            Ok(Some(installed)) => {
                evidence.push(installed.evidence.clone());
                installed_packs.push(installed);
                profile.installed_packs += 1;
            }
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
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                }
                None => {}
            },
            Err(error) => {
                failed = true;
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
    let mut diagnostics = BoundedDependencyDiagnostics::new(limits);
    let mut installed_packs = Vec::new();
    let mut evidence = Vec::new();
    let mut profile = DependencyPackPreparationProfile::default();
    let mut pending = Vec::new();
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
        if dependency.id.is_empty() {
            failed = true;
            diagnostics.error(
                "dependency.identity",
                None,
                None,
                "resolved dependency identity must not be empty",
            );
            continue;
        }
        let producible = !dependency.artifacts.is_empty() && adapter.can_produce(dependency);
        let mut settled = false;
        if producible {
            match compatible_curated_installed_pack(catalog, dependency) {
                Ok(Some(installed)) => {
                    evidence.push(installed.evidence.clone());
                    installed_packs.push(installed);
                    profile.installed_packs += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    failed = true;
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                }
            }
        } else {
            match compatible_installed_pack(catalog, dependency, &mut diagnostics) {
                Ok(Some(installed)) => {
                    settled = true;
                    evidence.push(installed.evidence.clone());
                    installed_packs.push(installed);
                    profile.installed_packs += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    failed = true;
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                }
            }
        }
        if producible || !settled {
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
    let complete = !failed && !cancelled && pending.is_empty();
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    InstalledDependencyPackPreparation {
        outcome: DependencyPackPreparationOutcome {
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
    input_digest: &str,
    exact_source_sha256: Option<&str>,
) -> Result<Option<PreparedDependencyPack>, CatalogError> {
    let Some(production) = catalog.generated_production(key)? else {
        return Ok(None);
    };
    Ok(Some(PreparedDependencyPack {
        dependency_id: dependency.id.clone(),
        completeness: production.completeness,
        production,
        status: DependencyPackPreparationStatus::Reused,
        evidence: activation_evidence(dependency, exact_source_sha256.unwrap_or(input_digest)),
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
    identity: &DependencySourceIdentity,
    dependency: &ResolvedDependency,
) -> Result<Option<PreparedDependencyPack>, CatalogError> {
    let Some(production) =
        catalog.generated_production_by_source_identity(identity.as_str(), producer)?
    else {
        return Ok(None);
    };
    let input_digest = production.key.input_digest().to_owned();
    Ok(Some(PreparedDependencyPack {
        dependency_id: dependency.id.clone(),
        completeness: production.completeness,
        production,
        status: DependencyPackPreparationStatus::Reused,
        evidence: activation_evidence(dependency, &input_digest),
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
) -> Result<Option<PreparedInstalledDependencyPack>, DeclaredPackCancelled> {
    match compatible_installed_pack(catalog, dependency, diagnostics) {
        Ok(Some(installed)) => return Ok(Some(installed)),
        Ok(None) => {}
        Err(error) => {
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            return Ok(None);
        }
    }

    // No usable pack. Distinguish "a pack exists for another version of this
    // exact coordinate" from "no pack at all": the near miss names the
    // installed and required versions so a version mismatch is attributable,
    // never silent (#1884). A near miss is also not an acquisition case: the
    // release bundle already supplied a pack for this coordinate, and the
    // version the workspace declares is what does not match.
    let Some(query) = installed_pack_query(dependency) else {
        diagnostics.error(
            "dependency.pack_unavailable",
            Some(&dependency.id),
            None,
            PACK_UNAVAILABLE_MESSAGE,
        );
        return Ok(None);
    };
    let near_misses = match catalog.version_near_misses(&query) {
        Ok(near_misses) => near_misses,
        Err(error) => {
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            return Ok(None);
        }
    };
    if !near_misses.is_empty() {
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
        diagnostics.error(
            "dependency.pack_unavailable",
            Some(&dependency.id),
            None,
            PACK_UNAVAILABLE_MESSAGE,
        );
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
    match compatible_installed_pack(catalog, dependency, diagnostics) {
        Ok(Some(installed)) => Ok(Some(installed)),
        Ok(None) => {
            diagnostics.error(
                "dependency.pack_unavailable",
                Some(&dependency.id),
                None,
                PACK_UNAVAILABLE_MESSAGE,
            );
            Ok(None)
        }
        Err(error) => {
            diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
            Ok(None)
        }
    }
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
    let candidates = compatible_installed_pack_candidates(catalog, dependency)?;
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
/// them. A locally installed partial pack still needs the ordinary extraction
/// accounting that makes it activation-ready; curated evidence must not turn
/// an arbitrary partial installation into trusted semantics.
pub(crate) fn compatible_curated_installed_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Option<PreparedInstalledDependencyPack>, CatalogError> {
    let mut candidates = compatible_installed_pack_candidates(catalog, dependency)?;
    if candidates.iter().any(|candidate| {
        !candidate.activation_ready && candidate.source_kind == CatalogPackSourceKind::Installed
    }) {
        return Ok(None);
    }
    candidates.retain(|candidate| {
        candidate.activation_ready
            || matches!(
                candidate.source_kind,
                CatalogPackSourceKind::PreShipped | CatalogPackSourceKind::Embedded
            )
    });
    Ok(prepared_installed_pack(dependency, &candidates))
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
    let Some(query) = installed_pack_query(dependency) else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    let mut accounted_manifests: HashSet<String> = set_with_capacity(4);
    for candidate in catalog.dependency_candidates(&query)? {
        if !matches!(
            candidate.source_kind(),
            CatalogPackSourceKind::Installed
                | CatalogPackSourceKind::PreShipped
                | CatalogPackSourceKind::Embedded
        ) {
            continue;
        }
        if accounted_manifests.insert(candidate.manifest_digest().to_owned()) {
            let extraction = catalog.extraction_accounting(candidate.manifest_digest())?;
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
    Ok(candidates)
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
                artifact_sha256: None,
            },
            provenance: Vec::new(),
            artifacts: Vec::new(),
            scope: DependencyScope::Unknown,
            declared_by: None,
        }
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
