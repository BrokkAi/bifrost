use std::path::{Path, PathBuf};

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

use super::{
    ArtifactProducerLimits, AuthoredSemanticModelPack, CatalogError, CatalogPackSourceKind,
    CompilerOptions, Completeness, ExactArtifact, ExactSourceEntry, ExternalArtifactKind,
    GeneratedProduction, GeneratedProductionKey, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, SEMANTIC_MODEL_SCHEMA_VERSION, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticPackCatalog, SemanticPackSelectorQuery, compile_pack,
    producer::{read_exact_artifact_while, read_exact_source_set_while},
};

const DEPENDENCY_INPUT_DOMAIN: &[u8] = b"bifrost.semantic-pack.dependency-input.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyArtifactRole {
    Metadata,
    Declarations,
    Binary,
    Sources,
    Reference,
    Runtime,
}

impl DependencyArtifactRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Declarations => "declarations",
            Self::Binary => "binary",
            Self::Sources => "sources",
            Self::Reference => "reference",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependencyArtifact {
    pub role: DependencyArtifactRole,
    pub kind: ExternalArtifactKind,
    /// Ecosystem-specific import identity for this artifact when production
    /// depends on more than its bytes. Python uses this for qualified module
    /// names, so nested packages cannot collapse to their terminal filename.
    pub module: Option<String>,
    pub input: ResolvedDependencyArtifactInput,
    /// When present, binds later artifact preparation to the exact file that
    /// dependency discovery approved. The stored path must also remain its own
    /// canonical path so a replaced symlink cannot redirect the later read.
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedDependencyArtifactInput {
    File(PathBuf),
    SourceSet {
        root: PathBuf,
        relative_paths: Vec<PathBuf>,
    },
}

impl ResolvedDependencyArtifact {
    pub fn file(role: DependencyArtifactRole, kind: ExternalArtifactKind, path: PathBuf) -> Self {
        Self {
            role,
            kind,
            module: None,
            input: ResolvedDependencyArtifactInput::File(path),
            expected_sha256: None,
        }
    }

    pub fn exact_file(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        path: PathBuf,
        expected_sha256: String,
    ) -> Self {
        Self {
            role,
            kind,
            module: None,
            input: ResolvedDependencyArtifactInput::File(path),
            expected_sha256: Some(expected_sha256),
        }
    }

    pub fn module_file(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        module: String,
        path: PathBuf,
    ) -> Self {
        Self {
            role,
            kind,
            module: Some(module),
            input: ResolvedDependencyArtifactInput::File(path),
            expected_sha256: None,
        }
    }

    pub fn source_set(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        root: PathBuf,
        relative_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            role,
            kind,
            module: None,
            input: ResolvedDependencyArtifactInput::SourceSet {
                root,
                relative_paths,
            },
            expected_sha256: None,
        }
    }

    pub fn path(&self) -> &Path {
        match &self.input {
            ResolvedDependencyArtifactInput::File(path) => path,
            ResolvedDependencyArtifactInput::SourceSet { root, .. } => root,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDependency {
    pub id: String,
    pub evidence: SemanticModelActivationEvidence,
    /// Ordered, normalized ecosystem evidence that affects production but is
    /// not itself an activation selector (for example an exact non-semver
    /// coordinate or asset role).
    pub provenance: Vec<DependencyProvenance>,
    pub artifacts: Vec<ResolvedDependencyArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyProvenance {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactDependencyArtifact {
    role: DependencyArtifactRole,
    kind: ExternalArtifactKind,
    module: Option<String>,
    artifact: ExactArtifact,
}

impl ExactDependencyArtifact {
    pub fn role(&self) -> DependencyArtifactRole {
        self.role
    }

    pub fn kind(&self) -> ExternalArtifactKind {
        self.kind
    }

    pub fn module(&self) -> Option<&str> {
        self.module.as_deref()
    }

    pub fn path(&self) -> &Path {
        self.artifact.path()
    }

    pub fn bytes(&self) -> &[u8] {
        self.artifact.bytes()
    }

    pub fn source_entries(&self) -> &[ExactSourceEntry] {
        self.artifact.source_entries()
    }

    pub(crate) fn exact(&self) -> &ExactArtifact {
        &self.artifact
    }

    pub fn sha256(&self) -> &str {
        self.artifact.sha256()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackProduction {
    pub pack: Option<AuthoredSemanticModelPack>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
}

pub trait DependencyPackAdapter {
    fn adapter_name(&self) -> &str;
    fn adapter_version(&self) -> &str;
    fn producer(&self) -> Producer;

    fn can_produce(&self, _dependency: &ResolvedDependency) -> bool {
        true
    }

    fn produce(
        &self,
        dependency: &ResolvedDependency,
        artifacts: &[ExactDependencyArtifact],
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyPackLimits {
    pub max_dependencies: usize,
    pub max_artifacts_per_dependency: usize,
    pub max_source_files_per_artifact: usize,
    pub max_source_path_depth: usize,
    pub max_total_artifact_bytes: u64,
    pub max_diagnostics: usize,
    pub max_diagnostic_message_bytes: usize,
    pub producer: ArtifactProducerLimits,
    pub compiler: CompilerOptions,
}

impl Default for DependencyPackLimits {
    fn default() -> Self {
        Self {
            max_dependencies: 1_024,
            max_artifacts_per_dependency: 4,
            max_source_files_per_artifact: 100_000,
            max_source_path_depth: 64,
            max_total_artifact_bytes: 512 * 1024 * 1024,
            max_diagnostics: 256,
            max_diagnostic_message_bytes: 4 * 1024,
            producer: ArtifactProducerLimits::default(),
            compiler: CompilerOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyPackDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackDiagnostic {
    pub severity: DependencyPackDiagnosticSeverity,
    pub code: String,
    pub dependency_id: Option<String>,
    pub location: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyPackPreparationStatus {
    Reused,
    Generated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDependencyPack {
    pub dependency_id: String,
    pub production: GeneratedProduction,
    pub status: DependencyPackPreparationStatus,
    pub completeness: Completeness,
    pub evidence: SemanticModelActivationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedInstalledDependencyPack {
    pub dependency_id: String,
    pub manifest_digests: Vec<String>,
    pub completeness: Completeness,
    pub evidence: SemanticModelActivationEvidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyPackPreparationProfile {
    pub dependencies_considered: usize,
    pub artifacts_read: usize,
    pub artifact_bytes_read: u64,
    pub reused_packs: usize,
    pub generated_packs: usize,
    pub installed_packs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackPreparationOutcome {
    pub packs: Vec<PreparedDependencyPack>,
    pub installed_packs: Vec<PreparedInstalledDependencyPack>,
    pub evidence: Vec<SemanticModelActivationEvidence>,
    pub diagnostics: Vec<DependencyPackDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub complete: bool,
    pub cancelled: bool,
    pub profile: DependencyPackPreparationProfile,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyDiscoveryProfile {
    pub metadata_inputs_considered: usize,
    pub dependencies_resolved: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDiscoveryOutcome {
    pub dependencies: Vec<ResolvedDependency>,
    pub diagnostics: Vec<DependencyPackDiagnostic>,
    pub suppressed_diagnostics: usize,
    pub complete: bool,
    pub cancelled: bool,
    pub profile: DependencyDiscoveryProfile,
}

impl DependencyDiscoveryOutcome {
    pub fn complete(dependencies: Vec<ResolvedDependency>) -> Self {
        Self {
            profile: DependencyDiscoveryProfile {
                metadata_inputs_considered: 0,
                dependencies_resolved: dependencies.len(),
            },
            dependencies,
            diagnostics: Vec::new(),
            suppressed_diagnostics: 0,
            complete: true,
            cancelled: false,
        }
    }

    /// Convert discovery completeness into the shared diagnostic suppression
    /// vocabulary. This does not start discovery or read the filesystem.
    pub fn semantic_diagnostic_incomplete_reasons(
        &self,
    ) -> Vec<crate::analyzer::SemanticDiagnosticIncompleteReason> {
        if self.cancelled {
            vec![crate::analyzer::SemanticDiagnosticIncompleteReason::Cancelled]
        } else if !self.complete {
            vec![crate::analyzer::SemanticDiagnosticIncompleteReason::Truncated]
        } else {
            Vec::new()
        }
    }
}

impl std::ops::Deref for DependencyDiscoveryOutcome {
    type Target = [ResolvedDependency];

    fn deref(&self) -> &Self::Target {
        &self.dependencies
    }
}

/// The queryable residue of one dependency-discovery run (#1601): the module
/// and package identities the build declared, and whether discovery could read
/// all of them.
///
/// Discovery is a caller-driven filesystem walk whose cost is unbounded in the
/// workspace's dependency count, so a query must never trigger it. Retaining
/// this summary on the analyzer when a host runs discovery gives boundary
/// refinement a cheap place to read "the build declares this dependency and
/// nothing indexed it" instead of collapsing it into "nothing is known".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDiscoveryEvidence {
    declared_modules: crate::hash::HashSet<String>,
    truncated: bool,
}

impl DependencyDiscoveryEvidence {
    pub fn from_outcome(outcome: &DependencyDiscoveryOutcome) -> Self {
        let mut declared_modules = crate::hash::HashSet::default();
        for dependency in &outcome.dependencies {
            for coordinate in [&dependency.evidence.package, &dependency.evidence.module]
                .into_iter()
                .flatten()
            {
                declared_modules.insert(coordinate.name.clone());
            }
            for artifact in &dependency.artifacts {
                if let Some(module) = &artifact.module {
                    declared_modules.insert(module.clone());
                }
            }
        }
        Self {
            declared_modules,
            truncated: !outcome.complete,
        }
    }

    /// Whether discovery could not read everything the build declared, so a
    /// miss against [`Self::declares_module_path`] is not proof of absence.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether the build declares `path` or a module containing it: an exact
    /// declared identity, or one reached by walking the dotted path back
    /// toward its root (`requests.adapters.HTTPAdapter` is declared when the
    /// `requests` distribution is). The declared identities are the normalized
    /// dotted module names discovery itself recorded, so segment-prefix
    /// containment is their defined structure, not a re-parse of source text.
    pub fn declares_module_path(&self, path: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        if self.declared_modules.contains(path) {
            return true;
        }
        let mut prefix = path;
        while let Some((head, _)) = prefix.rsplit_once('.') {
            if self.declared_modules.contains(head) {
                return true;
            }
            prefix = head;
        }
        false
    }
}

/// Read retained discovery evidence for a diagnostic request. A missing value
/// is incomplete external evidence. This function never starts discovery.
pub fn dependency_discovery_incomplete_reasons(
    evidence: Option<&DependencyDiscoveryEvidence>,
) -> Vec<crate::analyzer::SemanticDiagnosticIncompleteReason> {
    match evidence {
        None => vec![
            crate::analyzer::SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: crate::analyzer::structural::BoundaryStatus::ExternalUnknown,
            },
        ],
        Some(evidence) if evidence.truncated() => {
            vec![crate::analyzer::SemanticDiagnosticIncompleteReason::Truncated]
        }
        Some(_) => Vec::new(),
    }
}

impl DependencyPackPreparationOutcome {
    /// Compose successfully prepared dependency evidence into a host-owned
    /// activation request. A cancelled or wholly unavailable partial result
    /// returns `None`, so callers cannot accidentally replace a previously
    /// complete active set with authoritative empty dependency evidence.
    pub fn compose_activation_request(
        &self,
        mut request: SemanticModelActivationRequest,
    ) -> Option<SemanticModelActivationRequest> {
        if self.cancelled || (!self.complete && self.evidence.is_empty()) {
            return None;
        }
        request.evidence.extend(self.evidence.iter().cloned());
        request.evidence.sort();
        request.evidence.dedup();
        Some(request)
    }
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
            match compatible_installed_pack(catalog, dependency) {
                Ok(Some(installed)) => {
                    evidence.push(installed.evidence.clone());
                    installed_packs.push(installed);
                    profile.installed_packs += 1;
                }
                Ok(None) => diagnostics.error(
                    "dependency.pack_unavailable",
                    Some(&dependency.id),
                    None,
                    "resolved dependency has no exact locally producible artifact or compatible installed semantic pack",
                ),
                Err(error) => {
                    diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error)
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
        if cancelled {
            break;
        }
        if exact_artifacts.len() != dependency.artifacts.len() {
            continue;
        }

        let producer = adapter.producer();
        let input_digest = dependency_input_digest(adapter, dependency, &exact_artifacts, limits);
        let key = match GeneratedProductionKey::new(
            input_digest.clone(),
            producer.name.clone(),
            producer.version.clone(),
            SEMANTIC_MODEL_SCHEMA_VERSION,
        ) {
            Ok(key) => key,
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "production.identity", error);
                continue;
            }
        };
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        match catalog.generated_production(&key) {
            Ok(Some(production)) if production.completeness == Completeness::Complete => {
                let activation_evidence = activation_evidence(dependency, &input_digest);
                evidence.push(activation_evidence.clone());
                packs.push(PreparedDependencyPack {
                    dependency_id: dependency.id.clone(),
                    completeness: production.completeness,
                    production,
                    status: DependencyPackPreparationStatus::Reused,
                    evidence: activation_evidence,
                });
                profile.reused_packs += 1;
                continue;
            }
            Ok(Some(_)) => {}
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
        let production =
            adapter.produce(dependency, &exact_artifacts, &limits.producer, cancellation);
        let production_has_errors = production
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == ProducerDiagnosticSeverity::Error)
            || production.suppressed_diagnostics > 0;
        let production_has_diagnostics = !production.diagnostics.is_empty();
        diagnostics.suppressed = diagnostics
            .suppressed
            .saturating_add(production.suppressed_diagnostics);
        for diagnostic in production.diagnostics {
            diagnostics.producer(Some(&dependency.id), diagnostic);
        }
        let Some(mut pack) = production.pack else {
            continue;
        };
        if production_has_errors {
            pack.completeness = Completeness::Partial;
        }
        if pack.completeness == Completeness::Partial && !production_has_diagnostics {
            diagnostics.error(
                "production.partial",
                Some(&dependency.id),
                None,
                "dependency producer returned partial semantic coverage",
            );
        }
        if pack.producer != producer || pack.schema_version != SEMANTIC_MODEL_SCHEMA_VERSION {
            diagnostics.error(
                "production.identity_mismatch",
                Some(&dependency.id),
                None,
                "adapter output does not match its declared producer or schema identity",
            );
            continue;
        }
        if pack.language != dependency.evidence.language
            || pack.ecosystem != dependency.evidence.ecosystem
        {
            diagnostics.error(
                "production.evidence_mismatch",
                Some(&dependency.id),
                None,
                "adapter output language or ecosystem does not match dependency evidence",
            );
            continue;
        }
        if pack.shards.iter().any(|shard| shard.activation.is_empty()) {
            diagnostics.error(
                "production.activation_missing",
                Some(&dependency.id),
                None,
                "adapter output contains a shard without activation selectors",
            );
            continue;
        }
        for shard in &mut pack.shards {
            for selector in &mut shard.activation {
                selector.artifact_sha256 = Some(input_digest.clone());
            }
        }
        let completeness = pack.completeness;
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        let compiled = match compile_pack(&pack, &limits.compiler) {
            Ok(compiled) => compiled,
            Err(compile_diagnostics) => {
                for diagnostic in compile_diagnostics {
                    diagnostics.error_location(
                        &diagnostic.code,
                        Some(&dependency.id),
                        Some(diagnostic.path),
                        diagnostic.message,
                    );
                }
                continue;
            }
        };
        if is_cancelled(cancellation) {
            cancelled = true;
            break;
        }
        match catalog.install_generated(&key, &compiled) {
            Ok(installed) => {
                let activation_evidence = activation_evidence(dependency, &input_digest);
                evidence.push(activation_evidence.clone());
                packs.push(PreparedDependencyPack {
                    dependency_id: dependency.id.clone(),
                    production: installed.production,
                    status: DependencyPackPreparationStatus::Generated,
                    completeness,
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
    let complete = !cancelled
        && dependencies.len() <= limits.max_dependencies
        && packs.len().saturating_add(installed_packs.len()) == dependencies.len()
        && packs
            .iter()
            .all(|pack| pack.completeness == Completeness::Complete)
        && installed_packs
            .iter()
            .all(|pack| pack.completeness == Completeness::Complete)
        && !diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DependencyPackDiagnosticSeverity::Error);
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

fn compatible_installed_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Option<PreparedInstalledDependencyPack>, CatalogError> {
    let has_exact_coordinate = dependency
        .evidence
        .package
        .as_ref()
        .and_then(|coordinate| coordinate.version.as_ref())
        .is_some()
        || dependency
            .evidence
            .toolchain
            .as_ref()
            .and_then(|coordinate| coordinate.version.as_ref())
            .is_some();
    if !has_exact_coordinate {
        return Ok(None);
    }
    let query = SemanticPackSelectorQuery {
        language: dependency.evidence.language.clone(),
        ecosystem: dependency.evidence.ecosystem.clone(),
        package: dependency.evidence.package.clone(),
        module: dependency.evidence.module.clone(),
        toolchain: dependency.evidence.toolchain.clone(),
        target: dependency.evidence.target.clone(),
        configuration: dependency.evidence.configuration.clone(),
        artifact_sha256: None,
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("Bifrost package version must be semantic"),
    };
    let mut manifest_digests = Vec::new();
    let mut has_complete_pack = false;
    for candidate in catalog.candidates(&query)? {
        if !matches!(
            candidate.source_kind(),
            CatalogPackSourceKind::Installed
                | CatalogPackSourceKind::PreShipped
                | CatalogPackSourceKind::Embedded
        ) {
            continue;
        }
        has_complete_pack |= candidate.completeness() == Completeness::Complete;
        manifest_digests.push(candidate.manifest_digest().to_owned());
    }
    manifest_digests.sort();
    manifest_digests.dedup();
    Ok(
        (!manifest_digests.is_empty()).then(|| PreparedInstalledDependencyPack {
            dependency_id: dependency.id.clone(),
            manifest_digests,
            completeness: if has_complete_pack {
                Completeness::Complete
            } else {
                Completeness::Partial
            },
            evidence: dependency.evidence.clone(),
        }),
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
    let mut diagnostics = discovery.diagnostics;
    diagnostics.append(&mut outcome.diagnostics);
    if diagnostics.len() > limits.max_diagnostics {
        outcome.suppressed_diagnostics = outcome
            .suppressed_diagnostics
            .saturating_add(diagnostics.len() - limits.max_diagnostics);
        diagnostics.truncate(limits.max_diagnostics);
    }
    outcome.suppressed_diagnostics = outcome
        .suppressed_diagnostics
        .saturating_add(discovery.suppressed_diagnostics);
    outcome.complete &= discovery.complete;
    outcome.cancelled |= discovery.cancelled;
    outcome.diagnostics = diagnostics;
    outcome
}

fn dependency_input_digest(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    artifacts: &[ExactDependencyArtifact],
    limits: &DependencyPackLimits,
) -> String {
    let mut hasher = CanonicalHasher::new(DEPENDENCY_INPUT_DOMAIN);
    hasher.field("adapter_name", adapter.adapter_name().as_bytes());
    hasher.field("adapter_version", adapter.adapter_version().as_bytes());
    hash_evidence(&mut hasher, &dependency.evidence);
    let mut provenance: Vec<_> = dependency.provenance.iter().collect();
    provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
    hasher.sequence("provenance", &provenance, |hasher, entry| {
        hasher.field("key", entry.key.as_bytes());
        hasher.field("value", entry.value.as_bytes());
    });
    hasher.sequence("artifacts", artifacts, |hasher, artifact| {
        hasher.field("role", artifact.role.as_str().as_bytes());
        hasher.field("kind", artifact_kind_name(artifact.kind).as_bytes());
        hasher.field("module", artifact.module().unwrap_or("").as_bytes());
        hasher.field("sha256", artifact.sha256().as_bytes());
    });
    hash_production_profile(&mut hasher, limits);
    lower_hex_string(&hasher.finish())
}

fn hash_production_profile(hasher: &mut CanonicalHasher, limits: &DependencyPackLimits) {
    let producer = limits.producer;
    for (field, value) in [
        ("producer_max_artifact_bytes", producer.max_artifact_bytes),
        ("producer_max_records", producer.max_records as u64),
        (
            "producer_max_signature_depth",
            producer.max_signature_depth as u64,
        ),
        ("producer_max_diagnostics", producer.max_diagnostics as u64),
        (
            "producer_max_diagnostic_message_bytes",
            producer.max_diagnostic_message_bytes as u64,
        ),
        (
            "compiler_max_source_bytes",
            limits.compiler.max_source_bytes as u64,
        ),
        (
            "compiler_max_manifest_bytes",
            limits.compiler.max_manifest_bytes as u64,
        ),
        (
            "compiler_max_stored_shard_bytes",
            limits.compiler.max_stored_shard_bytes as u64,
        ),
        (
            "compiler_max_raw_shard_bytes",
            limits.compiler.max_raw_shard_bytes as u64,
        ),
        (
            "compiler_max_total_raw_bytes",
            limits.compiler.max_total_raw_bytes,
        ),
        ("compiler_max_shards", limits.compiler.max_shards as u64),
        (
            "compiler_max_records_per_shard",
            limits.compiler.max_records_per_shard as u64,
        ),
        (
            "compiler_max_records_per_pack",
            limits.compiler.max_records_per_pack as u64,
        ),
        (
            "compiler_max_text_bytes",
            limits.compiler.max_text_bytes as u64,
        ),
        ("compiler_max_depth", limits.compiler.max_depth as u64),
    ] {
        hasher.field(field, &value.to_be_bytes());
    }
    let compression = match limits.compiler.compression {
        super::CompressionPolicy::Automatic => "automatic",
        super::CompressionPolicy::AlwaysRaw => "raw",
        super::CompressionPolicy::AlwaysDeflate => "deflate",
    };
    hasher.field("compiler_compression", compression.as_bytes());
}

fn hash_evidence(hasher: &mut CanonicalHasher, evidence: &SemanticModelActivationEvidence) {
    hasher.field("language", evidence.language.as_bytes());
    hasher.field("ecosystem", evidence.ecosystem.as_bytes());
    hash_coordinate(hasher, "package", evidence.package.as_ref());
    hash_coordinate(hasher, "module", evidence.module.as_ref());
    hash_coordinate(hasher, "toolchain", evidence.toolchain.as_ref());
    hash_optional(hasher, "target", evidence.target.as_deref());
    hash_optional(hasher, "configuration", evidence.configuration.as_deref());
}

fn hash_coordinate(
    hasher: &mut CanonicalHasher,
    field: &str,
    coordinate: Option<&super::CatalogCoordinate>,
) {
    match coordinate {
        Some(coordinate) => {
            hasher.field(field, b"some");
            hasher.field("coordinate_name", coordinate.name.as_bytes());
            let version = coordinate.version.as_ref().map(ToString::to_string);
            hash_optional(hasher, "coordinate_version", version.as_deref());
        }
        None => hasher.field(field, b"none"),
    }
}

fn hash_optional(hasher: &mut CanonicalHasher, field: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.field(field, b"some");
            hasher.field("value", value.as_bytes());
        }
        None => hasher.field(field, b"none"),
    }
}

fn artifact_kind_name(kind: ExternalArtifactKind) -> &'static str {
    match kind {
        ExternalArtifactKind::NpmPackageManifest => "npm_package_manifest",
        ExternalArtifactKind::TypeScriptDeclarationFile => "typescript_declaration_file",
        ExternalArtifactKind::JavaSourceJar => "java_source_jar",
        ExternalArtifactKind::JavaClassJar => "java_class_jar",
        ExternalArtifactKind::ScalaSourceJar => "scala_source_jar",
        ExternalArtifactKind::KotlinSourceJar => "kotlin_source_jar",
        ExternalArtifactKind::JdkSourceZip => "jdk_source_zip",
        ExternalArtifactKind::DotNetAssembly => "dotnet_assembly",
        ExternalArtifactKind::RustdocJson => "rustdoc_json",
        ExternalArtifactKind::GoSourceSet => "go_source_set",
        ExternalArtifactKind::PythonStub => "python_stub",
        ExternalArtifactKind::PythonSource => "python_source",
        ExternalArtifactKind::RubyGemArchive => "ruby_gem_archive",
    }
}

fn activation_evidence(
    dependency: &ResolvedDependency,
    input_digest: &str,
) -> SemanticModelActivationEvidence {
    let mut evidence = dependency.evidence.clone();
    evidence.artifact_sha256 = Some(input_digest.to_owned());
    evidence
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

pub(crate) struct BoundedDependencyDiagnostics {
    diagnostics: Vec<DependencyPackDiagnostic>,
    suppressed: usize,
    max_diagnostics: usize,
    max_message_bytes: usize,
}

impl BoundedDependencyDiagnostics {
    pub(crate) fn new(limits: &DependencyPackLimits) -> Self {
        Self {
            diagnostics: Vec::new(),
            suppressed: 0,
            max_diagnostics: limits.max_diagnostics,
            max_message_bytes: limits.max_diagnostic_message_bytes,
        }
    }

    fn producer(&mut self, dependency_id: Option<&str>, diagnostic: ProducerDiagnostic) {
        let severity = match diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => DependencyPackDiagnosticSeverity::Warning,
            ProducerDiagnosticSeverity::Error => DependencyPackDiagnosticSeverity::Error,
        };
        self.push(DependencyPackDiagnostic {
            severity,
            code: diagnostic.code,
            dependency_id: dependency_id.map(str::to_owned),
            location: diagnostic.location,
            message: diagnostic.message,
        });
    }

    fn catalog(&mut self, dependency_id: Option<&str>, code: &str, error: CatalogError) {
        self.error(code, dependency_id, None, error.to_string());
    }

    fn error(
        &mut self,
        code: impl Into<String>,
        dependency_id: Option<&str>,
        location: Option<&Path>,
        message: impl Into<String>,
    ) {
        self.error_location(
            code,
            dependency_id,
            location.map(|path| path.to_string_lossy().into_owned()),
            message,
        );
    }

    fn error_location(
        &mut self,
        code: impl Into<String>,
        dependency_id: Option<&str>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        self.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: code.into(),
            dependency_id: dependency_id.map(str::to_owned),
            location,
            message: message.into(),
        });
    }

    pub(crate) fn push(&mut self, mut diagnostic: DependencyPackDiagnostic) {
        diagnostic.message = truncate_utf8(&diagnostic.message, self.max_message_bytes);
        if self.diagnostics.len() < self.max_diagnostics {
            self.diagnostics.push(diagnostic);
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }

    pub(crate) fn finish(self) -> (Vec<DependencyPackDiagnostic>, usize) {
        (self.diagnostics, self.suppressed)
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod semantic_diagnostic_evidence_tests {
    use super::*;
    use crate::analyzer::{SemanticDiagnosticIncompleteReason, structural::BoundaryStatus};

    #[test]
    fn discovery_outcome_maps_cancelled_and_truncated_states() {
        let mut outcome = DependencyDiscoveryOutcome::complete(Vec::new());
        assert!(outcome.semantic_diagnostic_incomplete_reasons().is_empty());

        outcome.complete = false;
        assert_eq!(
            outcome.semantic_diagnostic_incomplete_reasons(),
            vec![SemanticDiagnosticIncompleteReason::Truncated]
        );

        outcome.cancelled = true;
        assert_eq!(
            outcome.semantic_diagnostic_incomplete_reasons(),
            vec![SemanticDiagnosticIncompleteReason::Cancelled]
        );
    }

    #[test]
    fn retained_discovery_evidence_distinguishes_missing_and_truncated() {
        assert_eq!(
            dependency_discovery_incomplete_reasons(None),
            vec![
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                    boundary: BoundaryStatus::ExternalUnknown,
                }
            ]
        );

        let mut outcome = DependencyDiscoveryOutcome::complete(Vec::new());
        assert!(
            dependency_discovery_incomplete_reasons(Some(
                &DependencyDiscoveryEvidence::from_outcome(&outcome)
            ))
            .is_empty()
        );

        outcome.complete = false;
        assert_eq!(
            dependency_discovery_incomplete_reasons(Some(
                &DependencyDiscoveryEvidence::from_outcome(&outcome)
            )),
            vec![SemanticDiagnosticIncompleteReason::Truncated]
        );
    }
}
