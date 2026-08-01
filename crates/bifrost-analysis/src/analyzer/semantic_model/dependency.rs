use std::path::{Path, PathBuf};

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};

use super::{
    ArtifactProducerLimits, AuthoredSemanticModelPack, CatalogError, CompilerOptions, Completeness,
    ExactArtifact, ExternalArtifactKind, GeneratedProduction, GeneratedProductionKey, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, SEMANTIC_MODEL_SCHEMA_VERSION,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticPackCatalog,
    compile_pack, producer::read_exact_artifact_while,
};

const DEPENDENCY_INPUT_DOMAIN: &[u8] = b"bifrost.semantic-pack.dependency-input.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyArtifactRole {
    Binary,
    Sources,
    Reference,
    Runtime,
}

impl DependencyArtifactRole {
    fn as_str(self) -> &'static str {
        match self {
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
    pub path: PathBuf,
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
    artifact: ExactArtifact,
}

impl ExactDependencyArtifact {
    pub fn role(&self) -> DependencyArtifactRole {
        self.role
    }

    pub fn kind(&self) -> ExternalArtifactKind {
        self.kind
    }

    pub fn path(&self) -> &Path {
        self.artifact.path()
    }

    pub fn bytes(&self) -> &[u8] {
        self.artifact.bytes()
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyPackPreparationProfile {
    pub dependencies_considered: usize,
    pub artifacts_read: usize,
    pub artifact_bytes_read: u64,
    pub reused_packs: usize,
    pub generated_packs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackPreparationOutcome {
    pub packs: Vec<PreparedDependencyPack>,
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
}

impl std::ops::Deref for DependencyDiscoveryOutcome {
    type Target = [ResolvedDependency];

    fn deref(&self) -> &Self::Target {
        &self.dependencies
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
        if self.cancelled || (!self.complete && self.packs.is_empty()) {
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
        if dependency.artifacts.is_empty() {
            diagnostics.error(
                "dependency.artifacts",
                Some(&dependency.id),
                None,
                "resolved dependency has no exact local artifacts",
            );
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
                    Some(&artifact.path),
                    format!(
                        "dependency artifacts exceed configured total of {} bytes",
                        limits.max_total_artifact_bytes
                    ),
                );
                break;
            }
            let mut artifact_limits = limits.producer;
            artifact_limits.max_artifact_bytes = artifact_limits.max_artifact_bytes.min(remaining);
            match read_exact_artifact_while(&artifact.path, &artifact_limits, || {
                is_cancelled(cancellation)
            }) {
                Ok(exact) => {
                    profile.artifacts_read += 1;
                    profile.artifact_bytes_read = profile
                        .artifact_bytes_read
                        .saturating_add(exact.bytes().len() as u64);
                    exact_artifacts.push(ExactDependencyArtifact {
                        role: artifact.role,
                        kind: artifact.kind,
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
        && packs.len() == dependencies.len()
        && packs
            .iter()
            .all(|pack| pack.completeness == Completeness::Complete)
        && !diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DependencyPackDiagnosticSeverity::Error);
    DependencyPackPreparationOutcome {
        packs,
        evidence,
        diagnostics: diagnostics.diagnostics,
        suppressed_diagnostics: diagnostics.suppressed,
        complete,
        cancelled,
        profile,
    }
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
        ExternalArtifactKind::JavaSourceJar => "java_source_jar",
        ExternalArtifactKind::JavaClassJar => "java_class_jar",
        ExternalArtifactKind::ScalaSourceJar => "scala_source_jar",
        ExternalArtifactKind::DotNetAssembly => "dotnet_assembly",
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

struct BoundedDependencyDiagnostics {
    diagnostics: Vec<DependencyPackDiagnostic>,
    suppressed: usize,
    max_diagnostics: usize,
    max_message_bytes: usize,
}

impl BoundedDependencyDiagnostics {
    fn new(limits: &DependencyPackLimits) -> Self {
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

    fn push(&mut self, mut diagnostic: DependencyPackDiagnostic) {
        diagnostic.message = truncate_utf8(&diagnostic.message, self.max_message_bytes);
        if self.diagnostics.len() < self.max_diagnostics {
            self.diagnostics.push(diagnostic);
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
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
