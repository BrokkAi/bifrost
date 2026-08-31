use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use crate::CancellationToken;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use crate::analyzer::topology::DependencyScope;
use crate::hash::{HashSet, set_with_capacity};

use super::{
    ArtifactProducerLimits, AuthoredSemanticModelPack, CatalogCandidate, CatalogError,
    CatalogPackSourceKind, CompilerOptions, Completeness, Diagnostic, ExactArtifact,
    ExactSourceEntry, ExternalArtifactKind, GeneratedProduction, GeneratedProductionKey,
    PackExtractionAccounting, Producer, ProducerDiagnostic, ProducerDiagnosticSeverity,
    SEMANTIC_MODEL_SCHEMA_VERSION, SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticPackCatalog, SemanticPackSelectorQuery, compile_pack,
    producer::{read_exact_artifact_while, read_exact_source_set_while},
};

const DEPENDENCY_INPUT_DOMAIN: &[u8] = b"bifrost.semantic-pack.dependency-input.v1";
const GENERATED_PRODUCTION_LOCK_RETRY: Duration = Duration::from_millis(10);

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

    /// A source set whose ecosystem import identity is known. Composer uses this
    /// for a PSR-4 namespace prefix, so one package's separately mapped prefixes
    /// stay distinguishable after the files are collected.
    pub fn module_source_set(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        module: String,
        root: PathBuf,
        relative_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            role,
            kind,
            module: Some(module),
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
    /// The scope the build declares this dependency in, where the resolver can
    /// prove it (#2442). The vocabulary is shared with internal topology
    /// edges, so "compile-scoped" means one thing across the whole envelope.
    ///
    /// [`DependencyScope::Unknown`] is the default and the honest answer for a
    /// resolver that reads an installed-artifact layout rather than a
    /// declaration: a lockfile entry or a site-packages distribution says the
    /// package is present, not what depends on it and how.
    ///
    /// This deliberately does not feed the dependency input digest. Scope is
    /// evidence about the build, not about the artifact bytes a pack is
    /// produced from, so a dependency that moves from `compile` to `test`
    /// scope must not invalidate an otherwise identical generated pack.
    pub scope: DependencyScope,
    /// The topology entity that declares this dependency, where the resolver
    /// can prove it: the Maven target whose pom lists it, the Gradle project
    /// whose lockfile carries it. `None` when the evidence names no declaring
    /// entity, which is every ecosystem whose resolver reads an installed
    /// layout.
    pub declared_by: Option<String>,
}

impl ResolvedDependency {
    /// A dependency whose build scope and declaring entity are not established
    /// by the evidence the resolver read.
    ///
    /// Most resolvers are in this position by construction: they enumerate an
    /// installed artifact layout, which proves presence and nothing about the
    /// declaration. Naming that here keeps the twenty-odd construction sites
    /// from each repeating two `Unknown`s.
    pub fn undeclared_scope(
        id: String,
        evidence: SemanticModelActivationEvidence,
        provenance: Vec<DependencyProvenance>,
        artifacts: Vec<ResolvedDependencyArtifact>,
    ) -> Self {
        Self {
            id,
            evidence,
            provenance,
            artifacts,
            scope: DependencyScope::Unknown,
            declared_by: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyProvenance {
    pub key: String,
    pub value: String,
}

/// Whether one resolver may start a process (#2442).
///
/// This exists because the claim it replaces was false. The
/// `DependencyPackEcosystem::dependency_inputs` doc comment said "no resolver
/// runs a package manager and none opens a network connection", while JVM
/// discovery in `JvmDependencyDiscoveryMode::OfflineBuildTools` runs `mvn
/// dependency:list` and an init-script Gradle task, and Go discovery runs `go
/// list`. A per-resolver, configuration-aware answer cannot drift from the
/// resolvers the way one prose sentence did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubprocessPolicy {
    /// The resolver only reads files. Every network-facing tool stays
    /// unstarted.
    Forbidden,
    /// The resolver may run the configured build tool in its offline mode,
    /// under the bounded-process timeout and output caps. Still no network is
    /// opened by Bifrost; whether the tool itself honours offline mode is the
    /// tool's contract, which is why this is a distinct policy rather than a
    /// footnote on `Forbidden`.
    OfflineBuildTools,
}

impl SubprocessPolicy {
    pub const fn runs_processes(self) -> bool {
        matches!(self, Self::OfflineBuildTools)
    }
}

/// The work one dependency resolver may do before it must answer incomplete.
///
/// Each resolver declares the caps it enforces, so a host can compare
/// ecosystems and a reviewer can see one table instead of nine sets of private
/// constants. The values are per-resolver rather than global because the
/// ecosystems differ in kind: reading a `project.assets.json` is one file, and
/// walking a Python environment is a directory tree whose size is the
/// environment's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyResolverBounds {
    /// Upper bound on filesystem entries the resolver visits beyond the
    /// project's own file listing. `None` where the walk is that listing plus
    /// `DependencyPackLimits::max_dependencies`, which is most of them.
    pub max_files_walked: Option<usize>,
    /// Upper bound on bytes of build metadata the resolver reads from one
    /// file. `None` where the resolver reads whole artifacts under
    /// `DependencyPackLimits`'s byte budget instead of a per-file cap of its
    /// own.
    pub max_metadata_bytes: Option<u64>,
    pub subprocess: SubprocessPolicy,
    /// Upper bound on the resolver's own wall clock. `None` where the resolver
    /// starts no process, so there is no clock to bound: file reads are
    /// bounded by the byte and count caps above.
    pub wall_clock: Option<std::time::Duration>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactDependencyArtifact {
    role: DependencyArtifactRole,
    kind: ExternalArtifactKind,
    module: Option<String>,
    artifact: ExactArtifact,
}

impl ExactDependencyArtifact {
    /// Pair an exact artifact read with the dependency role and ecosystem
    /// kind that the adapter will use during production.
    pub fn from_exact(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        module: Option<String>,
        artifact: ExactArtifact,
    ) -> Self {
        Self {
            role,
            kind,
            module,
            artifact,
        }
    }

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

/// The exact, compiled result of producing one dependency semantic pack.
///
/// This is deliberately separate from catalog installation. Release tooling
/// and runtime preparation must compile the same bytes and derive the same
/// identity, while each caller remains responsible for where those bytes are
/// installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDependencyProduction {
    pub key: GeneratedProductionKey,
    pub compiled: super::CompiledSemanticModelPack,
    pub completeness: Completeness,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
}

/// Why exact dependency production did not return a compiled pack.
///
/// Producer diagnostics are retained on every producer-related variant so a
/// runtime caller can preserve the existing bounded diagnostic behavior while
/// release tooling can report the same extraction evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyProductionFailure {
    NoPack {
        diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: usize,
    },
    InvalidOutput {
        code: String,
        message: String,
        diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: usize,
    },
    Compilation {
        diagnostics: Vec<Diagnostic>,
        producer_diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: usize,
    },
    Cancelled {
        diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: usize,
    },
}

/// A process-wide, host-installed attempt to acquire one exact generated
/// production. The callback may install bytes into `catalog`, but cannot hand
/// a pack directly to preparation. Preparation always re-reads the catalog
/// after this hook, which keeps catalog verification authoritative.
pub type GeneratedProductionAcquisitionHook =
    fn(&SemanticPackCatalog, &GeneratedProductionKey) -> Result<(), String>;

static GENERATED_PRODUCTION_ACQUISITION_HOOK: OnceLock<
    RwLock<Option<GeneratedProductionAcquisitionHook>>,
> = OnceLock::new();

fn acquisition_hook_slot() -> &'static RwLock<Option<GeneratedProductionAcquisitionHook>> {
    GENERATED_PRODUCTION_ACQUISITION_HOOK.get_or_init(|| RwLock::new(None))
}

/// Install or clear the process-wide exact-production acquisition hook.
///
/// The previous hook is returned so a caller that temporarily owns process
/// configuration, such as a test harness, can restore it exactly.
pub fn set_generated_production_acquisition_hook(
    hook: Option<GeneratedProductionAcquisitionHook>,
) -> Option<GeneratedProductionAcquisitionHook> {
    let mut slot = acquisition_hook_slot()
        .write()
        .expect("generated-production acquisition hook mutex poisoned");
    std::mem::replace(&mut *slot, hook)
}

fn generated_production_acquisition_hook() -> Option<GeneratedProductionAcquisitionHook> {
    *acquisition_hook_slot()
        .read()
        .expect("generated-production acquisition hook mutex poisoned")
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

/// Derive the canonical key for one exact dependency production.
///
/// The digest includes the adapter identity, normalized dependency evidence,
/// exact artifact digests, and every production-affecting limit. It excludes
/// filesystem paths and modification times, allowing equal inputs from
/// separate workspaces to share a generated production.
pub fn generated_production_key(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    artifacts: &[ExactDependencyArtifact],
    limits: &DependencyPackLimits,
) -> Result<GeneratedProductionKey, CatalogError> {
    let input_digest = dependency_input_digest(adapter, dependency, artifacts, limits);
    let producer = adapter.producer();
    GeneratedProductionKey::new(
        input_digest,
        producer.name,
        producer.version,
        SEMANTIC_MODEL_SCHEMA_VERSION,
    )
}

/// Produce and compile one exact dependency semantic pack.
///
/// This is the single production path shared by runtime preparation and
/// release qualification. It validates the adapter's declared identity,
/// binds every activation selector to the exact input digest, and applies the
/// same compiler options used by runtime preparation.
pub fn compile_exact_dependency_production(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    artifacts: &[ExactDependencyArtifact],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<CompiledDependencyProduction, DependencyProductionFailure> {
    if is_cancelled(cancellation) {
        return Err(DependencyProductionFailure::Cancelled {
            diagnostics: Vec::new(),
            suppressed_diagnostics: 0,
        });
    }

    let producer = adapter.producer();
    let key =
        generated_production_key(adapter, dependency, artifacts, limits).map_err(|error| {
            DependencyProductionFailure::InvalidOutput {
                code: "production.identity".to_owned(),
                message: error.to_string(),
                diagnostics: Vec::new(),
                suppressed_diagnostics: 0,
            }
        })?;
    let production = {
        let _scope =
            crate::profiling::scope_with(|| format!("semantic_pack.produce[{}]", dependency.id));
        adapter.produce(dependency, artifacts, &limits.producer, cancellation)
    };
    let producer_diagnostics = production.diagnostics;
    let suppressed_diagnostics = production.suppressed_diagnostics;
    let production_has_errors = producer_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == ProducerDiagnosticSeverity::Error)
        || suppressed_diagnostics > 0;
    let Some(mut pack) = production.pack else {
        return Err(DependencyProductionFailure::NoPack {
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    };
    if production_has_errors {
        pack.completeness = Completeness::Partial;
    }
    if pack.producer != producer || pack.schema_version != SEMANTIC_MODEL_SCHEMA_VERSION {
        return Err(DependencyProductionFailure::InvalidOutput {
            code: "production.identity_mismatch".to_owned(),
            message: "adapter output does not match its declared producer or schema identity"
                .to_owned(),
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    if pack.language != dependency.evidence.language
        || pack.ecosystem != dependency.evidence.ecosystem
    {
        return Err(DependencyProductionFailure::InvalidOutput {
            code: "production.evidence_mismatch".to_owned(),
            message: "adapter output language or ecosystem does not match dependency evidence"
                .to_owned(),
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    if pack.shards.iter().any(|shard| shard.activation.is_empty()) {
        return Err(DependencyProductionFailure::InvalidOutput {
            code: "production.activation_missing".to_owned(),
            message: "adapter output contains a shard without activation selectors".to_owned(),
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    for shard in &mut pack.shards {
        for selector in &mut shard.activation {
            selector.artifact_sha256 = Some(key.input_digest().to_owned());
        }
    }
    let completeness = pack.completeness;
    if is_cancelled(cancellation) {
        return Err(DependencyProductionFailure::Cancelled {
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    let compiled = {
        let _scope =
            crate::profiling::scope_with(|| format!("semantic_pack.compile[{}]", dependency.id));
        match compile_pack(&pack, &limits.compiler) {
            Ok(compiled) => compiled,
            Err(diagnostics) => {
                return Err(DependencyProductionFailure::Compilation {
                    diagnostics,
                    producer_diagnostics,
                    suppressed_diagnostics,
                });
            }
        }
    };
    if is_cancelled(cancellation) {
        return Err(DependencyProductionFailure::Cancelled {
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    Ok(CompiledDependencyProduction {
        key,
        compiled,
        completeness,
        diagnostics: producer_diagnostics,
        suppressed_diagnostics,
    })
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
    pub gaps: usize,
    pub activation_ready: bool,
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
        self.declares_path_below(path, '.')
    }

    /// Whether the build declares the Go module that `import_path` routes
    /// through: an exact declared identity, or one reached by walking the
    /// slash-separated import path back toward its module root
    /// (`github.com/pkg/errors/internal` is declared when the
    /// `github.com/pkg/errors` module is).
    ///
    /// Go import paths are slash-separated, so [`Self::declares_module_path`]'s
    /// dotted walk cannot answer this: `github.com/pkg/errors/internal` splits
    /// on `.` into `github`, which names nothing. The declared identities are
    /// the module paths discovery itself recorded, so segment-prefix
    /// containment is their defined structure, not a re-parse of source text.
    pub fn declares_go_import_path(&self, import_path: &str) -> bool {
        self.declares_path_below(import_path, '/')
    }

    /// Whether the build declares the gem that a Ruby `require` argument loads:
    /// an exact declared gem name, or one reached by walking the load path back
    /// toward its root (`widget/core` is declared when the `widget` gem is).
    ///
    /// Ruby discovery records one identity per locked gem, which is the bare
    /// gem name (`crates/bifrost-analysis/src/analyzer/ruby/dependency_discovery.rs`
    /// puts `RubyGemApiArtifact::name` in the package coordinate and leaves the
    /// module coordinate empty). A require argument is the slash-separated load
    /// path a gem publishes, so this shares Go's walk rather than the dotted
    /// one: `widget/core` splits on `.` into itself and would match nothing.
    ///
    /// A Ruby *constant* path is not a load path and must not be asked here.
    /// `Widget::Config` is `::`-separated and its head, `Widget`, is a constant
    /// name that only an inflection rule relates to the gem name `widget`.
    /// Bifrost does not guess inflections, so a constant is classified against
    /// the activated overlay instead (see `ruby::constant_identity`).
    pub fn declares_ruby_require_path(&self, require_path: &str) -> bool {
        self.declares_path_below(require_path, '/')
    }

    /// The shared containment walk behind the three `declares_*` accessors: an
    /// exact declared identity, or one reached by removing trailing
    /// `separator`-delimited segments. Segment removal rather than
    /// `str::starts_with` is what keeps `requestsfoo` from matching `requests`.
    fn declares_path_below(&self, path: &str, separator: char) -> bool {
        if path.is_empty() {
            return false;
        }
        if self.declared_modules.contains(path) {
            return true;
        }
        let mut prefix = path;
        while let Some((head, _)) = prefix.rsplit_once(separator) {
            if self.declared_modules.contains(head) {
                return true;
            }
            prefix = head;
        }
        false
    }
}

/// What retained discovery evidence says about one module path when nothing
/// indexed it.
///
/// Resolution-trace boundary refinement and proof-gated diagnostics ask the
/// same question and must not answer it differently; they only render the
/// answer differently. The trace collapses everything but "the build knows
/// nothing about this" into `ExternalDeclaredUnindexed`, while diagnostics
/// keep truncation apart from a declared-but-unindexed distribution because
/// the two carry different typed suppression reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedDiscoveryVerdict {
    /// No discovery has run against this analyzer, so nothing is retained.
    NoDiscovery,
    /// Discovery could not read everything the build declared, so a miss is
    /// not proof that the build declares nothing.
    Truncated,
    /// The build declares this module, or a module containing it.
    Declared,
    /// Discovery ran completely and the build declares nothing containing it.
    Undeclared,
}

/// Classify `module_path` against retained discovery evidence. This reads what
/// the analyzer already holds; it never starts discovery.
pub fn retained_discovery_verdict(
    evidence: Option<&DependencyDiscoveryEvidence>,
    module_path: &str,
) -> RetainedDiscoveryVerdict {
    match evidence {
        None => RetainedDiscoveryVerdict::NoDiscovery,
        Some(evidence) if evidence.truncated() => RetainedDiscoveryVerdict::Truncated,
        Some(evidence) if evidence.declares_module_path(module_path) => {
            RetainedDiscoveryVerdict::Declared
        }
        Some(_) => RetainedDiscoveryVerdict::Undeclared,
    }
}

/// Whether retained discovery evidence can still account for `module_path`:
/// the build declares it, or discovery could not read everything the build
/// declared, so a miss is not proof of absence.
///
/// A caller that hits here is at [`BoundaryStatus::ExternalDeclaredUnindexed`];
/// one that misses, with no other evidence, is at
/// [`BoundaryStatus::ExternalUnknown`]. Where no discovery has run, nothing is
/// retained and the honest answer is `false`. This function never starts
/// discovery.
///
/// [`BoundaryStatus::ExternalDeclaredUnindexed`]: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed
/// [`BoundaryStatus::ExternalUnknown`]: crate::analyzer::structural::BoundaryStatus::ExternalUnknown
pub fn retained_evidence_declares(
    evidence: Option<&DependencyDiscoveryEvidence>,
    module_path: &str,
) -> bool {
    matches!(
        retained_discovery_verdict(evidence, module_path),
        RetainedDiscoveryVerdict::Truncated | RetainedDiscoveryVerdict::Declared
    )
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
            match compatible_installed_pack(catalog, dependency, &mut diagnostics) {
                Ok(Some(installed)) => {
                    evidence.push(installed.evidence.clone());
                    installed_packs.push(installed);
                    profile.installed_packs += 1;
                }
                // No usable pack. Distinguish "a pack exists for another
                // version of this exact coordinate" from "no pack at all":
                // the near miss names the installed and required versions so
                // a version mismatch is attributable, never silent (#1884).
                Ok(None) => match installed_pack_query(dependency)
                    .map(|query| catalog.version_near_misses(&query))
                {
                    Some(Ok(near_misses)) if !near_misses.is_empty() => {
                        for near_miss in near_misses {
                            diagnostics.error(
                                "dependency.pack_version_mismatch",
                                Some(&dependency.id),
                                None,
                                near_miss.describe(),
                            );
                        }
                    }
                    Some(Err(error)) => {
                        diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error)
                    }
                    Some(Ok(_)) | None => diagnostics.error(
                        "dependency.pack_unavailable",
                        Some(&dependency.id),
                        None,
                        "resolved dependency has no exact locally producible artifact or compatible installed semantic pack",
                    ),
                },
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
        match reusable_generated_pack(catalog, &key, dependency, &input_digest) {
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
        match reusable_generated_pack(catalog, &key, dependency, &input_digest) {
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
            Err(error) => {
                diagnostics.catalog(Some(&dependency.id), "catalog.lookup", error);
                continue;
            }
        }

        if let Some(acquire) = generated_production_acquisition_hook() {
            if is_cancelled(cancellation) {
                cancelled = true;
                break;
            }
            if let Err(error) = acquire(catalog, &key) {
                diagnostics.warning(
                    "production.acquire",
                    Some(&dependency.id),
                    format!("could not acquire exact generated production: {error}"),
                );
            }
            // The provider can only attempt installation. Re-read through the
            // ordinary verified catalog path before falling back to production.
            match reusable_generated_pack(catalog, &key, dependency, &input_digest) {
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
                        diagnostics.suppressed = diagnostics
                            .suppressed
                            .saturating_add(suppressed_diagnostics);
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
                        diagnostics.suppressed = diagnostics
                            .suppressed
                            .saturating_add(suppressed_diagnostics);
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
                        diagnostics.suppressed = diagnostics
                            .suppressed
                            .saturating_add(suppressed_diagnostics);
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
        diagnostics.suppressed = diagnostics
            .suppressed
            .saturating_add(production.suppressed_diagnostics);
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
            catalog.install_generated(&production.key, &production.compiled)
        };
        match install {
            Ok(installed) => {
                let activation_evidence =
                    activation_evidence(dependency, production.key.input_digest());
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

fn record_reused_generated_pack(
    prepared: PreparedDependencyPack,
    dependency: &ResolvedDependency,
    diagnostics: &mut BoundedDependencyDiagnostics,
    evidence: &mut Vec<SemanticModelActivationEvidence>,
    packs: &mut Vec<PreparedDependencyPack>,
    profile: &mut DependencyPackPreparationProfile,
) {
    if prepared.completeness == Completeness::Partial {
        diagnostics.error(
            "production.partial",
            Some(&dependency.id),
            None,
            "cached dependency production has partial semantic coverage",
        );
    }
    evidence.push(prepared.evidence.clone());
    packs.push(prepared);
    profile.reused_packs += 1;
}

fn reusable_generated_pack(
    catalog: &SemanticPackCatalog,
    key: &GeneratedProductionKey,
    dependency: &ResolvedDependency,
    input_digest: &str,
) -> Result<Option<PreparedDependencyPack>, CatalogError> {
    let Some(production) = catalog.generated_production(key)? else {
        return Ok(None);
    };
    Ok(Some(PreparedDependencyPack {
        dependency_id: dependency.id.clone(),
        completeness: production.completeness,
        production,
        status: DependencyPackPreparationStatus::Reused,
        evidence: activation_evidence(dependency, input_digest),
    }))
}

/// The evidence-only catalog query for one dependency, or `None` when the
/// dependency carries no exact package, module, or toolchain version. Version-exact
/// selection (#1884) starts here: a versionless dependency never consults
/// installed packs, and the same query later names version near misses.
fn installed_pack_query(dependency: &ResolvedDependency) -> Option<SemanticPackSelectorQuery> {
    let has_exact_coordinate = dependency
        .evidence
        .package
        .as_ref()
        .and_then(|coordinate| coordinate.version.as_ref())
        .is_some()
        || dependency
            .evidence
            .module
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
        return None;
    }
    Some(SemanticPackSelectorQuery {
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
    })
}

fn compatible_installed_pack(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
    diagnostics: &mut BoundedDependencyDiagnostics,
) -> Result<Option<PreparedInstalledDependencyPack>, CatalogError> {
    let Some((installed, not_activation_ready)) =
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
    Ok(Some(installed))
}

fn compatible_installed_pack_evaluation(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Option<(PreparedInstalledDependencyPack, Vec<String>)>, CatalogError> {
    let candidates = compatible_installed_pack_candidates(catalog, dependency)?;
    let not_activation_ready = candidates
        .iter()
        .filter(|candidate| !candidate.activation_ready)
        .map(|candidate| candidate.not_activation_ready.clone())
        .collect();
    Ok(prepared_installed_pack(dependency, &candidates)
        .map(|installed| (installed, not_activation_ready)))
}

/// Curated partial declaration subsets are trusted only when Bifrost shipped
/// them. A locally installed partial pack still needs the ordinary extraction
/// accounting that makes it activation-ready; curated evidence must not turn
/// an arbitrary partial installation into trusted semantics.
fn compatible_curated_installed_pack(
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
struct InstalledPackCandidateEvaluation {
    manifest_digest: String,
    completeness: Completeness,
    gaps: usize,
    activation_ready: bool,
    source_kind: CatalogPackSourceKind,
    not_activation_ready: String,
}

fn compatible_installed_pack_candidates(
    catalog: &SemanticPackCatalog,
    dependency: &ResolvedDependency,
) -> Result<Vec<InstalledPackCandidateEvaluation>, CatalogError> {
    let Some(query) = installed_pack_query(dependency) else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    let mut accounted_manifests: HashSet<String> = set_with_capacity(4);
    for candidate in catalog.candidates(&query)? {
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
            let candidate_ready =
                super::pack_is_activation_ready(candidate.completeness(), extraction.as_ref());
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

fn prepared_installed_pack(
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
fn describe_not_activation_ready(
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
            "named gaps {} != reject count {}",
            accounting.gaps.len(),
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

/// Hash every limit that can change the compiled bytes of a generated
/// production, so callers with different but content-equivalent limits still
/// converge on the same identity.
///
/// `producer.max_diagnostics` and `producer.max_diagnostic_message_bytes` are
/// deliberately excluded: `BoundedProducerDiagnostics` only ever grows or
/// truncates the separate diagnostics side-channel (see producer.rs), never
/// the pack's declarations, members, or shard bytes, so raising either bound
/// cannot change what a production means. Excluding them keeps a release
/// bundle -- which must size its diagnostics cap to name every reject
/// (`MAX_SOURCE_SET_FILES` in release_bundle.rs) -- reusable by an ordinary
/// workspace's default-limits production of the exact same dependency and
/// artifacts; hashing them in would make every pre-shipped generated
/// production unreachable by runtime lookups, forcing every workspace to
/// re-derive it locally under the interactive-safety-bounded default instead
/// of reusing the bundle's fully-accounted one.
fn hash_production_profile(hasher: &mut CanonicalHasher, limits: &DependencyPackLimits) {
    let producer = limits.producer;
    for (field, value) in [
        ("producer_max_artifact_bytes", producer.max_artifact_bytes),
        ("producer_max_records", producer.max_records as u64),
        (
            "producer_max_signature_depth",
            producer.max_signature_depth as u64,
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
        ExternalArtifactKind::JdkJmodSet => "jdk_jmod_set",
        ExternalArtifactKind::DotNetAssembly => "dotnet_assembly",
        ExternalArtifactKind::RustdocJson => "rustdoc_json",
        ExternalArtifactKind::RustdocJsonSet => "rustdoc_json_set",
        ExternalArtifactKind::TypeScriptLibrarySet => "typescript_library_set",
        ExternalArtifactKind::GoSourceSet => "go_source_set",
        ExternalArtifactKind::PythonStub => "python_stub",
        ExternalArtifactKind::PythonSource => "python_source",
        ExternalArtifactKind::RubyGemArchive => "ruby_gem_archive",
        ExternalArtifactKind::ComposerPackageSourceSet => "composer_package_source_set",
        ExternalArtifactKind::CppHeaderSourceSet => "cpp_header_source_set",
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

    fn warning(
        &mut self,
        code: impl Into<String>,
        dependency_id: Option<&str>,
        message: impl Into<String>,
    ) {
        self.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Warning,
            code: code.into(),
            dependency_id: dependency_id.map(str::to_owned),
            location: None,
            message: message.into(),
        });
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
