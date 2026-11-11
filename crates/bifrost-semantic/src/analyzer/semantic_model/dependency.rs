use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use crate::analyzer::semantic_model::GoPinnedPackage;

use crate::analyzer::semantic::topology::DependencyScope;

use crate::analyzer::semantic_model::ActivationSelector;

use crate::analyzer::semantic_model::ArtifactProducerLimits;

use crate::analyzer::semantic_model::AuthoredSemanticModelPack;

use crate::analyzer::semantic_model::CatalogCoordinate;

use crate::analyzer::semantic_model::CatalogError;

use crate::analyzer::semantic_model::CompilerOptions;

use crate::analyzer::semantic_model::Completeness;

use crate::analyzer::semantic_model::Diagnostic;

use crate::analyzer::semantic_model::ExactArtifact;

use crate::analyzer::semantic_model::ExactSourceEntry;

use crate::analyzer::semantic_model::ExternalArtifactKind;

use crate::analyzer::semantic_model::GeneratedProduction;

use crate::analyzer::semantic_model::GeneratedProductionKey;

use crate::analyzer::semantic_model::NameSelector;

use crate::analyzer::semantic_model::Producer;

use crate::analyzer::semantic_model::ProducerDiagnostic;

use crate::analyzer::semantic_model::ProducerDiagnosticSeverity;

use crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION;

use crate::analyzer::semantic_model::SemanticModelActivationEvidence;

use crate::analyzer::semantic_model::SemanticModelActivationRequest;

use crate::analyzer::semantic_model::SemanticPackSelectorQuery;

use crate::analyzer::semantic_model::compile_pack;

const DEPENDENCY_INPUT_DOMAIN: &[u8] = b"bifrost.semantic-pack.dependency-input.v1";
const DEPENDENCY_SOURCE_IDENTITY_DOMAIN: &[u8] =
    b"bifrost.semantic-pack.dependency-source-identity.v1";
#[doc(hidden)]
pub const GENERATED_PRODUCTION_LOCK_RETRY: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyArtifactRole {
    Metadata,
    Declarations,
    Binary,
    Sources,
    Reference,
    Runtime,
}

#[cfg(test)]
mod external_discovery_read_tests {
    use brokk_bifrost_core::analyzer::Language;

    use super::dependency_discovery_output_digest;
    use super::{
        DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, ExternalDiscoveryRead,
        UnverifiableDiscoveryRead,
    };

    #[test]
    fn output_digest_ignores_discovery_inputs_and_informational_evidence() {
        let base = DependencyDiscoveryEvidence::from_outcome(
            &DependencyDiscoveryOutcome::complete(Vec::new()),
        );
        let mut changed = base.clone();
        changed.informational_evidence.push(
            super::DependencyDiscoveryInformationalEvidence::CppMissingWorkspaceSources {
                count: 1,
                sample: vec!["missing.cc".into()],
            },
        );
        changed.project_read_identity =
            crate::analyzer::semantic::ids::StableDigest::sha256(b"other");
        changed.external_read_identity =
            crate::analyzer::semantic::ids::StableDigest::sha256(b"external");
        let digest = |value: &DependencyDiscoveryEvidence| {
            dependency_discovery_output_digest(|language| {
                (language == Language::Rust).then_some(value)
            })
        };
        assert_eq!(digest(&base), digest(&changed));
    }

    #[test]
    fn output_digest_tracks_modules_truncation_and_absence() {
        let base = DependencyDiscoveryEvidence::from_outcome(
            &DependencyDiscoveryOutcome::complete(Vec::new()),
        );
        let digest = |value: &DependencyDiscoveryEvidence| {
            dependency_discovery_output_digest(|language| {
                (language == Language::Rust).then_some(value)
            })
        };
        let mut module = base.clone();
        module.declared_modules.insert("example".into());
        let mut truncated = base.clone();
        truncated.truncated = true;
        assert_ne!(digest(&base), digest(&module));
        assert_ne!(digest(&base), digest(&truncated));
        assert_ne!(digest(&base), dependency_discovery_output_digest(|_| None));
    }

    #[test]
    fn external_file_content_controls_carry_and_process_output_refuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("configured.json");
        std::fs::write(&path, b"one").unwrap();
        let file = ExternalDiscoveryRead::file(&path, b"one");
        let mut evidence = DependencyDiscoveryEvidence::from_outcome(
            &DependencyDiscoveryOutcome::complete(Vec::new()),
        );
        assert!(evidence.carry_eligible_external_reads().is_none());
        evidence.external_reads_complete = true;
        evidence.external_reads.push(file.clone());
        assert!(evidence.carry_eligible_external_reads().is_some());
        assert!(file.still_matches());
        std::fs::write(&path, b"two").unwrap();
        assert!(!file.still_matches());
        evidence
            .external_reads
            .push(ExternalDiscoveryRead::Unverifiable(
                UnverifiableDiscoveryRead::ProcessOutput,
            ));
        assert!(evidence.carry_eligible_external_reads().is_none());
    }

    #[test]
    fn external_read_identity_frames_variant_and_path() {
        let outcome = DependencyDiscoveryOutcome::complete(Vec::new());
        let base = DependencyDiscoveryEvidence::from_outcome(&outcome);
        let first = base.clone().with_external_reads(
            vec![ExternalDiscoveryRead::AbsentFile {
                absolute_path: "/tmp/one".into(),
            }],
            true,
        );
        let other_path = base.clone().with_external_reads(
            vec![ExternalDiscoveryRead::AbsentFile {
                absolute_path: "/tmp/two".into(),
            }],
            true,
        );
        let other_variant = base.with_external_reads(
            vec![ExternalDiscoveryRead::OverBudgetFile {
                absolute_path: "/tmp/one".into(),
                size: 0,
            }],
            true,
        );
        assert_ne!(
            first.external_read_identity,
            other_path.external_read_identity
        );
        assert_ne!(
            first.external_read_identity,
            other_variant.external_read_identity
        );
        assert!(
            DependencyDiscoveryEvidence::from_outcome(&outcome)
                .with_external_reads(Vec::new(), true)
                .carry_eligible_external_reads()
                .is_some()
        );
        // Incompleteness the recorded reads determine, such as an approximate
        // standard library, is carried together with its truncated bit.
        let mut incomplete = DependencyDiscoveryOutcome::complete(Vec::new());
        incomplete.complete = false;
        let carried = DependencyDiscoveryEvidence::from_outcome(&incomplete)
            .with_external_reads(Vec::new(), true);
        assert!(carried.carry_eligible_external_reads().is_some());
        assert!(carried.truncated());
        // A diagnostic can stand for a failed read that left no key behind.
        incomplete
            .diagnostics
            .push(super::DependencyPackDiagnostic {
                severity: super::DependencyPackDiagnosticSeverity::Warning,
                code: "test.read_failed".to_owned(),
                dependency_id: None,
                location: None,
                message: "read failed".to_owned(),
            });
        assert!(
            DependencyDiscoveryEvidence::from_outcome(&incomplete)
                .with_external_reads(Vec::new(), true)
                .carry_eligible_external_reads()
                .is_none()
        );
    }
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
    /// Checked Rust declaration approximation carried to pack production.
    pub rust_artifact_approximation:
        Option<crate::analyzer::semantic_model::RustArtifactApproximation>,
    /// Ecosystem-specific import identity for this artifact when production
    /// depends on more than its bytes. Python uses this for qualified module
    /// names, so nested packages cannot collapse to their terminal filename.
    pub module: Option<String>,
    pub input: ResolvedDependencyArtifactInput,
    /// When present, binds later artifact preparation to the exact file that
    /// dependency discovery approved. The stored path must also remain its own
    /// canonical path so a replaced symlink cannot redirect the later read.
    pub expected_sha256: Option<String>,
    /// A digest the adapter can compute from cheap filesystem metadata without
    /// reading the artifact's bytes.
    ///
    /// It exists only to find an already recorded generated production before
    /// the exact read; it never decides what a production contains. Absent
    /// means "this artifact has no read-free identity", and preparation then
    /// reads the artifact exactly as it did before.
    pub source_identity: Option<ArtifactSourceIdentity>,
}

/// A read-free digest of one artifact's filesystem state.
///
/// The ecosystem adapter derives it from a structured projection of the
/// resolved artifact (a JDK's release digest plus every selected JMOD's
/// relative path, byte length, and modification time), never from artifact
/// bytes: computing it must not cost the read it exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSourceIdentity(String);

impl ArtifactSourceIdentity {
    pub fn from_digest(digest: String) -> Self {
        assert_lower_sha256_identity(&digest, "artifact source identity");
        Self(digest)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A read-free digest of one whole resolved dependency.
///
/// It folds the same adapter, evidence, provenance, and production-profile
/// frame as [`generated_production_key`] around each artifact's
/// [`ArtifactSourceIdentity`], so two callers with different limits cannot see
/// each other's mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencySourceIdentity(String);

impl DependencySourceIdentity {
    pub fn from_digest(digest: String) -> Self {
        assert_lower_sha256_identity(&digest, "dependency source identity");
        Self(digest)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn assert_lower_sha256_identity(digest: &str, identity: &str) {
    assert!(
        is_lower_sha256(digest),
        "{identity} must be a lowercase SHA-256 digest"
    );
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
            rust_artifact_approximation: None,
            module: None,
            input: ResolvedDependencyArtifactInput::File(path),
            expected_sha256: None,
            source_identity: None,
        }
    }

    pub fn exact_file(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        path: PathBuf,
        expected_sha256: String,
    ) -> Self {
        let mut artifact = Self::file(role, kind, path);
        artifact.expected_sha256 = Some(expected_sha256);
        artifact
    }

    pub fn module_file(
        role: DependencyArtifactRole,
        kind: ExternalArtifactKind,
        module: String,
        path: PathBuf,
    ) -> Self {
        let mut artifact = Self::file(role, kind, path);
        artifact.module = Some(module);
        artifact
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
            rust_artifact_approximation: None,
            module: None,
            input: ResolvedDependencyArtifactInput::SourceSet {
                root,
                relative_paths,
            },
            expected_sha256: None,
            source_identity: None,
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
        let mut artifact = Self::source_set(role, kind, root, relative_paths);
        artifact.module = Some(module);
        artifact
    }

    /// Attach the read-free identity an adapter derived for this artifact.
    ///
    /// Only an adapter that can prove the identity from the resolved artifact's
    /// structured metadata may attach one; preparation reuses a production
    /// without reading anything when every artifact of a dependency carries
    /// one.
    pub fn with_source_identity(mut self, identity: ArtifactSourceIdentity) -> Self {
        assert!(
            self.expected_sha256.is_none(),
            "a digest-bound artifact is already pinned to an exact byte digest"
        );
        self.source_identity = Some(identity);
        self
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

#[doc(hidden)]
pub fn activation_selector_for_evidence(
    evidence: &SemanticModelActivationEvidence,
) -> ActivationSelector {
    let name_selector = |coordinate: &CatalogCoordinate| NameSelector {
        name: coordinate.name.clone(),
        version: coordinate
            .version
            .as_ref()
            .map(|version| format!("={version}")),
    };
    ActivationSelector {
        package: evidence.package.as_ref().map(name_selector),
        module: evidence.module.as_ref().map(name_selector),
        toolchain: evidence.toolchain.as_ref().map(name_selector),
        targets: evidence.target.clone().into_iter().collect(),
        configurations: evidence.configuration.clone().into_iter().collect(),
        artifact_sha256: None,
    }
}

impl ResolvedDependency {
    #[doc(hidden)]
    pub fn has_language_artifact(&self, language: &str, kind: ExternalArtifactKind) -> bool {
        self.evidence.language == language
            && self.artifacts.iter().any(|artifact| artifact.kind == kind)
    }

    /// Whether discovery assumed this dependency instead of reading it from
    /// the workspace (see [`ASSUMED_DEPENDENCY_PROVENANCE_KEY`]).
    pub fn is_assumed(&self) -> bool {
        self.provenance
            .iter()
            .any(|entry| entry.key == ASSUMED_DEPENDENCY_PROVENANCE_KEY)
    }

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

/// The provenance key a resolver sets on a dependency it assumed because the
/// workspace states nothing, such as the CPython version of a Python
/// workspace that declares none (#10496). Its value says what was assumed.
///
/// An assumed dependency selects the same packs a declared one would, but no
/// installed pack for it is not a defect of the workspace: preparation
/// records no error for it and does not count it against completeness.
pub const ASSUMED_DEPENDENCY_PROVENANCE_KEY: &str = "dependency.assumed";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactDependencyArtifact {
    #[doc(hidden)]
    pub role: DependencyArtifactRole,
    #[doc(hidden)]
    pub kind: ExternalArtifactKind,
    #[doc(hidden)]
    pub module: Option<String>,
    #[doc(hidden)]
    pub artifact: ExactArtifact,
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

    #[doc(hidden)]
    pub fn exact(&self) -> &ExactArtifact {
        &self.artifact
    }

    pub fn sha256(&self) -> &str {
        self.artifact.sha256()
    }
}

impl crate::analyzer::semantic_model::ArtifactExtraction {
    /// Bind a producer's composite input to exact component bytes and their
    /// structured artifact slots, independently of enumeration and local paths.
    pub fn from_dependency_artifacts(
        kind: ExternalArtifactKind,
        artifacts: &[ExactDependencyArtifact],
    ) -> Self {
        let mut components = artifacts
            .iter()
            .map(|artifact| {
                let mut hasher = CanonicalHasher::new(b"bifrost.artifact-extraction.component.v1");
                hash_artifact_slot(
                    &mut hasher,
                    artifact.role(),
                    artifact.kind(),
                    artifact.module(),
                );
                hasher.field("sha256", artifact.sha256().as_bytes());
                hasher.finish()
            })
            .collect::<Vec<_>>();
        components.sort_unstable();
        let mut hasher = CanonicalHasher::new(b"bifrost.artifact-extraction.source-set.v1");
        hasher.sequence("components", &components, |hasher, digest| {
            hasher.field("component", digest)
        });
        Self::source_set(kind, &lower_hex_string(&hasher.finish()))
    }
}

#[derive(Debug, Deserialize)]
struct GoSourcePackageMetadata {
    import_path: String,
    name: String,
    files: Vec<String>,
}

#[doc(hidden)]
pub struct PreparedExactGoSource<'a> {
    #[doc(hidden)]
    pub artifact: &'a ExactArtifact,
    #[doc(hidden)]
    pub packages: Vec<GoPinnedPackage>,
}

#[doc(hidden)]
pub fn prepared_exact_go_source<'a>(
    dependency: &ResolvedDependency,
    artifacts: &'a [ExactDependencyArtifact],
) -> Result<Option<PreparedExactGoSource<'a>>, CatalogError> {
    // Other adapters may use the source-set framing as opaque production
    // input. Native Go source publication requires Go activation evidence.
    if dependency.evidence.language != "go" {
        return Ok(None);
    }
    let go_artifacts = artifacts
        .iter()
        .filter(|artifact| artifact.kind() == ExternalArtifactKind::GoSourceSet)
        .collect::<Vec<_>>();
    if go_artifacts.is_empty() {
        return Ok(None);
    }
    if go_artifacts.len() != 1 {
        return Err(CatalogError::Integrity(
            "Go exact source preparation requires exactly one Go source set".to_owned(),
        ));
    }
    let package_metadata = dependency
        .provenance
        .iter()
        .find(|entry| entry.key == "go.packages")
        .ok_or_else(|| {
            CatalogError::Integrity(
                "Go exact source preparation has no selected package metadata".to_owned(),
            )
        })?;
    let packages = serde_json::from_str::<Vec<GoSourcePackageMetadata>>(&package_metadata.value)
        .map_err(|error| {
            CatalogError::Integrity(format!(
                "Go exact source package metadata is invalid: {error}"
            ))
        })?;
    if packages.is_empty() {
        return Err(CatalogError::Integrity(
            "Go exact source preparation has no selected packages".to_owned(),
        ));
    }
    for (ordinal, package) in packages.iter().enumerate() {
        if package.import_path.is_empty() || package.name.is_empty() || package.files.is_empty() {
            return Err(CatalogError::Integrity(format!(
                "Go exact source package metadata entry {ordinal} must include a non-empty import path, package name, and file list"
            )));
        }
    }
    Ok(Some(PreparedExactGoSource {
        artifact: go_artifacts[0].exact(),
        packages: packages
            .into_iter()
            .map(|package| GoPinnedPackage {
                import_path: package.import_path,
                name: package.name,
                files: package.files,
            })
            .collect(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackProduction {
    pub pack: Option<AuthoredSemanticModelPack>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
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
    pub compiled: crate::analyzer::semantic_model::CompiledSemanticModelPack,
    pub completeness: Completeness,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
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
        suppressed_diagnostics: SuppressedDiagnostics,
    },
    InvalidOutput {
        code: String,
        message: String,
        diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: SuppressedDiagnostics,
    },
    Compilation {
        diagnostics: Vec<Diagnostic>,
        producer_diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: SuppressedDiagnostics,
    },
    Cancelled {
        diagnostics: Vec<ProducerDiagnostic>,
        suppressed_diagnostics: SuppressedDiagnostics,
    },
}

/// What one host-installed acquisition attempt is being asked for.
///
/// Both kinds name a catalog entry that preparation could not build locally.
/// An exact generated production is named by its key, because it is produced
/// from artifacts this workspace holds. A declared dependency has no local
/// artifact at all, so the only thing that identifies the pack it needs is the
/// evidence-only selector query preparation would use to select it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionRequest<'a> {
    GeneratedProduction(&'a GeneratedProductionKey),
    DeclaredPack(&'a SemanticPackSelectorQuery),
}

pub trait DependencyPackAdapter {
    fn adapter_name(&self) -> &str;
    fn adapter_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn producer(&self) -> Producer;
    /// The schema minted for this dependency's generated pack. The default
    /// preserves every existing adapter's production key and output contract.
    fn production_schema_version(&self, _dependency: &ResolvedDependency) -> u32 {
        SEMANTIC_MODEL_SCHEMA_VERSION
    }

    fn can_produce(&self, _dependency: &ResolvedDependency) -> bool {
        true
    }

    /// Whether this adapter's `expected_sha256` pins are content digests it
    /// computed from the opened artifact files through a trusted cache. Then a
    /// production already in the catalog under the pinned key was produced from
    /// bytes with those digests, and preparation reuses it without capturing the
    /// artifacts again. A pin a resolver took from one plain read at discovery
    /// does not qualify: preparation must read such an artifact again, because
    /// that read is what detects a replacement after discovery.
    fn reuses_productions_by_pinned_key(&self) -> bool {
        false
    }

    /// Whether `dependency` selects only compatible installed or reviewed
    /// workspace packs: an exact lockfile coordinate carries no artifact to
    /// produce from and names nothing to acquire.
    fn installed_packs_only(&self, _dependency: &ResolvedDependency) -> bool {
        false
    }

    /// Whether a compatible installed or reviewed pack for `dependency`'s
    /// coordinate replaces the declarations this adapter would generate from
    /// its artifacts. An ecosystem whose reviewed packs declare the same
    /// symbols as its generated ones opts in, because activating both would
    /// give one symbol two owners; the generated pack then serves only
    /// coordinates no reviewed pack covers.
    fn reviewed_pack_supersedes_production(&self, _dependency: &ResolvedDependency) -> bool {
        false
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
        adapter.production_schema_version(dependency),
    )
}

/// Derive the production key from selection's exact artifact pins.
pub fn pinned_generated_production_key(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    limits: &DependencyPackLimits,
) -> Result<Option<GeneratedProductionKey>, CatalogError> {
    if !adapter.can_produce(dependency)
        || dependency
            .artifacts
            .iter()
            .any(|a| a.expected_sha256.is_none())
    {
        return Ok(None);
    }
    let mut hasher = CanonicalHasher::new(DEPENDENCY_INPUT_DOMAIN);
    hash_dependency_frame(&mut hasher, adapter, dependency);
    hasher.sequence("artifacts", &dependency.artifacts, |hasher, artifact| {
        hash_artifact_slot(
            hasher,
            artifact.role,
            artifact.kind,
            artifact.module.as_deref(),
        );
        hasher.field(
            "sha256",
            artifact
                .expected_sha256
                .as_ref()
                .expect("pins checked")
                .as_bytes(),
        );
    });
    hash_production_profile(&mut hasher, limits);
    let producer = adapter.producer();
    GeneratedProductionKey::new(
        lower_hex_string(&hasher.finish()),
        producer.name,
        producer.version,
        adapter.production_schema_version(dependency),
    )
    .map(Some)
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
            suppressed_diagnostics: SuppressedDiagnostics::default(),
        });
    }

    let producer = adapter.producer();
    let key =
        generated_production_key(adapter, dependency, artifacts, limits).map_err(|error| {
            DependencyProductionFailure::InvalidOutput {
                code: "production.identity".to_owned(),
                message: error.to_string(),
                diagnostics: Vec::new(),
                suppressed_diagnostics: SuppressedDiagnostics::default(),
            }
        })?;
    let production = {
        let _scope = brokk_bifrost_core::profiling::scope_with(|| {
            format!("semantic_pack.produce[{}]", dependency.id)
        });
        adapter.produce(dependency, artifacts, &limits.producer, cancellation)
    };
    let producer_diagnostics = production.diagnostics;
    let suppressed_diagnostics = production.suppressed_diagnostics;
    let production_has_errors = producer_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == ProducerDiagnosticSeverity::Error)
        || suppressed_diagnostics.total() > 0;
    let Some(mut pack) = production.pack else {
        return Err(DependencyProductionFailure::NoPack {
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    };
    if production_has_errors {
        pack.completeness = Completeness::Partial;
    }
    // The key is minted before production. A producer writes the smallest
    // schema its content needs; dependency production may raise that label to
    // its exact key schema. Compilation below validates the raised pack before
    // any compiled output can be returned.
    if pack.schema_version > key.schema_version() {
        return Err(DependencyProductionFailure::InvalidOutput {
            code: "production.identity_mismatch".to_owned(),
            message: "adapter output schema exceeds its production key schema".to_owned(),
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
    pack.schema_version = key.schema_version();
    if pack.producer != producer || pack.schema_version != key.schema_version() {
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
    let go_source_sha256 = {
        let mut go_sources = artifacts
            .iter()
            .filter(|artifact| artifact.kind() == ExternalArtifactKind::GoSourceSet);
        match (go_sources.next(), go_sources.next()) {
            (Some(source), None) => Some(source.sha256().to_owned()),
            (None, None) => None,
            (_, Some(_)) => {
                return Err(DependencyProductionFailure::InvalidOutput {
                    code: "production.go_source_identity".to_owned(),
                    message: "Go production requires exactly one exact source set".to_owned(),
                    diagnostics: producer_diagnostics,
                    suppressed_diagnostics,
                });
            }
        }
    };
    let activation_artifact_sha256 = go_source_sha256
        .as_deref()
        .unwrap_or_else(|| key.input_digest());
    for shard in &mut pack.shards {
        for selector in &mut shard.activation {
            selector.artifact_sha256 = Some(activation_artifact_sha256.to_owned());
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
        let _scope = brokk_bifrost_core::profiling::scope_with(|| {
            format!("semantic_pack.compile[{}]", dependency.id)
        });
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
    pub suppressed_diagnostics: SuppressedDiagnostics,
    pub complete: bool,
    pub cancelled: bool,
    pub profile: DependencyPackPreparationProfile,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_path_independent_pack_reuse(
    first: &DependencyPackPreparationOutcome,
    second: &DependencyPackPreparationOutcome,
) {
    assert!(
        first.complete && second.complete,
        "first={:#?}\nsecond={:#?}",
        first,
        second
    );
    assert_eq!(
        second.packs[0].status,
        DependencyPackPreparationStatus::Reused
    );
    assert_eq!(first.packs[0].production, second.packs[0].production);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencyDiscoveryProfile {
    pub metadata_inputs_considered: usize,
    pub dependencies_resolved: usize,
    /// Bounded, non-gating observations about the discovery inputs. These do
    /// not imply a discovery failure and must not affect completeness.
    pub informational_evidence: Vec<DependencyDiscoveryInformationalEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyDiscoveryInformationalEvidence {
    /// Compile-database source entries structurally inside the workspace but
    /// absent from the analyzer's C/C++ workspace listing.
    CppMissingWorkspaceSources { count: usize, sample: Vec<PathBuf> },
    /// The standard-library pack this ecosystem's discovery expects for a
    /// language present in the workspace, and whether the workspace selects
    /// it. Not selecting a pack is an answer, not a discovery failure.
    StandardLibraryPack(StandardLibraryPackExpectation),
}

/// The standard-library semantic pack Bifrost's activation contract expects
/// for one language present in the workspace (#3464).
///
/// Every workspace in a language calls that language's standard library, so
/// its pack is never optional context. A workspace that declared no toolchain
/// used to resolve no dependency at all, and the report then said nothing
/// about the pack: not selected, not rejected, not considered. Discovery
/// records the expectation instead, so a report names the pack whether or not
/// it activated, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardLibraryPackExpectation {
    pub language: brokk_bifrost_core::analyzer::model::Language,
    pub pack_id: &'static str,
    /// Select newest catalog pack without claiming exact toolchain evidence.
    pub approximate: bool,
    pub selection: StandardLibraryPackSelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardLibraryPackSelection {
    /// Discovery resolved these artifact-less dependencies from a workspace
    /// declaration, or assumed them where the workspace declares nothing
    /// ([`ResolvedDependency::is_assumed`]). Preparation and the runtime
    /// decide whether the pack activates.
    Declared { dependency_ids: Vec<String> },
    /// No toolchain pin supplies exact dependency coordinates.
    Unpinned,
    /// The workspace states nothing that selects the pack, or states it in a
    /// form discovery refuses to read as exact evidence. The reason names what
    /// discovery read and what would select the pack.
    NotSelected { reason: String },
}

impl StandardLibraryPackExpectation {
    pub fn declared(
        language: brokk_bifrost_core::analyzer::model::Language,
        pack_id: &'static str,
        dependency_ids: Vec<String>,
    ) -> Self {
        assert!(
            !dependency_ids.is_empty(),
            "a declared {pack_id} expectation names the dependencies that declare it"
        );
        Self {
            language,
            pack_id,
            approximate: false,
            selection: StandardLibraryPackSelection::Declared { dependency_ids },
        }
    }

    pub fn approximate(
        language: brokk_bifrost_core::analyzer::model::Language,
        pack_id: &'static str,
    ) -> Self {
        Self {
            language,
            pack_id,
            approximate: true,
            selection: StandardLibraryPackSelection::Unpinned,
        }
    }

    pub fn not_selected(
        language: brokk_bifrost_core::analyzer::model::Language,
        pack_id: &'static str,
        reason: String,
    ) -> Self {
        Self {
            language,
            pack_id,
            approximate: false,
            selection: StandardLibraryPackSelection::NotSelected { reason },
        }
    }

    /// The reason a declared expectation reports when no installed pack serves
    /// the declaration.
    ///
    /// Analysis and catalog activation never download packs. The `bifrost`
    /// executable may acquire open content during bootstrap; other hosts must
    /// provide packs before activation. A missing pack therefore names the
    /// installation route, so the remedy is in the report.
    pub fn not_installed_reason(&self) -> String {
        let StandardLibraryPackSelection::Declared { dependency_ids } = &self.selection else {
            panic!(
                "only a declared {} expectation can lack an installed pack",
                self.pack_id
            );
        };
        format!(
            "{} selects it, but no installed pack serves it. Pack acquisition is a bootstrap step and does not run during analysis; \
             install a Bifrost-packs release with `bifrost install-semantic-packs` or \
             BIFROST_OPEN_SEMANTIC_PACK_BUNDLE",
            dependency_ids.join(", ")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDiscoveryOutcome {
    pub dependencies: Vec<ResolvedDependency>,
    pub diagnostics: Vec<DependencyPackDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
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
                informational_evidence: Vec::new(),
            },
            dependencies,
            diagnostics: Vec::new(),
            suppressed_diagnostics: SuppressedDiagnostics::default(),
            complete: true,
            cancelled: false,
        }
    }

    #[doc(hidden)]
    pub fn cancelled(
        diagnostics: Vec<DependencyPackDiagnostic>,
        suppressed_diagnostics: SuppressedDiagnostics,
        profile: DependencyDiscoveryProfile,
    ) -> Self {
        Self {
            dependencies: Vec::new(),
            diagnostics,
            suppressed_diagnostics,
            complete: false,
            cancelled: true,
            profile,
        }
    }

    #[doc(hidden)]
    pub fn cancelled_with_message(message: impl Into<String>) -> Self {
        Self::cancelled(
            vec![DependencyPackDiagnostic {
                severity: DependencyPackDiagnosticSeverity::Error,
                code: "discovery.cancelled".to_owned(),
                dependency_id: None,
                location: None,
                message: message.into(),
            }],
            SuppressedDiagnostics::default(),
            DependencyDiscoveryProfile::default(),
        )
    }

    /// The standard-library pack expectations this discovery recorded.
    pub fn standard_library_pack_expectations(
        &self,
    ) -> impl Iterator<Item = &StandardLibraryPackExpectation> {
        self.profile
            .informational_evidence
            .iter()
            .filter_map(|evidence| match evidence {
                DependencyDiscoveryInformationalEvidence::StandardLibraryPack(expectation) => {
                    Some(expectation)
                }
                DependencyDiscoveryInformationalEvidence::CppMissingWorkspaceSources { .. } => None,
            })
    }

    /// Record one standard-library pack expectation. It never changes
    /// completeness: declaring nothing is an answer, not a failure.
    pub fn expect_standard_library_pack(&mut self, expectation: StandardLibraryPackExpectation) {
        self.profile
            .informational_evidence
            .push(DependencyDiscoveryInformationalEvidence::StandardLibraryPack(expectation));
    }

    /// Convert discovery completeness into the shared diagnostic suppression
    /// vocabulary. This does not start discovery or read the filesystem.
    pub fn semantic_diagnostic_incomplete_reasons(
        &self,
    ) -> Vec<brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason> {
        if self.cancelled {
            vec![brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason::Cancelled]
        } else if !self.complete {
            vec![brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason::Truncated]
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
    declared_modules: brokk_bifrost_core::hash::HashSet<String>,
    truncated: bool,
    /// Discovery reported a diagnostic. A diagnostic can stand for a failed or
    /// transient read that left no recorded key, so this evidence is never
    /// carried across an update. An approximate standard-library expectation
    /// sets `truncated` without a diagnostic; its recorded absent toolchain
    /// probes pin it, so that evidence can be carried with its `truncated` bit.
    reported_diagnostics: bool,
    informational_evidence: Vec<DependencyDiscoveryInformationalEvidence>,
    /// Exact project inputs observed while discovering this ecosystem.
    pub project_read_keys: std::sync::Arc<[crate::analyzer::semantic::read_ledger::ReadKey]>,
    pub project_read_identity: crate::analyzer::semantic::ids::StableDigest,
    /// External inputs observed by discovery. An empty list is not a certificate
    /// until the resolver has been instrumented for every external read.
    pub external_reads: Vec<ExternalDiscoveryRead>,
    /// Only a fully instrumented resolver may set this to true.
    pub external_reads_complete: bool,
    pub external_read_identity: crate::analyzer::semantic::ids::StableDigest,
}

/// A discovery input outside the workspace project-read boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalDiscoveryRead {
    AbsentFile {
        absolute_path: std::path::PathBuf,
    },
    File {
        absolute_path: std::path::PathBuf,
        content: crate::analyzer::semantic::ids::StableDigest,
        size: u64,
    },
    OverBudgetFile {
        absolute_path: std::path::PathBuf,
        size: u64,
    },
    Environment {
        name: Box<str>,
        value: Option<std::ffi::OsString>,
    },
    Unverifiable(UnverifiableDiscoveryRead),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableDiscoveryRead {
    ProcessOutput,
    ExternalCacheWalk,
}

impl ExternalDiscoveryRead {
    pub fn file(path: &std::path::Path, bytes: &[u8]) -> Self {
        assert!(
            path.is_absolute(),
            "discovery file key needs an absolute path"
        );
        Self::File {
            absolute_path: path.to_path_buf(),
            content: crate::analyzer::semantic::ids::StableDigest::sha256(bytes),
            size: bytes.len() as u64,
        }
    }

    /// Check a file key without reading beyond the original byte budget.
    pub fn still_matches(&self) -> bool {
        match self {
            Self::AbsentFile { absolute_path } => !absolute_path.exists(),
            Self::File {
                absolute_path,
                content,
                size,
            } => {
                use std::io::Read;
                let Ok(file) = std::fs::File::open(absolute_path) else {
                    return false;
                };
                let mut bytes = Vec::new();
                if file
                    .take(size.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .is_err()
                {
                    return false;
                }
                bytes.len() as u64 == *size
                    && crate::analyzer::semantic::ids::StableDigest::sha256(&bytes) == *content
            }
            Self::Environment { name, value } => std::env::var_os(name.as_ref()) == *value,
            Self::OverBudgetFile { .. } | Self::Unverifiable(_) => false,
        }
    }
}

impl DependencyDiscoveryEvidence {
    /// Returns the external keys M2 can verify, or refuses carry when a read
    /// cannot be reproduced from a fixed input.
    pub fn carry_eligible_external_reads(&self) -> Option<&[ExternalDiscoveryRead]> {
        // Cancelled discovery never publishes evidence: activation stops
        // before it pushes the ecosystem's evidence.
        (!self.reported_diagnostics
            && self.external_reads_complete
            && self.external_reads.iter().all(|read| {
                matches!(
                    read,
                    ExternalDiscoveryRead::File { .. }
                        | ExternalDiscoveryRead::AbsentFile { .. }
                        | ExternalDiscoveryRead::Environment { .. }
                )
            }))
        .then_some(&self.external_reads)
    }
    pub fn with_project_reads(
        mut self,
        keys: std::sync::Arc<[crate::analyzer::semantic::read_ledger::ReadKey]>,
        identity: crate::analyzer::semantic::ids::StableDigest,
    ) -> Self {
        self.project_read_keys = keys;
        self.project_read_identity = identity;
        self
    }

    pub fn with_external_reads(mut self, keys: Vec<ExternalDiscoveryRead>, complete: bool) -> Self {
        let mut hash = CanonicalHasher::new(b"bifrost.external-discovery-reads.v1");
        hash.sequence("reads", &keys, |hash, key| {
            let path =
                |path: &Path| brokk_bifrost_core::path_utils::workspace_relative_slash_path(path);
            match key {
                ExternalDiscoveryRead::AbsentFile { absolute_path } => {
                    hash.field("kind", b"absent-file");
                    hash.field("path", path(absolute_path).as_bytes());
                }
                ExternalDiscoveryRead::File {
                    absolute_path,
                    content,
                    size,
                } => {
                    hash.field("kind", b"file");
                    hash.field("path", path(absolute_path).as_bytes());
                    hash.field("content", content.as_bytes());
                    hash.field("size", &size.to_be_bytes());
                }
                ExternalDiscoveryRead::OverBudgetFile {
                    absolute_path,
                    size,
                } => {
                    hash.field("kind", b"over-budget-file");
                    hash.field("path", path(absolute_path).as_bytes());
                    hash.field("size", &size.to_be_bytes());
                }
                ExternalDiscoveryRead::Environment { name, value } => {
                    hash.field("kind", b"environment");
                    hash.field("name", name.as_bytes());
                    hash.field("present", &[value.is_some() as u8]);
                    if let Some(value) = value {
                        hash.field("value", value.to_string_lossy().as_bytes());
                    }
                }
                ExternalDiscoveryRead::Unverifiable(reason) => {
                    hash.field("kind", b"unverifiable");
                    hash.field(
                        "reason",
                        match reason {
                            UnverifiableDiscoveryRead::ProcessOutput => b"process-output",
                            UnverifiableDiscoveryRead::ExternalCacheWalk => b"external-cache-walk",
                        },
                    );
                }
            }
        });
        self.external_read_identity =
            crate::analyzer::semantic::ids::StableDigest::from_array(hash.finish());
        self.external_reads = keys;
        self.external_reads_complete = complete;
        self
    }

    pub fn from_outcome(outcome: &DependencyDiscoveryOutcome) -> Self {
        let mut declared_modules = brokk_bifrost_core::hash::HashSet::default();
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
            reported_diagnostics: !outcome.diagnostics.is_empty(),
            informational_evidence: outcome.profile.informational_evidence.clone(),
            project_read_keys: std::sync::Arc::from([]),
            project_read_identity: crate::analyzer::semantic::ids::StableDigest::sha256([]),
            external_reads: Vec::new(),
            external_reads_complete: false,
            external_read_identity: crate::analyzer::semantic::ids::StableDigest::sha256([]),
        }
    }

    /// Whether discovery could not read everything the build declared, so a
    /// miss against [`Self::declares_module_path`] is not proof of absence.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Non-gating observations retained from discovery. Their presence does
    /// not make the dependency set incomplete.
    pub fn informational_evidence(&self) -> &[DependencyDiscoveryInformationalEvidence] {
        &self.informational_evidence
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

/// Identity of the dependency facts consumed by query-time boundary refinement.
/// Every language has an entry, including languages with no published evidence.
pub fn dependency_discovery_output_digest<'a>(
    mut evidence: impl FnMut(
        brokk_bifrost_core::analyzer::Language,
    ) -> Option<&'a DependencyDiscoveryEvidence>,
) -> crate::analyzer::semantic::ids::StableDigest {
    use brokk_bifrost_core::analyzer::Language;

    let mut hash = CanonicalHasher::new(b"bifrost.dependency-discovery-output.v1");
    for language in Language::ALL {
        hash.field("language", language.config_label().as_bytes());
        match evidence(language) {
            None => hash.field("state", b"absent"),
            Some(value) => {
                hash.field("state", b"present");
                let mut modules: Vec<_> = value.declared_modules.iter().collect();
                modules.sort_unstable();
                hash.sequence("declared-modules", &modules, |hash, module| {
                    hash.value(module.as_bytes());
                });
                hash.field("truncated", &[u8::from(value.truncated)]);
            }
        }
    }
    crate::analyzer::semantic::ids::StableDigest::from_array(hash.finish())
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

#[doc(hidden)]
pub const fn missing_dependency_boundary(
    declared: bool,
) -> brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus {
    if declared {
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalDeclaredUnindexed
    } else {
        brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalUnknown
    }
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
) -> Vec<brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason> {
    match evidence {
        None => vec![
            brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalUnknown,
            },
        ],
        Some(evidence) if evidence.truncated() => {
            vec![brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason::Truncated]
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

/// The installed-pack stage's per-ecosystem result: the preparation outcome
/// over the packs already installed in the catalog, plus the identities of the
/// dependencies that still need the full activation stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledDependencyPackPreparation {
    pub outcome: DependencyPackPreparationOutcome,
    pub pending: Vec<String>,
}

#[doc(hidden)]
pub fn record_reused_generated_pack(
    prepared: PreparedDependencyPack,
    dependency: &ResolvedDependency,
    diagnostics: &mut BoundedDependencyDiagnostics,
    evidence: &mut Vec<SemanticModelActivationEvidence>,
    packs: &mut Vec<PreparedDependencyPack>,
    profile: &mut DependencyPackPreparationProfile,
) {
    if prepared.completeness != Completeness::Complete {
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

#[doc(hidden)]
pub const PACK_UNAVAILABLE_MESSAGE: &str = "resolved dependency has no exact locally producible artifact or compatible installed \
     semantic pack";

/// The artifact-less dependency route observed cancellation and stopped
/// before it could resolve anything. Preparation stops with it.
#[doc(hidden)]
pub struct DeclaredPackCancelled;

/// The evidence-only catalog query for one dependency, or `None` when the
/// dependency carries no exact package, module, or toolchain version. Version-exact
/// selection (#1884) starts here: a versionless dependency never consults
/// installed packs, and the same query later names version near misses.
#[doc(hidden)]
pub fn installed_pack_query(dependency: &ResolvedDependency) -> Option<SemanticPackSelectorQuery> {
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

fn dependency_input_digest(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    artifacts: &[ExactDependencyArtifact],
    limits: &DependencyPackLimits,
) -> String {
    let mut hasher = CanonicalHasher::new(DEPENDENCY_INPUT_DOMAIN);
    hash_dependency_frame(&mut hasher, adapter, dependency);
    hasher.sequence("artifacts", artifacts, |hasher, artifact| {
        hash_artifact_slot(hasher, artifact.role, artifact.kind, artifact.module());
        hasher.field("sha256", artifact.sha256().as_bytes());
    });
    hash_production_profile(&mut hasher, limits);
    lower_hex_string(&hasher.finish())
}

/// Derive the read-free identity of one resolved dependency.
///
/// `None` means the exact read must happen: some artifact carries no read-free
/// identity, or one is already bound to an exact byte digest, so no catalog
/// answer can be trusted without reading.
pub fn dependency_source_identity(
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
    limits: &DependencyPackLimits,
) -> Option<DependencySourceIdentity> {
    if dependency.evidence.language == "go" {
        return None;
    }
    if dependency.artifacts.is_empty()
        || dependency.artifacts.iter().any(|artifact| {
            artifact.expected_sha256.is_some() || artifact.source_identity.is_none()
        })
    {
        return None;
    }
    let mut hasher = CanonicalHasher::new(DEPENDENCY_SOURCE_IDENTITY_DOMAIN);
    hash_dependency_frame(&mut hasher, adapter, dependency);
    hasher.sequence("artifacts", &dependency.artifacts, |hasher, artifact| {
        hash_artifact_slot(
            hasher,
            artifact.role,
            artifact.kind,
            artifact.module.as_deref(),
        );
        hasher.field(
            "source_identity",
            artifact
                .source_identity
                .as_ref()
                .expect("every artifact carries a source identity here")
                .as_str()
                .as_bytes(),
        );
    });
    hash_production_profile(&mut hasher, limits);
    Some(DependencySourceIdentity::from_digest(lower_hex_string(
        &hasher.finish(),
    )))
}

/// Hash the frame both dependency digests share: who produced the pack and
/// which dependency the pack describes.
///
/// The two digests differ only in how they name each artifact's contribution
/// (exact bytes versus a read-free identity), so a mapping recorded under one
/// can never be resolved as the other. Each caller hashes its own artifact
/// sequence and then [`hash_production_profile`], so the order of fields in
/// the canonical hash stays exactly what it was before this frame was shared.
fn hash_dependency_frame(
    hasher: &mut CanonicalHasher,
    adapter: &dyn DependencyPackAdapter,
    dependency: &ResolvedDependency,
) {
    hasher.field("adapter_name", adapter.adapter_name().as_bytes());
    hasher.field("adapter_version", adapter.adapter_version().as_bytes());
    hash_evidence(hasher, &dependency.evidence);
    let mut provenance: Vec<_> = dependency.provenance.iter().collect();
    provenance.sort_by(|left, right| (&left.key, &left.value).cmp(&(&right.key, &right.value)));
    hasher.sequence("provenance", &provenance, |hasher, entry| {
        hasher.field("key", entry.key.as_bytes());
        hasher.field("value", entry.value.as_bytes());
    });
}

fn hash_artifact_slot(
    hasher: &mut CanonicalHasher,
    role: DependencyArtifactRole,
    kind: ExternalArtifactKind,
    module: Option<&str>,
) {
    hasher.field("role", role.as_str().as_bytes());
    hasher.field("kind", artifact_kind_name(kind).as_bytes());
    hasher.field("module", module.unwrap_or("").as_bytes());
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
        crate::analyzer::semantic_model::CompressionPolicy::Automatic => "automatic",
        crate::analyzer::semantic_model::CompressionPolicy::AlwaysRaw => "raw",
        crate::analyzer::semantic_model::CompressionPolicy::AlwaysDeflate => "deflate",
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
    coordinate: Option<&crate::analyzer::semantic_model::CatalogCoordinate>,
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
        ExternalArtifactKind::PhpDeclarationStub => "php_declaration_stub",
        ExternalArtifactKind::CppHeaderSourceSet => "cpp_header_source_set",
    }
}

#[doc(hidden)]
pub fn activation_evidence(
    dependency: &ResolvedDependency,
    input_digest: &str,
) -> SemanticModelActivationEvidence {
    let mut evidence = dependency.evidence.clone();
    evidence.artifact_sha256 = Some(input_digest.to_owned());
    evidence
}

#[doc(hidden)]
pub fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    brokk_bifrost_core::cancellation::optional_is_cancelled(cancellation)
}

/// The diagnostics a bounded collector could not retain.
///
/// `errors` counts dropped error-severity diagnostics: the number that says
/// the evidence for a failure is missing. `warnings` counts every other
/// bounded omission recorded alongside them, so `total()` remains the single
/// number callers reported before the split.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SuppressedDiagnostics {
    pub warnings: usize,
    pub errors: usize,
}

impl SuppressedDiagnostics {
    pub fn total(&self) -> usize {
        self.warnings.saturating_add(self.errors)
    }
}

impl std::ops::AddAssign for SuppressedDiagnostics {
    fn add_assign(&mut self, other: Self) {
        self.warnings = self.warnings.saturating_add(other.warnings);
        self.errors = self.errors.saturating_add(other.errors);
    }
}

/// Decide whether one arriving diagnostic can take a slot in a bounded vector
/// that already holds its maximum, and record what that decision suppresses.
///
/// An arriving warning is dropped and counted. An arriving error evicts the
/// last retained warning and takes its slot: removing the last warning rather
/// than the first keeps the retained prefix in arrival order, so the earliest
/// context survives. When every retained diagnostic is already an error there
/// is nothing to evict, so the arriving error is dropped and counted.
///
/// Returns whether the caller should now push the arriving diagnostic.
#[doc(hidden)]
pub fn admit_into_full_diagnostics<T>(
    retained: &mut Vec<T>,
    suppressed: &mut SuppressedDiagnostics,
    incoming_is_warning: bool,
    is_warning: impl Fn(&T) -> bool,
) -> bool {
    if incoming_is_warning {
        suppressed.warnings = suppressed.warnings.saturating_add(1);
        return false;
    }
    let Some(index) = retained.iter().rposition(is_warning) else {
        suppressed.errors = suppressed.errors.saturating_add(1);
        return false;
    };
    retained.remove(index);
    suppressed.warnings = suppressed.warnings.saturating_add(1);
    true
}

#[doc(hidden)]
pub struct BoundedDependencyDiagnostics {
    #[doc(hidden)]
    pub diagnostics: Vec<DependencyPackDiagnostic>,
    #[doc(hidden)]
    pub suppressed: SuppressedDiagnostics,
    max_diagnostics: usize,
    max_message_bytes: usize,
}

impl BoundedDependencyDiagnostics {
    #[doc(hidden)]
    pub fn new(limits: &DependencyPackLimits) -> Self {
        Self {
            diagnostics: Vec::new(),
            suppressed: SuppressedDiagnostics::default(),
            max_diagnostics: limits.max_diagnostics,
            max_message_bytes: limits.max_diagnostic_message_bytes,
        }
    }

    #[doc(hidden)]
    pub fn producer(&mut self, dependency_id: Option<&str>, diagnostic: ProducerDiagnostic) {
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

    #[doc(hidden)]
    pub fn catalog(&mut self, dependency_id: Option<&str>, code: &str, error: CatalogError) {
        self.error(code, dependency_id, None, error.to_string());
    }

    #[doc(hidden)]
    pub fn warning(
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

    #[doc(hidden)]
    pub fn error(
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

    #[doc(hidden)]
    pub fn error_location(
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

    #[doc(hidden)]
    pub fn push(&mut self, mut diagnostic: DependencyPackDiagnostic) {
        diagnostic.message = truncate_utf8(&diagnostic.message, self.max_message_bytes);
        if self.diagnostics.len() < self.max_diagnostics
            || admit_into_full_diagnostics(
                &mut self.diagnostics,
                &mut self.suppressed,
                diagnostic.severity == DependencyPackDiagnosticSeverity::Warning,
                |retained| retained.severity == DependencyPackDiagnosticSeverity::Warning,
            )
        {
            self.diagnostics.push(diagnostic);
        }
    }

    #[doc(hidden)]
    pub fn finish(self) -> (Vec<DependencyPackDiagnostic>, SuppressedDiagnostics) {
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn diagnostic_codes(diagnostics: &[DependencyPackDiagnostic]) -> Vec<&str> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[cfg(test)]
mod semantic_diagnostic_evidence_tests {

    use crate::analyzer::semantic_model::dependency::*;

    use brokk_bifrost_core::analyzer::model::SemanticDiagnosticIncompleteReason;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

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

#[cfg(test)]
mod bounded_dependency_diagnostics_tests {

    use crate::analyzer::semantic_model::dependency::*;

    fn diagnostic(
        severity: DependencyPackDiagnosticSeverity,
        code: impl Into<String>,
    ) -> DependencyPackDiagnostic {
        DependencyPackDiagnostic {
            severity,
            code: code.into(),
            dependency_id: None,
            location: None,
            message: "bounded diagnostic".to_owned(),
        }
    }

    #[test]
    fn error_at_the_cap_evicts_the_last_retained_warning() {
        let limits = DependencyPackLimits::default();
        let mut collector = BoundedDependencyDiagnostics::new(&limits);
        for index in 0..limits.max_diagnostics {
            collector.push(diagnostic(
                DependencyPackDiagnosticSeverity::Warning,
                format!("warning.{index}"),
            ));
        }
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Error,
            "compile_pack",
        ));
        let (diagnostics, suppressed) = collector.finish();

        assert_eq!(diagnostics.len(), limits.max_diagnostics);
        let mut expected: Vec<String> = (0..limits.max_diagnostics - 1)
            .map(|index| format!("warning.{index}"))
            .collect();
        expected.push("compile_pack".to_owned());
        assert_eq!(
            crate::analyzer::semantic_model::dependency::diagnostic_codes(&diagnostics),
            expected
        );
        assert_eq!(
            suppressed,
            SuppressedDiagnostics {
                warnings: 1,
                errors: 0
            }
        );
    }

    #[test]
    fn a_full_error_vector_counts_both_suppressed_severities() {
        let limits = DependencyPackLimits::default();
        let mut collector = BoundedDependencyDiagnostics::new(&limits);
        for index in 0..limits.max_diagnostics {
            collector.push(diagnostic(
                DependencyPackDiagnosticSeverity::Error,
                format!("error.{index}"),
            ));
        }
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Warning,
            "late.warning",
        ));
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Error,
            "late.error",
        ));
        let (diagnostics, suppressed) = collector.finish();

        let expected: Vec<String> = (0..limits.max_diagnostics)
            .map(|index| format!("error.{index}"))
            .collect();
        assert_eq!(
            crate::analyzer::semantic_model::dependency::diagnostic_codes(&diagnostics),
            expected
        );
        assert_eq!(
            suppressed,
            SuppressedDiagnostics {
                warnings: 1,
                errors: 1
            }
        );
    }

    #[test]
    fn below_the_cap_nothing_is_suppressed_and_arrival_order_holds() {
        let limits = DependencyPackLimits::default();
        let mut collector = BoundedDependencyDiagnostics::new(&limits);
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Warning,
            "first",
        ));
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Error,
            "second",
        ));
        collector.push(diagnostic(
            DependencyPackDiagnosticSeverity::Warning,
            "third",
        ));
        let (diagnostics, suppressed) = collector.finish();

        assert_eq!(
            crate::analyzer::semantic_model::dependency::diagnostic_codes(&diagnostics),
            vec!["first", "second", "third"]
        );
        assert_eq!(suppressed, SuppressedDiagnostics::default());
        assert_eq!(suppressed.total(), 0);
    }
}
