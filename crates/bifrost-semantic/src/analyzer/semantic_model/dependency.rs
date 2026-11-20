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

use crate::analyzer::semantic_model::ApproximationReason;

use crate::analyzer::semantic_model::ApproximationReasons;

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

const DEPENDENCY_INPUT_DOMAIN: &[u8] = b"bifrost.semantic-pack.dependency-input.v1";
const DEPENDENCY_SOURCE_IDENTITY_DOMAIN: &[u8] =
    b"bifrost.semantic-pack.dependency-source-identity.v1";
#[doc(hidden)]
pub const GENERATED_PRODUCTION_LOCK_RETRY: Duration = Duration::from_millis(10);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
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
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: unbound preparation failures incorrectly permitted activation carry"
    )]
    fn unbound_preparation_failures_refuse_carry() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dependency.jar");
        let mut dependency = ResolvedDependency::undeclared_scope(
            "dependency".into(),
            SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            },
            Vec::new(),
            Vec::new(),
        );
        for scenario in 0..3 {
            if scenario != 0 {
                dependency.artifacts = vec![ResolvedDependencyArtifact::file(
                    DependencyArtifactRole::Binary,
                    ExternalArtifactKind::JavaClassJar,
                    path.clone(),
                )];
            }
            if scenario == 2 {
                std::fs::write(&path, b"before").unwrap();
            }
            let discovery = DependencyDiscoveryOutcome::complete(vec![dependency.clone()]);
            let bindings = preparation_input_bindings(
                &discovery.dependencies,
                &DependencyPackLimits::default(),
                None,
            );
            let capped = DependencyPackLimits {
                max_dependencies: 0,
                ..Default::default()
            };
            assert!(preparation_input_bindings(&discovery.dependencies, &capped, None).is_empty());
            let cancellation = CancellationToken::new();
            cancellation.cancel();
            assert!(
                preparation_input_bindings(
                    &discovery.dependencies,
                    &Default::default(),
                    Some(&cancellation)
                )
                .is_empty()
            );
            if scenario == 2 {
                let mut source_dependency = dependency.clone();
                source_dependency.artifacts[0].input = ResolvedDependencyArtifactInput::SourceSet {
                    root: dir.path().to_path_buf(),
                    relative_paths: vec![PathBuf::from("dependency.jar")],
                };
                let capped = DependencyPackLimits {
                    max_source_files_per_artifact: 0,
                    ..Default::default()
                };
                assert_eq!(
                    preparation_input_bindings(&[source_dependency], &capped, None),
                    vec![None]
                );
            }

            if scenario == 2 {
                std::fs::write(&path, b"changed during preparation").unwrap();
            }
            let evidence = DependencyDiscoveryEvidence::from_outcome(&discovery)
                .with_external_reads(Vec::new(), true);
            assert!(evidence.carry_eligible_external_reads().is_some());
            let evidence = evidence.with_preparation_failures(
                &discovery.dependencies,
                &[DependencyPreparationFailure {
                    dependency_id: dependency.id.clone(),
                    cause: DependencyPreparationFailureCause::PackUnavailable,
                }],
                &bindings,
            );
            // #9559 3d: 721150524d marked discovery truncated here, which
            // also flipped PHP's no-pack unknown boundary. An unbound failure
            // is instead recorded with its dependency and cause, so JVM gaps
            // can name it; it refuses carry and never replays. It has no
            // inputs to verify, so the reader does not treat it as stale.
            assert_eq!(
                evidence.preparation_failures,
                vec![RecordedPreparationFailure {
                    dependency: dependency.clone(),
                    cause: DependencyPreparationFailureCause::PackUnavailable,
                    inputs: PreparationFailureInputs::Unbound,
                }]
            );
            assert!(evidence.has_unbound_preparation_failures());
            assert!(!evidence.preparation_failures[0].inputs.still_match());
            assert!(
                !evidence.preparation_failures[0]
                    .inputs
                    .changed_since_binding()
            );
            assert!(!evidence.truncated());
            assert!(evidence.carry_eligible_external_reads().is_none());
        }
    }

    #[test]
    fn file_key_stat_fast_path_is_dropped_in_the_racy_window_and_never_enters_the_identity() {
        use brokk_bifrost_core::content_digest::metadata_change_identity;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("artifact.jar");
        std::fs::write(&path, b"one").unwrap();
        let identity = metadata_change_identity(&path).unwrap();
        let now = std::time::SystemTime::now();
        let later = now + std::time::Duration::from_secs(60);
        let identity_of = |read: ExternalDiscoveryRead| {
            DependencyDiscoveryEvidence::from_outcome(&DependencyDiscoveryOutcome::complete(
                Vec::new(),
            ))
            .with_external_reads(vec![read], true)
            .external_read_identity
        };

        // A write inside the observation's tick can hide a same-size rewrite,
        // so no stat identity is trusted and verification reads the bytes.
        let racy = ExternalDiscoveryRead::file_with_identity(&path, b"one", identity.clone(), now);
        assert!(matches!(
            racy,
            ExternalDiscoveryRead::File { identity: None, .. }
        ));
        let trusted = ExternalDiscoveryRead::file_with_identity(&path, b"one", identity, later);
        assert!(matches!(
            trusted,
            ExternalDiscoveryRead::File {
                identity: Some(_),
                ..
            }
        ));
        assert_eq!(
            identity_of(racy.clone()),
            identity_of(trusted.clone()),
            "the stat identity is not part of the observed fact"
        );

        // A matching identity answers without reading: a key whose recorded
        // content is wrong still matches, while the same key without the
        // identity falls back to the bytes and does not.
        let wrong = |read: ExternalDiscoveryRead| match read {
            ExternalDiscoveryRead::File {
                absolute_path,
                size,
                identity,
                ..
            } => ExternalDiscoveryRead::File {
                absolute_path,
                content: crate::analyzer::semantic::ids::StableDigest::sha256(b"zzz"),
                size,
                identity,
            },
            other => other,
        };
        assert!(racy.still_matches());
        assert!(trusted.still_matches());
        assert!(wrong(trusted.clone()).still_matches());
        assert!(!wrong(racy.clone()).still_matches());

        // The tick-sharing rewrite the racy rule exists for: same size, new
        // bytes. The dropped identity cannot vouch for it.
        std::fs::write(&path, b"two").unwrap();
        assert!(!racy.still_matches());
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
        // The incompleteness is part of a cold status, so a carried discovery
        // must be able to re-emit it: refused without the retained residue.
        assert!(carried.carry_eligible_external_reads().is_none());
        let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_tests();
        let carried = carried.with_retained_status(super::RetainedEcosystemStatus::retain(
            &incomplete,
            None,
            &budget,
        ));
        assert!(carried.carry_eligible_external_reads().is_some());
        assert!(carried.truncated());
        // A budget that refused the residue leaves nothing to re-emit, even
        // for a discovery that reported nothing.
        assert!(
            DependencyDiscoveryEvidence::from_outcome(&outcome)
                .with_external_reads(Vec::new(), true)
                .with_retained_status(None)
                .carry_eligible_external_reads()
                .is_none()
        );
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13517: a carried ecosystem replayed a preparation state that no carry check judged"
    )]
    fn an_unsettled_preparation_refuses_carry() {
        let mut unsettled = super::DependencyPackPreparationOutcome {
            failures: Vec::new(),
            packs: Vec::new(),
            installed_packs: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            suppressed_diagnostics: Default::default(),
            complete: true,
            cancelled: false,
            profile: Default::default(),
        };
        let complete_outcome = DependencyDiscoveryOutcome::complete(Vec::new());
        let carries = |preparation: &super::DependencyPackPreparationOutcome| {
            DependencyDiscoveryEvidence::from_outcome(&complete_outcome)
                .with_external_reads(Vec::new(), true)
                .with_retained_status(super::RetainedEcosystemStatus::retain(
                    &complete_outcome,
                    Some(preparation),
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ))
                .carry_eligible_external_reads()
                .is_some()
        };
        assert!(carries(&unsettled));
        unsettled.complete = false;
        assert!(!carries(&unsettled), "an incomplete preparation");
        unsettled.complete = true;
        unsettled.diagnostics.push(super::DependencyPackDiagnostic {
            severity: super::DependencyPackDiagnosticSeverity::Warning,
            code: "test.preparation_warning".to_owned(),
            dependency_id: None,
            location: None,
            message: "a preparation warning".to_owned(),
        });
        assert!(
            !carries(&unsettled),
            "a preparation that reported a diagnostic"
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
        production_input_digest: None,
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

/// Canonical inputs consumed by one production, including per-slot modules.
pub fn verified_raw_slots(
    artifacts: &[ExactDependencyArtifact],
) -> Vec<crate::analyzer::semantic_model::runtime::VerifiedRawArtifact> {
    let mut slots = artifacts
        .iter()
        .map(|artifact| {
            let mut slot =
                crate::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(
                    artifact.role(),
                    artifact.kind(),
                    artifact.sha256(),
                );
            slot.module = artifact.module().map(str::to_owned);
            slot
        })
        .collect::<Vec<_>>();
    slots.sort_unstable();
    slots.dedup();
    slots
}

impl crate::analyzer::semantic_model::ArtifactExtraction {
    /// Bind a producer's composite input to exact component bytes and their
    /// structured artifact slots, independently of enumeration and local paths.
    pub fn from_verified_slots(
        kind: ExternalArtifactKind,
        slots: &[crate::analyzer::semantic_model::runtime::VerifiedRawArtifact],
    ) -> Self {
        assert!(
            !slots.is_empty(),
            "extraction requires verified input slots"
        );
        let mut slots = slots.iter().collect::<Vec<_>>();
        slots.sort_unstable();
        slots.dedup();
        if let [slot] = slots.as_slice() {
            let digest = lower_hex_string(&slot.sha256);
            return match slot.kind {
                ExternalArtifactKind::RustdocJsonSet
                | ExternalArtifactKind::TypeScriptLibrarySet
                | ExternalArtifactKind::GoSourceSet
                | ExternalArtifactKind::JdkJmodSet
                | ExternalArtifactKind::ComposerPackageSourceSet
                | ExternalArtifactKind::CppHeaderSourceSet => Self::source_set(kind, &digest),
                _ => Self::single(kind, &digest),
            };
        }
        let mut components = slots
            .iter()
            .map(|slot| {
                let mut hasher = CanonicalHasher::new(b"bifrost.artifact-extraction.component.v1");
                hash_artifact_slot(&mut hasher, slot.role, slot.kind, slot.module.as_deref());
                hasher.field("sha256", lower_hex_string(&slot.sha256).as_bytes());
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
    /// The schema this producer mints for its generated packs. It belongs to
    /// the producer, not to one dependency, so release verification can judge
    /// a recorded production's currentness without reconstructing the
    /// dependency. The default preserves every existing adapter's production
    /// key and output contract.
    fn production_schema_version(&self) -> u32 {
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
        adapter.production_schema_version(),
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
        adapter.production_schema_version(),
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
    // Cancellation takes precedence over every terminal producer outcome.
    if is_cancelled(cancellation) {
        return Err(DependencyProductionFailure::Cancelled {
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    }
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
    let slots = verified_raw_slots(artifacts);
    let Some(first) = slots.first() else {
        return Err(DependencyProductionFailure::InvalidOutput {
            code: "production.inputs_missing".to_owned(),
            message: "generated dependency has no verified input slots".to_owned(),
            diagnostics: producer_diagnostics,
            suppressed_diagnostics,
        });
    };
    let old_extraction = pack.extraction.take();
    let kind = old_extraction
        .as_ref()
        .map_or(first.kind, |extraction| extraction.kind);
    let mut extraction =
        crate::analyzer::semantic_model::ArtifactExtraction::from_verified_slots(kind, &slots);
    if let Some(previous) = old_extraction {
        extraction.verified_sysroot = previous.verified_sysroot;
    }
    pack.extraction = Some(extraction);
    for shard in &mut pack.shards {
        for selector in &mut shard.activation {
            selector.artifact_sha256 = None;
            selector.production_input_digest = Some(key.input_digest().to_owned());
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
        match crate::analyzer::semantic_model::compiler::compile_generated_pack(
            &pack,
            &limits.compiler,
        ) {
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

/// Terminal preparation outcomes only. Cancellation and unattempted work are
/// deliberately absent: neither establishes a dependency-scoped failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyPreparationFailureCause {
    Rejected,
    PackUnavailable,
    ProducerFailed,
}

/// The operation a coordinate resolution applied to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmProbeOperation {
    Canonicalize,
    List,
    File,
}

/// A path that resolving one coordinate looked for and did not find. Only
/// absence is recorded here: a probe that failed for another reason is an
/// unreadable probe, which never makes a gap replayable. The path is a host
/// path and never reaches rendered output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmAbsentProbe {
    pub path: PathBuf,
    pub operation: JvmProbeOperation,
}

/// In-process reasons for incomplete JVM dependency coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmDependencyGapCause {
    MissingRevisionBuildAuthority,
    PreparationFailure(DependencyPreparationFailureCause),
    PartialCoverage,
    /// No exact local artifact exists for the declared coordinate. The probes
    /// are the absences that selection observed while looking for it. For
    /// unchanged inputs the same probes find the same absences, so the gap is
    /// deterministic, unlike an unreadable probe.
    Unresolved(Vec<JvmAbsentProbe>),
    /// The workspace file listing omitted these paths (workspace-relative),
    /// and each could hide a dependency manifest. No declared dependency owns
    /// the gap: a hidden manifest could add a candidate to any name, so every
    /// answer that reads the selection carries it. It is not fixed for
    /// unchanged inputs, because the omission may be repaired.
    ListingOmitted(Vec<PathBuf>),
}

/// A dependency whose content is unknown to a JVM selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmDependencyGap {
    pub dependency_id: String,
    pub cause: JvmDependencyGapCause,
    /// The pack whose installed shard is partial, for `PartialCoverage`. A
    /// declaration that pack provides is exact for its own type lookups, so a
    /// reader tells the provider's own gap from another dependency's.
    pub partial_pack_id: Option<String>,
}

impl JvmDependencyGap {
    pub fn missing_revision_build_authority() -> Self {
        Self {
            dependency_id: "revision build authority".into(),
            cause: JvmDependencyGapCause::MissingRevisionBuildAuthority,
            partial_pack_id: None,
        }
    }

    pub fn unresolved(dependency_id: String, probes: Vec<JvmAbsentProbe>) -> Self {
        Self {
            dependency_id,
            cause: JvmDependencyGapCause::Unresolved(probes),
            partial_pack_id: None,
        }
    }

    /// The gap for a listing that omitted manifest-capable `paths`. It names
    /// no dependency, so `dependency_id` is the listing itself.
    pub fn listing_omitted(paths: Vec<PathBuf>) -> Self {
        Self {
            dependency_id: "workspace file listing".into(),
            cause: JvmDependencyGapCause::ListingOmitted(paths),
            partial_pack_id: None,
        }
    }

    pub fn message(&self) -> String {
        match &self.cause {
            JvmDependencyGapCause::MissingRevisionBuildAuthority => "the full revision build authority is unavailable; dependency selection remains limited to selected revision files (#12427)".into(),
            JvmDependencyGapCause::ListingOmitted(paths) => {
                // Slash-joined components keep the note identical on every host.
                // An empty path is a listing that cannot say which part it left out.
                let mut names: Vec<String> = paths
                    .iter()
                    .map(|path| {
                        if path.as_os_str().is_empty() {
                            return "(unlisted part of the workspace)".to_owned();
                        }
                        path.components()
                            .map(|component| component.as_os_str().to_string_lossy())
                            .collect::<Vec<_>>()
                            .join("/")
                    })
                    .collect();
                names.sort();
                format!(
                    "the workspace file listing omitted paths that may hold dependency manifests: {}",
                    names.join(", ")
                )
            }
            JvmDependencyGapCause::Unresolved(_) => format!(
                "exact local artifact was not found for {}",
                self.dependency_id
            ),
            JvmDependencyGapCause::PartialCoverage => {
                format!("dependency {} has partial coverage", self.dependency_id)
            }
            JvmDependencyGapCause::PreparationFailure(_) => format!(
                "dependency {} preparation failed: {}",
                self.dependency_id,
                self.cause_label()
            ),
        }
    }

    pub fn cause_label(&self) -> &'static str {
        match &self.cause {
            JvmDependencyGapCause::MissingRevisionBuildAuthority => {
                "missing-revision-build-authority"
            }
            JvmDependencyGapCause::Unresolved(_) => "unresolved",
            JvmDependencyGapCause::ListingOmitted(_) => "listing-omitted",
            JvmDependencyGapCause::PartialCoverage => "partial-coverage",
            JvmDependencyGapCause::PreparationFailure(
                DependencyPreparationFailureCause::Rejected,
            ) => "rejected",
            JvmDependencyGapCause::PreparationFailure(
                DependencyPreparationFailureCause::PackUnavailable,
            ) => "pack-unavailable",
            JvmDependencyGapCause::PreparationFailure(
                DependencyPreparationFailureCause::ProducerFailed,
            ) => "producer-failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPreparationFailure {
    pub dependency_id: String,
    pub cause: DependencyPreparationFailureCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPackPreparationOutcome {
    /// Explicit terminal outcomes, independent of bounded diagnostics.
    pub failures: Vec<DependencyPreparationFailure>,
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
    /// The lowest toolchain release a workspace declares when discovery did
    /// not observe its toolchain. Standard-library packs whose requirements
    /// admit every release from the floor activate as approximate.
    ToolchainFloor(ToolchainFloorExpectation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainFloorExpectation {
    pub language: brokk_bifrost_core::analyzer::model::Language,
    /// The manifest ecosystem of the standard-library packs.
    pub pack_ecosystem: &'static str,
    pub toolchain: &'static str,
    pub floor: semver::Version,
    /// No release of the toolchain reaches this version.
    pub ceiling: semver::Version,
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
    /// Select newest catalog pack without claiming exact toolchain evidence,
    /// and why the evidence is not exact. Discovery is the only producer.
    pub approximation: Option<ApproximationReasons>,
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
            approximation: None,
            selection: StandardLibraryPackSelection::Declared { dependency_ids },
        }
    }

    /// No toolchain was observed: neither the version nor the target is known.
    pub fn unpinned(
        language: brokk_bifrost_core::analyzer::model::Language,
        pack_id: &'static str,
    ) -> Self {
        Self {
            language,
            pack_id,
            approximation: Some(
                ApproximationReasons::only(ApproximationReason::TargetUnknown)
                    .with(ApproximationReason::ToolchainVersionUnknown),
            ),
            selection: StandardLibraryPackSelection::Unpinned,
        }
    }

    /// Whether the pack is selected without exact toolchain evidence.
    pub fn approximate(&self) -> bool {
        self.approximation.is_some()
    }

    pub fn not_selected(
        language: brokk_bifrost_core::analyzer::model::Language,
        pack_id: &'static str,
        reason: String,
    ) -> Self {
        Self {
            language,
            pack_id,
            approximation: None,
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

/// A named boundary that prevented discovery from observing its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyDiscoveryIncompleteReason {
    GenerationListingUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDiscoveryOutcome {
    pub incomplete_reason: Option<DependencyDiscoveryIncompleteReason>,
    pub dependencies: Vec<ResolvedDependency>,
    pub diagnostics: Vec<DependencyPackDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
    pub complete: bool,
    pub cancelled: bool,
    pub profile: DependencyDiscoveryProfile,
}

impl DependencyDiscoveryOutcome {
    /// Whether any reported diagnostic is of a kind `follows_recorded_reads`
    /// does not vouch for. The one predicate behind every carry decision
    /// (cross-request carry and the same-warm handoff): a diagnostic carries
    /// only when its kind is known to be a function of the discovery's
    /// recorded reads, so an unknown kind fails closed. Diagnostics dropped
    /// by the bound have unknown kinds, so they refuse too, as does an
    /// outcome that names an incompleteness reason.
    pub fn has_unrecorded_diagnostics(
        &self,
        follows_recorded_reads: impl Fn(&str) -> bool,
    ) -> bool {
        self.incomplete_reason.is_some()
            || self
                .diagnostics
                .iter()
                .any(|diagnostic| !follows_recorded_reads(&diagnostic.code))
            || self.suppressed_diagnostics.total() > 0
    }

    pub fn generation_listing_unavailable(
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Self {
        let mut outcome = Self::complete(Vec::new());
        outcome.complete = false;
        outcome.cancelled = cancellation.is_cancelled();
        outcome.incomplete_reason =
            Some(DependencyDiscoveryIncompleteReason::GenerationListingUnavailable);
        outcome.diagnostics.push(DependencyPackDiagnostic {
            severity: DependencyPackDiagnosticSeverity::Error,
            code: "discovery.generation_listing_unavailable".into(),
            dependency_id: None,
            location: None,
            message: "This generation has no captured workspace listing; rebuild the analyzer before dependency discovery".into(),
        });
        outcome
    }

    pub fn complete(dependencies: Vec<ResolvedDependency>) -> Self {
        Self {
            incomplete_reason: None,
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
            incomplete_reason: None,
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
                DependencyDiscoveryInformationalEvidence::CppMissingWorkspaceSources { .. }
                | DependencyDiscoveryInformationalEvidence::ToolchainFloor(_) => None,
            })
    }

    /// The standard-library packs this discovery requests without exact
    /// toolchain evidence, as activation expectations for `ecosystem`.
    pub fn approximate_standard_libraries(
        &self,
        ecosystem: &str,
    ) -> impl Iterator<Item = crate::analyzer::semantic_model::ApproximateSemanticModelExpectation>
    {
        use crate::analyzer::semantic_model::{
            ApproximateSemanticModelExpectation, ApproximateStandardLibrarySelection,
        };
        use brokk_bifrost_core::analyzer::model::Language;
        self.profile
            .informational_evidence
            .iter()
            .filter_map(move |evidence| match evidence {
                DependencyDiscoveryInformationalEvidence::StandardLibraryPack(expectation)
                    if expectation.approximation.is_some() =>
                {
                    Some(ApproximateSemanticModelExpectation {
                        reasons: expectation.approximation?,
                        toolchain: (expectation.language == Language::Rust)
                            .then(|| "rust".to_owned()),
                        language: expectation.language.config_label().to_owned(),
                        ecosystem: ecosystem.to_owned(),
                        selection: ApproximateStandardLibrarySelection::Pack(
                            expectation.pack_id.to_owned(),
                        ),
                    })
                }
                DependencyDiscoveryInformationalEvidence::ToolchainFloor(floor) => {
                    Some(ApproximateSemanticModelExpectation {
                        reasons: ApproximationReasons::only(
                            ApproximationReason::ToolchainVersionUnknown,
                        ),
                        toolchain: None,
                        language: floor.language.config_label().to_owned(),
                        ecosystem: ecosystem.to_owned(),
                        selection: ApproximateStandardLibrarySelection::ToolchainFloor {
                            pack_ecosystem: floor.pack_ecosystem.to_owned(),
                            toolchain: floor.toolchain.to_owned(),
                            floor: floor.floor.clone(),
                            ceiling: floor.ceiling.clone(),
                        },
                    })
                }
                DependencyDiscoveryInformationalEvidence::StandardLibraryPack(_)
                | DependencyDiscoveryInformationalEvidence::CppMissingWorkspaceSources { .. } => {
                    None
                }
            })
    }

    /// Record the toolchain floor the workspace declares. Like a pack
    /// expectation, it never changes completeness.
    pub fn expect_toolchain_floor(&mut self, floor: ToolchainFloorExpectation) {
        self.profile.informational_evidence.push(
            DependencyDiscoveryInformationalEvidence::ToolchainFloor(floor),
        );
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

/// What an activation status reads from one ecosystem's outcome, kept for an
/// ecosystem whose discovery carries across a scoped refresh. The carried
/// ecosystem is not rediscovered, so its diagnostics, completeness and
/// preparation failures would otherwise vanish from the status the refresh
/// rebuilds. The dependency lists, prepared packs, activation evidence and
/// profile are not kept: a status never reads them, so this residue must reach
/// only status reducers and never the consumers of an activation outcome that
/// read those fields (for example the policy coordinator's pack decisions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedEcosystemStatus {
    pub discovery: DependencyDiscoveryOutcome,
    pub preparation: Option<DependencyPackPreparationOutcome>,
    /// The retained bytes, owned by the value: every `Arc` clone keeps them
    /// charged and the last drop releases them.
    charge: brokk_bifrost_core::retention_budget::AllocationCharge,
}

impl RetainedEcosystemStatus {
    /// The status residue of one ecosystem's outcome, or `None` when the
    /// budget cannot hold it. An unretained status means the ecosystem's
    /// diagnostics cannot be re-emitted, so the caller must not carry it.
    pub fn retain(
        discovery: &DependencyDiscoveryOutcome,
        preparation: Option<&DependencyPackPreparationOutcome>,
        budget: &brokk_bifrost_core::retention_budget::RetentionBudget,
    ) -> Option<std::sync::Arc<Self>> {
        let discovery = DependencyDiscoveryOutcome {
            incomplete_reason: discovery.incomplete_reason,
            dependencies: Vec::new(),
            diagnostics: discovery.diagnostics.clone(),
            suppressed_diagnostics: discovery.suppressed_diagnostics,
            complete: discovery.complete,
            cancelled: discovery.cancelled,
            profile: DependencyDiscoveryProfile::default(),
        };
        let preparation = preparation.map(|preparation| DependencyPackPreparationOutcome {
            failures: preparation.failures.clone(),
            packs: Vec::new(),
            installed_packs: Vec::new(),
            evidence: Vec::new(),
            diagnostics: preparation.diagnostics.clone(),
            suppressed_diagnostics: preparation.suppressed_diagnostics,
            complete: preparation.complete,
            cancelled: preparation.cancelled,
            profile: Default::default(),
        });
        // Estimate the owned metadata as `retain_dependency_activation` does:
        // Debug expands strings and nested collections, and eight bytes per
        // rendered byte covers inline elements of short-string collections.
        let bytes = std::mem::size_of::<Self>()
            + format!("{discovery:?}{preparation:?}")
                .len()
                .saturating_mul(8);
        let charge = brokk_bifrost_core::retention_budget::AllocationCharge::acquire(budget, bytes);
        charge.is_charged().then(|| {
            std::sync::Arc::new(Self {
                discovery,
                preparation,
                charge,
            })
        })
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
    /// Terminal outcomes paired with the inputs reported by discovery.
    pub preparation_failures: Vec<RecordedPreparationFailure>,
    // Even an unbindable failure prevents carry: discovery does not certify preparation.
    preparation_failure_count: usize,
    declared_modules: brokk_bifrost_core::hash::HashSet<String>,
    truncated: bool,
    /// Discovery reported a diagnostic whose kind is not known to follow only
    /// recorded reads. A diagnostic of a known kind is a function of the
    /// recorded, verifiable reads, so it carries with the evidence; any other
    /// kind can stand for an unrecorded probe or a transient failure that left
    /// no key, so this evidence is never carried across an update. An
    /// approximate standard-library expectation sets `truncated` without a
    /// diagnostic; its recorded absent toolchain probes pin it, so that
    /// evidence can be carried with its `truncated` bit.
    unrecorded_diagnostics: bool,
    /// Discovery reported at least one diagnostic.
    reported_diagnostics: bool,
    /// What a status reads from this ecosystem's outcome, so a carried
    /// ecosystem keeps its diagnostics and incompleteness across a scoped
    /// refresh. `None` when the budget refused it: such evidence with
    /// diagnostics or incompleteness is not carried.
    pub retained_status: Option<std::sync::Arc<RetainedEcosystemStatus>>,
    /// The budget refused to retain this ecosystem's status, or its
    /// preparation was unsettled (incomplete, cancelled or reporting
    /// diagnostics). Neither can be re-emitted or vouched for, so this
    /// evidence is not carried.
    status_refused: bool,
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
        /// The metadata identity taken before the bytes were read, kept only
        /// when it was not racy at observation time. It is a verification
        /// fast path, not part of the fact: `external_read_identity` folds
        /// only `content` and `size`, and the observation clock is not
        /// retained after the racy check.
        identity: Option<brokk_bifrost_core::content_digest::FileIdentity>,
    },
    /// An observation of one path: its kind, its canonical form or its sorted
    /// directory listing, summarized by `digest`.
    PathObservation {
        absolute_path: std::path::PathBuf,
        op: PathObservationOp,
        digest: crate::analyzer::semantic::ids::StableDigest,
    },
    /// An input verified by its owner. `identity` names the exact observed
    /// answer; `verifier` re-observes it.
    Observed {
        identity: crate::analyzer::semantic::ids::StableDigest,
        verifier: ExternalVerifier,
    },
    OverBudgetFile {
        absolute_path: std::path::PathBuf,
        size: u64,
    },
    Environment {
        name: Box<str>,
        value: Option<std::ffi::OsString>,
        /// The process directory used to resolve a relative environment path.
        /// Ephemeral only; durable acquisition records retain its hash.
        working_directory: Option<std::path::PathBuf>,
    },
    Unverifiable(UnverifiableDiscoveryRead),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableDiscoveryRead {
    ProcessOutput,
    ExternalCacheWalk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathObservationOp {
    /// Absent, file, directory or other.
    Stat,
    /// The canonical path, or absent.
    Canonicalize,
    /// The sorted names and entry kinds of a directory, or absent.
    ListNames,
}

/// A directory entry kind as a listing reports it, without following links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ListedKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListedEntry {
    pub name: std::ffi::OsString,
    pub kind: ListedKind,
}

/// Lists a directory once, sorted by name, so one read serves both the
/// consumer and its observation. Any entry error fails the whole listing.
pub fn list_names(path: &std::path::Path) -> std::io::Result<Vec<ListedEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        entries.push(ListedEntry {
            name: entry.file_name(),
            kind: if file_type.is_symlink() {
                ListedKind::Symlink
            } else if file_type.is_dir() {
                ListedKind::Directory
            } else if file_type.is_file() {
                ListedKind::File
            } else {
                ListedKind::Other
            },
        });
    }
    entries.sort();
    Ok(entries)
}

fn observation_digest(
    kind: &[u8],
    body: impl FnOnce(&mut CanonicalHasher),
) -> crate::analyzer::semantic::ids::StableDigest {
    let mut hash = CanonicalHasher::new(b"bifrost.path-observation.v1");
    hash.field("kind", kind);
    body(&mut hash);
    crate::analyzer::semantic::ids::StableDigest::from_array(hash.finish())
}

/// Maps a probe outcome to its digest. Absence is an observation; any other
/// error is unreadable, because restoring access could change the answer.
fn absent_or_unreadable<T>(
    result: &std::io::Result<T>,
    found: impl FnOnce(&T) -> crate::analyzer::semantic::ids::StableDigest,
) -> std::io::Result<crate::analyzer::semantic::ids::StableDigest> {
    match result {
        Ok(value) => Ok(found(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(observation_digest(b"absent", |_| {}))
        }
        Err(error) => Err(std::io::Error::new(error.kind(), error.to_string())),
    }
}

pub fn stat_observation(
    metadata: &std::io::Result<std::fs::Metadata>,
) -> std::io::Result<crate::analyzer::semantic::ids::StableDigest> {
    absent_or_unreadable(metadata, |metadata| {
        let kind: &[u8] = if metadata.is_file() {
            b"file"
        } else if metadata.is_dir() {
            b"directory"
        } else {
            b"other"
        };
        observation_digest(kind, |_| {})
    })
}

pub fn canonicalize_observation(
    canonical: &std::io::Result<std::path::PathBuf>,
) -> std::io::Result<crate::analyzer::semantic::ids::StableDigest> {
    absent_or_unreadable(canonical, |path| {
        observation_digest(b"canonical", |hash| {
            hash.field("path", path.as_os_str().as_encoded_bytes());
        })
    })
}

pub fn list_observation(
    listing: &std::io::Result<Vec<ListedEntry>>,
) -> std::io::Result<crate::analyzer::semantic::ids::StableDigest> {
    absent_or_unreadable(listing, |entries| {
        observation_digest(b"listing", |hash| {
            hash.sequence("entries", entries, |hash, entry| {
                hash.field("name", entry.name.as_encoded_bytes());
                hash.field(
                    "kind",
                    match entry.kind {
                        ListedKind::File => b"file",
                        ListedKind::Directory => b"directory",
                        ListedKind::Symlink => b"symlink",
                        ListedKind::Other => b"other",
                    },
                );
            });
        })
    })
}

/// Re-observes a path as a `PathObservation` key did. `None` when unreadable.
pub fn observe_path(
    path: &std::path::Path,
    op: PathObservationOp,
) -> Option<crate::analyzer::semantic::ids::StableDigest> {
    match op {
        PathObservationOp::Stat => stat_observation(&std::fs::metadata(path)),
        PathObservationOp::Canonicalize => canonicalize_observation(&path.canonicalize()),
        PathObservationOp::ListNames => list_observation(&list_names(path)),
    }
    .ok()
}

/// Verifies an input whose owner can re-observe it.
pub trait ExternalObservation: Send + Sync {
    fn still_matches(&self) -> bool;
}

/// The verifier of an `Observed` key. Keys compare by their `identity`, so
/// every verifier is equal to every other one.
#[derive(Clone)]
pub struct ExternalVerifier(pub std::sync::Arc<dyn ExternalObservation>);

impl std::fmt::Debug for ExternalVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalVerifier")
    }
}

impl PartialEq for ExternalVerifier {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ExternalVerifier {}

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
            identity: None,
        }
    }

    /// A file key whose verification may skip the read while the metadata
    /// identity taken before the read still holds. The identity is dropped
    /// when `observed_at` shows it could hide a rewrite inside its timestamp
    /// tick. The observation clock itself is not part of the key.
    pub fn file_with_identity(
        path: &std::path::Path,
        bytes: &[u8],
        identity: Option<brokk_bifrost_core::content_digest::FileIdentity>,
        observed_at: std::time::SystemTime,
    ) -> Self {
        let Self::File {
            absolute_path,
            content,
            size,
            ..
        } = Self::file(path, bytes)
        else {
            unreachable!("file() builds a File key")
        };
        Self::File {
            absolute_path,
            content,
            size,
            identity: identity.filter(|identity| {
                !identity.racy_at(
                    observed_at,
                    brokk_bifrost_core::content_digest::FILE_TIMESTAMP_GRANULARITY,
                )
            }),
        }
    }

    /// Check a file key without reading beyond the original byte budget.
    pub fn still_matches(&self) -> bool {
        match self {
            Self::AbsentFile { absolute_path } => std::fs::metadata(absolute_path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            Self::File {
                absolute_path,
                content,
                size,
                identity,
            } => {
                use std::io::Read;
                if let Some(identity) = identity
                    && brokk_bifrost_core::content_digest::metadata_change_identity(absolute_path)
                        .ok()
                        .flatten()
                        .as_ref()
                        == Some(identity)
                {
                    return true;
                }
                let Ok(file) = brokk_bifrost_core::content_digest::open_regular_file(absolute_path)
                else {
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
            Self::Environment {
                name,
                value,
                working_directory,
            } => {
                std::env::var_os(name.as_ref()) == *value
                    && working_directory.as_ref().is_none_or(|directory| {
                        std::env::current_dir().is_ok_and(|current| current == *directory)
                    })
            }
            Self::PathObservation {
                absolute_path,
                op,
                digest,
            } => observe_path(absolute_path, *op).as_ref() == Some(digest),
            Self::Observed { verifier, .. } => verifier.0.still_matches(),
            Self::OverBudgetFile { .. } | Self::Unverifiable(_) => false,
        }
    }
}

/// The files a terminal preparation failure observed, when they can be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparationFailureInputs {
    /// Every input's metadata identity was unchanged when the failure was attached.
    Bound(PreparationInputBinding),
    /// No stable binding exists: no observable input file, a limit, a changed
    /// input, or an artifact-less dependency. Nothing can verify this record,
    /// so it never certifies a selection and never lets activation be carried.
    Unbound,
}

impl PreparationFailureInputs {
    /// True when the recorded inputs still match the files on disk. An
    /// unbound record has no inputs to verify and never matches.
    pub fn still_match(&self) -> bool {
        match self {
            Self::Bound(inputs) => Self::bound_inputs_match(inputs),
            Self::Unbound => false,
        }
    }

    /// True when a bound input changed since activation. Staleness asks whether
    /// what a record observed moved, so an unbound record, which observed
    /// nothing that can move, is never stale. It is still never current: carry
    /// refuses while any failure exists, and no gap for a failure replays.
    pub fn changed_since_binding(&self) -> bool {
        match self {
            Self::Bound(inputs) => !Self::bound_inputs_match(inputs),
            Self::Unbound => false,
        }
    }

    fn bound_inputs_match(inputs: &PreparationInputBinding) -> bool {
        inputs.iter().all(|(path, identity)| {
            brokk_bifrost_core::content_digest::metadata_change_identity(path)
                .ok()
                .flatten()
                .as_ref()
                == Some(identity)
        })
    }

    pub fn is_unbound(&self) -> bool {
        matches!(self, Self::Unbound)
    }
}

/// A terminal outcome with its dependency identity, closed cause, and the
/// files observed around preparation when they can be bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPreparationFailure {
    pub dependency: ResolvedDependency,
    pub cause: DependencyPreparationFailureCause,
    pub inputs: PreparationFailureInputs,
}

/// Owned storage retained by preparation records, including source-set paths.
pub fn preparation_failures_retained_bytes(failures: &Vec<RecordedPreparationFailure>) -> u64 {
    use brokk_bifrost_core::retention_budget::RetainedBytes;
    let mut bytes = failures
        .capacity()
        .saturating_mul(std::mem::size_of::<RecordedPreparationFailure>());
    for failure in failures {
        let dependency = &failure.dependency;
        bytes = bytes.saturating_add(dependency.id.capacity());
        let evidence = &dependency.evidence;
        bytes = bytes
            .saturating_add(evidence.language.capacity())
            .saturating_add(evidence.ecosystem.capacity());
        for coordinate in [&evidence.package, &evidence.module, &evidence.toolchain]
            .into_iter()
            .flatten()
        {
            bytes = bytes.saturating_add(coordinate.name.capacity());
            if let Some(version) = &coordinate.version {
                bytes = bytes
                    .saturating_add(version.pre.len())
                    .saturating_add(version.build.len());
            }
        }
        bytes = bytes.saturating_add(
            evidence
                .verified_raw_artifacts
                .iter()
                .filter_map(|slot| slot.module.as_ref())
                .map(String::capacity)
                .sum::<usize>(),
        );
        bytes = bytes.saturating_add(evidence.verified_raw_artifacts.capacity().saturating_mul(
            std::mem::size_of::<crate::analyzer::semantic_model::runtime::VerifiedRawArtifact>(),
        ));
        for value in [
            &evidence.target,
            &evidence.configuration,
            &evidence.production_input_digest,
            &dependency.declared_by,
        ]
        .into_iter()
        .flatten()
        {
            bytes = bytes.saturating_add(value.capacity());
        }
        bytes = bytes.saturating_add(
            dependency
                .provenance
                .capacity()
                .saturating_mul(std::mem::size_of::<DependencyProvenance>()),
        );
        for value in &dependency.provenance {
            bytes = bytes
                .saturating_add(value.key.capacity())
                .saturating_add(value.value.capacity());
        }
        bytes = bytes.saturating_add(
            dependency
                .artifacts
                .capacity()
                .saturating_mul(std::mem::size_of::<ResolvedDependencyArtifact>()),
        );
        for artifact in &dependency.artifacts {
            for value in [&artifact.module, &artifact.expected_sha256]
                .into_iter()
                .flatten()
            {
                bytes = bytes.saturating_add(value.capacity());
            }
            if let Some(identity) = &artifact.source_identity {
                bytes = bytes.saturating_add(identity.0.capacity());
            }
            match &artifact.input {
                ResolvedDependencyArtifactInput::File(path) => {
                    bytes = bytes.saturating_add(path.capacity())
                }
                ResolvedDependencyArtifactInput::SourceSet {
                    root,
                    relative_paths,
                } => {
                    bytes = bytes.saturating_add(root.capacity()).saturating_add(
                        relative_paths
                            .retained_bytes()
                            .saturating_sub(std::mem::size_of_val(relative_paths)),
                    );
                }
            }
            if let Some(value) = &artifact.rust_artifact_approximation {
                for text in [
                    &value.built_from_version,
                    &value.target,
                    &value.toolchain,
                    &value.original_sha256,
                    &value.produced_sha256,
                    &value.activation_version_requirement,
                    &value.selection_rule_id,
                ] {
                    bytes = bytes.saturating_add(text.capacity());
                }
                bytes = bytes
                    .saturating_add(
                        value
                            .built_from_features
                            .retained_bytes()
                            .saturating_sub(std::mem::size_of_val(&value.built_from_features)),
                    )
                    .saturating_add(
                        value
                            .built_from_cfgs
                            .retained_bytes()
                            .saturating_sub(std::mem::size_of_val(&value.built_from_cfgs)),
                    )
                    .saturating_add(value.mismatch_kinds.capacity().saturating_mul(
                        std::mem::size_of::<
                            crate::analyzer::semantic_model::RustArtifactMismatchKind,
                        >(),
                    ));
            }
        }
        if let PreparationFailureInputs::Bound(inputs) = &failure.inputs {
            bytes = bytes.saturating_add(inputs.capacity().saturating_mul(std::mem::size_of::<(
                PathBuf,
                brokk_bifrost_core::content_digest::FileIdentity,
            )>()));
            for (path, _) in inputs {
                bytes = bytes.saturating_add(path.capacity());
            }
        }
    }
    bytes.try_into().unwrap_or(u64::MAX)
}

/// Canonical identity of terminal outcomes and the exact inputs they observed.
pub fn preparation_failures_digest(failures: &[RecordedPreparationFailure]) -> [u8; 32] {
    let mut hash = CanonicalHasher::new(b"activation-preparation-failures-v2");
    hash.sequence("failures", failures, |hash, failure| {
        hash.field("dependency", failure.dependency.id.as_bytes());
        hash_evidence(hash, &failure.dependency.evidence);
        hash_optional(
            hash,
            "production_input_digest",
            failure
                .dependency
                .evidence
                .production_input_digest
                .as_deref(),
        );
        hash.sequence(
            "verified_raw_artifacts",
            &failure.dependency.evidence.verified_raw_artifacts,
            |hash, input| {
                hash.field("role", &[input.role as u8]);
                hash.field("kind", artifact_kind_name(input.kind).as_bytes());
                hash_optional(hash, "module", input.module.as_deref());
                hash.field("sha256", &input.sha256);
            },
        );
        hash.field("scope", failure.dependency.scope.label().as_bytes());
        hash_optional(
            hash,
            "declared_by",
            failure.dependency.declared_by.as_deref(),
        );
        hash.sequence(
            "provenance",
            &failure.dependency.provenance,
            |hash, entry| {
                hash.field("key", entry.key.as_bytes());
                hash.field("value", entry.value.as_bytes());
            },
        );
        hash.sequence(
            "artifacts",
            &failure.dependency.artifacts,
            |hash, artifact| {
                hash_artifact_slot(
                    hash,
                    artifact.role,
                    artifact.kind,
                    artifact.module.as_deref(),
                );
                hash_optional(hash, "expected_sha256", artifact.expected_sha256.as_deref());
                hash.field(
                    "approximation_present",
                    &[u8::from(artifact.rust_artifact_approximation.is_some())],
                );
                if let Some(approximation) = &artifact.rust_artifact_approximation {
                    for (name, value) in [
                        ("built_from_version", &approximation.built_from_version),
                        ("target", &approximation.target),
                        ("toolchain", &approximation.toolchain),
                        ("original_sha256", &approximation.original_sha256),
                        ("produced_sha256", &approximation.produced_sha256),
                        (
                            "activation_version_requirement",
                            &approximation.activation_version_requirement,
                        ),
                        ("selection_rule_id", &approximation.selection_rule_id),
                    ] {
                        hash.field(name, value.as_bytes());
                    }
                    hash.sequence(
                        "features",
                        &approximation.built_from_features,
                        |hash, value| hash.value(value.as_bytes()),
                    );
                    hash.sequence("cfgs", &approximation.built_from_cfgs, |hash, value| {
                        hash.value(value.as_bytes())
                    });
                    hash.field(
                        "format_version",
                        &approximation.format_version.to_be_bytes(),
                    );
                    hash.field(
                        "selection_rule_version",
                        &approximation.selection_rule_version.to_be_bytes(),
                    );
                    hash.field("docsrs_build", &[u8::from(approximation.docsrs_build)]);
                    hash.sequence(
                        "mismatch_kinds",
                        &approximation.mismatch_kinds,
                        |hash, kind| {
                            use crate::analyzer::semantic_model::RustArtifactMismatchKind;
                            hash.value(&[match kind {
                                RustArtifactMismatchKind::VersionNearby => 0,
                                RustArtifactMismatchKind::FeatureSuperset => 1,
                                RustArtifactMismatchKind::FormatConverted => 2,
                            }]);
                        },
                    );
                }
                hash_optional(
                    hash,
                    "source_identity",
                    artifact
                        .source_identity
                        .as_ref()
                        .map(ArtifactSourceIdentity::as_str),
                );
                match &artifact.input {
                    ResolvedDependencyArtifactInput::File(path) => {
                        hash.field("file", path.as_os_str().as_encoded_bytes())
                    }
                    ResolvedDependencyArtifactInput::SourceSet {
                        root,
                        relative_paths,
                    } => {
                        hash.field("root", root.as_os_str().as_encoded_bytes());
                        hash.sequence("relative_paths", relative_paths, |hash, path| {
                            hash.field("path", path.as_os_str().as_encoded_bytes())
                        });
                    }
                }
            },
        );
        hash.field(
            "cause",
            &[match failure.cause {
                DependencyPreparationFailureCause::Rejected => 0,
                DependencyPreparationFailureCause::PackUnavailable => 1,
                DependencyPreparationFailureCause::ProducerFailed => 2,
            }],
        );
        match &failure.inputs {
            PreparationFailureInputs::Bound(inputs) => {
                hash.field("binding", b"bound");
                hash.sequence("inputs", inputs, |hash, (path, identity)| {
                    hash.field("path", path.as_os_str().as_encoded_bytes());
                    hash.field("metadata", &identity.digest());
                });
            }
            PreparationFailureInputs::Unbound => hash.field("binding", b"unbound"),
        }
    });
    hash.finish()
}

pub type PreparationInputBinding = Vec<(PathBuf, brokk_bifrost_core::content_digest::FileIdentity)>;

/// Snapshot regular-file inputs before preparation. Unobservable inputs cannot
/// certify a scoped failure; they retain the ordinary missing-membership refusal.
pub fn preparation_input_bindings(
    dependencies: &[ResolvedDependency],
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Vec<Option<PreparationInputBinding>> {
    let cancelled = || cancellation.is_some_and(CancellationToken::is_cancelled);
    dependencies
        .iter()
        .take(limits.max_dependencies)
        .take_while(|_| !cancelled())
        .map(|dependency| {
            if dependency.artifacts.len() > limits.max_artifacts_per_dependency {
                return None;
            }
            let mut inputs = Vec::new();
            for artifact in &dependency.artifacts {
                let mut observe = |path: PathBuf| {
                    if cancelled() {
                        return None;
                    }
                    let identity =
                        brokk_bifrost_core::content_digest::metadata_change_identity(&path)
                            .ok()
                            .flatten()?;
                    inputs.push((path, identity));
                    Some(())
                };
                match &artifact.input {
                    ResolvedDependencyArtifactInput::File(path) => observe(path.clone())?,
                    ResolvedDependencyArtifactInput::SourceSet {
                        root,
                        relative_paths,
                    } => {
                        if relative_paths.len() > limits.max_source_files_per_artifact {
                            return None;
                        }
                        for path in relative_paths {
                            if path.components().count() > limits.max_source_path_depth {
                                return None;
                            }
                            observe(root.join(path))?;
                        }
                    }
                }
            }
            (!inputs.is_empty()).then_some(inputs)
        })
        .collect()
}

impl DependencyDiscoveryEvidence {
    /// Record every explicit terminal outcome with its dependency identity and
    /// closed cause. A failure whose inputs can be bound keeps them, so
    /// selection verification rejects this evidence after a repair. Any other
    /// failure is recorded as unbound: it can never certify a selection or
    /// permit carry, but it still names its dependency. Preparation never
    /// truncates discovery; that flag describes unreadable discovery inputs.
    pub fn with_preparation_failures(
        mut self,
        dependencies: &[ResolvedDependency],
        failures: &[DependencyPreparationFailure],
        bindings: &[Option<PreparationInputBinding>],
    ) -> Self {
        self.preparation_failure_count = failures.len();
        self.preparation_failures = failures
            .iter()
            .map(|failure| {
                let index = dependencies
                    .iter()
                    .position(|dependency| dependency.id == failure.dependency_id)
                    .expect("failure belongs to discovery");
                let inputs = match bindings.get(index).and_then(Option::as_ref) {
                    Some(inputs) => {
                        let bound = PreparationFailureInputs::Bound(inputs.clone());
                        if bound.still_match() {
                            bound
                        } else {
                            PreparationFailureInputs::Unbound
                        }
                    }
                    None => PreparationFailureInputs::Unbound,
                };
                RecordedPreparationFailure {
                    dependency: dependencies[index].clone(),
                    cause: failure.cause,
                    inputs,
                }
            })
            .collect();
        self
    }

    /// A terminal failure without a stable input binding cannot certify a selection.
    pub fn has_unbound_preparation_failures(&self) -> bool {
        self.preparation_failures
            .iter()
            .any(|failure| failure.inputs.is_unbound())
    }

    /// Returns the external keys M2 can verify, or refuses carry when a read
    /// cannot be reproduced from a fixed input.
    pub fn carry_eligible_external_reads(&self) -> Option<&[ExternalDiscoveryRead]> {
        // A carried ecosystem is not rediscovered, so a status rebuilt after a
        // scoped refresh can show its diagnostics only from the retained
        // residue. Without it the diagnostics, or the incompleteness a cold status
        // reports, could not be re-emitted.
        if self.status_refused
            || ((self.reported_diagnostics || self.truncated) && self.retained_status.is_none())
        {
            return None;
        }
        Self::carry_eligible_external_reads_for_parts(
            self.unrecorded_diagnostics,
            self.preparation_failure_count,
            self.external_reads_complete,
            &self.external_reads,
        )
    }

    /// Returns the external keys M2 can verify from unbundled discovery receipt
    /// parts, or refuses carry when a read cannot be reproduced from a fixed input.
    pub fn carry_eligible_external_reads_for_parts(
        unrecorded_diagnostics: bool,
        preparation_failure_count: usize,
        external_reads_complete: bool,
        external_reads: &[ExternalDiscoveryRead],
    ) -> Option<&[ExternalDiscoveryRead]> {
        // Cancelled discovery never publishes evidence: activation stops
        // before it pushes the ecosystem's evidence.
        (!unrecorded_diagnostics
            // Discovery reads do not certify the later failed preparation.
            && preparation_failure_count == 0
            && external_reads_complete
            && external_reads.iter().all(|read| {
                matches!(
                    read,
                    ExternalDiscoveryRead::File { .. }
                        | ExternalDiscoveryRead::PathObservation { .. }
                        | ExternalDiscoveryRead::Observed { .. }
                        | ExternalDiscoveryRead::AbsentFile { .. }
                        | ExternalDiscoveryRead::Environment { .. }
                )
            }))
        .then_some(external_reads)
    }
    /// Record whether this discovery's diagnostics all follow its recorded
    /// reads, as judged by `follows_recorded_reads`. Without this call every
    /// diagnostic counts as unrecorded.
    pub fn with_diagnostics_judged_by(
        mut self,
        outcome: &DependencyDiscoveryOutcome,
        follows_recorded_reads: impl Fn(&str) -> bool,
    ) -> Self {
        self.unrecorded_diagnostics = outcome.has_unrecorded_diagnostics(follows_recorded_reads);
        self
    }

    pub fn with_retained_status(
        mut self,
        status: Option<std::sync::Arc<RetainedEcosystemStatus>>,
    ) -> Self {
        // Preparation is not rerun for a carried ecosystem and the carry gate
        // judges only discovery. A preparation that was incomplete, cancelled or
        // reported diagnostics depends on state (installed packs, the catalog)
        // that no recorded read covers, so such evidence is not carried either.
        self.status_refused = status.as_ref().is_none_or(|status| {
            status.preparation.as_ref().is_some_and(|preparation| {
                !preparation.complete
                    || preparation.cancelled
                    || !preparation.diagnostics.is_empty()
            })
        });
        self.retained_status = status;
        self
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
                    identity: _,
                } => {
                    hash.field("kind", b"file");
                    hash.field("path", path(absolute_path).as_bytes());
                    hash.field("content", content.as_bytes());
                    hash.field("size", &size.to_be_bytes());
                }
                ExternalDiscoveryRead::PathObservation {
                    absolute_path,
                    op,
                    digest,
                } => {
                    hash.field("kind", b"path-observation");
                    hash.field("path", path(absolute_path).as_bytes());
                    hash.field(
                        "op",
                        match op {
                            PathObservationOp::Stat => b"stat",
                            PathObservationOp::Canonicalize => b"canonicalize",
                            PathObservationOp::ListNames => b"list-names",
                        },
                    );
                    hash.field("digest", digest.as_bytes());
                }
                ExternalDiscoveryRead::Observed { identity, .. } => {
                    hash.field("kind", b"observed");
                    hash.field("identity", identity.as_bytes());
                }
                ExternalDiscoveryRead::OverBudgetFile {
                    absolute_path,
                    size,
                } => {
                    hash.field("kind", b"over-budget-file");
                    hash.field("path", path(absolute_path).as_bytes());
                    hash.field("size", &size.to_be_bytes());
                }
                ExternalDiscoveryRead::Environment {
                    name,
                    value,
                    working_directory,
                } => {
                    hash.field("kind", b"environment");
                    hash.field("name", name.as_bytes());
                    hash.field("present", &[value.is_some() as u8]);
                    if let Some(value) = value {
                        hash.field("value", value.to_string_lossy().as_bytes());
                    }
                    if let Some(directory) = working_directory {
                        hash.field("working-directory", path(directory).as_bytes());
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
            preparation_failures: Vec::new(),
            preparation_failure_count: 0,
            declared_modules,
            truncated: !outcome.complete,
            unrecorded_diagnostics: !outcome.diagnostics.is_empty(),
            reported_diagnostics: !outcome.diagnostics.is_empty(),
            retained_status: None,
            status_refused: false,
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
        self.declared_identity_below(path, separator).is_some()
    }

    /// The declared identity that `path` names or lies below: `path` itself
    /// when declared, otherwise the nearest declared prefix reached by removing
    /// trailing `separator`-delimited segments.
    fn declared_identity_below<'a>(&self, path: &'a str, separator: char) -> Option<&'a str> {
        if path.is_empty() {
            return None;
        }
        let mut prefix = path;
        loop {
            if self.declared_modules.contains(prefix) {
                return Some(prefix);
            }
            prefix = prefix.rsplit_once(separator)?.0;
        }
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

/// A declared dependency is indexed only when its own package is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredDependencyVerdict {
    Undeclared,
    Truncated,
    DeclaredIndexed,
    DeclaredUnindexed,
}

/// Classify a dependency path using retained declarations and package activation.
/// The separator describes a module/load-path value, not source syntax.
pub fn declared_dependency_verdict(
    evidence: Option<&DependencyDiscoveryEvidence>,
    path: &str,
    separator: char,
    package_active: impl Fn(&str) -> bool,
) -> DeclaredDependencyVerdict {
    let Some(evidence) = evidence else {
        return DeclaredDependencyVerdict::Undeclared;
    };
    if evidence.truncated() {
        return DeclaredDependencyVerdict::Truncated;
    }
    let mut prefix = path;
    loop {
        if evidence.declared_modules.contains(prefix) {
            return if package_active(prefix) {
                DeclaredDependencyVerdict::DeclaredIndexed
            } else {
                DeclaredDependencyVerdict::DeclaredUnindexed
            };
        }
        let Some((head, _)) = prefix.rsplit_once(separator) else {
            return DeclaredDependencyVerdict::Undeclared;
        };
        prefix = head;
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
        verified_raw_artifacts: Vec::new(),
        production_input_digest: None,
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

pub fn artifact_kind_name(kind: ExternalArtifactKind) -> &'static str {
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
    artifacts: &[ExactDependencyArtifact],
) -> SemanticModelActivationEvidence {
    let mut evidence = dependency.evidence.clone();
    evidence.verified_raw_artifacts = verified_raw_slots(artifacts);
    evidence.production_input_digest = Some(input_digest.to_owned());
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
