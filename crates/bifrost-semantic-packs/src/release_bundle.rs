//! Reproducible, content-addressed release bundles for pinned API packs.
//!
//! The pinned-spec schema is ecosystem neutral. One spec kind exists for each
//! producer family that can consume one pinned exact artifact today: the JVM
//! source archives, Java class JARs, TypeScript declaration files, .NET
//! assemblies, rustdoc JSON documents, Python stub trees, npm packages, Go
//! modules, Ruby gem archives, and Composer packages. A spec that names an
//! unknown family fails parsing, it is never skipped.
//!
//! Four of those families -- npm, Go, Ruby, Composer -- have no on-disk
//! installed layout to derive their structure from when a pinned spec is
//! authored, unlike a workspace dependency adapter, which learns that
//! structure from a lockfile or `go list`. Their pinned kinds name the
//! structure explicitly instead: `NpmPackage` and `GoModule` name each
//! declaration file's or source file's owning module/package, and
//! `ComposerPackage` names each autoload rule's admitted files. `RubyGemArchive`
//! needs none of this: a `.gem` file is already the exact artifact its
//! dependency adapter reads, so it is promoted unchanged.
//!
//! The three JVM spec files in `semantic-packs/jvm/` were kept as-is instead
//! of adding a compatibility path: the JSON vocabulary (field names, tags,
//! `schema_version` 1) is unchanged by the generalization, so every existing
//! spec still parses with the same meaning. Only the Rust-level type names
//! dropped their JVM prefix.
//!
//! Extraction rejects are a structured burn-down artifact: `rejects.json`
//! lists every rejected entry with its reject reason, is content-addressed by
//! `SHA256SUMS`, and is validated by `verify` so pack completeness converges
//! release over release.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, ArtifactEncoding, ArtifactProducerLimits, ArtifactProduction,
    ArtifactProductionRequest, CatalogCoordinate, CatalogOptions, Compatibility,
    CompiledSemanticModelPack, CompilerOptions, Completeness, DecodeLimits, DependencyArtifactRole,
    DependencyPackLimits, DurablePackSource, DurablePackSourceKind, ExactArtifact,
    ExactDependencyArtifact, ExternalArtifactKind, GENERATED_PRODUCTION_CACHE_VERSION,
    GeneratedProductionKey, PackExtractionAccounting, PackExtractionGap, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Provenance, ResolvedActiveSemanticModels,
    SEMANTIC_MODEL_SCHEMA_VERSION, Safety, SemanticModelActivationControl,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelControlAction,
    SemanticModelControlScope, SemanticModelPackSelector, SemanticModelResolutionOutcome,
    SemanticPackCatalog, compile_exact_dependency_production, compile_pack, decode_manifest,
    decode_shard_for_manifest, pack_rejects_are_warning_only, read_exact_artifact,
    read_exact_source_set, resolve_active_semantic_models,
};
use brokk_bifrost_analysis::analyzer::{
    CSharpAssemblyPackProducer, ComposerPackagePackProducer, ComposerPinnedAutoloadRule,
    GoModulePackProducer, GoPinnedPackage as AnalysisGoPinnedPackage, JavaJarPackProducer,
    JdkSourceArchiveLayout, JdkSourceArchivePackProducer, JvmDependencyPackAdapter,
    KotlinSourceJarPackProducer, PythonArtifactPackProducer, RubyGemArchivePackProducer,
    RustdocJsonPackProducer, ScalaSourceJarPackProducer, TypeScriptDeclarationPackProducer,
};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

pub const PACK_SPEC_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_BUNDLE_SCHEMA_VERSION: u32 = 2;

fn current_release_generator() -> ReleaseGenerator {
    ReleaseGenerator {
        name: "brokk-bifrost-semantic-packs".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// Bounds for pinned source-set inputs, matching the workspace dependency
/// scanner's `DependencyPackLimits` defaults.
const MAX_SOURCE_SET_FILES: usize = 100_000;
const MAX_SOURCE_SET_PATH_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedPackSpec {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub ecosystem: String,
    pub kind: PinnedPackKind,
    pub artifact: PinnedArtifact,
    pub compatibility: Compatibility,
    pub activation: Vec<ActivationSelector>,
    pub provenance: Provenance,
    pub license: String,
    pub safety: Safety,
    pub notices: Vec<String>,
    pub measurement_activation: ActivationSelector,
    pub measurement_queries: Vec<PinnedLookupQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinnedLookupQuery {
    Type { name: String },
    Member { owner: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinnedPackKind {
    JdkSourceZip {
        layout: PinnedJdkSourceLayout,
    },
    KotlinSourceJar,
    ScalaSourceJar,
    JavaSourceJar,
    JavaClassJar,
    TypeScriptDeclarationFile,
    TypeScriptLibrarySet {
        manifest: String,
        libraries: Vec<PinnedTypeScriptLibrary>,
    },
    DotNetAssembly,
    RustdocJson,
    RustdocJsonSet {
        crates: Vec<PinnedRustdocCrate>,
    },
    /// One pinned Python stub tree. The generate artifact argument names the
    /// tree root directory; `stubs` lists the pinned `.pyi` files relative to
    /// that root. The pinned artifact digest is the canonical source-set
    /// digest over the listed paths and bytes.
    PythonStub {
        stubs: Vec<String>,
    },
    /// One pinned npm package: its manifest plus the pinned TypeScript
    /// declaration files that make up its public surface. `manifest` names
    /// the pinned `package.json` path; each entry in `declarations` names its
    /// own importable module explicitly, mirroring how npm's subpath exports
    /// work, since a pinned tree has no installed `node_modules` layout to
    /// derive that mapping from.
    NpmPackage {
        manifest: String,
        declarations: Vec<PinnedNpmDeclaration>,
    },
    /// One pinned Go module's exact `.go` source set, grouped into the
    /// packages the spec names explicitly. There is no `go list` invocation
    /// available to derive package boundaries from a bare source tree, so the
    /// spec names each package's import path, declared name, and files the
    /// same way `PythonStub` names its files.
    GoModule {
        packages: Vec<PinnedGoPackage>,
    },
    /// One pinned `.gem` archive, read and projected exactly as the Ruby
    /// dependency adapter projects an installed gem: RBS is authoritative
    /// where present, Sorbet RBI and plain Ruby fill the remainder.
    RubyGemArchive,
    /// One pinned Composer package's exact PHP source set, grouped into the
    /// autoload rules the spec names explicitly. There is no installed vendor
    /// tree available to derive PSR-4/classmap/files rules from, so the spec
    /// names each rule and the files it admits directly.
    ComposerPackage {
        rules: Vec<PinnedComposerAutoloadRule>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedNpmDeclaration {
    pub module: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedTypeScriptLibrary {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRustdocCrate {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedGoPackage {
    pub import_path: String,
    pub name: String,
    pub files: Vec<String>,
}

/// `namespace_prefix` is Bifrost's canonical dotted namespace form (e.g.
/// `Vendor.Widget`, not `Vendor\Widget\`), matching how the pack's declared
/// type names are stored and how a measurement query names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinnedComposerAutoloadRule {
    Psr4 {
        namespace_prefix: String,
        files: Vec<String>,
    },
    Classmap {
        files: Vec<String>,
    },
    Files {
        files: Vec<String>,
    },
}

impl PinnedComposerAutoloadRule {
    fn files(&self) -> &[String] {
        match self {
            Self::Psr4 { files, .. } | Self::Classmap { files } | Self::Files { files } => files,
        }
    }

    fn to_producer_rule(&self) -> ComposerPinnedAutoloadRule {
        match self {
            Self::Psr4 {
                namespace_prefix,
                files,
            } => ComposerPinnedAutoloadRule::Psr4 {
                namespace_prefix: namespace_prefix.clone(),
                files: files.clone(),
            },
            Self::Classmap { files } => ComposerPinnedAutoloadRule::Classmap {
                files: files.clone(),
            },
            Self::Files { files } => ComposerPinnedAutoloadRule::Files {
                files: files.clone(),
            },
        }
    }
}

impl PinnedPackKind {
    fn artifact_kind(&self) -> ExternalArtifactKind {
        match self {
            Self::JdkSourceZip { .. } => ExternalArtifactKind::JdkSourceZip,
            Self::KotlinSourceJar => ExternalArtifactKind::KotlinSourceJar,
            Self::ScalaSourceJar => ExternalArtifactKind::ScalaSourceJar,
            Self::JavaSourceJar => ExternalArtifactKind::JavaSourceJar,
            Self::JavaClassJar => ExternalArtifactKind::JavaClassJar,
            Self::TypeScriptDeclarationFile => ExternalArtifactKind::TypeScriptDeclarationFile,
            Self::TypeScriptLibrarySet { .. } => ExternalArtifactKind::TypeScriptLibrarySet,
            Self::DotNetAssembly => ExternalArtifactKind::DotNetAssembly,
            Self::RustdocJson => ExternalArtifactKind::RustdocJson,
            Self::RustdocJsonSet { .. } => ExternalArtifactKind::RustdocJsonSet,
            Self::PythonStub { .. } => ExternalArtifactKind::PythonStub,
            Self::NpmPackage { .. } => ExternalArtifactKind::NpmPackageManifest,
            Self::GoModule { .. } => ExternalArtifactKind::GoSourceSet,
            Self::RubyGemArchive => ExternalArtifactKind::RubyGemArchive,
            Self::ComposerPackage { .. } => ExternalArtifactKind::ComposerPackageSourceSet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedJdkSourceLayout {
    ModulePrefixed,
    Flat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedArtifact {
    pub file_name: String,
    pub sha256: String,
    pub url: Option<String>,
    pub container: Option<PinnedArtifactContainer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedArtifactContainer {
    pub file_name: String,
    pub sha256: String,
    pub url: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundleIndex {
    pub schema_version: u32,
    pub generator: ReleaseGenerator,
    pub packs: Vec<ReleasePack>,
    /// Exact dependency productions are separate from curated release packs.
    /// The latter are selected by their reviewed upstream identity; these
    /// entries are selected by the runtime generated-production key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_productions: Vec<ReleaseGeneratedProduction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGenerator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePack {
    pub pack_id: String,
    pub pack_version: String,
    pub language: String,
    pub ecosystem: String,
    pub artifact: PinnedArtifact,
    pub artifact_bytes: u64,
    pub manifest: ReleaseAsset,
    pub manifest_semantic_sha256: String,
    pub manifest_content_sha256: String,
    pub completeness: Completeness,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub notices: Vec<ReleaseNotice>,
    pub shards: Vec<ReleaseShard>,
}

/// One exact dependency production emitted by the runtime adapter during
/// release qualification. This is intentionally separate from [`ReleasePack`]
/// so a curated pack can retain its upstream producer identity and exhaustive
/// extraction report without being mistaken for a generated cache entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGeneratedProduction {
    /// The curated release recipe that supplied the exact artifact bytes.
    pub source_pack_id: String,
    pub source_pack_version: String,
    pub artifact_sha256: String,
    pub input_digest: String,
    pub producer_name: String,
    pub producer_version: String,
    pub schema_version: u32,
    pub cache_version: u32,
    pub production_digest: String,
    pub pack_id: String,
    pub pack_version: String,
    pub language: String,
    pub ecosystem: String,
    pub manifest: ReleaseAsset,
    pub manifest_semantic_sha256: String,
    pub manifest_content_sha256: String,
    pub completeness: Completeness,
    pub shards: Vec<ReleaseShard>,
    pub rejects: Vec<ReleaseReject>,
    pub suppressed_rejects: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseNotice {
    pub source_path: String,
    pub asset: ReleaseAsset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseShard {
    pub shard_id: String,
    pub asset: ReleaseAsset,
    pub encoding: ArtifactEncoding,
    pub raw_bytes: u64,
    pub records: u64,
    pub semantic_sha256: String,
    pub content_sha256: String,
}

/// The structured extraction burn-down artifact stored as `rejects.json`.
///
/// One entry exists for every producer diagnostic recorded while extracting a
/// pinned artifact, so a partial pack names exactly which inputs it dropped
/// and why. The file is deterministic for the same pinned inputs and is part
/// of the checksummed release inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundleRejects {
    pub schema_version: u32,
    pub generator: ReleaseGenerator,
    pub packs: Vec<ReleasePackRejects>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePackRejects {
    pub pack_id: String,
    pub pack_version: String,
    pub completeness: Completeness,
    pub rejects: Vec<ReleaseReject>,
    pub suppressed_rejects: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseReject {
    pub severity: ReleaseRejectSeverity,
    pub code: String,
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseRejectSeverity {
    Warning,
    Error,
}

impl Display for ReleaseRejectSeverity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// One verified release bundle: the canonical index and the structured
/// extraction burn-down report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBundle {
    pub index: ReleaseBundleIndex,
    pub rejects: ReleaseBundleRejects,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundleMeasurements {
    pub schema_version: u32,
    pub generator: ReleaseGenerator,
    pub packs: Vec<ReleasePackMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePackMeasurement {
    pub pack_id: String,
    pub pack_version: String,
    pub generation_millis: u64,
    pub artifact_bytes: u64,
    pub manifest_bytes: u64,
    pub stored_shard_bytes: u64,
    pub raw_shard_bytes: u64,
    pub shard_count: u64,
    pub record_count: u64,
    pub completeness: Completeness,
    pub activation_micros: u64,
    pub activation_selection_nanos: u64,
    pub cold_decode_hydration_nanos: u64,
    pub matcher_construction_nanos: u64,
    pub activation_catalog_sql_statements: u64,
    pub activation_candidate_count: u64,
    pub matcher_index_entries: u64,
    pub retained_model_bytes: u64,
    pub lookups: Vec<ReleaseLookupMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseLookupMeasurement {
    pub query: PinnedLookupQuery,
    pub cold_nanos: u64,
    pub warm_nanos: u64,
    pub records: u64,
}

struct RuntimeMeasurement {
    activation_micros: u64,
    activation_selection_nanos: u64,
    cold_decode_hydration_nanos: u64,
    matcher_construction_nanos: u64,
    activation_catalog_sql_statements: u64,
    activation_candidate_count: u64,
    matcher_index_entries: u64,
    retained_model_bytes: u64,
    lookups: Vec<ReleaseLookupMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleInput {
    pub spec_path: PathBuf,
    pub artifact_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePackInstallation {
    pub pack_id: String,
    pub pack_version: String,
    pub manifest_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(String);

impl BundleError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for BundleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BundleError {}

pub fn generate_release_bundle(
    output_root: &Path,
    inputs: &[BundleInput],
) -> Result<ReleaseBundle, BundleError> {
    if inputs.is_empty() {
        return Err(BundleError::new(
            "at least one spec/artifact pair is required",
        ));
    }
    fs::create_dir_all(output_root)
        .map_err(|error| BundleError::new(format!("create {}: {error}", output_root.display())))?;
    let specs = inputs
        .iter()
        .map(|input| read_and_validate_spec(&input.spec_path))
        .collect::<Result<Vec<_>, BundleError>>()?;
    assert_eq!(
        inputs.len(),
        specs.len(),
        "each release input must have one parsed spec"
    );
    let generator = current_release_generator();
    let mut packs = Vec::with_capacity(inputs.len());
    let mut measurements = Vec::with_capacity(inputs.len());
    let mut rejects = Vec::with_capacity(inputs.len());
    for (input, spec) in inputs.iter().zip(&specs) {
        let (pack, measurement, pack_rejects) = generate_one(output_root, input, spec)?;
        packs.push(pack);
        measurements.push(measurement);
        rejects.push(pack_rejects);
    }
    packs.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    measurements.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    rejects.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    for pair in packs.windows(2) {
        if pair[0].pack_id == pair[1].pack_id && pair[0].pack_version == pair[1].pack_version {
            return Err(BundleError::new(format!(
                "duplicate release pack {}@{}",
                pair[0].pack_id, pair[0].pack_version
            )));
        }
    }
    let generated_productions =
        generate_generated_productions(output_root, inputs, &specs, &packs)?;
    let index = ReleaseBundleIndex {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator: generator.clone(),
        packs,
        generated_productions,
    };
    write_new_or_identical(output_root, Path::new("index.json"), &json_bytes(&index)?)?;
    let rejects = ReleaseBundleRejects {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator: generator.clone(),
        packs: rejects,
    };
    write_new_or_identical(
        output_root,
        Path::new("rejects.json"),
        &json_bytes(&rejects)?,
    )?;
    let measurements = ReleaseBundleMeasurements {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator,
        packs: measurements,
    };
    write_replace(
        output_root,
        Path::new("measurements.json"),
        &json_bytes(&measurements)?,
    )?;
    write_checksums(output_root, &index)?;
    verify_release_bundle(output_root)
}

fn read_and_validate_spec(spec_path: &Path) -> Result<PinnedPackSpec, BundleError> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|error| BundleError::new(format!("read spec {}: {error}", spec_path.display())))?;
    let spec: PinnedPackSpec = serde_json::from_slice(&spec_bytes).map_err(|error| {
        BundleError::new(format!("parse spec {}: {error}", spec_path.display()))
    })?;
    validate_spec(&spec, spec_path)?;
    Ok(spec)
}

fn generate_one(
    output_root: &Path,
    input: &BundleInput,
    spec: &PinnedPackSpec,
) -> Result<(ReleasePack, ReleasePackMeasurement, ReleasePackRejects), BundleError> {
    // A release bundle is the durable extraction-accounting boundary. Retain
    // the interactive safety bound, but size it to the already-bounded source
    // set so every rejected declaration can be named in `rejects.json`.
    let producer_limits = ArtifactProducerLimits {
        max_diagnostics: MAX_SOURCE_SET_FILES,
        ..ArtifactProducerLimits::default()
    };
    let artifact = read_pinned_artifact(spec, &input.artifact_path, &producer_limits)?;
    if artifact.sha256() != spec.artifact.sha256 {
        return Err(BundleError::new(format!(
            "artifact {} SHA-256 {} does not match pinned {}",
            input.artifact_path.display(),
            artifact.sha256(),
            spec.artifact.sha256
        )));
    }
    if input
        .artifact_path
        .file_name()
        .and_then(|name| name.to_str())
        != Some(spec.artifact.file_name.as_str())
    {
        return Err(BundleError::new(format!(
            "artifact file name must be pinned as {}",
            spec.artifact.file_name
        )));
    }

    let request = ArtifactProductionRequest {
        path: input.artifact_path.clone(),
        artifact_kind: spec.kind.artifact_kind(),
        pack_id: spec.pack_id.clone(),
        pack_version: spec.pack_version.clone(),
        ecosystem: spec.ecosystem.clone(),
        compatibility: spec.compatibility.clone(),
        activation: spec.activation.clone(),
        provenance: spec.provenance.clone(),
        license: spec.license.clone(),
        safety: spec.safety.clone(),
    };
    let started = Instant::now();
    let cancellation = CancellationToken::default();
    let production = produce_pinned_pack(
        &spec.kind,
        &request,
        &producer_limits,
        &cancellation,
        &artifact,
    );
    let authored = production.pack.as_ref().ok_or_else(|| {
        BundleError::new(format!(
            "pack production failed: {}",
            render_diagnostics(&production.diagnostics)
        ))
    })?;
    if production.artifact_sha256.as_deref() != Some(spec.artifact.sha256.as_str()) {
        return Err(BundleError::new(
            "producer did not retain the pinned artifact identity",
        ));
    }
    let compiled = compile_pack(authored, &CompilerOptions::default()).map_err(|diagnostics| {
        BundleError::new(format!("pack compilation failed: {diagnostics:#?}"))
    })?;
    let elapsed = started.elapsed();
    let runtime_measurement = measure_runtime(spec, &compiled, &cancellation)?;

    let (manifest, manifest_semantic_sha256, manifest_content_sha256, shards) =
        write_compiled_assets(output_root, &compiled)?;
    let notices = copy_notices(output_root, &input.spec_path, &spec.notices)?;
    let measurement = measurement(
        spec,
        artifact.bytes().len() as u64,
        &compiled,
        elapsed.as_millis().try_into().unwrap_or(u64::MAX),
        runtime_measurement,
    );
    let pack_rejects = ReleasePackRejects {
        pack_id: spec.pack_id.clone(),
        pack_version: spec.pack_version.clone(),
        completeness: compiled.manifest.completeness,
        rejects: production
            .diagnostics
            .iter()
            .map(|diagnostic| ReleaseReject {
                severity: match diagnostic.severity {
                    ProducerDiagnosticSeverity::Warning => ReleaseRejectSeverity::Warning,
                    ProducerDiagnosticSeverity::Error => ReleaseRejectSeverity::Error,
                },
                code: diagnostic.code.clone(),
                location: diagnostic.location.clone(),
                declaration: diagnostic.declaration.clone(),
                message: diagnostic.message.clone(),
            })
            .collect(),
        suppressed_rejects: production
            .suppressed_diagnostics
            .try_into()
            .unwrap_or(u64::MAX),
    };
    Ok((
        ReleasePack {
            pack_id: spec.pack_id.clone(),
            pack_version: spec.pack_version.clone(),
            language: compiled.manifest.language.clone(),
            ecosystem: spec.ecosystem.clone(),
            artifact: spec.artifact.clone(),
            artifact_bytes: artifact.bytes().len() as u64,
            manifest,
            manifest_semantic_sha256,
            manifest_content_sha256,
            completeness: compiled.manifest.completeness,
            compatibility: spec.compatibility.clone(),
            provenance: spec.provenance.clone(),
            license: spec.license.clone(),
            notices,
            shards,
        },
        measurement,
        pack_rejects,
    ))
}

fn generate_generated_productions(
    output_root: &Path,
    inputs: &[BundleInput],
    specs: &[PinnedPackSpec],
    curated_packs: &[ReleasePack],
) -> Result<Vec<ReleaseGeneratedProduction>, BundleError> {
    assert_eq!(
        inputs.len(),
        specs.len(),
        "each release input must have one parsed spec"
    );
    let mut generated = Vec::new();
    for (input, spec) in inputs.iter().zip(specs) {
        if !matches!(&spec.kind, PinnedPackKind::JdkSourceZip { .. }) {
            continue;
        }
        let curated = curated_packs
            .iter()
            .find(|pack| pack.pack_id == spec.pack_id && pack.pack_version == spec.pack_version)
            .ok_or_else(|| {
                BundleError::new(format!(
                    "generated JDK production has no curated source pack {}@{}",
                    spec.pack_id, spec.pack_version
                ))
            })?;
        generated.push(generate_jdk_production(output_root, input, spec, curated)?);
    }
    generated.sort_unstable_by(|left, right| {
        left.production_digest
            .cmp(&right.production_digest)
            .then_with(|| left.source_pack_id.cmp(&right.source_pack_id))
            .then_with(|| left.source_pack_version.cmp(&right.source_pack_version))
    });
    Ok(generated)
}

fn generate_jdk_production(
    output_root: &Path,
    input: &BundleInput,
    spec: &PinnedPackSpec,
    curated: &ReleasePack,
) -> Result<ReleaseGeneratedProduction, BundleError> {
    let version = exact_jdk_version(spec)?;
    // `read_exact_artifact` reports at most one diagnostic (a hard read
    // failure), so it never feeds the bounded-diagnostics accounting below;
    // the interactive default is fine here.
    let artifact_limits = ArtifactProducerLimits::default();
    let artifact = read_exact_artifact(&input.artifact_path, &artifact_limits)
        .map_err(|diagnostic| BundleError::new(render_diagnostics(&[diagnostic])))?;
    if artifact.sha256() != spec.artifact.sha256 || artifact.sha256() != curated.artifact.sha256 {
        return Err(BundleError::new(format!(
            "generated JDK artifact {} does not match curated pinned digest",
            input.artifact_path.display()
        )));
    }
    let dependency =
        JvmDependencyPackAdapter::jdk_source_dependency(version, input.artifact_path.clone());
    let exact = ExactDependencyArtifact::from_exact(
        DependencyArtifactRole::Sources,
        ExternalArtifactKind::JdkSourceZip,
        None,
        artifact,
    );
    // Same durable-extraction-accounting boundary as `generate_one`: the
    // derived production must be able to name every rejected declaration, not
    // just the interactive-safety-bounded first 256.
    let limits = DependencyPackLimits {
        max_diagnostics: MAX_SOURCE_SET_FILES,
        producer: ArtifactProducerLimits {
            max_diagnostics: MAX_SOURCE_SET_FILES,
            ..ArtifactProducerLimits::default()
        },
        ..DependencyPackLimits::default()
    };
    let cancellation = CancellationToken::default();
    let production = compile_exact_dependency_production(
        &JvmDependencyPackAdapter,
        &dependency,
        &[exact],
        &limits,
        Some(&cancellation),
    )
    .map_err(|error| {
        BundleError::new(format!(
            "compile generated JDK production for {}@{}: {error:?}",
            spec.pack_id, spec.pack_version
        ))
    })?;
    let (manifest, manifest_semantic_sha256, manifest_content_sha256, shards) =
        write_compiled_assets(output_root, &production.compiled)?;
    let rejects = production
        .diagnostics
        .iter()
        .map(release_reject)
        .collect::<Vec<_>>();
    Ok(ReleaseGeneratedProduction {
        source_pack_id: curated.pack_id.clone(),
        source_pack_version: curated.pack_version.clone(),
        artifact_sha256: spec.artifact.sha256.clone(),
        input_digest: production.key.input_digest().to_owned(),
        producer_name: production.key.producer_name().to_owned(),
        producer_version: production.key.producer_version().to_owned(),
        schema_version: production.key.schema_version(),
        cache_version: GENERATED_PRODUCTION_CACHE_VERSION,
        production_digest: production.key.production_digest().to_owned(),
        pack_id: production.compiled.manifest.pack_id.clone(),
        pack_version: production.compiled.manifest.version.clone(),
        language: production.compiled.manifest.language.clone(),
        ecosystem: production.compiled.manifest.ecosystem.clone(),
        manifest,
        manifest_semantic_sha256,
        manifest_content_sha256,
        completeness: production.completeness,
        shards,
        rejects,
        suppressed_rejects: production
            .suppressed_diagnostics
            .try_into()
            .unwrap_or(u64::MAX),
    })
}

fn exact_jdk_version(spec: &PinnedPackSpec) -> Result<Version, BundleError> {
    let selector = spec
        .activation
        .iter()
        .find_map(|selector| selector.toolchain.as_ref())
        .ok_or_else(|| {
            BundleError::new(format!(
                "JDK spec {}@{} requires an exact toolchain selector",
                spec.pack_id, spec.pack_version
            ))
        })?;
    let requirement = selector.version.as_deref().ok_or_else(|| {
        BundleError::new(format!(
            "JDK spec {}@{} requires an exact toolchain version",
            spec.pack_id, spec.pack_version
        ))
    })?;
    let version = requirement.strip_prefix('=').ok_or_else(|| {
        BundleError::new(format!(
            "JDK spec {}@{} toolchain selector must be exact",
            spec.pack_id, spec.pack_version
        ))
    })?;
    Version::parse(version).map_err(|error| {
        BundleError::new(format!(
            "JDK spec {}@{} has invalid toolchain version {version:?}: {error}",
            spec.pack_id, spec.pack_version
        ))
    })
}

fn write_compiled_assets(
    output_root: &Path,
    compiled: &CompiledSemanticModelPack,
) -> Result<(ReleaseAsset, String, String, Vec<ReleaseShard>), BundleError> {
    let manifest_sha256 = sha256_bytes(&compiled.manifest_bytes);
    let manifest_path = format!("manifests/{manifest_sha256}.json");
    write_content_addressed(output_root, &manifest_path, &compiled.manifest_bytes)?;
    let mut shards = compiled
        .shards
        .iter()
        .map(|shard| {
            let path = format!("shards/{}.bin", shard.descriptor.stored_sha256);
            write_content_addressed(output_root, &path, &shard.bytes)?;
            Ok(ReleaseShard {
                shard_id: shard.descriptor.shard_id.clone(),
                asset: ReleaseAsset {
                    path,
                    sha256: shard.descriptor.stored_sha256.clone(),
                    bytes: shard.descriptor.stored_size,
                },
                encoding: shard.descriptor.encoding,
                raw_bytes: shard.descriptor.raw_size,
                records: shard.descriptor.record_count,
                semantic_sha256: shard.descriptor.semantic_sha256.clone(),
                content_sha256: shard.descriptor.content_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    shards.sort_unstable_by(|left, right| left.shard_id.cmp(&right.shard_id));
    Ok((
        ReleaseAsset {
            path: manifest_path,
            sha256: manifest_sha256,
            bytes: compiled.manifest_bytes.len().try_into().unwrap_or(u64::MAX),
        },
        compiled.manifest.semantic_sha256.clone(),
        compiled.manifest.content_sha256.clone(),
        shards,
    ))
}

fn release_reject(diagnostic: &ProducerDiagnostic) -> ReleaseReject {
    ReleaseReject {
        severity: match diagnostic.severity {
            ProducerDiagnosticSeverity::Warning => ReleaseRejectSeverity::Warning,
            ProducerDiagnosticSeverity::Error => ReleaseRejectSeverity::Error,
        },
        code: diagnostic.code.clone(),
        location: diagnostic.location.clone(),
        declaration: diagnostic.declaration.clone(),
        message: diagnostic.message.clone(),
    }
}

/// Read the pinned input exactly as the spec kind defines it: a single
/// artifact file for archive and document kinds, or a canonical source set
/// for tree kinds.
fn read_pinned_artifact(
    spec: &PinnedPackSpec,
    artifact_path: &Path,
    limits: &ArtifactProducerLimits,
) -> Result<ExactArtifact, BundleError> {
    match &spec.kind {
        PinnedPackKind::PythonStub { stubs } => {
            let relative_paths = stubs.iter().map(PathBuf::from).collect::<Vec<_>>();
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        PinnedPackKind::NpmPackage {
            manifest,
            declarations,
        } => {
            let mut relative_paths = vec![PathBuf::from(manifest)];
            relative_paths.extend(
                declarations
                    .iter()
                    .map(|declaration| PathBuf::from(&declaration.path)),
            );
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        PinnedPackKind::TypeScriptLibrarySet {
            manifest,
            libraries,
        } => {
            let mut relative_paths = vec![PathBuf::from(manifest)];
            relative_paths.extend(libraries.iter().map(|library| PathBuf::from(&library.path)));
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        PinnedPackKind::GoModule { packages } => {
            let relative_paths = packages
                .iter()
                .flat_map(|package| package.files.iter().map(PathBuf::from))
                .collect::<Vec<_>>();
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        PinnedPackKind::ComposerPackage { rules } => {
            let relative_paths = rules
                .iter()
                .flat_map(|rule| rule.files().iter().map(PathBuf::from))
                .collect::<Vec<_>>();
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        PinnedPackKind::RustdocJsonSet { crates } => {
            let relative_paths = crates
                .iter()
                .map(|crate_spec| PathBuf::from(&crate_spec.path))
                .collect::<Vec<_>>();
            read_exact_source_set(
                artifact_path,
                &relative_paths,
                MAX_SOURCE_SET_FILES,
                MAX_SOURCE_SET_PATH_DEPTH,
                limits,
            )
        }
        _ => read_exact_artifact(artifact_path, limits),
    }
    .map_err(|diagnostic| BundleError::new(render_diagnostics(&[diagnostic])))
}

fn produce_pinned_pack(
    kind: &PinnedPackKind,
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    cancellation: &CancellationToken,
    artifact: &ExactArtifact,
) -> ArtifactProduction {
    let cancellation = Some(cancellation);
    match kind {
        PinnedPackKind::JdkSourceZip { layout } => {
            JdkSourceArchivePackProducer::new(match *layout {
                PinnedJdkSourceLayout::ModulePrefixed => JdkSourceArchiveLayout::ModulePrefixed,
                PinnedJdkSourceLayout::Flat => JdkSourceArchiveLayout::Flat,
            })
            .produce_loaded_artifact(request, limits, cancellation, artifact)
        }
        PinnedPackKind::KotlinSourceJar => KotlinSourceJarPackProducer.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::ScalaSourceJar => ScalaSourceJarPackProducer.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::JavaSourceJar | PinnedPackKind::JavaClassJar => {
            JavaJarPackProducer.produce_loaded_artifact(request, limits, cancellation, artifact)
        }
        PinnedPackKind::TypeScriptDeclarationFile => TypeScriptDeclarationPackProducer
            .produce_loaded_artifact(request, limits, cancellation, artifact),
        PinnedPackKind::TypeScriptLibrarySet {
            manifest,
            libraries,
        } => {
            let libraries = libraries
                .iter()
                .map(|library| (library.name.clone(), library.path.clone()))
                .collect::<Vec<_>>();
            TypeScriptDeclarationPackProducer.produce_loaded_library_set(
                request,
                limits,
                cancellation,
                artifact,
                manifest,
                &libraries,
            )
        }
        PinnedPackKind::DotNetAssembly => CSharpAssemblyPackProducer.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::RustdocJson => {
            RustdocJsonPackProducer.produce_loaded_artifact(request, limits, cancellation, artifact)
        }
        PinnedPackKind::RustdocJsonSet { crates } => {
            let crates = crates
                .iter()
                .map(|crate_spec| (crate_spec.name.clone(), crate_spec.path.clone()))
                .collect::<Vec<_>>();
            RustdocJsonPackProducer.produce_loaded_source_set(
                request,
                limits,
                cancellation,
                artifact,
                &crates,
            )
        }
        PinnedPackKind::PythonStub { .. } => PythonArtifactPackProducer.produce_loaded_source_set(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::NpmPackage {
            manifest,
            declarations,
        } => {
            let declarations = declarations
                .iter()
                .map(|declaration| (declaration.module.clone(), declaration.path.clone()))
                .collect::<Vec<_>>();
            TypeScriptDeclarationPackProducer.produce_loaded_source_set(
                request,
                limits,
                cancellation,
                artifact,
                manifest,
                &declarations,
            )
        }
        PinnedPackKind::GoModule { packages } => {
            let packages = packages
                .iter()
                .map(|package| AnalysisGoPinnedPackage {
                    import_path: package.import_path.clone(),
                    name: package.name.clone(),
                    files: package.files.clone(),
                })
                .collect::<Vec<_>>();
            GoModulePackProducer.produce_loaded_source_set(
                request,
                limits,
                cancellation,
                artifact,
                &packages,
            )
        }
        PinnedPackKind::RubyGemArchive => RubyGemArchivePackProducer.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::ComposerPackage { rules } => {
            let rules = rules
                .iter()
                .map(PinnedComposerAutoloadRule::to_producer_rule)
                .collect::<Vec<_>>();
            ComposerPackagePackProducer.produce_loaded_source_set(
                request,
                limits,
                cancellation,
                artifact,
                &rules,
            )
        }
    }
}

fn validate_spec(spec: &PinnedPackSpec, spec_path: &Path) -> Result<(), BundleError> {
    if spec.schema_version != PACK_SPEC_SCHEMA_VERSION {
        return Err(BundleError::new(format!(
            "spec {} has unsupported schema version {}",
            spec_path.display(),
            spec.schema_version
        )));
    }
    if spec.pack_id.is_empty() || spec.pack_version.is_empty() || spec.activation.is_empty() {
        return Err(BundleError::new(format!(
            "spec {} requires pack identity and activation selectors",
            spec_path.display()
        )));
    }
    if spec.license.trim().is_empty() || spec.license == "NOASSERTION" {
        return Err(BundleError::new(format!(
            "spec {} must name the upstream license as an SPDX expression",
            spec_path.display()
        )));
    }
    if spec.provenance.source.trim().is_empty() {
        return Err(BundleError::new(format!(
            "spec {} must name its upstream provenance source",
            spec_path.display()
        )));
    }
    if spec.notices.is_empty() {
        return Err(BundleError::new(format!(
            "spec {} must name at least one license or notice file",
            spec_path.display()
        )));
    }
    if let PinnedPackKind::PythonStub { stubs } = &spec.kind {
        if stubs.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned stub file",
                spec_path.display()
            )));
        }
        for stub in stubs {
            let stub_path = Path::new(stub);
            require_safe_relative(stub_path)?;
            if stub_path
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("pyi")
            {
                return Err(BundleError::new(format!(
                    "spec {} pins non-stub source {stub}; every pinned stub must be a .pyi file",
                    spec_path.display()
                )));
            }
        }
    }
    if let PinnedPackKind::NpmPackage {
        manifest,
        declarations,
    } = &spec.kind
    {
        require_safe_relative(Path::new(manifest))?;
        if declarations.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned npm declaration file",
                spec_path.display()
            )));
        }
        for declaration in declarations {
            if declaration.module.trim().is_empty() {
                return Err(BundleError::new(format!(
                    "spec {} pins declaration {} with no importable module name",
                    spec_path.display(),
                    declaration.path
                )));
            }
            let declaration_path = Path::new(&declaration.path);
            require_safe_relative(declaration_path)?;
            if !declaration.path.ends_with(".d.ts") {
                return Err(BundleError::new(format!(
                    "spec {} pins non-declaration source {}; every pinned npm declaration must be a .d.ts file",
                    spec_path.display(),
                    declaration.path
                )));
            }
        }
    }
    if let PinnedPackKind::TypeScriptLibrarySet {
        manifest,
        libraries,
    } = &spec.kind
    {
        require_safe_relative(Path::new(manifest))?;
        if libraries.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned TypeScript library file",
                spec_path.display()
            )));
        }
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for library in libraries {
            if library.name.trim().is_empty()
                || !library
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
            {
                return Err(BundleError::new(format!(
                    "spec {} pins a TypeScript library with a non-canonical name {}",
                    spec_path.display(),
                    library.name
                )));
            }
            if !names.insert(library.name.clone()) {
                return Err(BundleError::new(format!(
                    "spec {} lists duplicate TypeScript library name {}",
                    spec_path.display(),
                    library.name
                )));
            }
            let library_path = Path::new(&library.path);
            require_safe_relative(library_path)?;
            if !paths.insert(library.path.clone()) {
                return Err(BundleError::new(format!(
                    "spec {} lists duplicate TypeScript library path {}",
                    spec_path.display(),
                    library.path
                )));
            }
            let canonical_name = library_path
                .parent()
                .filter(|parent| *parent == Path::new("lib"))
                .and_then(|_| library_path.file_name())
                .and_then(|file_name| file_name.to_str())
                .and_then(|file_name| file_name.strip_prefix("lib."))
                .and_then(|file_name| file_name.strip_suffix(".d.ts"));
            if canonical_name != Some(library.name.as_str()) {
                return Err(BundleError::new(format!(
                    "spec {} TypeScript library {} does not match its canonical path {}",
                    spec_path.display(),
                    library.name,
                    library.path
                )));
            }
        }
    }
    if let PinnedPackKind::GoModule { packages } = &spec.kind {
        if packages.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned Go package",
                spec_path.display()
            )));
        }
        for package in packages {
            if package.import_path.trim().is_empty() || package.name.trim().is_empty() {
                return Err(BundleError::new(format!(
                    "spec {} pins a Go package with no import path or declared name",
                    spec_path.display()
                )));
            }
            if package.files.is_empty() {
                return Err(BundleError::new(format!(
                    "spec {} pins Go package {} with no files",
                    spec_path.display(),
                    package.import_path
                )));
            }
            for file in &package.files {
                let file_path = Path::new(file);
                require_safe_relative(file_path)?;
                if file_path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    != Some("go")
                {
                    return Err(BundleError::new(format!(
                        "spec {} pins non-Go source {file} in package {}; every pinned file must be a .go file",
                        spec_path.display(),
                        package.import_path
                    )));
                }
            }
        }
    }
    if let PinnedPackKind::ComposerPackage { rules } = &spec.kind {
        if rules.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned Composer autoload rule",
                spec_path.display()
            )));
        }
        for rule in rules {
            if rule.files().is_empty() {
                return Err(BundleError::new(format!(
                    "spec {} pins a Composer autoload rule with no files",
                    spec_path.display()
                )));
            }
            for file in rule.files() {
                let file_path = Path::new(file);
                require_safe_relative(file_path)?;
                if file_path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    != Some("php")
                {
                    return Err(BundleError::new(format!(
                        "spec {} pins non-PHP source {file}; every pinned Composer file must be a .php file",
                        spec_path.display()
                    )));
                }
            }
        }
    }
    if let PinnedPackKind::RustdocJsonSet { crates } = &spec.kind {
        if crates.is_empty() {
            return Err(BundleError::new(format!(
                "spec {} must list at least one pinned rustdoc JSON crate",
                spec_path.display()
            )));
        }
        for crate_spec in crates {
            if crate_spec.name.trim().is_empty() {
                return Err(BundleError::new(format!(
                    "spec {} pins a rustdoc JSON crate with no crate name",
                    spec_path.display()
                )));
            }
            let crate_path = Path::new(&crate_spec.path);
            require_safe_relative(crate_path)?;
            if !crate_spec.path.ends_with(".json") {
                return Err(BundleError::new(format!(
                    "spec {} pins non-JSON rustdoc source {}; every pinned crate must be a .json file",
                    spec_path.display(),
                    crate_spec.path
                )));
            }
        }
    }
    if spec.measurement_queries.is_empty() {
        return Err(BundleError::new(format!(
            "spec {} must name at least one representative lookup",
            spec_path.display()
        )));
    }
    validate_sha256("artifact", &spec.artifact.sha256)?;
    let artifact_name = Path::new(&spec.artifact.file_name);
    if artifact_name.file_name().and_then(|name| name.to_str())
        != Some(spec.artifact.file_name.as_str())
    {
        return Err(BundleError::new(
            "artifact file_name must be one path component",
        ));
    }
    if spec.artifact.url.is_none() && spec.artifact.container.is_none() {
        return Err(BundleError::new(
            "artifact requires a direct URL or pinned container",
        ));
    }
    if let Some(container) = &spec.artifact.container {
        validate_sha256("artifact container", &container.sha256)?;
        if container.url.is_empty() || container.artifact_path.is_empty() {
            return Err(BundleError::new(
                "artifact container metadata must be complete",
            ));
        }
    }
    let mut notice_paths = BTreeSet::new();
    for notice in &spec.notices {
        require_safe_relative(Path::new(notice))?;
        if !notice_paths.insert(notice) {
            return Err(BundleError::new(format!(
                "spec {} lists duplicate notice source path {notice}",
                spec_path.display()
            )));
        }
    }
    for selector in [
        spec.measurement_activation.package.as_ref(),
        spec.measurement_activation.module.as_ref(),
        spec.measurement_activation.toolchain.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(requirement) = &selector.version
            && requirement
                .strip_prefix('=')
                .and_then(|version| Version::parse(version).ok())
                .is_none()
        {
            return Err(BundleError::new(format!(
                "measurement selector {} requires an exact semantic version",
                selector.name
            )));
        }
    }
    Ok(())
}

fn copy_notices(
    output_root: &Path,
    spec_path: &Path,
    notices: &[String],
) -> Result<Vec<ReleaseNotice>, BundleError> {
    let spec_root = fs::canonicalize(spec_path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|error| BundleError::new(format!("resolve spec directory: {error}")))?;
    let mut result = Vec::with_capacity(notices.len());
    for source_path in notices {
        let unresolved = spec_root.join(source_path);
        let metadata = fs::symlink_metadata(&unresolved)
            .map_err(|error| BundleError::new(format!("inspect notice {source_path}: {error}")))?;
        if metadata.file_type().is_symlink() {
            return Err(BundleError::new(format!(
                "notice {source_path} must not be a symbolic link"
            )));
        }
        let resolved = fs::canonicalize(&unresolved)
            .map_err(|error| BundleError::new(format!("resolve notice {source_path}: {error}")))?;
        if !resolved.starts_with(&spec_root) {
            return Err(BundleError::new(format!(
                "notice {source_path} resolves outside its spec directory"
            )));
        }
        let bytes = fs::read(&resolved)
            .map_err(|error| BundleError::new(format!("read notice {source_path}: {error}")))?;
        let sha256 = sha256_bytes(&bytes);
        let path = format!("notices/{sha256}.txt");
        write_content_addressed(output_root, &path, &bytes)?;
        result.push(ReleaseNotice {
            source_path: source_path.clone(),
            asset: ReleaseAsset {
                path,
                sha256,
                bytes: bytes.len().try_into().unwrap_or(u64::MAX),
            },
        });
    }
    result.sort_unstable_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(result)
}

fn measurement(
    spec: &PinnedPackSpec,
    artifact_bytes: u64,
    compiled: &CompiledSemanticModelPack,
    generation_millis: u64,
    runtime: RuntimeMeasurement,
) -> ReleasePackMeasurement {
    ReleasePackMeasurement {
        pack_id: spec.pack_id.clone(),
        pack_version: spec.pack_version.clone(),
        generation_millis,
        artifact_bytes,
        manifest_bytes: compiled.manifest_bytes.len().try_into().unwrap_or(u64::MAX),
        stored_shard_bytes: compiled
            .shards
            .iter()
            .map(|shard| shard.descriptor.stored_size)
            .sum(),
        raw_shard_bytes: compiled
            .shards
            .iter()
            .map(|shard| shard.descriptor.raw_size)
            .sum(),
        shard_count: compiled.shards.len().try_into().unwrap_or(u64::MAX),
        record_count: compiled
            .shards
            .iter()
            .map(|shard| shard.descriptor.record_count)
            .sum(),
        completeness: compiled.manifest.completeness,
        activation_micros: runtime.activation_micros,
        activation_selection_nanos: runtime.activation_selection_nanos,
        cold_decode_hydration_nanos: runtime.cold_decode_hydration_nanos,
        matcher_construction_nanos: runtime.matcher_construction_nanos,
        activation_catalog_sql_statements: runtime.activation_catalog_sql_statements,
        activation_candidate_count: runtime.activation_candidate_count,
        matcher_index_entries: runtime.matcher_index_entries,
        retained_model_bytes: runtime.retained_model_bytes,
        lookups: runtime.lookups,
    }
}

fn measure_runtime(
    spec: &PinnedPackSpec,
    compiled: &CompiledSemanticModelPack,
    cancellation: &CancellationToken,
) -> Result<RuntimeMeasurement, BundleError> {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .map_err(|error| BundleError::new(format!("open measurement catalog: {error}")))?;
    catalog
        .install(
            compiled,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: format!("release:{}@{}", spec.pack_id, spec.pack_version),
            },
        )
        .map_err(|error| BundleError::new(format!("install measurement pack: {error}")))?;
    let selector = &spec.measurement_activation;
    let target_evidence = if selector.targets.is_empty() {
        vec![None]
    } else {
        selector.targets.iter().cloned().map(Some).collect()
    };
    let configuration_evidence = if selector.configurations.is_empty() {
        vec![None]
    } else {
        selector.configurations.iter().cloned().map(Some).collect()
    };
    let evidence = target_evidence
        .into_iter()
        .flat_map(|target| {
            configuration_evidence
                .iter()
                .cloned()
                .map(move |configuration| (target.clone(), configuration))
        })
        .map(|(target, configuration)| SemanticModelActivationEvidence {
            language: compiled.manifest.language.clone(),
            ecosystem: compiled.manifest.ecosystem.clone(),
            package: selector.package.as_ref().map(catalog_coordinate),
            module: selector.module.as_ref().map(catalog_coordinate),
            toolchain: selector.toolchain.as_ref().map(catalog_coordinate),
            target,
            configuration,
            artifact_sha256: Some(spec.artifact.sha256.clone()),
        })
        .collect();
    let request = SemanticModelActivationRequest {
        bifrost_version: env!("CARGO_PKG_VERSION")
            .parse()
            .expect("crate package version is valid semver"),
        evidence,
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: spec.pack_id.clone(),
                version: Some(
                    VersionReq::parse(&format!("={}", spec.pack_version)).map_err(|error| {
                        BundleError::new(format!(
                            "invalid pinned pack version {}: {error}",
                            spec.pack_version
                        ))
                    })?,
                ),
                manifest_digest: Some(compiled.manifest.content_sha256.clone()),
            },
        }],
        limits: Default::default(),
    };
    let started = Instant::now();
    let resolved = resolve_active_semantic_models(&catalog, &request, cancellation);
    let activation_micros = started.elapsed().as_micros().try_into().unwrap_or(u64::MAX);
    let active = match &resolved {
        SemanticModelResolutionOutcome::Ready(active) => active,
        SemanticModelResolutionOutcome::Incomplete {
            usable: Some(active),
            ..
        } => active,
        outcome => {
            return Err(BundleError::new(format!(
                "measurement activation did not produce a usable model: {outcome:?}"
            )));
        }
    };
    let lookups = spec
        .measurement_queries
        .iter()
        .map(|query| measure_lookup(active, query))
        .collect::<Result<Vec<_>, BundleError>>()?;
    let report = active.activation_report();
    Ok(RuntimeMeasurement {
        activation_micros,
        activation_selection_nanos: report.phase_measurements.selection_nanos,
        cold_decode_hydration_nanos: report.phase_measurements.decode_hydration_nanos,
        matcher_construction_nanos: report.phase_measurements.matcher_construction_nanos,
        activation_catalog_sql_statements: report.phase_measurements.catalog_sql_statements,
        activation_candidate_count: report.catalog_candidates.try_into().unwrap_or(u64::MAX),
        matcher_index_entries: report.index_entries.try_into().unwrap_or(u64::MAX),
        retained_model_bytes: active.retained_bytes(),
        lookups,
    })
}

fn catalog_coordinate(
    selector: &brokk_bifrost_analysis::analyzer::semantic_model::NameSelector,
) -> CatalogCoordinate {
    CatalogCoordinate {
        name: selector.name.clone(),
        version: selector.version.as_deref().map(|requirement| {
            Version::parse(
                requirement
                    .strip_prefix('=')
                    .expect("measurement selector version is exact"),
            )
            .expect("measurement selector version was validated")
        }),
    }
}

fn measure_lookup(
    active: &ResolvedActiveSemanticModels,
    query: &PinnedLookupQuery,
) -> Result<ReleaseLookupMeasurement, BundleError> {
    let started = Instant::now();
    let records = lookup_record_count(active, query);
    let cold_nanos = started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
    let started = Instant::now();
    let warm_records = lookup_record_count(active, query);
    let warm_nanos = started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
    assert_eq!(
        records, warm_records,
        "semantic-model lookup changed between runs"
    );
    if records == 0 {
        return Err(BundleError::new(format!(
            "representative lookup did not resolve any records: {query:?}"
        )));
    }
    Ok(ReleaseLookupMeasurement {
        query: query.clone(),
        cold_nanos,
        warm_nanos,
        records,
    })
}

fn lookup_record_count(active: &ResolvedActiveSemanticModels, query: &PinnedLookupQuery) -> u64 {
    let count = match query {
        PinnedLookupQuery::Type { name } => active.types_named(name).records.len(),
        PinnedLookupQuery::Member { owner, name } => active
            .types_named(owner)
            .records
            .iter()
            .map(|owner| active.members_named(&owner.record.id, name).records.len())
            .sum(),
    };
    count.try_into().unwrap_or(u64::MAX)
}

pub fn verify_release_bundle(output_root: &Path) -> Result<ReleaseBundle, BundleError> {
    let index_path = safe_asset_path(output_root, Path::new("index.json"))?;
    let index_bytes = fs::read(&index_path)
        .map_err(|error| BundleError::new(format!("read {}: {error}", index_path.display())))?;
    let index: ReleaseBundleIndex = serde_json::from_slice(&index_bytes)
        .map_err(|error| BundleError::new(format!("parse {}: {error}", index_path.display())))?;
    if index.schema_version != RELEASE_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::new(format!(
            "unsupported release bundle schema {}",
            index.schema_version
        )));
    }
    if index.generator != current_release_generator() {
        return Err(BundleError::new(format!(
            "release bundle generator {:?} is not the current generator {:?}",
            index.generator,
            current_release_generator()
        )));
    }
    ensure_unique_pack_identities(&index.packs)?;
    ensure_unique_generated_productions(&index.generated_productions)?;
    verify_checksums(output_root, &index)?;
    let rejects = verify_rejects(output_root, &index)?;
    let measurements_path = safe_asset_path(output_root, Path::new("measurements.json"))?;
    verify_measurements(&measurements_path, &index)?;
    let limits = DecodeLimits::default();
    for pack in &index.packs {
        let manifest_bytes = verify_asset(output_root, &pack.manifest)?;
        let manifest = decode_manifest(&manifest_bytes, &limits).map_err(|error| {
            BundleError::new(format!("decode manifest for {}: {error}", pack.pack_id))
        })?;
        if manifest.pack_id != pack.pack_id
            || manifest.version != pack.pack_version
            || manifest.semantic_sha256 != pack.manifest_semantic_sha256
            || manifest.content_sha256 != pack.manifest_content_sha256
            || manifest.shards.len() != pack.shards.len()
            || manifest.language != pack.language
            || manifest.ecosystem != pack.ecosystem
            || manifest.completeness != pack.completeness
            || manifest.compatibility != pack.compatibility
            || manifest.provenance != pack.provenance
            || manifest.license != pack.license
        {
            return Err(BundleError::new(format!(
                "release index metadata does not match manifest for {}@{}",
                pack.pack_id, pack.pack_version
            )));
        }
        for descriptor in &manifest.shards {
            let indexed = pack
                .shards
                .iter()
                .find(|shard| shard.shard_id == descriptor.shard_id)
                .ok_or_else(|| {
                    BundleError::new(format!("missing indexed shard {}", descriptor.shard_id))
                })?;
            if indexed.encoding != descriptor.encoding
                || indexed.raw_bytes != descriptor.raw_size
                || indexed.records != descriptor.record_count
                || indexed.semantic_sha256 != descriptor.semantic_sha256
                || indexed.content_sha256 != descriptor.content_sha256
                || indexed.asset.sha256 != descriptor.stored_sha256
                || indexed.asset.bytes != descriptor.stored_size
            {
                return Err(BundleError::new(format!(
                    "release index metadata does not match shard {}",
                    descriptor.shard_id
                )));
            }
            let bytes = verify_asset(output_root, &indexed.asset)?;
            decode_shard_for_manifest(&manifest, descriptor, &bytes, &limits).map_err(|error| {
                BundleError::new(format!("decode shard {}: {error}", descriptor.shard_id))
            })?;
        }
        if pack.notices.is_empty() {
            return Err(BundleError::new(format!(
                "release pack {}@{} must include at least one license or notice asset",
                pack.pack_id, pack.pack_version
            )));
        }
        validate_release_notices(&pack.notices)?;
        for notice in &pack.notices {
            verify_asset(output_root, &notice.asset)?;
        }
    }
    for generated in &index.generated_productions {
        verify_generated_production(output_root, &index, generated)?;
    }
    Ok(ReleaseBundle { index, rejects })
}

/// Merge independently generated, fully verified release bundles into one
/// deterministic bundle. Every source bundle is verified before any output is
/// written; content-addressed assets may be shared only when their bytes are
/// identical.
pub fn merge_release_bundles(
    output_root: &Path,
    input_roots: &[PathBuf],
) -> Result<ReleaseBundle, BundleError> {
    if input_roots.is_empty() {
        return Err(BundleError::new(
            "at least one input release bundle is required",
        ));
    }
    let generator = current_release_generator();
    let mut packs = Vec::new();
    let mut generated_productions = Vec::new();
    let mut rejects = Vec::new();
    let mut measurements = Vec::new();
    let mut assets = BTreeMap::<String, Vec<u8>>::new();
    let mut identities = BTreeSet::new();
    let mut generated_identities = BTreeSet::new();

    // Verify every input and retain all source bytes before touching the
    // output. The output must be a new or empty directory, so a stale or
    // source bundle file can never be retained accidentally.
    prepare_merge_output(output_root, input_roots)?;
    for input_root in input_roots {
        let bundle = verify_release_bundle(input_root)?;
        if bundle.index.generator != generator {
            return Err(BundleError::new(format!(
                "input bundle {} uses incompatible generator {:?}",
                input_root.display(),
                bundle.index.generator
            )));
        }
        let input_measurements =
            read_measurements(&input_root.join("measurements.json"), &bundle.index)?;
        for pack in &bundle.index.packs {
            let identity = (pack.pack_id.clone(), pack.pack_version.clone());
            if !identities.insert(identity.clone()) {
                return Err(BundleError::new(format!(
                    "duplicate release pack {}@{} across input bundles",
                    identity.0, identity.1
                )));
            }
            collect_asset(input_root, &mut assets, &pack.manifest)?;
            for shard in &pack.shards {
                collect_asset(input_root, &mut assets, &shard.asset)?;
            }
            for notice in &pack.notices {
                collect_asset(input_root, &mut assets, &notice.asset)?;
            }
        }
        for generated in &bundle.index.generated_productions {
            if !generated_identities.insert(generated.production_digest.clone()) {
                return Err(BundleError::new(format!(
                    "duplicate generated production {} across input bundles",
                    generated.production_digest
                )));
            }
            collect_asset(input_root, &mut assets, &generated.manifest)?;
            for shard in &generated.shards {
                collect_asset(input_root, &mut assets, &shard.asset)?;
            }
        }
        packs.extend(bundle.index.packs);
        generated_productions.extend(bundle.index.generated_productions);
        rejects.extend(bundle.rejects.packs);
        measurements.extend(input_measurements.packs);
    }

    packs.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    generated_productions.sort_unstable_by(|left, right| {
        left.production_digest
            .cmp(&right.production_digest)
            .then_with(|| left.pack_id.cmp(&right.pack_id))
            .then_with(|| left.pack_version.cmp(&right.pack_version))
    });
    rejects.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    measurements.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    for pack in &mut packs {
        pack.shards
            .sort_unstable_by(|left, right| left.shard_id.cmp(&right.shard_id));
        pack.notices
            .sort_unstable_by(|left, right| left.source_path.cmp(&right.source_path));
    }

    let index = ReleaseBundleIndex {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator: generator.clone(),
        packs,
        generated_productions,
    };
    let rejects = ReleaseBundleRejects {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator: generator.clone(),
        packs: rejects,
    };
    let measurements = ReleaseBundleMeasurements {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator,
        packs: measurements,
    };

    fs::create_dir_all(output_root)
        .map_err(|error| BundleError::new(format!("create {}: {error}", output_root.display())))?;
    for (path, bytes) in assets {
        write_content_addressed(output_root, &path, &bytes)?;
    }
    write_new_or_identical(output_root, Path::new("index.json"), &json_bytes(&index)?)?;
    write_new_or_identical(
        output_root,
        Path::new("rejects.json"),
        &json_bytes(&rejects)?,
    )?;
    write_new_or_identical(
        output_root,
        Path::new("measurements.json"),
        &json_bytes(&measurements)?,
    )?;
    write_checksums(output_root, &index)?;
    verify_release_bundle(output_root)
}

fn collect_asset(
    input_root: &Path,
    assets: &mut BTreeMap<String, Vec<u8>>,
    asset: &ReleaseAsset,
) -> Result<(), BundleError> {
    let bytes = verify_asset(input_root, asset)?;
    if let Some(existing) = assets.get(&asset.path) {
        if existing != &bytes {
            return Err(BundleError::new(format!(
                "conflicting bytes for release asset {}",
                asset.path
            )));
        }
    } else {
        assets.insert(asset.path.clone(), bytes);
    }
    Ok(())
}

fn prepare_merge_output(output_root: &Path, input_roots: &[PathBuf]) -> Result<(), BundleError> {
    reject_symlink_components(output_root, None)?;
    let metadata = match fs::symlink_metadata(output_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(BundleError::new(format!(
                "inspect merge output {}: {error}",
                output_root.display()
            )));
        }
    };
    if !metadata.is_dir() {
        return Err(BundleError::new(format!(
            "merge output {} must be a directory",
            output_root.display()
        )));
    }
    if fs::read_dir(output_root)
        .map_err(|error| BundleError::new(format!("read merge output: {error}")))?
        .next()
        .is_some()
    {
        return Err(BundleError::new(
            "merge output must be a new or empty directory",
        ));
    }
    let output = fs::canonicalize(output_root)
        .map_err(|error| BundleError::new(format!("resolve merge output: {error}")))?;
    for input_root in input_roots {
        let input = fs::canonicalize(input_root).map_err(|error| {
            BundleError::new(format!(
                "resolve input bundle {}: {error}",
                input_root.display()
            ))
        })?;
        if input == output {
            return Err(BundleError::new(
                "merge output must not be one of the input bundle directories",
            ));
        }
    }
    Ok(())
}

fn validate_release_notices(notices: &[ReleaseNotice]) -> Result<(), BundleError> {
    let mut seen = BTreeSet::new();
    for pair in notices.windows(2) {
        if pair[0].source_path >= pair[1].source_path {
            return Err(BundleError::new(
                "release notice source paths must be unique and in canonical order",
            ));
        }
    }
    for notice in notices {
        require_safe_relative(Path::new(&notice.source_path))?;
        if !seen.insert(&notice.source_path) {
            return Err(BundleError::new(format!(
                "release notice source path is duplicated: {}",
                notice.source_path
            )));
        }
    }
    Ok(())
}

fn ensure_unique_pack_identities(packs: &[ReleasePack]) -> Result<(), BundleError> {
    let mut identities = BTreeSet::new();
    for pack in packs {
        let identity = (pack.pack_id.clone(), pack.pack_version.clone());
        if !identities.insert(identity.clone()) {
            return Err(BundleError::new(format!(
                "duplicate release pack {}@{}",
                identity.0, identity.1
            )));
        }
    }
    Ok(())
}

fn ensure_unique_generated_productions(
    productions: &[ReleaseGeneratedProduction],
) -> Result<(), BundleError> {
    let mut identities = BTreeSet::new();
    for production in productions {
        if !identities.insert(&production.production_digest) {
            return Err(BundleError::new(format!(
                "duplicate generated production {}",
                production.production_digest
            )));
        }
    }
    Ok(())
}

fn verify_generated_production(
    output_root: &Path,
    index: &ReleaseBundleIndex,
    generated: &ReleaseGeneratedProduction,
) -> Result<(), BundleError> {
    validate_sha256("generated artifact", &generated.artifact_sha256)?;
    validate_sha256("generated input digest", &generated.input_digest)?;
    validate_sha256("generated production digest", &generated.production_digest)?;
    if generated.producer_name.is_empty()
        || generated.producer_version.is_empty()
        || generated.schema_version == 0
        || generated.cache_version == 0
    {
        return Err(BundleError::new(
            "generated production identity metadata must be non-empty",
        ));
    }
    if generated.schema_version != SEMANTIC_MODEL_SCHEMA_VERSION {
        return Err(BundleError::new(format!(
            "unsupported generated production semantic schema {}",
            generated.schema_version
        )));
    }
    if generated.cache_version != GENERATED_PRODUCTION_CACHE_VERSION {
        return Err(BundleError::new(format!(
            "generated production cache version {} is not current {}",
            generated.cache_version, GENERATED_PRODUCTION_CACHE_VERSION
        )));
    }
    let key = GeneratedProductionKey::new(
        generated.input_digest.clone(),
        generated.producer_name.clone(),
        generated.producer_version.clone(),
        generated.schema_version,
    )
    .map_err(|error| BundleError::new(format!("invalid generated production key: {error}")))?;
    if key.production_digest() != generated.production_digest {
        return Err(BundleError::new(
            "generated production digest does not match its key fields",
        ));
    }
    let source = index
        .packs
        .iter()
        .find(|pack| {
            pack.pack_id == generated.source_pack_id
                && pack.pack_version == generated.source_pack_version
        })
        .ok_or_else(|| {
            BundleError::new(format!(
                "generated production references missing curated pack {}@{}",
                generated.source_pack_id, generated.source_pack_version
            ))
        })?;
    if source.language != "java"
        || source.ecosystem != "jdk"
        || source.artifact.sha256 != generated.artifact_sha256
    {
        return Err(BundleError::new(
            "generated production does not bind the curated JDK artifact",
        ));
    }
    let compiled = read_compiled_pack(
        output_root,
        &generated.pack_id,
        &generated.manifest,
        &generated.shards,
    )?;
    if compiled.manifest.pack_id != generated.pack_id
        || compiled.manifest.version != generated.pack_version
        || compiled.manifest.language != generated.language
        || compiled.manifest.ecosystem != generated.ecosystem
        || compiled.manifest.semantic_sha256 != generated.manifest_semantic_sha256
        || compiled.manifest.content_sha256 != generated.manifest_content_sha256
        || compiled.manifest.completeness != generated.completeness
        || compiled.manifest.producer.name != generated.producer_name
        || compiled.manifest.producer.version != generated.producer_version
        || compiled.manifest.schema_version != generated.schema_version
    {
        return Err(BundleError::new(
            "generated production index metadata does not match its manifest",
        ));
    }
    let extraction = generated_extraction_accounting(generated);
    if !pack_rejects_are_warning_only(&extraction) {
        return Err(BundleError::new(
            "generated production has error-grade extraction rejects",
        ));
    }
    // A generated production is never curated by hand, so a partial one must
    // clear the same activation bar `warning_only_and_fully_accounted` gives
    // installed packs at runtime (catalog/mod.rs `pack_is_activation_ready`):
    // every reject accounted for by a named gap, nothing suppressed.
    // Otherwise the bundle ships a production that can never activate,
    // silently -- the way #2756 shipped 3,535 suppressed JDK rejects behind
    // an empty diagnostics list. This hard gate applies only to generated
    // productions; a curated pack can still ship with named-but-unaccounted
    // rejects (tracked separately) because a human reviewed it.
    if generated.completeness == Completeness::Partial
        && !extraction.warning_only_and_fully_accounted()
    {
        return Err(BundleError::new(format!(
            "generated production {}@{} is not activation-ready: partial completeness requires \
             warning-only fully-accounted extraction (reject_count={}, suppressed_reject_count={}, \
             named_gaps={})",
            generated.pack_id,
            generated.pack_version,
            extraction.reject_count,
            extraction.suppressed_reject_count,
            extraction.gaps.len()
        )));
    }
    if extraction.reject_count != generated.rejects.len().try_into().unwrap_or(u64::MAX)
        || extraction.suppressed_reject_count != generated.suppressed_rejects
    {
        return Err(BundleError::new(
            "generated production extraction accounting is inconsistent",
        ));
    }
    let _ = key;
    Ok(())
}

/// Read and cross-check the structured extraction burn-down report.
///
/// The report is a mandatory release asset: a bundle without it, or with
/// packs that do not match the index exactly, fails verification.
fn verify_rejects(
    output_root: &Path,
    index: &ReleaseBundleIndex,
) -> Result<ReleaseBundleRejects, BundleError> {
    let rejects_path = safe_asset_path(output_root, Path::new("rejects.json"))?;
    let rejects_bytes = fs::read(&rejects_path)
        .map_err(|error| BundleError::new(format!("read {}: {error}", rejects_path.display())))?;
    let rejects: ReleaseBundleRejects = serde_json::from_slice(&rejects_bytes)
        .map_err(|error| BundleError::new(format!("parse {}: {error}", rejects_path.display())))?;
    if rejects.schema_version != RELEASE_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::new(format!(
            "unsupported release rejects schema {}",
            rejects.schema_version
        )));
    }
    if rejects.generator != index.generator
        || rejects.packs.len() != index.packs.len()
        || rejects
            .packs
            .iter()
            .zip(&index.packs)
            .any(|(rejects, pack)| {
                rejects.pack_id != pack.pack_id
                    || rejects.pack_version != pack.pack_version
                    || rejects.completeness != pack.completeness
            })
    {
        return Err(BundleError::new(
            "release rejects do not match the indexed packs",
        ));
    }
    for (pack, pack_rejects) in index.packs.iter().zip(&rejects.packs) {
        let extraction = release_extraction_accounting(pack_rejects);
        if !pack_rejects_are_warning_only(&extraction) {
            return Err(BundleError::new(format!(
                "release pack {}@{} has error-grade extraction rejects",
                pack.pack_id, pack.pack_version
            )));
        }
    }
    Ok(rejects)
}

fn release_extraction_accounting(rejects: &ReleasePackRejects) -> PackExtractionAccounting {
    extraction_accounting(&rejects.rejects, rejects.suppressed_rejects)
}

fn generated_extraction_accounting(
    generated: &ReleaseGeneratedProduction,
) -> PackExtractionAccounting {
    extraction_accounting(&generated.rejects, generated.suppressed_rejects)
}

fn extraction_accounting(
    rejects: &[ReleaseReject],
    suppressed_rejects: u64,
) -> PackExtractionAccounting {
    PackExtractionAccounting {
        reject_count: rejects.len().try_into().unwrap_or(u64::MAX),
        suppressed_reject_count: suppressed_rejects,
        error_reject_count: rejects
            .iter()
            .filter(|reject| reject.severity == ReleaseRejectSeverity::Error)
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        gaps: rejects
            .iter()
            .filter_map(|reject| {
                reject
                    .declaration
                    .as_ref()
                    .map(|declaration| PackExtractionGap {
                        declaration: declaration.clone(),
                        reason: format!("{}: {}", reject.code, reject.message),
                    })
            })
            .collect(),
    }
}

/// Verify and install every compiled pack in a downloaded release bundle.
///
/// Download policy remains outside ordinary analysis. Once a caller has
/// selected and unpacked a bundle, this provides the explicit bridge into the
/// durable catalog used by normal semantic-model activation.
pub fn install_release_bundle(
    bundle_root: &Path,
    catalog: &SemanticPackCatalog,
) -> Result<Vec<ReleasePackInstallation>, BundleError> {
    let bundle = verify_release_bundle(bundle_root)?;
    let mut installed = bundle
        .index
        .packs
        .iter()
        .zip(&bundle.rejects.packs)
        .map(|(pack, rejects)| {
            let compiled =
                read_compiled_pack(bundle_root, &pack.pack_id, &pack.manifest, &pack.shards)?;
            let extraction = release_extraction_accounting(rejects);
            let installed = catalog
                .install_release(
                    &compiled,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::PreShipped,
                        source_id: format!(
                            "release:{}@{}:{}",
                            pack.pack_id, pack.pack_version, pack.manifest.sha256
                        ),
                    },
                    &extraction,
                )
                .map_err(|error| {
                    BundleError::new(format!(
                        "install {}@{}: {error}",
                        pack.pack_id, pack.pack_version
                    ))
                })?;
            Ok(ReleasePackInstallation {
                pack_id: pack.pack_id.clone(),
                pack_version: pack.pack_version.clone(),
                manifest_digest: installed.manifest_digest,
            })
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    for generated in &bundle.index.generated_productions {
        let key = GeneratedProductionKey::new(
            generated.input_digest.clone(),
            generated.producer_name.clone(),
            generated.producer_version.clone(),
            generated.schema_version,
        )
        .map_err(|error| BundleError::new(format!("invalid generated production key: {error}")))?;
        let compiled = read_compiled_pack(
            bundle_root,
            &generated.pack_id,
            &generated.manifest,
            &generated.shards,
        )?;
        let source = DurablePackSource {
            kind: DurablePackSourceKind::PreShipped,
            source_id: format!(
                "release-generated:{}@{}:{}",
                generated.source_pack_id,
                generated.source_pack_version,
                generated.production_digest
            ),
        };
        let installation = catalog
            .install_release_generated(
                &key,
                &compiled,
                &source,
                &generated_extraction_accounting(generated),
            )
            .map_err(|error| {
                BundleError::new(format!(
                    "install generated {}@{}: {error}",
                    generated.pack_id, generated.pack_version
                ))
            })?;
        installed.push(ReleasePackInstallation {
            pack_id: generated.pack_id.clone(),
            pack_version: generated.pack_version.clone(),
            manifest_digest: installation.install.manifest_digest,
        });
    }
    Ok(installed)
}

fn read_compiled_pack(
    bundle_root: &Path,
    pack_id: &str,
    manifest_asset: &ReleaseAsset,
    indexed_shards: &[ReleaseShard],
) -> Result<CompiledSemanticModelPack, BundleError> {
    let manifest_bytes = verify_asset(bundle_root, manifest_asset)?;
    let limits = DecodeLimits::default();
    let manifest = decode_manifest(&manifest_bytes, &limits)
        .map_err(|error| BundleError::new(format!("decode manifest for {pack_id}: {error}")))?;
    if indexed_shards.len() != manifest.shards.len() {
        return Err(BundleError::new(format!(
            "indexed shard count does not match manifest for {pack_id}"
        )));
    }
    let mut indexed_ids = BTreeSet::new();
    let shards = manifest
        .shards
        .iter()
        .map(|descriptor| {
            let indexed = indexed_shards
                .iter()
                .find(|shard| shard.shard_id == descriptor.shard_id)
                .ok_or_else(|| {
                    BundleError::new(format!("missing indexed shard {}", descriptor.shard_id))
                })?;
            if !indexed_ids.insert(indexed.shard_id.as_str()) {
                return Err(BundleError::new(format!(
                    "duplicate indexed shard {} for {pack_id}",
                    indexed.shard_id
                )));
            }
            if indexed.encoding != descriptor.encoding
                || indexed.raw_bytes != descriptor.raw_size
                || indexed.records != descriptor.record_count
                || indexed.semantic_sha256 != descriptor.semantic_sha256
                || indexed.content_sha256 != descriptor.content_sha256
                || indexed.asset.sha256 != descriptor.stored_sha256
                || indexed.asset.bytes != descriptor.stored_size
            {
                return Err(BundleError::new(format!(
                    "indexed shard metadata does not match {} for {pack_id}",
                    descriptor.shard_id
                )));
            }
            let bytes = verify_asset(bundle_root, &indexed.asset)?;
            Ok(
                brokk_bifrost_analysis::analyzer::semantic_model::CompiledShardArtifact {
                    descriptor: descriptor.clone(),
                    bytes,
                },
            )
        })
        .collect::<Result<Vec<_>, BundleError>>()?;
    Ok(CompiledSemanticModelPack {
        manifest,
        manifest_bytes,
        shards,
    })
}

fn verify_checksums(output_root: &Path, index: &ReleaseBundleIndex) -> Result<(), BundleError> {
    let checksum_path = safe_asset_path(output_root, Path::new("SHA256SUMS"))?;
    let checksum_text = fs::read_to_string(&checksum_path)
        .map_err(|error| BundleError::new(format!("read {}: {error}", checksum_path.display())))?;
    let mut actual_paths = Vec::new();
    for (line_number, line) in checksum_text.lines().enumerate() {
        let (sha256, path) = line.split_once("  ").ok_or_else(|| {
            BundleError::new(format!("invalid SHA256SUMS line {}", line_number + 1))
        })?;
        validate_sha256("checksum", sha256)?;
        let asset_path = safe_asset_path(output_root, Path::new(path))?;
        let (actual_sha256, _) = sha256_file(&asset_path)?;
        if actual_sha256 != sha256 {
            return Err(BundleError::new(format!(
                "checksum for {path} does not match SHA256SUMS"
            )));
        }
        actual_paths.push(path.to_owned());
    }
    let expected_paths = release_asset_paths(index);
    if actual_paths != expected_paths {
        return Err(BundleError::new(
            "SHA256SUMS does not list the release assets exactly once in canonical order",
        ));
    }
    Ok(())
}

fn verify_asset(output_root: &Path, asset: &ReleaseAsset) -> Result<Vec<u8>, BundleError> {
    let relative = Path::new(&asset.path);
    let path = safe_asset_path(output_root, relative)?;
    let bytes = fs::read(path)
        .map_err(|error| BundleError::new(format!("read asset {}: {error}", asset.path)))?;
    if bytes.len() as u64 != asset.bytes || sha256_bytes(&bytes) != asset.sha256 {
        return Err(BundleError::new(format!(
            "asset {} does not match its declared digest and size",
            asset.path
        )));
    }
    Ok(bytes)
}

fn verify_measurements(
    measurements_path: &Path,
    index: &ReleaseBundleIndex,
) -> Result<(), BundleError> {
    read_measurements(measurements_path, index).map(|_| ())
}

fn read_measurements(
    measurements_path: &Path,
    index: &ReleaseBundleIndex,
) -> Result<ReleaseBundleMeasurements, BundleError> {
    let root = measurements_path.parent().ok_or_else(|| {
        BundleError::new(format!(
            "measurements path has no root: {}",
            measurements_path.display()
        ))
    })?;
    let relative = measurements_path.file_name().ok_or_else(|| {
        BundleError::new(format!(
            "measurements path has no file name: {}",
            measurements_path.display()
        ))
    })?;
    let safe_path = safe_asset_path(root, Path::new(relative))?;
    let measurements_bytes = fs::read(&safe_path).map_err(|error| {
        BundleError::new(format!("read {}: {error}", measurements_path.display()))
    })?;
    let measurements: ReleaseBundleMeasurements = serde_json::from_slice(&measurements_bytes)
        .map_err(|error| {
            BundleError::new(format!("parse {}: {error}", measurements_path.display()))
        })?;
    if measurements.schema_version != RELEASE_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::new(format!(
            "unsupported release measurements schema {}",
            measurements.schema_version
        )));
    }
    if measurements.generator != index.generator
        || measurements.packs.len() != index.packs.len()
        || measurements
            .packs
            .iter()
            .zip(&index.packs)
            .any(|(measurement, pack)| {
                measurement.pack_id != pack.pack_id
                    || measurement.pack_version != pack.pack_version
                    || measurement.artifact_bytes != pack.artifact_bytes
                    || measurement.manifest_bytes != pack.manifest.bytes
                    || measurement.stored_shard_bytes
                        != pack
                            .shards
                            .iter()
                            .map(|shard| shard.asset.bytes)
                            .sum::<u64>()
                    || measurement.raw_shard_bytes
                        != pack.shards.iter().map(|shard| shard.raw_bytes).sum::<u64>()
                    || measurement.shard_count
                        != u64::try_from(pack.shards.len()).unwrap_or(u64::MAX)
                    || measurement.record_count
                        != pack.shards.iter().map(|shard| shard.records).sum::<u64>()
                    || measurement.completeness != pack.completeness
                    || measurement.lookups.is_empty()
                    || measurement.lookups.iter().any(|lookup| lookup.records == 0)
                    || measurement
                        .lookups
                        .iter()
                        .enumerate()
                        .any(|(index, lookup)| {
                            measurement.lookups[index + 1..]
                                .iter()
                                .any(|other| other.query == lookup.query)
                        })
            })
    {
        return Err(BundleError::new(
            "release measurements do not match the indexed packs",
        ));
    }
    Ok(measurements)
}

fn write_content_addressed(
    output_root: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<(), BundleError> {
    let path = Path::new(relative);
    write_new_or_identical(output_root, path, bytes)
}

fn write_new_or_identical(
    output_root: &Path,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), BundleError> {
    let path = safe_asset_path(output_root, relative)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(BundleError::new(format!(
                "refusing symbolic-link release asset {}",
                path.display()
            )));
        }
        Ok(_) => {
            let existing = fs::read(&path).map_err(|error| {
                BundleError::new(format!("read existing {}: {error}", path.display()))
            })?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(BundleError::new(format!(
                    "refusing to overwrite non-identical release asset {}",
                    path.display()
                )))
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(BundleError::new(format!(
                "inspect release asset {}: {error}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| BundleError::new(format!("create {}: {error}", parent.display())))?;
        let root = fs::canonicalize(output_root).map_err(|error| {
            BundleError::new(format!(
                "resolve output root {}: {error}",
                output_root.display()
            ))
        })?;
        let resolved_parent = fs::canonicalize(parent).map_err(|error| {
            BundleError::new(format!(
                "resolve output directory {}: {error}",
                parent.display()
            ))
        })?;
        if !resolved_parent.starts_with(root) {
            return Err(BundleError::new(format!(
                "release asset parent resolves outside the output root: {}",
                parent.display()
            )));
        }
        let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
            BundleError::new(format!(
                "create temporary asset in {}: {error}",
                parent.display()
            ))
        })?;
        temporary
            .write_all(bytes)
            .map_err(|error| BundleError::new(format!("write temporary asset: {error}")))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| BundleError::new(format!("sync temporary asset: {error}")))?;
        temporary.persist_noclobber(&path).map_err(|error| {
            BundleError::new(format!(
                "publish release asset {}: {}",
                path.display(),
                error.error
            ))
        })?;
    }
    Ok(())
}

fn write_replace(output_root: &Path, relative: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    let path = safe_asset_path(output_root, relative)?;
    let parent = path.parent().expect("relative output has a parent");
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        BundleError::new(format!(
            "create temporary observation in {}: {error}",
            parent.display()
        ))
    })?;
    temporary
        .write_all(bytes)
        .map_err(|error| BundleError::new(format!("write temporary observation: {error}")))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| BundleError::new(format!("sync temporary observation: {error}")))?;
    temporary.persist(&path).map_err(|error| {
        BundleError::new(format!(
            "publish observation {}: {}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}

fn write_checksums(output_root: &Path, index: &ReleaseBundleIndex) -> Result<(), BundleError> {
    let paths = release_asset_paths(index);
    let mut output = String::new();
    for path in paths {
        let asset_path = safe_asset_path(output_root, Path::new(&path))?;
        let (sha256, _) = sha256_file(&asset_path)?;
        output.push_str(&sha256);
        output.push_str("  ");
        output.push_str(&path);
        output.push('\n');
    }
    write_new_or_identical(output_root, Path::new("SHA256SUMS"), output.as_bytes())
}

fn release_asset_paths(index: &ReleaseBundleIndex) -> Vec<String> {
    // Measurements are required and structurally verified, but intentionally
    // remain outside the reproducibility checksum because they contain wall-
    // clock observations from each generation run.
    let mut paths = vec!["index.json".to_owned(), "rejects.json".to_owned()];
    for pack in &index.packs {
        paths.push(pack.manifest.path.clone());
        paths.extend(pack.shards.iter().map(|shard| shard.asset.path.clone()));
        paths.extend(pack.notices.iter().map(|notice| notice.asset.path.clone()));
    }
    for generated in &index.generated_productions {
        paths.push(generated.manifest.path.clone());
        paths.extend(
            generated
                .shards
                .iter()
                .map(|shard| shard.asset.path.clone()),
        );
    }
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn require_safe_relative(path: &Path) -> Result<(), BundleError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BundleError::new(format!(
            "release paths must be relative and contain no traversal: {}",
            path.display()
        )));
    }
    Ok(())
}

fn safe_asset_path(root: &Path, relative: &Path) -> Result<PathBuf, BundleError> {
    require_safe_relative(relative)?;
    reject_symlink_components(root, Some(relative))?;
    let path = root.join(relative);
    if path.exists() {
        let resolved_root = fs::canonicalize(root).map_err(|error| {
            BundleError::new(format!(
                "resolve release output root {}: {error}",
                root.display()
            ))
        })?;
        let resolved_path = fs::canonicalize(&path).map_err(|error| {
            BundleError::new(format!("resolve release asset {}: {error}", path.display()))
        })?;
        if !resolved_path.starts_with(&resolved_root) {
            return Err(BundleError::new(format!(
                "release asset resolves outside the output root: {}",
                path.display()
            )));
        }
    }
    Ok(path)
}

fn reject_symlink_components(root: &Path, relative: Option<&Path>) -> Result<(), BundleError> {
    if let Ok(metadata) = fs::symlink_metadata(root)
        && metadata.file_type().is_symlink()
    {
        return Err(BundleError::new(format!(
            "refusing symbolic-link release output root {}",
            root.display()
        )));
    }
    let Some(relative) = relative else {
        return Ok(());
    };
    let mut path = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            unreachable!("require_safe_relative validates release paths first")
        };
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BundleError::new(format!(
                    "refusing symbolic-link release asset component {}",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(BundleError::new(format!(
                    "inspect release asset component {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), BundleError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BundleError::new(format!(
            "{label} SHA-256 must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<(String, u64), BundleError> {
    let mut file = File::open(path)
        .map_err(|error| BundleError::new(format!("open {}: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| BundleError::new(format!("read {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok((format!("{:x}", hasher.finalize()), bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, BundleError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| BundleError::new(format!("serialize release metadata: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn render_diagnostics(diagnostics: &[ProducerDiagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic_model::{NameSelector, VersionConstraint};
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    fn selector(package: &str, toolchain: &str, version: &str) -> ActivationSelector {
        ActivationSelector {
            package: Some(NameSelector {
                name: package.to_owned(),
                version: Some(format!("={version}")),
            }),
            module: None,
            toolchain: Some(NameSelector {
                name: toolchain.to_owned(),
                version: Some(format!("={version}")),
            }),
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn pinned_spec(
        pack_id: &str,
        version: &str,
        ecosystem: &str,
        kind: PinnedPackKind,
        artifact: PinnedArtifact,
        toolchain: &str,
        package: &str,
        measurement_queries: Vec<PinnedLookupQuery>,
    ) -> PinnedPackSpec {
        PinnedPackSpec {
            schema_version: PACK_SPEC_SCHEMA_VERSION,
            pack_id: pack_id.to_owned(),
            pack_version: version.to_owned(),
            ecosystem: ecosystem.to_owned(),
            kind,
            artifact,
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![VersionConstraint {
                    name: toolchain.to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![selector(package, toolchain, version)],
            provenance: Provenance {
                source: "fixture".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "Apache-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
            notices: vec!["NOTICE.txt".to_owned()],
            measurement_activation: selector(package, toolchain, version),
            measurement_queries,
        }
    }

    fn assert_deterministic_and_installable(
        first: &Path,
        second: &Path,
        first_bundle: &ReleaseBundle,
        second_bundle: &ReleaseBundle,
    ) {
        assert_eq!(first_bundle, second_bundle);
        for asset in ["index.json", "rejects.json", "SHA256SUMS"] {
            assert_eq!(
                fs::read(first.join(asset)).unwrap(),
                fs::read(second.join(asset)).unwrap(),
                "{asset} must be deterministic"
            );
        }
        for pack in &first_bundle.index.packs {
            assert_eq!(
                fs::read(first.join(&pack.manifest.path)).unwrap(),
                fs::read(second.join(&pack.manifest.path)).unwrap()
            );
            for shard in &pack.shards {
                assert_eq!(
                    fs::read(first.join(&shard.asset.path)).unwrap(),
                    fs::read(second.join(&shard.asset.path)).unwrap()
                );
            }
        }
        for generated in &first_bundle.index.generated_productions {
            assert_eq!(
                fs::read(first.join(&generated.manifest.path)).unwrap(),
                fs::read(second.join(&generated.manifest.path)).unwrap()
            );
            for shard in &generated.shards {
                assert_eq!(
                    fs::read(first.join(&shard.asset.path)).unwrap(),
                    fs::read(second.join(&shard.asset.path)).unwrap()
                );
            }
        }
        assert_eq!(&verify_release_bundle(first).unwrap(), first_bundle);
    }

    #[test]
    fn jdk_generated_production_is_deterministic_verifiable_and_installable() {
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("src.zip");
        write_zip(
            &artifact,
            &[
                (
                    "java.base/module-info.java",
                    "module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    "package java.lang; public class Object { public int hashCode() { return 0; } }",
                ),
            ],
        );
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let artifact_path = artifact.clone();
        let version = "21.0.8";
        let activation = ActivationSelector {
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jdk".to_owned(),
                version: Some(format!("={version}")),
            }),
            targets: vec!["jvm".to_owned()],
            configurations: Vec::new(),
            artifact_sha256: None,
        };
        let spec = fixture.path().join("temurin-jdk.json");
        let pinned = PinnedPackSpec {
            schema_version: PACK_SPEC_SCHEMA_VERSION,
            pack_id: "bifrost.jdk".to_owned(),
            pack_version: version.to_owned(),
            ecosystem: "jdk".to_owned(),
            kind: PinnedPackKind::JdkSourceZip {
                layout: PinnedJdkSourceLayout::ModulePrefixed,
            },
            artifact: PinnedArtifact {
                file_name: "src.zip".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/src.zip".to_owned()),
                container: None,
            },
            compatibility: Compatibility {
                bifrost: ">=0.8.18, <1.0.0".to_owned(),
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![activation.clone()],
            provenance: Provenance {
                source: "fixture".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
            notices: vec!["NOTICE.txt".to_owned()],
            measurement_activation: ActivationSelector {
                module: Some(NameSelector {
                    name: "java.base".to_owned(),
                    version: None,
                }),
                ..activation
            },
            measurement_queries: vec![PinnedLookupQuery::Type {
                name: "java.lang.Object".to_owned(),
            }],
        };
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: artifact,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);

        let generated = first_bundle
            .index
            .generated_productions
            .first()
            .expect("pinned JDK must have one generated production");
        assert_eq!(generated.source_pack_id, "bifrost.jdk");
        assert_eq!(generated.source_pack_version, version);
        // #2756 regression: the derivation's diagnostics caps must be sized
        // to the durable release boundary (`MAX_SOURCE_SET_FILES`), not the
        // interactive-safety default of 256, or a JDK source set with more
        // rejects than that would ship with suppressed rejects and fewer
        // named gaps than the reject count -- exactly the shape
        // `warning_only_and_fully_accounted` exists to catch.
        let generated_accounting = generated_extraction_accounting(generated);
        assert_eq!(generated_accounting.suppressed_reject_count, 0);
        assert_eq!(
            generated_accounting.gaps.len() as u64,
            generated_accounting.reject_count
        );
        let key = GeneratedProductionKey::new(
            generated.input_digest.clone(),
            generated.producer_name.clone(),
            generated.producer_version.clone(),
            generated.schema_version,
        )
        .unwrap();
        assert_eq!(key.production_digest(), generated.production_digest);

        // The release path and the runtime JDK path must use the same
        // dependency identity and exact compiler seam, or a release asset
        // would never satisfy a local generated lookup.
        let runtime_dependency = JvmDependencyPackAdapter::jdk_source_dependency(
            Version::parse(version).unwrap(),
            artifact_path.clone(),
        );
        let runtime_artifact =
            read_exact_artifact(&artifact_path, &ArtifactProducerLimits::default()).unwrap();
        let runtime_production = compile_exact_dependency_production(
            &JvmDependencyPackAdapter,
            &runtime_dependency,
            &[ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::JdkSourceZip,
                None,
                runtime_artifact,
            )],
            &DependencyPackLimits::default(),
            Some(&CancellationToken::default()),
        )
        .unwrap();
        assert_eq!(
            runtime_production.key.production_digest(),
            generated.production_digest
        );

        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(
            installed.len(),
            2,
            "curated and generated JDK packs install"
        );
        assert!(catalog.generated_production(&key).unwrap().is_some());

        fs::OpenOptions::new()
            .append(true)
            .open(first.join(&generated.manifest.path))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        assert!(verify_release_bundle(&first).is_err());
    }

    #[test]
    fn generated_jdk_production_with_an_unnamed_reject_fails_the_activability_gate() {
        // A warning that the JDK source producer cannot attach a declaration
        // to (an archive entry that is skipped for being oversized, not for
        // naming a specific type) is a real, non-error reject with no gap.
        // That is exactly the shape #2756 shipped silently: completeness is
        // Partial, nothing is an error-grade reject, but the accounting is
        // not fully named. This must fail the bundle build, not just log a
        // reject count. 8 MiB + 1 matches the JVM producer's fixed
        // per-source-file bound (`MAX_SOURCE_ENTRY_BYTES` in
        // crates/bifrost-analysis/src/analyzer/jvm/java_artifact.rs).
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("src.zip");
        let oversized_source = " ".repeat(8 * 1024 * 1024 + 1);
        write_zip(
            &artifact,
            &[
                (
                    "java.base/module-info.java",
                    "module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    "package java.lang; public class Object { public int hashCode() { return 0; } }",
                ),
                ("java.base/java/lang/Oversized.java", &oversized_source),
            ],
        );
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let version = "21.0.9";
        let activation = ActivationSelector {
            package: None,
            module: None,
            toolchain: Some(NameSelector {
                name: "jdk".to_owned(),
                version: Some(format!("={version}")),
            }),
            targets: vec!["jvm".to_owned()],
            configurations: Vec::new(),
            artifact_sha256: None,
        };
        let spec = fixture.path().join("temurin-jdk.json");
        let pinned = PinnedPackSpec {
            schema_version: PACK_SPEC_SCHEMA_VERSION,
            pack_id: "bifrost.jdk".to_owned(),
            pack_version: version.to_owned(),
            ecosystem: "jdk".to_owned(),
            kind: PinnedPackKind::JdkSourceZip {
                layout: PinnedJdkSourceLayout::ModulePrefixed,
            },
            artifact: PinnedArtifact {
                file_name: "src.zip".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/src.zip".to_owned()),
                container: None,
            },
            compatibility: Compatibility {
                bifrost: ">=0.8.18, <1.0.0".to_owned(),
                toolchains: vec![VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![activation.clone()],
            provenance: Provenance {
                source: "fixture".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
            notices: vec!["NOTICE.txt".to_owned()],
            measurement_activation: ActivationSelector {
                module: Some(NameSelector {
                    name: "java.base".to_owned(),
                    version: None,
                }),
                ..activation
            },
            measurement_queries: vec![PinnedLookupQuery::Type {
                name: "java.lang.Object".to_owned(),
            }],
        };
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: artifact,
        };
        let output = fixture.path().join("bundle");
        let error = generate_release_bundle(&output, std::slice::from_ref(&input))
            .expect_err("a generated production with an unnamed reject must fail the bundle gate");
        let message = error.to_string();
        assert!(
            message.contains("not activation-ready") && message.contains("bifrost.external.java"),
            "{message}"
        );
        assert!(
            message.contains("reject_count=1")
                && message.contains("suppressed_reject_count=0")
                && message.contains("named_gaps=0"),
            "{message}"
        );
    }

    #[test]
    fn release_bundle_is_deterministic_and_verifiable() {
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("scala-library-sources.jar");
        write_zip(
            &artifact,
            &[(
                "scala/Core.scala",
                "package scala\ntrait Any\nobject Predef { def identity[A](value: A): A = value }\n",
            )],
        );
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let spec = fixture.path().join("scala.json");
        let pinned = pinned_spec(
            "scala-library-fixture",
            "2.13.16",
            "maven",
            PinnedPackKind::ScalaSourceJar,
            PinnedArtifact {
                file_name: "scala-library-sources.jar".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/scala-library-sources.jar".to_owned()),
                container: None,
            },
            "scala",
            "org.scala-lang:scala-library",
            vec![PinnedLookupQuery::Type {
                name: "scala.Any".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: artifact,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        assert_eq!(first_bundle.rejects.packs.len(), 1);
        assert!(first_bundle.rejects.packs[0].rejects.is_empty());
        assert_eq!(first_bundle.rejects.packs[0].suppressed_rejects, 0);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "scala".to_owned(),
                    ecosystem: "maven".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "org.scala-lang:scala-library".to_owned(),
                        version: Some(Version::parse("2.13.16").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "scala".to_owned(),
                        version: Some(Version::parse("2.13.16").unwrap()),
                    }),
                    target: Some("jvm".to_owned()),
                    configuration: None,
                    artifact_sha256: Some(first_bundle.index.packs[0].artifact.sha256.clone()),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed release pack must resolve through normal activation");
        };
        assert_eq!(active.types_named("scala.Any").records.len(), 1);
        fs::write(first.join("SHA256SUMS"), "invalid\n").unwrap();
        assert!(verify_release_bundle(&first).is_err());
    }

    #[test]
    fn python_stub_tree_bundle_round_trips_through_generate_verify_install() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("stubs");
        fs::create_dir_all(root.join("collections")).unwrap();
        fs::write(
            root.join("builtins.pyi"),
            "class object: ...\ndef len(sized: object) -> int: ...\n",
        )
        .unwrap();
        fs::write(
            root.join("collections/__init__.pyi"),
            "from . import abc\nclass deque: ...\n",
        )
        .unwrap();
        fs::write(
            root.join("collections/abc.pyi"),
            "class Iterable: ...\nclass Iterator(Iterable): ...\n",
        )
        .unwrap();
        fs::write(
            fixture.path().join("NOTICE.txt"),
            "typeshed fixture notice\n",
        )
        .unwrap();
        let stubs = vec![
            "builtins.pyi".to_owned(),
            "collections/__init__.pyi".to_owned(),
            "collections/abc.pyi".to_owned(),
        ];
        let relative_paths = stubs.iter().map(PathBuf::from).collect::<Vec<_>>();
        let artifact_sha256 = read_exact_source_set(
            &root,
            &relative_paths,
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let spec = fixture.path().join("python-stubs.json");
        let pinned = pinned_spec(
            "python-stubs-fixture",
            "1.0.0",
            "pypi",
            PinnedPackKind::PythonStub { stubs },
            PinnedArtifact {
                file_name: "stubs".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/typeshed-fixture".to_owned()),
                container: None,
            },
            "python",
            "typeshed-fixture",
            vec![
                PinnedLookupQuery::Type {
                    name: "collections.abc.Iterable".to_owned(),
                },
                PinnedLookupQuery::Member {
                    owner: "builtins".to_owned(),
                    name: "len".to_owned(),
                },
            ],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: root,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        let pack = &first_bundle.index.packs[0];
        assert_eq!(pack.language, "python");
        assert_eq!(pack.completeness, Completeness::Complete);
        assert!(!pack.notices.is_empty());
        assert_eq!(first_bundle.rejects.packs[0].rejects, Vec::new());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "python".to_owned(),
                    ecosystem: "pypi".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "typeshed-fixture".to_owned(),
                        version: Some(Version::parse("1.0.0").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "python".to_owned(),
                        version: Some(Version::parse("1.0.0").unwrap()),
                    }),
                    target: None,
                    configuration: None,
                    artifact_sha256: Some(artifact_sha256),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed Python stub pack must resolve through normal activation");
        };
        assert_eq!(
            active.types_named("collections.abc.Iterable").records.len(),
            1
        );
        assert_eq!(active.types_named("collections.deque").records.len(), 1);
    }

    #[test]
    fn typescript_library_set_authoring_uses_manifest_and_library_mapping() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("typescript-7.0.2");
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        fs::write(
            root.join("lib/lib.es5.d.ts"),
            "interface Array<T> { length: number; }\n",
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let libraries = vec![PinnedTypeScriptLibrary {
            name: "es5".to_owned(),
            path: "lib/lib.es5.d.ts".to_owned(),
        }];
        let artifact = read_exact_source_set(
            &root,
            &[
                PathBuf::from("package.json"),
                PathBuf::from("lib/lib.es5.d.ts"),
            ],
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let pinned = pinned_spec(
            "typescript-library-fixture",
            "7.0.2",
            "npm",
            PinnedPackKind::TypeScriptLibrarySet {
                manifest: "package.json".to_owned(),
                libraries,
            },
            PinnedArtifact {
                file_name: "typescript-7.0.2".to_owned(),
                sha256: artifact.sha256().to_owned(),
                url: Some("https://example.invalid/typescript-7.0.2".to_owned()),
                container: None,
            },
            "typescript",
            "typescript",
            vec![PinnedLookupQuery::Type {
                name: "Array".to_owned(),
            }],
        );
        let request = ArtifactProductionRequest {
            path: root,
            artifact_kind: pinned.kind.artifact_kind(),
            pack_id: pinned.pack_id,
            pack_version: pinned.pack_version,
            ecosystem: pinned.ecosystem,
            compatibility: pinned.compatibility,
            activation: pinned.activation,
            provenance: pinned.provenance,
            license: pinned.license,
            safety: pinned.safety,
        };
        let production = produce_pinned_pack(
            &pinned.kind,
            &request,
            &ArtifactProducerLimits::default(),
            &CancellationToken::default(),
            &artifact,
        );
        assert_eq!(production.completeness, Completeness::Complete);
        assert!(production.diagnostics.is_empty());
        let pack = production.pack.expect("TypeScript library pack");
        assert_eq!(pack.language, "typescript");
        assert_eq!(pack.shards.len(), 1);
        assert_eq!(pack.shards[0].id, "declarations.typescript.lib.es5");
    }

    #[test]
    fn reviewed_typescript_measurement_enables_all_selected_configuration_shards() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("typescript-7.0.2");
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"typescript","version":"7.0.2","license":"Apache-2.0"}"#,
        )
        .unwrap();
        fs::write(
            root.join("lib/lib.es2020.d.ts"),
            "interface Promise<T> { then(): void; }\n",
        )
        .unwrap();
        fs::write(
            root.join("lib/lib.dom.d.ts"),
            "interface Document { title: string; }\n",
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let relative_paths = [
            PathBuf::from("package.json"),
            PathBuf::from("lib/lib.es2020.d.ts"),
            PathBuf::from("lib/lib.dom.d.ts"),
        ];
        let artifact_sha256 = read_exact_source_set(
            &root,
            &relative_paths,
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let mut pinned = pinned_spec(
            "typescript-measurement-fixture",
            "7.0.2",
            "npm",
            PinnedPackKind::TypeScriptLibrarySet {
                manifest: "package.json".to_owned(),
                libraries: vec![
                    PinnedTypeScriptLibrary {
                        name: "es2020".to_owned(),
                        path: "lib/lib.es2020.d.ts".to_owned(),
                    },
                    PinnedTypeScriptLibrary {
                        name: "dom".to_owned(),
                        path: "lib/lib.dom.d.ts".to_owned(),
                    },
                ],
            },
            PinnedArtifact {
                file_name: "typescript-7.0.2".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/typescript-7.0.2".to_owned()),
                container: None,
            },
            "typescript",
            "typescript",
            vec![
                PinnedLookupQuery::Type {
                    name: "Promise".to_owned(),
                },
                PinnedLookupQuery::Type {
                    name: "Document".to_owned(),
                },
            ],
        );
        pinned.safety.review_required = true;
        pinned.activation[0].configurations = vec![
            "typescript-lib:es2020".to_owned(),
            "typescript-lib:dom".to_owned(),
        ];
        pinned.measurement_activation.configurations = vec![
            "typescript-lib:es2020".to_owned(),
            "typescript-lib:dom".to_owned(),
        ];
        let spec = fixture.path().join("typescript.json");
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let bundle = generate_release_bundle(
            &fixture.path().join("bundle"),
            &[BundleInput {
                spec_path: spec,
                artifact_path: root,
            }],
        )
        .unwrap();
        assert_eq!(bundle.index.packs.len(), 1);
        let measurements = serde_json::from_slice::<ReleaseBundleMeasurements>(
            &fs::read(fixture.path().join("bundle/measurements.json")).unwrap(),
        )
        .unwrap();
        let measurements = &measurements.packs[0];
        assert_eq!(measurements.lookups.len(), 2);
        assert!(measurements.lookups.iter().all(|lookup| lookup.records > 0));
    }

    #[test]
    fn typescript_library_set_validation_requires_canonical_unique_names_and_paths() {
        let fixture = tempdir().unwrap();
        let artifact = PinnedArtifact {
            file_name: "typescript.tgz".to_owned(),
            sha256: "a".repeat(64),
            url: Some("https://example.invalid/typescript.tgz".to_owned()),
            container: None,
        };
        let make_spec = |libraries| {
            pinned_spec(
                "typescript-validation",
                "7.0.2",
                "npm",
                PinnedPackKind::TypeScriptLibrarySet {
                    manifest: "package.json".to_owned(),
                    libraries,
                },
                artifact.clone(),
                "typescript",
                "typescript",
                vec![PinnedLookupQuery::Type {
                    name: "Array".to_owned(),
                }],
            )
        };
        let error = validate_spec(
            &make_spec(vec![PinnedTypeScriptLibrary {
                name: "ES5".to_owned(),
                path: "lib/lib.es5.d.ts".to_owned(),
            }]),
            fixture.path().join("uppercase.json").as_path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("non-canonical name"), "{error}");

        let error = validate_spec(
            &make_spec(vec![PinnedTypeScriptLibrary {
                name: "dom".to_owned(),
                path: "lib/lib.es5.d.ts".to_owned(),
            }]),
            fixture.path().join("mismatch.json").as_path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");

        let duplicate = PinnedTypeScriptLibrary {
            name: "es5".to_owned(),
            path: "lib/lib.es5.d.ts".to_owned(),
        };
        let error = validate_spec(
            &make_spec(vec![duplicate.clone(), duplicate]),
            fixture.path().join("duplicate.json").as_path(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("duplicate TypeScript library"),
            "{error}"
        );
    }

    #[test]
    fn checked_in_typescript_and_rust_specs_parse_through_release_tooling() {
        let semantic_packs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../semantic-packs");
        for ecosystem in ["typescript", "rust"] {
            let directory = semantic_packs.join(ecosystem);
            let mut paths = fs::read_dir(&directory)
                .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.extension().and_then(|extension| extension.to_str()) == Some("json")
                })
                .collect::<Vec<_>>();
            paths.sort();
            assert!(!paths.is_empty(), "no checked-in {ecosystem} specs found");
            let specs = paths
                .into_iter()
                .map(|path| {
                    let bytes = fs::read(&path).unwrap();
                    let spec: PinnedPackSpec = serde_json::from_slice(&bytes)
                        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
                    (path, spec)
                })
                .collect::<Vec<_>>();
            for (path, spec) in specs {
                validate_spec(&spec, &path)
                    .unwrap_or_else(|error| panic!("validate {}: {error}", path.display()));
            }
        }
    }

    #[test]
    fn rustdoc_json_set_authoring_routes_to_source_set_producer() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("rustdoc");
        fs::create_dir_all(&root).unwrap();
        // This is intentionally the smallest malformed document: the
        // source-set producer must report a rustdoc parse diagnostic rather
        // than the old authoring.unsupported_artifact_kind placeholder.
        fs::write(root.join("core.json"), r#"{"format_version":60}"#).unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let crates = vec![PinnedRustdocCrate {
            name: "core".to_owned(),
            path: "core.json".to_owned(),
        }];
        let artifact_sha256 = read_exact_source_set(
            &root,
            &[PathBuf::from("core.json")],
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let spec = fixture.path().join("rustdoc.json");
        let pinned = pinned_spec(
            "rustdoc-json-fixture",
            "1.100.0-nightly",
            "cargo",
            PinnedPackKind::RustdocJsonSet { crates },
            PinnedArtifact {
                file_name: "rustdoc".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/rustdoc".to_owned()),
                container: None,
            },
            "rust",
            "rust",
            vec![PinnedLookupQuery::Type {
                name: "core.Option".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let error = generate_release_bundle(
            &fixture.path().join("bundle"),
            &[BundleInput {
                spec_path: spec,
                artifact_path: root,
            }],
        )
        .unwrap_err();
        assert!(!error.to_string().contains("unsupported_artifact_kind"));
        assert!(error.to_string().contains("rust.rustdoc"), "{error}");
    }

    #[test]
    fn ruby_gem_archive_bundle_round_trips_through_generate_verify_install() {
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("widget-1.2.3.gem");
        fs::write(
            &artifact,
            ruby_gem_archive(&[(
                "sig/widget.rbs",
                b"class Widget\n  def call: (String value) -> Integer\nend",
            )]),
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let spec = fixture.path().join("widget.json");
        let pinned = pinned_spec(
            "widget-gem-fixture",
            "1.2.3",
            "rubygems",
            PinnedPackKind::RubyGemArchive,
            PinnedArtifact {
                file_name: "widget-1.2.3.gem".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/widget-1.2.3.gem".to_owned()),
                container: None,
            },
            "ruby",
            "widget",
            vec![PinnedLookupQuery::Type {
                name: "Widget".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: artifact,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        let pack = &first_bundle.index.packs[0];
        assert_eq!(pack.language, "ruby");
        assert_eq!(pack.completeness, Completeness::Complete);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "ruby".to_owned(),
                    ecosystem: "rubygems".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "widget".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "ruby".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    target: Some("ruby".to_owned()),
                    configuration: None,
                    artifact_sha256: Some(first_bundle.index.packs[0].artifact.sha256.clone()),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed Ruby gem pack must resolve through normal activation");
        };
        assert_eq!(active.types_named("Widget").records.len(), 1);
    }

    #[test]
    fn npm_package_bundle_round_trips_through_generate_verify_install() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("widget");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"name":"widget","version":"1.2.3","types":"index.d.ts"}"#,
        )
        .unwrap();
        fs::write(
            root.join("index.d.ts"),
            "export declare class Widget {\n  render(width: number): string;\n}\n",
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let relative_paths = vec![PathBuf::from("package.json"), PathBuf::from("index.d.ts")];
        let artifact_sha256 = read_exact_source_set(
            &root,
            &relative_paths,
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let spec = fixture.path().join("widget.json");
        let pinned = pinned_spec(
            "widget-npm-fixture",
            "1.2.3",
            "npm",
            PinnedPackKind::NpmPackage {
                manifest: "package.json".to_owned(),
                declarations: vec![PinnedNpmDeclaration {
                    module: "widget".to_owned(),
                    path: "index.d.ts".to_owned(),
                }],
            },
            PinnedArtifact {
                file_name: "widget".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/widget-1.2.3.tgz".to_owned()),
                container: None,
            },
            "node",
            "widget",
            vec![PinnedLookupQuery::Member {
                owner: "widget.Widget".to_owned(),
                name: "render".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: root,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        let pack = &first_bundle.index.packs[0];
        assert_eq!(pack.language, "typescript");
        assert_eq!(pack.completeness, Completeness::Complete);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "typescript".to_owned(),
                    ecosystem: "npm".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "widget".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "node".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    target: None,
                    configuration: None,
                    artifact_sha256: Some(artifact_sha256),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed npm declaration pack must resolve through normal activation");
        };
        assert_eq!(active.types_named("widget.Widget").records.len(), 1);
    }

    #[test]
    fn go_module_bundle_round_trips_through_generate_verify_install() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("widget-src");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("widget.go"),
            "package widget\n\ntype Widget struct {\n\tLabel string\n}\n\nfunc (w Widget) Render(width int) string { return w.Label }\n",
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let relative_paths = vec![PathBuf::from("widget.go")];
        let artifact_sha256 = read_exact_source_set(
            &root,
            &relative_paths,
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let spec = fixture.path().join("widget.json");
        let pinned = pinned_spec(
            "widget-go-fixture",
            "1.2.3",
            "go",
            PinnedPackKind::GoModule {
                packages: vec![PinnedGoPackage {
                    import_path: "example.com/widget".to_owned(),
                    name: "widget".to_owned(),
                    files: vec!["widget.go".to_owned()],
                }],
            },
            PinnedArtifact {
                file_name: "widget-src".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/example.com/widget/@v/v1.2.3.zip".to_owned()),
                container: None,
            },
            "go",
            "example.com/widget",
            vec![PinnedLookupQuery::Member {
                owner: "example.com/widget.Widget".to_owned(),
                name: "Render".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: root,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        let pack = &first_bundle.index.packs[0];
        assert_eq!(pack.language, "go");
        assert_eq!(pack.completeness, Completeness::Complete);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "example.com/widget".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "go".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    target: None,
                    configuration: None,
                    artifact_sha256: Some(artifact_sha256),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed Go module pack must resolve through normal activation");
        };
        assert_eq!(
            active
                .types_named("example.com/widget.Widget")
                .records
                .len(),
            1
        );
    }

    #[test]
    fn composer_package_bundle_round_trips_through_generate_verify_install() {
        let fixture = tempdir().unwrap();
        let root = fixture.path().join("widget-src");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Widget.php"),
            "<?php\nnamespace Vendor\\Widget;\n\nclass Widget {\n    public function render(int $width): string { return 'ok'; }\n}\n",
        )
        .unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let relative_paths = vec![PathBuf::from("Widget.php")];
        let artifact_sha256 = read_exact_source_set(
            &root,
            &relative_paths,
            MAX_SOURCE_SET_FILES,
            MAX_SOURCE_SET_PATH_DEPTH,
            &ArtifactProducerLimits::default(),
        )
        .unwrap()
        .sha256()
        .to_owned();
        let spec = fixture.path().join("widget.json");
        let pinned = pinned_spec(
            "widget-composer-fixture",
            "1.2.3",
            "composer",
            PinnedPackKind::ComposerPackage {
                rules: vec![PinnedComposerAutoloadRule::Psr4 {
                    namespace_prefix: "Vendor.Widget".to_owned(),
                    files: vec!["Widget.php".to_owned()],
                }],
            },
            PinnedArtifact {
                file_name: "widget-src".to_owned(),
                sha256: artifact_sha256.clone(),
                url: Some("https://example.invalid/vendor-widget-1.2.3.zip".to_owned()),
                container: None,
            },
            "php",
            "vendor/widget",
            vec![PinnedLookupQuery::Member {
                owner: "Vendor.Widget.Widget".to_owned(),
                name: "render".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: root,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_bundle = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_bundle = generate_release_bundle(&second, &[input]).unwrap();
        assert_deterministic_and_installable(&first, &second, &first_bundle, &second_bundle);
        let pack = &first_bundle.index.packs[0];
        assert_eq!(pack.language, "php");
        assert_eq!(pack.completeness, Completeness::Complete);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let installed = install_release_bundle(&first, &catalog).unwrap();
        assert_eq!(installed.len(), 1);
        let SemanticModelResolutionOutcome::Ready(active) = resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "php".to_owned(),
                    ecosystem: "composer".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "vendor/widget".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    module: None,
                    toolchain: Some(CatalogCoordinate {
                        name: "php".to_owned(),
                        version: Some(Version::parse("1.2.3").unwrap()),
                    }),
                    target: None,
                    configuration: None,
                    artifact_sha256: Some(artifact_sha256),
                }],
                controls: Vec::new(),
                limits: Default::default(),
            },
            &CancellationToken::default(),
        ) else {
            panic!("installed Composer package pack must resolve through normal activation");
        };
        assert_eq!(active.types_named("Vendor.Widget.Widget").records.len(), 1);
    }

    #[test]
    fn extraction_rejects_are_reported_structurally_and_checksummed() {
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("kotlin-fixture-sources.jar");
        write_zip(
            &artifact,
            &[
                ("kotlin/Bad.kt", "class {{{ fun ]] broken"),
                ("kotlin/Good.kt", "package fixture\nclass Good\n"),
            ],
        );
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let spec = fixture.path().join("kotlin.json");
        let pinned = pinned_spec(
            "kotlin-fixture",
            "2.2.20",
            "maven",
            PinnedPackKind::KotlinSourceJar,
            PinnedArtifact {
                file_name: "kotlin-fixture-sources.jar".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/kotlin-fixture-sources.jar".to_owned()),
                container: None,
            },
            "kotlin",
            "org.jetbrains.kotlin:kotlin-stdlib",
            vec![PinnedLookupQuery::Type {
                name: "fixture.Good".to_owned(),
            }],
        );
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let output = fixture.path().join("bundle");
        let bundle = generate_release_bundle(
            &output,
            &[BundleInput {
                spec_path: spec,
                artifact_path: artifact,
            }],
        )
        .unwrap();

        let pack_rejects = &bundle.rejects.packs[0];
        assert_eq!(pack_rejects.completeness, Completeness::Partial);
        assert_eq!(
            pack_rejects.rejects,
            vec![ReleaseReject {
                severity: ReleaseRejectSeverity::Warning,
                code: "kotlin.source.parse".to_owned(),
                location: Some("kotlin/Bad.kt".to_owned()),
                declaration: None,
                message: "Kotlin source entry contains syntax unsupported by the pinned parser"
                    .to_owned(),
            }]
        );
        assert_eq!(pack_rejects.suppressed_rejects, 0);
        assert_eq!(verify_release_bundle(&output).unwrap(), bundle);

        // The burn-down report is part of the checksummed inventory: dropping
        // one reject from it must fail verification.
        let mut tampered: ReleaseBundleRejects =
            serde_json::from_slice(&fs::read(output.join("rejects.json")).unwrap()).unwrap();
        tampered.packs[0].rejects.clear();
        fs::write(output.join("rejects.json"), json_bytes(&tampered).unwrap()).unwrap();
        assert!(verify_release_bundle(&output).is_err());
    }

    #[test]
    fn spec_validation_rejects_unknown_family_and_missing_or_placeholder_license() {
        let fixture = tempdir().unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();
        let artifact = fixture.path().join("artifact.jar");
        write_zip(
            &artifact,
            &[("scala/Core.scala", "package scala\ntrait Any\n")],
        );
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let valid = pinned_spec(
            "fixture",
            "1.0.0",
            "maven",
            PinnedPackKind::ScalaSourceJar,
            PinnedArtifact {
                file_name: "artifact.jar".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/artifact.jar".to_owned()),
                container: None,
            },
            "scala",
            "org.scala-lang:scala-library",
            vec![PinnedLookupQuery::Type {
                name: "scala.Any".to_owned(),
            }],
        );
        let generate_with = |name: &str, spec_json: &serde_json::Value| {
            let spec_path = fixture.path().join(name);
            fs::write(&spec_path, serde_json::to_vec_pretty(spec_json).unwrap()).unwrap();
            generate_release_bundle(
                &fixture.path().join("out").join(name),
                &[BundleInput {
                    spec_path,
                    artifact_path: artifact.clone(),
                }],
            )
        };
        let valid_json = serde_json::to_value(&valid).unwrap();

        let mut unknown_family = valid_json.clone();
        unknown_family["kind"] = serde_json::json!({ "artifact_kind": "nuget_package" });
        let error = generate_with("unknown-family.json", &unknown_family).unwrap_err();
        assert!(error.to_string().contains("parse spec"), "{error}");

        let mut missing_license = valid_json.clone();
        missing_license
            .as_object_mut()
            .unwrap()
            .remove("license")
            .unwrap();
        let error = generate_with("missing-license.json", &missing_license).unwrap_err();
        assert!(error.to_string().contains("license"), "{error}");

        let mut placeholder_license = valid_json.clone();
        placeholder_license["license"] = serde_json::json!("NOASSERTION");
        let error = generate_with("placeholder-license.json", &placeholder_license).unwrap_err();
        assert!(error.to_string().contains("SPDX"), "{error}");

        let mut empty_provenance = valid_json.clone();
        empty_provenance["provenance"]["source"] = serde_json::json!("");
        let error = generate_with("empty-provenance.json", &empty_provenance).unwrap_err();
        assert!(error.to_string().contains("provenance"), "{error}");

        let mut empty_stubs = valid_json.clone();
        empty_stubs["kind"] = serde_json::json!({ "artifact_kind": "python_stub", "stubs": [] });
        let error = generate_with("empty-stubs.json", &empty_stubs).unwrap_err();
        assert!(error.to_string().contains("stub"), "{error}");

        let mut non_stub_source = valid_json.clone();
        non_stub_source["kind"] = serde_json::json!({
            "artifact_kind": "python_stub",
            "stubs": ["module.py"]
        });
        let error = generate_with("non-stub-source.json", &non_stub_source).unwrap_err();
        assert!(error.to_string().contains(".pyi"), "{error}");
    }

    #[test]
    fn verifier_rejects_tampered_content_addressed_asset() {
        let fixture = tempdir().unwrap();
        let asset = ReleaseAsset {
            path: "notices/example.txt".to_owned(),
            sha256: sha256_bytes(b"expected"),
            bytes: 8,
        };
        fs::create_dir_all(fixture.path().join("notices")).unwrap();
        fs::write(fixture.path().join(&asset.path), b"tampered").unwrap();
        assert!(verify_asset(fixture.path(), &asset).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn verifier_rejects_symlink_asset_components() {
        use std::os::unix::fs::symlink;

        let fixture = tempdir().unwrap();
        let outside = fixture.path().join("outside.txt");
        fs::write(&outside, b"expected").unwrap();
        fs::create_dir_all(fixture.path().join("notices")).unwrap();
        symlink(&outside, fixture.path().join("notices/example.txt")).unwrap();
        let asset = ReleaseAsset {
            path: "notices/example.txt".to_owned(),
            sha256: sha256_bytes(b"expected"),
            bytes: 8,
        };
        let error = verify_asset(fixture.path(), &asset).unwrap_err();
        assert!(error.to_string().contains("symbolic-link"), "{error}");

        fs::remove_file(fixture.path().join("notices/example.txt")).unwrap();
        fs::remove_dir(fixture.path().join("notices")).unwrap();
        symlink(
            fixture.path().join("outside-dir"),
            fixture.path().join("notices"),
        )
        .unwrap();
        let error = verify_asset(fixture.path(), &asset).unwrap_err();
        assert!(error.to_string().contains("symbolic-link"), "{error}");
    }

    #[test]
    fn release_notice_validation_rejects_unsafe_duplicate_and_unsorted_sources() {
        let asset = ReleaseAsset {
            path: "notices/example.txt".to_owned(),
            sha256: sha256_bytes(b"notice"),
            bytes: 6,
        };
        let notice = |source_path: &str| ReleaseNotice {
            source_path: source_path.to_owned(),
            asset: asset.clone(),
        };
        assert!(validate_release_notices(&[notice("../NOTICE.txt")]).is_err());
        assert!(validate_release_notices(&[notice("z.txt"), notice("a.txt")]).is_err());
        assert!(validate_release_notices(&[notice("NOTICE.txt"), notice("NOTICE.txt")]).is_err());
    }

    #[test]
    fn merge_release_bundles_is_sorted_deterministic_and_fail_closed() {
        let fixture = tempdir().unwrap();
        fs::write(fixture.path().join("NOTICE.txt"), "fixture notice\n").unwrap();

        let scala_artifact = fixture.path().join("scala.jar");
        write_zip(
            &scala_artifact,
            &[("scala/Core.scala", "package scala\ntrait Any\n")],
        );
        let (scala_sha256, _) = sha256_file(&scala_artifact).unwrap();
        let scala_spec = fixture.path().join("scala.json");
        fs::write(
            &scala_spec,
            serde_json::to_vec_pretty(&pinned_spec(
                "scala-merge-fixture",
                "2.13.16",
                "maven",
                PinnedPackKind::ScalaSourceJar,
                PinnedArtifact {
                    file_name: "scala.jar".to_owned(),
                    sha256: scala_sha256,
                    url: Some("https://example.invalid/scala.jar".to_owned()),
                    container: None,
                },
                "scala",
                "org.scala-lang:scala-library",
                vec![PinnedLookupQuery::Type {
                    name: "scala.Any".to_owned(),
                }],
            ))
            .unwrap(),
        )
        .unwrap();

        let java_artifact = fixture.path().join("java.jar");
        write_zip(
            &java_artifact,
            &[(
                "fixture/Widget.java",
                "package fixture; public class Widget {}\n",
            )],
        );
        let (java_sha256, _) = sha256_file(&java_artifact).unwrap();
        let java_spec = fixture.path().join("java.json");
        fs::write(
            &java_spec,
            serde_json::to_vec_pretty(&pinned_spec(
                "java-merge-fixture",
                "1.0.0",
                "maven",
                PinnedPackKind::JavaSourceJar,
                PinnedArtifact {
                    file_name: "java.jar".to_owned(),
                    sha256: java_sha256,
                    url: Some("https://example.invalid/java.jar".to_owned()),
                    container: None,
                },
                "jdk",
                "fixture:java",
                vec![PinnedLookupQuery::Type {
                    name: "fixture.Widget".to_owned(),
                }],
            ))
            .unwrap(),
        )
        .unwrap();

        let scala_bundle = fixture.path().join("scala-bundle");
        generate_release_bundle(
            &scala_bundle,
            &[BundleInput {
                spec_path: scala_spec,
                artifact_path: scala_artifact,
            }],
        )
        .unwrap();
        let java_bundle = fixture.path().join("java-bundle");
        generate_release_bundle(
            &java_bundle,
            &[BundleInput {
                spec_path: java_spec,
                artifact_path: java_artifact,
            }],
        )
        .unwrap();

        let merged = fixture.path().join("merged");
        let merged_bundle =
            merge_release_bundles(&merged, &[java_bundle.clone(), scala_bundle.clone()]).unwrap();
        assert_eq!(
            merged_bundle
                .index
                .packs
                .iter()
                .map(|pack| pack.pack_id.as_str())
                .collect::<Vec<_>>(),
            ["java-merge-fixture", "scala-merge-fixture"]
        );
        let measurements: ReleaseBundleMeasurements =
            serde_json::from_slice(&fs::read(merged.join("measurements.json")).unwrap()).unwrap();
        assert_eq!(
            measurements
                .packs
                .iter()
                .map(|pack| pack.pack_id.as_str())
                .collect::<Vec<_>>(),
            ["java-merge-fixture", "scala-merge-fixture"]
        );
        assert_eq!(verify_release_bundle(&merged).unwrap(), merged_bundle);

        let stale = fixture.path().join("stale");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("old.txt"), b"stale").unwrap();
        let error = merge_release_bundles(&stale, &[java_bundle.clone(), scala_bundle.clone()])
            .unwrap_err();
        assert!(error.to_string().contains("new or empty"), "{error}");

        let mut empty_measurements: ReleaseBundleMeasurements =
            serde_json::from_slice(&fs::read(merged.join("measurements.json")).unwrap()).unwrap();
        empty_measurements.packs[0].lookups.clear();
        fs::write(
            merged.join("measurements.json"),
            json_bytes(&empty_measurements).unwrap(),
        )
        .unwrap();
        let error = verify_release_bundle(&merged).unwrap_err();
        assert!(error.to_string().contains("measurements"), "{error}");

        let repeat = fixture.path().join("merged-repeat");
        merge_release_bundles(&repeat, &[scala_bundle.clone(), java_bundle.clone()]).unwrap();
        assert_eq!(
            fs::read(merged.join("index.json")).unwrap(),
            fs::read(repeat.join("index.json")).unwrap()
        );
        assert_eq!(
            fs::read(merged.join("rejects.json")).unwrap(),
            fs::read(repeat.join("rejects.json")).unwrap()
        );
        assert_eq!(
            fs::read(merged.join("SHA256SUMS")).unwrap(),
            fs::read(repeat.join("SHA256SUMS")).unwrap()
        );

        let duplicate = fixture.path().join("duplicate");
        let error =
            merge_release_bundles(&duplicate, &[scala_bundle.clone(), scala_bundle.clone()])
                .unwrap_err();
        assert!(
            error.to_string().contains("duplicate release pack"),
            "{error}"
        );

        fs::remove_file(java_bundle.join("measurements.json")).unwrap();
        assert!(verify_release_bundle(&java_bundle).is_err());
        fs::write(scala_bundle.join("SHA256SUMS"), b"tampered\n").unwrap();
        assert!(verify_release_bundle(&scala_bundle).is_err());
    }

    fn write_zip(path: &Path, entries: &[(&str, &str)]) {
        let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
        for (entry_name, source) in entries {
            writer
                .start_file(*entry_name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(source.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }

    /// Build a `.gem` archive: an outer tar containing one `data.tar.gz`
    /// entry, itself a gzip-compressed tar of the gem's declaration files.
    fn ruby_gem_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let encoder =
                flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::default());
            let mut data = tar::Builder::new(encoder);
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                data.append_data(&mut header, path, *bytes).unwrap();
            }
            data.into_inner().unwrap().finish().unwrap();
        }
        let mut gem = Vec::new();
        {
            let mut outer = tar::Builder::new(&mut gem);
            let mut header = tar::Header::new_gnu();
            header.set_size(compressed.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            outer
                .append_data(&mut header, "data.tar.gz", compressed.as_slice())
                .unwrap();
            outer.finish().unwrap();
        }
        gem
    }
}
