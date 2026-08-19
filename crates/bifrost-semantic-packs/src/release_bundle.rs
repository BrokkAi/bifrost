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
    CompiledSemanticModelPack, CompilerOptions, Completeness, DecodeLimits, DurablePackSource,
    DurablePackSourceKind, ExactArtifact, ExternalArtifactKind, PackExtractionAccounting,
    PackExtractionGap, ProducerDiagnostic, ProducerDiagnosticSeverity, Provenance,
    ResolvedActiveSemanticModels, Safety, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelResolutionOutcome, SemanticPackCatalog,
    compile_pack, decode_manifest, decode_shard_for_manifest, pack_rejects_are_warning_only,
    read_exact_artifact, read_exact_source_set, resolve_active_semantic_models,
};
use brokk_bifrost_analysis::analyzer::{
    CSharpAssemblyPackProducer, ComposerPackagePackProducer, ComposerPinnedAutoloadRule,
    GoModulePackProducer, GoPinnedPackage as AnalysisGoPinnedPackage, JavaJarPackProducer,
    JdkSourceArchiveLayout, JdkSourceArchivePackProducer, KotlinSourceJarPackProducer,
    PythonArtifactPackProducer, RubyGemArchivePackProducer, RustdocJsonPackProducer,
    ScalaSourceJarPackProducer, TypeScriptDeclarationPackProducer,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

pub const PACK_SPEC_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_BUNDLE_SCHEMA_VERSION: u32 = 1;

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
    DotNetAssembly,
    RustdocJson,
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
            Self::DotNetAssembly => ExternalArtifactKind::DotNetAssembly,
            Self::RustdocJson => ExternalArtifactKind::RustdocJson,
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
    let generator = ReleaseGenerator {
        name: "brokk-bifrost-semantic-packs".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let mut packs = Vec::with_capacity(inputs.len());
    let mut measurements = Vec::with_capacity(inputs.len());
    let mut rejects = Vec::with_capacity(inputs.len());
    for input in inputs {
        let (pack, measurement, pack_rejects) = generate_one(output_root, input)?;
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
    let index = ReleaseBundleIndex {
        schema_version: RELEASE_BUNDLE_SCHEMA_VERSION,
        generator: generator.clone(),
        packs,
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

fn generate_one(
    output_root: &Path,
    input: &BundleInput,
) -> Result<(ReleasePack, ReleasePackMeasurement, ReleasePackRejects), BundleError> {
    let spec_bytes = fs::read(&input.spec_path).map_err(|error| {
        BundleError::new(format!("read spec {}: {error}", input.spec_path.display()))
    })?;
    let spec: PinnedPackSpec = serde_json::from_slice(&spec_bytes).map_err(|error| {
        BundleError::new(format!("parse spec {}: {error}", input.spec_path.display()))
    })?;
    validate_spec(&spec, &input.spec_path)?;
    // A release bundle is the durable extraction-accounting boundary. Retain
    // the interactive safety bound, but size it to the already-bounded source
    // set so every rejected declaration can be named in `rejects.json`.
    let producer_limits = ArtifactProducerLimits {
        max_diagnostics: MAX_SOURCE_SET_FILES,
        ..ArtifactProducerLimits::default()
    };
    let artifact = read_pinned_artifact(&spec, &input.artifact_path, &producer_limits)?;
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
    if production.artifact_sha256.as_deref() != Some(spec.artifact.sha256.as_str()) {
        return Err(BundleError::new(
            "producer did not retain the pinned artifact identity",
        ));
    }
    let authored = production.pack.as_ref().ok_or_else(|| {
        BundleError::new(format!(
            "pack production failed: {}",
            render_diagnostics(&production.diagnostics)
        ))
    })?;
    let compiled = compile_pack(authored, &CompilerOptions::default()).map_err(|diagnostics| {
        BundleError::new(format!("pack compilation failed: {diagnostics:#?}"))
    })?;
    let elapsed = started.elapsed();
    let runtime_measurement = measure_runtime(&spec, &compiled, &cancellation)?;

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
    let notices = copy_notices(output_root, &input.spec_path, &spec.notices)?;
    let measurement = measurement(
        &spec,
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
            pack_id: spec.pack_id,
            pack_version: spec.pack_version,
            language: compiled.manifest.language.clone(),
            ecosystem: spec.ecosystem,
            artifact: spec.artifact,
            artifact_bytes: artifact.bytes().len() as u64,
            manifest: ReleaseAsset {
                path: manifest_path,
                sha256: manifest_sha256,
                bytes: compiled.manifest_bytes.len().try_into().unwrap_or(u64::MAX),
            },
            manifest_semantic_sha256: compiled.manifest.semantic_sha256.clone(),
            manifest_content_sha256: compiled.manifest.content_sha256.clone(),
            completeness: compiled.manifest.completeness,
            compatibility: spec.compatibility,
            provenance: spec.provenance,
            license: spec.license,
            notices,
            shards,
        },
        measurement,
        pack_rejects,
    ))
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
        PinnedPackKind::DotNetAssembly => CSharpAssemblyPackProducer.produce_loaded_artifact(
            request,
            limits,
            cancellation,
            artifact,
        ),
        PinnedPackKind::RustdocJson => {
            RustdocJsonPackProducer.produce_loaded_artifact(request, limits, cancellation, artifact)
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
    for notice in &spec.notices {
        require_safe_relative(Path::new(notice))?;
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
    let request = SemanticModelActivationRequest {
        bifrost_version: env!("CARGO_PKG_VERSION")
            .parse()
            .expect("crate package version is valid semver"),
        evidence: vec![SemanticModelActivationEvidence {
            language: compiled.manifest.language.clone(),
            ecosystem: compiled.manifest.ecosystem.clone(),
            package: selector.package.as_ref().map(catalog_coordinate),
            module: selector.module.as_ref().map(catalog_coordinate),
            toolchain: selector.toolchain.as_ref().map(catalog_coordinate),
            target: selector.targets.first().cloned(),
            configuration: selector.configurations.first().cloned(),
            artifact_sha256: Some(spec.artifact.sha256.clone()),
        }],
        controls: Vec::new(),
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
    let index_path = output_root.join("index.json");
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
    verify_checksums(output_root, &index)?;
    let rejects = verify_rejects(output_root, &index)?;
    let measurements_path = output_root.join("measurements.json");
    if measurements_path.exists() {
        verify_measurements(&measurements_path, &index)?;
    }
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
        for notice in &pack.notices {
            verify_asset(output_root, &notice.asset)?;
        }
    }
    Ok(ReleaseBundle { index, rejects })
}

/// Read and cross-check the structured extraction burn-down report.
///
/// The report is a mandatory release asset: a bundle without it, or with
/// packs that do not match the index exactly, fails verification.
fn verify_rejects(
    output_root: &Path,
    index: &ReleaseBundleIndex,
) -> Result<ReleaseBundleRejects, BundleError> {
    let rejects_path = output_root.join("rejects.json");
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
    PackExtractionAccounting {
        reject_count: rejects.rejects.len().try_into().unwrap_or(u64::MAX),
        suppressed_reject_count: rejects.suppressed_rejects,
        error_reject_count: rejects
            .rejects
            .iter()
            .filter(|reject| reject.severity == ReleaseRejectSeverity::Error)
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
        gaps: rejects
            .rejects
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
    let limits = DecodeLimits::default();
    bundle
        .index
        .packs
        .iter()
        .zip(&bundle.rejects.packs)
        .map(|(pack, rejects)| {
            let manifest_bytes = verify_asset(bundle_root, &pack.manifest)?;
            let manifest = decode_manifest(&manifest_bytes, &limits).map_err(|error| {
                BundleError::new(format!("decode manifest for {}: {error}", pack.pack_id))
            })?;
            let shards =
                manifest
                    .shards
                    .iter()
                    .map(|descriptor| {
                        let indexed = pack
                            .shards
                            .iter()
                            .find(|shard| shard.shard_id == descriptor.shard_id)
                            .expect("verified bundle indexes every manifest shard");
                        let bytes = verify_asset(bundle_root, &indexed.asset)?;
                        Ok(brokk_bifrost_analysis::analyzer::semantic_model::CompiledShardArtifact {
                        descriptor: descriptor.clone(),
                        bytes,
                    })
                    })
                    .collect::<Result<Vec<_>, BundleError>>()?;
            let compiled = CompiledSemanticModelPack {
                manifest,
                manifest_bytes,
                shards,
            };
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
        .collect()
}

fn verify_checksums(output_root: &Path, index: &ReleaseBundleIndex) -> Result<(), BundleError> {
    let checksum_path = output_root.join("SHA256SUMS");
    let checksum_text = fs::read_to_string(&checksum_path)
        .map_err(|error| BundleError::new(format!("read {}: {error}", checksum_path.display())))?;
    let mut actual_paths = Vec::new();
    for (line_number, line) in checksum_text.lines().enumerate() {
        let (sha256, path) = line.split_once("  ").ok_or_else(|| {
            BundleError::new(format!("invalid SHA256SUMS line {}", line_number + 1))
        })?;
        validate_sha256("checksum", sha256)?;
        require_safe_relative(Path::new(path))?;
        let (actual_sha256, _) = sha256_file(&output_root.join(path))?;
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
    require_safe_relative(relative)?;
    let bytes = fs::read(output_root.join(relative))
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
    let measurements_bytes = fs::read(measurements_path).map_err(|error| {
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
                    || measurement.lookups.iter().any(|lookup| lookup.records == 0)
            })
    {
        return Err(BundleError::new(
            "release measurements do not match the indexed packs",
        ));
    }
    Ok(())
}

fn write_content_addressed(
    output_root: &Path,
    relative: &str,
    bytes: &[u8],
) -> Result<(), BundleError> {
    let path = Path::new(relative);
    require_safe_relative(path)?;
    write_new_or_identical(output_root, path, bytes)
}

fn write_new_or_identical(
    output_root: &Path,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), BundleError> {
    require_safe_relative(relative)?;
    let path = output_root.join(relative);
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
    require_safe_relative(relative)?;
    let path = output_root.join(relative);
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
        let (sha256, _) = sha256_file(&output_root.join(&path))?;
        output.push_str(&sha256);
        output.push_str("  ");
        output.push_str(&path);
        output.push('\n');
    }
    write_new_or_identical(output_root, Path::new("SHA256SUMS"), output.as_bytes())
}

fn release_asset_paths(index: &ReleaseBundleIndex) -> Vec<String> {
    let mut paths = vec!["index.json".to_owned(), "rejects.json".to_owned()];
    for pack in &index.packs {
        paths.push(pack.manifest.path.clone());
        paths.extend(pack.shards.iter().map(|shard| shard.asset.path.clone()));
        paths.extend(pack.notices.iter().map(|notice| notice.asset.path.clone()));
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
        assert_eq!(&verify_release_bundle(first).unwrap(), first_bundle);
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
