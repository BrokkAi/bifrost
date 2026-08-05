//! Reproducible, content-addressed release bundles for pinned JVM API packs.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, ArtifactEncoding, ArtifactProducerLimits, CatalogCoordinate,
    CatalogOptions, Compatibility, CompiledSemanticModelPack, CompilerOptions, Completeness,
    DecodeLimits, DurablePackSource, DurablePackSourceKind, ExternalArtifactKind,
    ProducerDiagnostic, Provenance, ResolvedActiveSemanticModels, Safety,
    SemanticModelActivationEvidence, SemanticModelActivationRequest,
    SemanticModelResolutionOutcome, SemanticPackCatalog, compile_pack, decode_manifest,
    decode_shard_for_manifest, read_exact_artifact, resolve_active_semantic_models,
};
use brokk_bifrost_analysis::analyzer::{
    JdkSourceArchiveLayout, JdkSourceArchivePackProducer, KotlinSourceJarPackProducer,
    ScalaSourceJarPackProducer,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

pub const JVM_PACK_SPEC_SCHEMA_VERSION: u32 = 1;
pub const RELEASE_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedJvmPackSpec {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub ecosystem: String,
    pub kind: PinnedJvmPackKind,
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
pub enum PinnedJvmPackKind {
    JdkSourceZip { layout: PinnedJdkSourceLayout },
    KotlinSourceJar,
    ScalaSourceJar,
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
    pub diagnostics: Vec<String>,
    pub suppressed_diagnostics: usize,
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
) -> Result<ReleaseBundleIndex, BundleError> {
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
    for input in inputs {
        let (pack, measurement) = generate_one(output_root, input)?;
        packs.push(pack);
        measurements.push(measurement);
    }
    packs.sort_unstable_by(|left, right| {
        (&left.pack_id, &left.pack_version).cmp(&(&right.pack_id, &right.pack_version))
    });
    measurements.sort_unstable_by(|left, right| {
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
    verify_release_bundle(output_root)?;
    Ok(index)
}

fn generate_one(
    output_root: &Path,
    input: &BundleInput,
) -> Result<(ReleasePack, ReleasePackMeasurement), BundleError> {
    let spec_bytes = fs::read(&input.spec_path).map_err(|error| {
        BundleError::new(format!("read spec {}: {error}", input.spec_path.display()))
    })?;
    let spec: PinnedJvmPackSpec = serde_json::from_slice(&spec_bytes).map_err(|error| {
        BundleError::new(format!("parse spec {}: {error}", input.spec_path.display()))
    })?;
    validate_spec(&spec, &input.spec_path)?;
    let producer_limits = ArtifactProducerLimits::default();
    let artifact = read_exact_artifact(&input.artifact_path, &producer_limits)
        .map_err(|diagnostic| BundleError::new(render_diagnostics(&[diagnostic])))?;
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

    let request = brokk_bifrost_analysis::analyzer::semantic_model::ArtifactProductionRequest {
        path: input.artifact_path.clone(),
        artifact_kind: match &spec.kind {
            PinnedJvmPackKind::JdkSourceZip { .. } => ExternalArtifactKind::JdkSourceZip,
            PinnedJvmPackKind::KotlinSourceJar => ExternalArtifactKind::KotlinSourceJar,
            PinnedJvmPackKind::ScalaSourceJar => ExternalArtifactKind::ScalaSourceJar,
        },
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
    let production = match &spec.kind {
        PinnedJvmPackKind::JdkSourceZip { layout } => {
            JdkSourceArchivePackProducer::new(match *layout {
                PinnedJdkSourceLayout::ModulePrefixed => JdkSourceArchiveLayout::ModulePrefixed,
                PinnedJdkSourceLayout::Flat => JdkSourceArchiveLayout::Flat,
            })
            .produce_loaded_artifact(
                &request,
                &producer_limits,
                Some(&cancellation),
                &artifact,
            )
        }
        PinnedJvmPackKind::ScalaSourceJar => ScalaSourceJarPackProducer.produce_loaded_artifact(
            &request,
            &producer_limits,
            Some(&cancellation),
            &artifact,
        ),
        PinnedJvmPackKind::KotlinSourceJar => KotlinSourceJarPackProducer.produce_loaded_artifact(
            &request,
            &producer_limits,
            Some(&cancellation),
            &artifact,
        ),
    };
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
        &production.diagnostics,
        production.suppressed_diagnostics,
    );
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
    ))
}

fn validate_spec(spec: &PinnedJvmPackSpec, spec_path: &Path) -> Result<(), BundleError> {
    if spec.schema_version != JVM_PACK_SPEC_SCHEMA_VERSION {
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
    if spec.notices.is_empty() {
        return Err(BundleError::new(format!(
            "spec {} must name at least one license or notice file",
            spec_path.display()
        )));
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
    spec: &PinnedJvmPackSpec,
    artifact_bytes: u64,
    compiled: &CompiledSemanticModelPack,
    generation_millis: u64,
    runtime: RuntimeMeasurement,
    diagnostics: &[ProducerDiagnostic],
    suppressed_diagnostics: usize,
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
        diagnostics: diagnostics
            .iter()
            .map(|diagnostic| {
                format!(
                    "{:?} {} {}: {}",
                    diagnostic.severity,
                    diagnostic.code,
                    diagnostic.location.as_deref().unwrap_or("<pack>"),
                    diagnostic.message
                )
            })
            .collect(),
        suppressed_diagnostics,
    }
}

fn measure_runtime(
    spec: &PinnedJvmPackSpec,
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

pub fn verify_release_bundle(output_root: &Path) -> Result<ReleaseBundleIndex, BundleError> {
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
    Ok(index)
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
    let index = verify_release_bundle(bundle_root)?;
    let limits = DecodeLimits::default();
    index
        .packs
        .iter()
        .map(|pack| {
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
            let installed = catalog
                .install(
                    &compiled,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::PreShipped,
                        source_id: format!(
                            "release:{}@{}:{}",
                            pack.pack_id, pack.pack_version, pack.manifest.sha256
                        ),
                    },
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
    let mut paths = vec!["index.json".to_owned()];
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

    #[test]
    fn release_bundle_is_deterministic_and_verifiable() {
        let fixture = tempdir().unwrap();
        let artifact = fixture.path().join("scala-library-sources.jar");
        write_zip(
            &artifact,
            "scala/Core.scala",
            "package scala\ntrait Any\nobject Predef { def identity[A](value: A): A = value }\n",
        );
        let notice = fixture.path().join("NOTICE.txt");
        fs::write(&notice, "fixture notice\n").unwrap();
        let (artifact_sha256, _) = sha256_file(&artifact).unwrap();
        let spec = fixture.path().join("scala.json");
        let pinned = PinnedJvmPackSpec {
            schema_version: JVM_PACK_SPEC_SCHEMA_VERSION,
            pack_id: "scala-library-fixture".to_owned(),
            pack_version: "2.13.16".to_owned(),
            ecosystem: "maven".to_owned(),
            kind: PinnedJvmPackKind::ScalaSourceJar,
            artifact: PinnedArtifact {
                file_name: "scala-library-sources.jar".to_owned(),
                sha256: artifact_sha256,
                url: Some("https://example.invalid/scala-library-sources.jar".to_owned()),
                container: None,
            },
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![VersionConstraint {
                    name: "scala".to_owned(),
                    requirement: "=2.13.16".to_owned(),
                }],
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "org.scala-lang:scala-library".to_owned(),
                    version: Some("=2.13.16".to_owned()),
                }),
                module: None,
                toolchain: Some(NameSelector {
                    name: "scala".to_owned(),
                    version: Some("=2.13.16".to_owned()),
                }),
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
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
            measurement_activation: ActivationSelector {
                package: Some(NameSelector {
                    name: "org.scala-lang:scala-library".to_owned(),
                    version: Some("=2.13.16".to_owned()),
                }),
                module: None,
                toolchain: Some(NameSelector {
                    name: "scala".to_owned(),
                    version: Some("=2.13.16".to_owned()),
                }),
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            },
            measurement_queries: vec![PinnedLookupQuery::Type {
                name: "scala.Any".to_owned(),
            }],
        };
        fs::write(&spec, serde_json::to_vec_pretty(&pinned).unwrap()).unwrap();
        let input = BundleInput {
            spec_path: spec,
            artifact_path: artifact,
        };
        let first = fixture.path().join("first");
        let second = fixture.path().join("second");
        let first_index = generate_release_bundle(&first, std::slice::from_ref(&input)).unwrap();
        let second_index = generate_release_bundle(&second, &[input]).unwrap();
        assert_eq!(first_index, second_index);
        assert_eq!(
            fs::read(first.join("index.json")).unwrap(),
            fs::read(second.join("index.json")).unwrap()
        );
        assert_eq!(
            fs::read(first.join("SHA256SUMS")).unwrap(),
            fs::read(second.join("SHA256SUMS")).unwrap()
        );
        for pack in &first_index.packs {
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
        assert_eq!(verify_release_bundle(&first).unwrap(), first_index);
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
                    artifact_sha256: Some(first_index.packs[0].artifact.sha256.clone()),
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

    fn write_zip(path: &Path, entry_name: &str, source: &str) {
        let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
        writer
            .start_file(entry_name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(source.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
}
