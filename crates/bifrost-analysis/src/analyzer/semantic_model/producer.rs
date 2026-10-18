use super::dependency::admit_into_full_diagnostics;
use super::validate::is_canonical_relative_path;
use super::{
    ActivationSelector, AuthoredSemanticModelPack, AuthoredShard, Compatibility, Completeness,
    Producer, Provenance, Safety, SuppressedDiagnostics, carried_source_paths,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use crate::analyzer::common::bounded_message;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalArtifactKind {
    NpmPackageManifest,
    TypeScriptDeclarationFile,
    JavaSourceJar,
    JavaClassJar,
    ScalaSourceJar,
    KotlinSourceJar,
    JdkSourceZip,
    JdkJmodSet,
    DotNetAssembly,
    RustdocJson,
    RustdocJsonSet,
    TypeScriptLibrarySet,
    GoSourceSet,
    PythonStub,
    PythonSource,
    RubyGemArchive,
    /// One Composer-installed package tree. Composer installs sources rather
    /// than a compiled artifact, so the ecosystem names the input instead of
    /// the language, exactly as `NpmPackageManifest` does.
    ComposerPackageSourceSet,
    /// One tree of plain PHP declaration stubs: PHP source that states the
    /// runtime's classes, interfaces, constants and functions with native
    /// signatures and empty bodies. Distinct from `ComposerPackageSourceSet`,
    /// which is an installed package's real, executable sources.
    PhpDeclarationStub,
    /// One explicit C++ include root containing exact header sources.
    CppHeaderSourceSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProductionRequest {
    pub path: PathBuf,
    pub artifact_kind: ExternalArtifactKind,
    pub pack_id: String,
    pub pack_version: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub activation: Vec<ActivationSelector>,
    pub provenance: Provenance,
    pub license: String,
    pub safety: Safety,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactProducerLimits {
    pub max_artifact_bytes: u64,
    pub max_records: usize,
    pub max_signature_depth: usize,
    pub max_diagnostics: usize,
    pub max_diagnostic_message_bytes: usize,
}

impl Default for ArtifactProducerLimits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 256 * 1024 * 1024,
            max_records: 250_000,
            max_signature_depth: 64,
            max_diagnostics: 256,
            max_diagnostic_message_bytes: 4 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerDiagnostic {
    pub severity: ProducerDiagnosticSeverity,
    pub code: String,
    pub location: Option<String>,
    /// Stable artifact-relative source entry accountable for a file-level reject.
    pub source_entry: Option<Box<str>>,
    /// Canonical fully-qualified declaration whose extraction failed.
    pub declaration: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProduction {
    pub artifact_sha256: Option<String>,
    pub pack: Option<AuthoredSemanticModelPack>,
    pub completeness: Completeness,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
}

impl ArtifactProduction {
    pub fn failed(diagnostic: ProducerDiagnostic, limits: &ArtifactProducerLimits) -> Self {
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        diagnostics.push_diagnostic(diagnostic);
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        Self {
            artifact_sha256: None,
            pack: None,
            completeness: Completeness::Partial,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

pub(crate) fn failed_artifact_production(
    code: &str,
    message: impl Into<String>,
    limits: &ArtifactProducerLimits,
) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.into(),
        },
        limits,
    )
}

pub(crate) fn finish_authored_pack_production(
    request: &ArtifactProductionRequest,
    artifact_sha256: &str,
    producer_name: &str,
    language: &str,
    diagnostics: Vec<ProducerDiagnostic>,
    suppressed_diagnostics: SuppressedDiagnostics,
    mut shards: Vec<AuthoredShard>,
) -> ArtifactProduction {
    for shard in &mut shards {
        for selector in &mut shard.activation {
            selector.artifact_sha256 = Some(artifact_sha256.to_owned());
        }
    }
    let completeness = if diagnostics.is_empty() && suppressed_diagnostics.total() == 0 {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    let carried_sources = carried_source_paths(&shards);
    let pack = (!shards.is_empty()).then(|| AuthoredSemanticModelPack {
        schema_version: super::SEMANTIC_MODEL_SCHEMA_VERSION,
        pack_id: request.pack_id.clone(),
        version: request.pack_version.clone(),
        producer: Producer {
            name: producer_name.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        language: language.to_owned(),
        ecosystem: request.ecosystem.clone(),
        compatibility: request.compatibility.clone(),
        provenance: request.provenance.clone(),
        license: request.license.clone(),
        completeness,
        safety: request.safety.clone(),
        carried_sources,
        cpp_portability: None,
        python_correspondence: None,
        shards,
    });
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack,
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

pub trait ExternalArtifactPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction;

    fn produce_exact_artifact_with_cancellation(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    source_entry: None,
                    code: "artifact.cancelled".to_owned(),
                    location: None,
                    declaration: None,
                    message: "exact artifact production was cancelled".to_owned(),
                },
                limits,
            );
        }
        self.produce_exact_artifact(request, limits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifact {
    path: PathBuf,
    bytes: Vec<u8>,
    source_entries: Vec<ExactSourceEntry>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSourceEntry {
    relative_path: String,
    bytes: Vec<u8>,
}

impl ExactSourceEntry {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ExactArtifact {
    /// Reconstruct an exact source-set artifact from durable source rows.
    ///
    /// The digest is derived from the normalized paths and bytes. Callers
    /// cannot provide or override it, and the path is used only as diagnostic
    /// context; it never participates in the source identity.
    pub fn from_source_entries(
        path: PathBuf,
        entries: Vec<(String, Vec<u8>)>,
        max_path_depth: usize,
        limits: &ArtifactProducerLimits,
    ) -> Result<Self, ProducerDiagnostic> {
        let mut normalized = entries
            .into_iter()
            .map(|(path, bytes)| {
                let (normalized, _) =
                    normalize_source_set_path(Path::new(&path), max_path_depth, limits)?;
                Ok(ExactSourceEntry {
                    relative_path: normalized,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>, ProducerDiagnostic>>()?;
        if normalized.is_empty() {
            return Err(source_set_diagnostic(
                "artifact.source_set_empty",
                &path,
                "exact source set must contain at least one selected file",
                limits,
            ));
        }
        normalized.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if normalized
            .windows(2)
            .any(|entries| entries[0].relative_path == entries[1].relative_path)
        {
            return Err(source_set_diagnostic(
                "artifact.source_set_duplicate",
                &path,
                "exact source set contains a duplicate normalized path",
                limits,
            ));
        }
        let bytes = canonical_source_set_bytes(&normalized);
        if bytes.len() as u64 > limits.max_artifact_bytes {
            return Err(source_set_diagnostic(
                "limit.artifact_bytes",
                &path,
                format!(
                    "exact source set exceeds {} bytes",
                    limits.max_artifact_bytes
                ),
                limits,
            ));
        }
        let sha256 = lower_hex_string(&sha256_bytes(&bytes));
        Ok(Self {
            path,
            bytes,
            source_entries: normalized,
            sha256,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn source_entries(&self) -> &[ExactSourceEntry] {
        &self.source_entries
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

pub fn read_exact_artifact(
    path: &Path,
    limits: &ArtifactProducerLimits,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    read_exact_artifact_while(path, limits, || false)
}

/// Read an explicitly selected set of files under one root as a single exact
/// artifact with a canonical, enumeration-independent digest.
///
/// Release tooling uses this to pin source-tree inputs such as a Python stub
/// tree the same way a single archive file is pinned.
pub fn read_exact_source_set(
    root: &Path,
    relative_paths: &[PathBuf],
    max_files: usize,
    max_path_depth: usize,
    limits: &ArtifactProducerLimits,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    read_exact_source_set_while(
        root,
        relative_paths,
        max_files,
        max_path_depth,
        limits,
        || false,
    )
}

/// Expand selected sources using dependencies read from the very bytes that
/// will be hashed and produced. Each file is read once; all state belongs to
/// this acquisition. Missing optional dependencies are the resolver's decision,
/// while selected files retain the exact source-set reader's error contract.
pub(crate) fn read_exact_source_closure_while(
    root: &Path,
    seeds: &[PathBuf],
    max_files: usize,
    max_path_depth: usize,
    limits: &ArtifactProducerLimits,
    mut is_cancelled: impl FnMut() -> bool,
    mut dependencies: impl FnMut(&ExactSourceEntry) -> Result<Vec<PathBuf>, ProducerDiagnostic>,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    let mut pending = BTreeSet::new();
    for seed in seeds {
        pending.insert(normalize_source_set_path(seed, max_path_depth, limits)?.0);
        if pending.len() > max_files {
            return Err(source_set_diagnostic(
                "limit.source_files",
                root,
                format!("exact source closure exceeds {max_files} selected files"),
                limits,
            ));
        }
    }
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    let mut consumed = 0_u64;
    while let Some(relative) = pending.pop_first() {
        assert!(visited.insert(relative.clone()));
        let remaining_limits = ArtifactProducerLimits {
            max_artifact_bytes: limits.max_artifact_bytes.saturating_sub(consumed),
            ..*limits
        };
        let artifact = read_exact_source_set_while(
            root,
            &[PathBuf::from(relative)],
            1,
            max_path_depth,
            &remaining_limits,
            &mut is_cancelled,
        )?;
        let mut acquired = artifact.source_entries;
        let entry = acquired
            .pop()
            .expect("one selected file yields one exact source entry");
        assert!(acquired.is_empty());
        for dependency in dependencies(&entry)? {
            let (relative, _) = normalize_source_set_path(&dependency, max_path_depth, limits)?;
            if !visited.contains(&relative) {
                pending.insert(relative);
                if visited.len() + pending.len() > max_files {
                    return Err(source_set_diagnostic(
                        "limit.source_files",
                        root,
                        format!("exact source closure exceeds {max_files} selected files"),
                        limits,
                    ));
                }
            }
        }
        // Keep the shared source-set header in every remaining read budget;
        // only entry framing and content have already consumed that budget.
        consumed += 16 + entry.relative_path.len() as u64 + entry.bytes.len() as u64;
        entries.push((entry.relative_path, entry.bytes));
    }
    if is_cancelled() {
        return Err(source_set_diagnostic(
            "artifact.cancelled",
            root,
            "exact source closure read was cancelled",
            limits,
        ));
    }
    ExactArtifact::from_source_entries(root.to_owned(), entries, max_path_depth, limits)
}

pub(crate) fn read_exact_artifact_while(
    path: &Path,
    limits: &ArtifactProducerLimits,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    let metadata = path.metadata().map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        source_entry: None,
        code: "artifact.metadata".to_owned(),
        location: None,
        declaration: None,
        message: bounded_message(
            format!("could not inspect exact artifact: {error}"),
            limits.max_diagnostic_message_bytes,
        ),
    })?;
    if !metadata.is_file() {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: "artifact.not_file".to_owned(),
            location: None,
            declaration: None,
            message: "exact artifact path is not a regular file".to_owned(),
        });
    }
    if metadata.len() > limits.max_artifact_bytes {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: "limit.artifact_bytes".to_owned(),
            location: None,
            declaration: None,
            message: bounded_message(
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
                limits.max_diagnostic_message_bytes,
            ),
        });
    }

    let file = File::open(path).map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        source_entry: None,
        code: "artifact.open".to_owned(),
        location: None,
        declaration: None,
        message: bounded_message(
            format!("could not open exact artifact: {error}"),
            limits.max_diagnostic_message_bytes,
        ),
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut reader = file.take(limits.max_artifact_bytes.saturating_add(1));
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if is_cancelled() {
            return Err(ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                source_entry: None,
                code: "artifact.cancelled".to_owned(),
                location: None,
                declaration: None,
                message: "exact artifact read was cancelled".to_owned(),
            });
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|error| ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                source_entry: None,
                code: "artifact.read".to_owned(),
                location: None,
                declaration: None,
                message: bounded_message(
                    format!("could not read exact artifact: {error}"),
                    limits.max_diagnostic_message_bytes,
                ),
            })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() as u64 > limits.max_artifact_bytes {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: "limit.artifact_bytes".to_owned(),
            location: None,
            declaration: None,
            message: bounded_message(
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
                limits.max_diagnostic_message_bytes,
            ),
        });
    }

    Ok(ExactArtifact {
        path: path.to_path_buf(),
        sha256: lower_hex_string(&sha256_bytes(&bytes)),
        bytes,
        source_entries: Vec::new(),
    })
}

pub(crate) fn read_exact_source_set_while(
    root: &Path,
    relative_paths: &[PathBuf],
    max_files: usize,
    max_path_depth: usize,
    limits: &ArtifactProducerLimits,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    if relative_paths.is_empty() {
        return Err(source_set_diagnostic(
            "artifact.source_set_empty",
            root,
            "exact source set must contain at least one selected file",
            limits,
        ));
    }
    if relative_paths.len() > max_files {
        return Err(source_set_diagnostic(
            "limit.source_files",
            root,
            format!("exact source set exceeds {max_files} selected files"),
            limits,
        ));
    }
    let root_metadata = std::fs::symlink_metadata(root).map_err(|error| {
        source_set_diagnostic(
            "artifact.metadata",
            root,
            format!("could not inspect exact source-set root: {error}"),
            limits,
        )
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(source_set_diagnostic(
            "artifact.source_set_root",
            root,
            "exact source-set root must be a real directory",
            limits,
        ));
    }
    let canonical_root = root.canonicalize().map_err(|error| {
        source_set_diagnostic(
            "artifact.canonicalize",
            root,
            format!("could not canonicalize exact source-set root: {error}"),
            limits,
        )
    })?;

    let mut normalized_paths = relative_paths
        .iter()
        .map(|path| normalize_source_set_path(path, max_path_depth, limits))
        .collect::<Result<Vec<_>, _>>()?;
    normalized_paths.sort_by(|left, right| left.0.cmp(&right.0));
    if normalized_paths
        .windows(2)
        .any(|paths| paths[0].0 == paths[1].0)
    {
        return Err(source_set_diagnostic(
            "artifact.source_set_duplicate",
            root,
            "exact source set contains a duplicate normalized path",
            limits,
        ));
    }

    let selected_path_count = normalized_paths.len();
    let mut entries = Vec::with_capacity(selected_path_count);
    for (normalized, relative) in normalized_paths {
        if is_cancelled() {
            return Err(source_set_diagnostic(
                "artifact.cancelled",
                root,
                "exact source-set read was cancelled",
                limits,
            ));
        }
        let path = root.join(&relative);
        source_set_path_exists(root, &relative, limits)?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            source_set_diagnostic(
                "artifact.metadata",
                &path,
                format!("could not inspect exact source file: {error}"),
                limits,
            )
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(source_set_diagnostic(
                "artifact.source_file",
                &path,
                "selected source path must be a real regular file",
                limits,
            ));
        }
        let canonical_path = path.canonicalize().map_err(|error| {
            source_set_diagnostic(
                "artifact.canonicalize",
                &path,
                format!("could not canonicalize selected source file: {error}"),
                limits,
            )
        })?;
        if !canonical_path.starts_with(&canonical_root) {
            return Err(source_set_diagnostic(
                "artifact.path_escape",
                &path,
                "selected source path escapes the exact source-set root",
                limits,
            ));
        }
        let consumed = entries
            .iter()
            .map(|entry: &ExactSourceEntry| {
                16_u64
                    .saturating_add(entry.relative_path.len() as u64)
                    .saturating_add(entry.bytes.len() as u64)
            })
            .sum::<u64>()
            .saturating_add(36);
        let framing_bytes = 16_u64.saturating_add(normalized.len() as u64);
        let remaining = limits
            .max_artifact_bytes
            .saturating_sub(consumed.saturating_add(framing_bytes));
        if metadata.len() > remaining {
            return Err(source_set_diagnostic(
                "limit.artifact_bytes",
                &path,
                format!(
                    "exact source set exceeds {} bytes",
                    limits.max_artifact_bytes
                ),
                limits,
            ));
        }
        let mut file = File::open(&path).map_err(|error| {
            source_set_diagnostic(
                "artifact.open",
                &path,
                format!("could not open exact source file: {error}"),
                limits,
            )
        })?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            if is_cancelled() {
                return Err(source_set_diagnostic(
                    "artifact.cancelled",
                    &path,
                    "exact source-set read was cancelled",
                    limits,
                ));
            }
            let read = file.read(&mut buffer).map_err(|error| {
                source_set_diagnostic(
                    "artifact.read",
                    &path,
                    format!("could not read exact source file: {error}"),
                    limits,
                )
            })?;
            if read == 0 {
                break;
            }
            if bytes.len().saturating_add(read) as u64 > remaining {
                return Err(source_set_diagnostic(
                    "limit.artifact_bytes",
                    &path,
                    format!(
                        "exact source set exceeds {} bytes",
                        limits.max_artifact_bytes
                    ),
                    limits,
                ));
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        entries.push(ExactSourceEntry {
            relative_path: normalized,
            bytes,
        });
    }

    ExactArtifact::from_source_entries(
        root.to_path_buf(),
        entries
            .into_iter()
            .map(|entry| (entry.relative_path, entry.bytes))
            .collect(),
        max_path_depth,
        limits,
    )
}

fn canonical_source_set_bytes(entries: &[ExactSourceEntry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"bifrost.exact-source-set.v1\0");
    bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&(entry.relative_path.len() as u64).to_le_bytes());
        bytes.extend_from_slice(entry.relative_path.as_bytes());
        bytes.extend_from_slice(&(entry.bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&entry.bytes);
    }
    bytes
}

fn normalize_source_set_path(
    path: &Path,
    max_path_depth: usize,
    limits: &ArtifactProducerLimits,
) -> Result<(String, PathBuf), ProducerDiagnostic> {
    let mut normalized = String::new();
    let mut relative = PathBuf::new();
    let mut depth = 0_usize;
    for component in path.components() {
        let Component::Normal(segment) = component else {
            return Err(source_set_diagnostic(
                "artifact.source_path",
                path,
                "selected source paths must be relative and cannot contain parent traversal",
                limits,
            ));
        };
        depth += 1;
        if depth > max_path_depth {
            return Err(source_set_diagnostic(
                "limit.source_path_depth",
                path,
                format!("selected source path exceeds depth {max_path_depth}"),
                limits,
            ));
        }
        let segment = segment.to_str().ok_or_else(|| {
            source_set_diagnostic(
                "artifact.path_encoding",
                path,
                "selected source path is not valid UTF-8",
                limits,
            )
        })?;
        if segment.is_empty() {
            return Err(source_set_diagnostic(
                "artifact.source_path",
                path,
                "selected source path contains an empty segment",
                limits,
            ));
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(segment);
        relative.push(segment);
    }
    if depth == 0 {
        return Err(source_set_diagnostic(
            "artifact.source_path",
            path,
            "selected source path must not be empty",
            limits,
        ));
    }
    Ok((normalized, relative))
}

/// Probe an optional source without following symlinks or hiding I/O errors.
/// Inspect parents even when the leaf is missing, so dangling symlinks cannot
/// masquerade as unresolved dependencies.
pub(crate) fn source_set_path_exists(
    root: &Path,
    relative: &Path,
    limits: &ArtifactProducerLimits,
) -> Result<bool, ProducerDiagnostic> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(source_set_diagnostic(
                "artifact.source_path",
                relative,
                "selected source paths must be relative and cannot contain parent traversal",
                limits,
            ));
        };
        current.push(segment);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(source_set_diagnostic(
                    "artifact.metadata",
                    &current,
                    format!("could not inspect exact source path component: {error}"),
                    limits,
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(source_set_diagnostic(
                "artifact.symlink",
                &current,
                "exact source sets cannot contain symlink path components",
                limits,
            ));
        }
    }
    Ok(true)
}

pub(crate) fn source_set_diagnostic(
    code: &str,
    path: &Path,
    message: impl Into<String>,
    limits: &ArtifactProducerLimits,
) -> ProducerDiagnostic {
    ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        source_entry: None,
        code: code.to_owned(),
        location: Some(path.to_string_lossy().into_owned()),
        declaration: None,
        message: bounded_message(message.into(), limits.max_diagnostic_message_bytes),
    }
}

pub struct BoundedProducerDiagnostics {
    diagnostics: Vec<ProducerDiagnostic>,
    suppressed: SuppressedDiagnostics,
    max_diagnostics: usize,
    max_message_bytes: usize,
}

impl BoundedProducerDiagnostics {
    pub fn new(limits: &ArtifactProducerLimits) -> Self {
        Self {
            diagnostics: Vec::new(),
            suppressed: SuppressedDiagnostics::default(),
            max_diagnostics: limits.max_diagnostics,
            max_message_bytes: limits.max_diagnostic_message_bytes,
        }
    }

    /// A set that retains every diagnostic it is given.
    ///
    /// A producer that cannot bound diagnostics as it goes - one that splits
    /// its work across workers and only knows the artifact-wide arrival order
    /// once the work is done - collects each worker's diagnostics in one of
    /// these, then folds the batches into the artifact's single bounded set in
    /// arrival order ([`Self::absorb`]). Nothing is dropped on the way in, so
    /// the bounded set makes every retention decision exactly once, in the
    /// order it would have seen the diagnostics in a single pass. The message
    /// bound still applies, and it is idempotent, so folding a batch does not
    /// truncate a message twice.
    pub fn unbounded(limits: &ArtifactProducerLimits) -> Self {
        Self {
            diagnostics: Vec::new(),
            suppressed: SuppressedDiagnostics::default(),
            max_diagnostics: usize::MAX,
            max_message_bytes: limits.max_diagnostic_message_bytes,
        }
    }

    /// Take every diagnostic retained so far, in arrival order.
    ///
    /// The set keeps collecting afterwards, so a producer cuts its work into
    /// batches at the points where the artifact-wide order has to be
    /// reconstructed.
    pub fn take_retained(&mut self) -> Vec<ProducerDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub fn warning(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        self.warning_for_source_entry(code, location, None, message);
    }

    pub fn warning_for_declaration(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        declaration: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.push(
            ProducerDiagnosticSeverity::Warning,
            code,
            location,
            None,
            Some(declaration.into()),
            message,
        );
    }

    /// Record a warning whose accountable subject is one artifact source entry.
    ///
    /// The source entry is identity, not display text, so an invalid or
    /// over-limit value is dropped and the warning remains anonymous. That
    /// keeps downstream activation fail-closed instead of accounting for a
    /// truncated or rewritten path.
    pub fn warning_for_source_entry(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        source_entry: Option<String>,
        message: impl Into<String>,
    ) {
        self.push(
            ProducerDiagnosticSeverity::Warning,
            code,
            location,
            source_entry,
            None,
            message,
        );
    }

    pub fn error(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        self.push(
            ProducerDiagnosticSeverity::Error,
            code,
            location,
            None,
            None,
            message,
        );
    }

    fn push(
        &mut self,
        severity: ProducerDiagnosticSeverity,
        code: impl Into<String>,
        location: Option<String>,
        source_entry: Option<String>,
        declaration: Option<String>,
        message: impl Into<String>,
    ) {
        if self.diagnostics.len() >= self.max_diagnostics
            && !admit_into_full_diagnostics(
                &mut self.diagnostics,
                &mut self.suppressed,
                severity == ProducerDiagnosticSeverity::Warning,
                |retained| retained.severity == ProducerDiagnosticSeverity::Warning,
            )
        {
            return;
        }
        self.diagnostics.push(ProducerDiagnostic {
            severity,
            code: code.into(),
            location: location.map(|location| bounded_message(location, self.max_message_bytes)),
            source_entry: source_entry
                .filter(|entry| {
                    !entry.is_empty()
                        && entry.len() <= self.max_message_bytes
                        && is_canonical_relative_path(entry)
                })
                .map(String::into_boxed_str),
            declaration: declaration
                .map(|declaration| bounded_message(declaration, self.max_message_bytes)),
            message: bounded_message(message.into(), self.max_message_bytes),
        });
    }

    fn push_diagnostic(&mut self, diagnostic: ProducerDiagnostic) {
        self.push(
            diagnostic.severity,
            diagnostic.code,
            diagnostic.location,
            diagnostic.source_entry.map(String::from),
            diagnostic.declaration,
            diagnostic.message,
        );
    }

    pub fn finish(self) -> (Vec<ProducerDiagnostic>, SuppressedDiagnostics) {
        (self.diagnostics, self.suppressed)
    }

    /// Fold a batch of diagnostics produced elsewhere into this set, in
    /// arrival order.
    ///
    /// The batch must come from an unbounded set ([`Self::unbounded`]), which
    /// drops nothing, so this set makes the retention decision for every
    /// diagnostic of the batch exactly as it would for one arriving directly.
    pub fn absorb(&mut self, diagnostics: Vec<ProducerDiagnostic>) {
        for diagnostic in diagnostics {
            self.push_diagnostic(diagnostic);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty() && self.suppressed.total() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::cell::Cell;
    use std::io::Write;

    #[test]
    fn exact_artifact_reader_hashes_bounded_bytes() {
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(b"artifact").unwrap();
        let artifact = read_exact_artifact(
            temp.path(),
            &ArtifactProducerLimits {
                max_artifact_bytes: 8,
                ..ArtifactProducerLimits::default()
            },
        )
        .unwrap();

        assert_eq!(artifact.path(), temp.path());
        assert_eq!(artifact.bytes(), b"artifact");
        assert_eq!(
            artifact.sha256(),
            lower_hex_string(&sha256_bytes(b"artifact"))
        );
        assert_eq!(
            read_exact_artifact(
                temp.path(),
                &ArtifactProducerLimits {
                    max_artifact_bytes: 7,
                    ..ArtifactProducerLimits::default()
                }
            )
            .unwrap_err()
            .code,
            "limit.artifact_bytes"
        );
    }

    #[test]
    fn exact_artifact_reader_can_cancel_between_chunks() {
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&vec![b'x'; 128 * 1024]).unwrap();
        let checks = Cell::new(0);

        let diagnostic =
            read_exact_artifact_while(temp.path(), &ArtifactProducerLimits::default(), || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            })
            .unwrap_err();

        assert_eq!(diagnostic.code, "artifact.cancelled");
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn exact_source_set_is_mount_and_enumeration_independent() {
        fn fixture() -> tempfile::TempDir {
            let temp = tempfile::tempdir().unwrap();
            std::fs::create_dir(temp.path().join("pkg")).unwrap();
            std::fs::write(
                temp.path().join("pkg/a.go"),
                b"package pkg\ntype A struct{}\n",
            )
            .unwrap();
            std::fs::write(temp.path().join("pkg/b.go"), b"package pkg\nfunc B() {}\n").unwrap();
            temp
        }

        let first_root = fixture();
        let second_root = fixture();
        let limits = ArtifactProducerLimits::default();
        let first = read_exact_source_set_while(
            first_root.path(),
            &[PathBuf::from("pkg/b.go"), PathBuf::from("pkg/a.go")],
            10,
            8,
            &limits,
            || false,
        )
        .unwrap();
        let second = read_exact_source_set_while(
            second_root.path(),
            &[PathBuf::from("pkg/a.go"), PathBuf::from("pkg/b.go")],
            10,
            8,
            &limits,
            || false,
        )
        .unwrap();

        assert_eq!(first.sha256(), second.sha256());
        assert_eq!(first.bytes(), second.bytes());
        assert_eq!(
            first
                .source_entries()
                .iter()
                .map(ExactSourceEntry::relative_path)
                .collect::<Vec<_>>(),
            ["pkg/a.go", "pkg/b.go"]
        );
        assert_ne!(first.path(), second.path());
    }

    #[test]
    fn exact_source_set_rejects_escape_duplicates_and_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.go"), b"package fixture\n").unwrap();
        let limits = ArtifactProducerLimits::default();

        let escape = read_exact_source_set_while(
            temp.path(),
            &[PathBuf::from("../a.go")],
            10,
            8,
            &limits,
            || false,
        )
        .unwrap_err();
        assert_eq!(escape.code, "artifact.source_path");

        let duplicate = read_exact_source_set_while(
            temp.path(),
            &[PathBuf::from("a.go"), PathBuf::from("a.go")],
            10,
            8,
            &limits,
            || false,
        )
        .unwrap_err();
        assert_eq!(duplicate.code, "artifact.source_set_duplicate");

        let cancelled = read_exact_source_set_while(
            temp.path(),
            &[PathBuf::from("a.go")],
            10,
            8,
            &limits,
            || true,
        )
        .unwrap_err();
        assert_eq!(cancelled.code, "artifact.cancelled");
    }

    #[test]
    #[hardwon("#2876: producer diagnostic cap failed to retain errors and bound messages")]
    fn diagnostic_collection_is_count_and_message_bounded() {
        let limits = ArtifactProducerLimits {
            max_diagnostics: 1,
            max_diagnostic_message_bytes: 4,
            ..ArtifactProducerLimits::default()
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        diagnostics.warning("metadata.unsupported", Some("entry".to_owned()), "abcdef");
        let (bounded, suppressed) = diagnostics.finish();

        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0].location.as_deref(), Some("entr"));
        assert_eq!(bounded[0].message, "abcd");
        assert_eq!(suppressed, SuppressedDiagnostics::default());

        // An error arriving at a full collector evicts the last retained
        // warning and takes its slot, so the failure stays visible (#2876).
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        diagnostics.warning("metadata.unsupported", Some("entry".to_owned()), "abcdef");
        diagnostics.error("metadata.invalid", None, "second");
        let (bounded, suppressed) = diagnostics.finish();

        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0].code, "metadata.invalid");
        assert_eq!(bounded[0].message, "seco");
        assert_eq!(
            suppressed,
            SuppressedDiagnostics {
                warnings: 1,
                errors: 0
            }
        );

        let failure = ArtifactProduction::failed(
            ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                source_entry: None,
                code: "failure".to_owned(),
                location: Some("unbounded-location".to_owned()),
                declaration: None,
                message: "unbounded-message".to_owned(),
            },
            &ArtifactProducerLimits {
                max_diagnostics: 0,
                ..limits
            },
        );
        assert!(failure.diagnostics.is_empty());
        assert_eq!(
            failure.suppressed_diagnostics,
            SuppressedDiagnostics {
                warnings: 0,
                errors: 1
            }
        );
    }

    #[test]
    #[hardwon("#2761: rejected source paths could be mistaken for exact entry identity")]
    fn source_entry_identity_is_kept_exact_or_left_anonymous() {
        let limits = ArtifactProducerLimits {
            max_diagnostic_message_bytes: 16,
            ..ArtifactProducerLimits::default()
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        diagnostics.warning_for_source_entry(
            "source.parse",
            Some("display location".to_owned()),
            Some("src/example.kt".to_owned()),
            "unsupported syntax",
        );
        diagnostics.warning_for_source_entry(
            "source.parse",
            Some("../example.kt".to_owned()),
            Some("../example.kt".to_owned()),
            "unsupported syntax",
        );
        diagnostics.warning_for_source_entry(
            "source.parse",
            Some("long/example.kt".to_owned()),
            Some("a-very-long-source-entry-path".to_owned()),
            "path exceeds the identity budget",
        );
        let (diagnostics, suppressed) = diagnostics.finish();

        assert_eq!(diagnostics.len(), 3);
        assert_eq!(suppressed, SuppressedDiagnostics::default());
        assert_eq!(
            diagnostics[0].source_entry.as_deref(),
            Some("src/example.kt")
        );
        assert_eq!(diagnostics[0].location.as_deref(), Some("display location"));
        assert_eq!(diagnostics[0].declaration, None);
        assert_eq!(diagnostics[1].source_entry, None);
        assert_eq!(diagnostics[2].source_entry, None);
    }
}
