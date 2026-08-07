use super::{
    ActivationSelector, AuthoredSemanticModelPack, Compatibility, Completeness, Provenance, Safety,
};
use crate::CancellationToken;
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
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
    DotNetAssembly,
    RustdocJson,
    GoSourceSet,
    PythonStub,
    PythonSource,
    RubyGemArchive,
    /// One Composer-installed package tree. Composer installs sources rather
    /// than a compiled artifact, so the ecosystem names the input instead of
    /// the language, exactly as `NpmPackageManifest` does.
    ComposerPackageSourceSet,
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
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProduction {
    pub artifact_sha256: Option<String>,
    pub pack: Option<AuthoredSemanticModelPack>,
    pub completeness: Completeness,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: usize,
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
                    code: "artifact.cancelled".to_owned(),
                    location: None,
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

pub(crate) fn read_exact_artifact_while(
    path: &Path,
    limits: &ArtifactProducerLimits,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    let metadata = path.metadata().map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        code: "artifact.metadata".to_owned(),
        location: None,
        message: bounded_message(
            format!("could not inspect exact artifact: {error}"),
            limits.max_diagnostic_message_bytes,
        ),
    })?;
    if !metadata.is_file() {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "artifact.not_file".to_owned(),
            location: None,
            message: "exact artifact path is not a regular file".to_owned(),
        });
    }
    if metadata.len() > limits.max_artifact_bytes {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "limit.artifact_bytes".to_owned(),
            location: None,
            message: bounded_message(
                format!("exact artifact exceeds {} bytes", limits.max_artifact_bytes),
                limits.max_diagnostic_message_bytes,
            ),
        });
    }

    let file = File::open(path).map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        code: "artifact.open".to_owned(),
        location: None,
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
                code: "artifact.cancelled".to_owned(),
                location: None,
                message: "exact artifact read was cancelled".to_owned(),
            });
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|error| ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                code: "artifact.read".to_owned(),
                location: None,
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
            code: "limit.artifact_bytes".to_owned(),
            location: None,
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

    let mut entries = Vec::with_capacity(normalized_paths.len());
    let mut canonical_bytes = Vec::new();
    canonical_bytes.extend_from_slice(b"bifrost.exact-source-set.v1\0");
    canonical_bytes.extend_from_slice(&(normalized_paths.len() as u64).to_le_bytes());
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
        reject_symlink_components(root, &relative, limits)?;
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
        let consumed = canonical_bytes.len() as u64;
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
        canonical_bytes.extend_from_slice(&(normalized.len() as u64).to_le_bytes());
        canonical_bytes.extend_from_slice(normalized.as_bytes());
        canonical_bytes.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        canonical_bytes.extend_from_slice(&bytes);
        entries.push(ExactSourceEntry {
            relative_path: normalized,
            bytes,
        });
    }

    Ok(ExactArtifact {
        path: root.to_path_buf(),
        sha256: lower_hex_string(&sha256_bytes(&canonical_bytes)),
        bytes: canonical_bytes,
        source_entries: entries,
    })
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

fn reject_symlink_components(
    root: &Path,
    relative: &Path,
    limits: &ArtifactProducerLimits,
) -> Result<(), ProducerDiagnostic> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            unreachable!("source path was normalized before symlink validation");
        };
        current.push(segment);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            source_set_diagnostic(
                "artifact.metadata",
                &current,
                format!("could not inspect exact source path component: {error}"),
                limits,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(source_set_diagnostic(
                "artifact.symlink",
                &current,
                "exact source sets cannot contain symlink path components",
                limits,
            ));
        }
    }
    Ok(())
}

fn source_set_diagnostic(
    code: &str,
    path: &Path,
    message: impl Into<String>,
    limits: &ArtifactProducerLimits,
) -> ProducerDiagnostic {
    ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        code: code.to_owned(),
        location: Some(path.to_string_lossy().into_owned()),
        message: bounded_message(message.into(), limits.max_diagnostic_message_bytes),
    }
}

pub struct BoundedProducerDiagnostics {
    diagnostics: Vec<ProducerDiagnostic>,
    suppressed: usize,
    max_diagnostics: usize,
    max_message_bytes: usize,
}

impl BoundedProducerDiagnostics {
    pub fn new(limits: &ArtifactProducerLimits) -> Self {
        Self {
            diagnostics: Vec::new(),
            suppressed: 0,
            max_diagnostics: limits.max_diagnostics,
            max_message_bytes: limits.max_diagnostic_message_bytes,
        }
    }

    pub fn warning(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        self.push(ProducerDiagnosticSeverity::Warning, code, location, message);
    }

    pub fn error(
        &mut self,
        code: impl Into<String>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        self.push(ProducerDiagnosticSeverity::Error, code, location, message);
    }

    fn push(
        &mut self,
        severity: ProducerDiagnosticSeverity,
        code: impl Into<String>,
        location: Option<String>,
        message: impl Into<String>,
    ) {
        if self.diagnostics.len() >= self.max_diagnostics {
            self.suppressed = self.suppressed.saturating_add(1);
            return;
        }
        self.diagnostics.push(ProducerDiagnostic {
            severity,
            code: code.into(),
            location: location.map(|location| bounded_message(location, self.max_message_bytes)),
            message: bounded_message(message.into(), self.max_message_bytes),
        });
    }

    fn push_diagnostic(&mut self, diagnostic: ProducerDiagnostic) {
        self.push(
            diagnostic.severity,
            diagnostic.code,
            diagnostic.location,
            diagnostic.message,
        );
    }

    pub fn finish(self) -> (Vec<ProducerDiagnostic>, usize) {
        (self.diagnostics, self.suppressed)
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty() && self.suppressed == 0
    }
}

fn bounded_message(mut message: String, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn diagnostic_collection_is_count_and_message_bounded() {
        let limits = ArtifactProducerLimits {
            max_diagnostics: 1,
            max_diagnostic_message_bytes: 4,
            ..ArtifactProducerLimits::default()
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(&limits);
        diagnostics.warning("metadata.unsupported", Some("entry".to_owned()), "abcdef");
        diagnostics.error("metadata.invalid", None, "second");
        let (diagnostics, suppressed) = diagnostics.finish();

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].location.as_deref(), Some("entr"));
        assert_eq!(diagnostics[0].message, "abcd");
        assert_eq!(suppressed, 1);

        let failure = ArtifactProduction::failed(
            ProducerDiagnostic {
                severity: ProducerDiagnosticSeverity::Error,
                code: "failure".to_owned(),
                location: Some("unbounded-location".to_owned()),
                message: "unbounded-message".to_owned(),
            },
            &ArtifactProducerLimits {
                max_diagnostics: 0,
                ..limits
            },
        );
        assert!(failure.diagnostics.is_empty());
        assert_eq!(failure.suppressed_diagnostics, 1);
    }
}
