use super::{
    ActivationSelector, AuthoredSemanticModelPack, Compatibility, Completeness, Provenance, Safety,
};
use crate::analyzer::canonical_hash::{lower_hex_string, sha256_bytes};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalArtifactKind {
    JavaSourceJar,
    JavaClassJar,
    DotNetAssembly,
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
    pub fn failed(diagnostic: ProducerDiagnostic) -> Self {
        Self {
            artifact_sha256: None,
            pack: None,
            completeness: Completeness::Partial,
            diagnostics: vec![diagnostic],
            suppressed_diagnostics: 0,
        }
    }
}

pub trait ExternalArtifactPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifact {
    path: PathBuf,
    bytes: Vec<u8>,
    sha256: String,
}

impl ExactArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

pub fn read_exact_artifact(
    path: &Path,
    max_artifact_bytes: u64,
) -> Result<ExactArtifact, ProducerDiagnostic> {
    let metadata = path.metadata().map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        code: "artifact.metadata".to_owned(),
        location: None,
        message: bounded_message(
            format!("could not inspect exact artifact: {error}"),
            ArtifactProducerLimits::default().max_diagnostic_message_bytes,
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
    if metadata.len() > max_artifact_bytes {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "limit.artifact_bytes".to_owned(),
            location: None,
            message: format!("exact artifact exceeds {max_artifact_bytes} bytes"),
        });
    }

    let file = File::open(path).map_err(|error| ProducerDiagnostic {
        severity: ProducerDiagnosticSeverity::Error,
        code: "artifact.open".to_owned(),
        location: None,
        message: bounded_message(
            format!("could not open exact artifact: {error}"),
            ArtifactProducerLimits::default().max_diagnostic_message_bytes,
        ),
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_artifact_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "artifact.read".to_owned(),
            location: None,
            message: bounded_message(
                format!("could not read exact artifact: {error}"),
                ArtifactProducerLimits::default().max_diagnostic_message_bytes,
            ),
        })?;
    if bytes.len() as u64 > max_artifact_bytes {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "limit.artifact_bytes".to_owned(),
            location: None,
            message: format!("exact artifact exceeds {max_artifact_bytes} bytes"),
        });
    }

    Ok(ExactArtifact {
        path: path.to_path_buf(),
        sha256: lower_hex_string(&sha256_bytes(&bytes)),
        bytes,
    })
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
            location,
            message: bounded_message(message.into(), self.max_message_bytes),
        });
    }

    pub fn finish(self) -> (Vec<ProducerDiagnostic>, usize) {
        (self.diagnostics, self.suppressed)
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
    use std::io::Write;

    #[test]
    fn exact_artifact_reader_hashes_bounded_bytes() {
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(b"artifact").unwrap();
        let artifact = read_exact_artifact(temp.path(), 8).unwrap();

        assert_eq!(artifact.path(), temp.path());
        assert_eq!(artifact.bytes(), b"artifact");
        assert_eq!(
            artifact.sha256(),
            lower_hex_string(&sha256_bytes(b"artifact"))
        );
        assert_eq!(
            read_exact_artifact(temp.path(), 7).unwrap_err().code,
            "limit.artifact_bytes"
        );
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
        assert_eq!(diagnostics[0].message, "abcd");
        assert_eq!(suppressed, 1);
    }
}
