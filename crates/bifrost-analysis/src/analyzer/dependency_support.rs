use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, DependencyPackDiagnostic,
    DependencyPackDiagnosticSeverity, DependencyPackLimits, DependencyPackProduction,
    DependencyProvenance, ExactArtifact, Locator, ProducerDiagnostic, ProducerDiagnosticSeverity,
    SuppressedDiagnostics, read_exact_artifact_while,
};

#[derive(Debug)]
#[doc(hidden)]
pub enum BoundedReadError {
    Io(io::Error),
    LimitExceeded,
}

#[doc(hidden)]
pub fn read_bounded_bytes(reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, BoundedReadError> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::Io)?;
    if bytes.len() as u64 > max_bytes {
        return Err(BoundedReadError::LimitExceeded);
    }
    Ok(bytes)
}

pub fn resolve_dependency_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[doc(hidden)]
pub fn dependency_provenance_entry(key: &str, value: impl ToString) -> DependencyProvenance {
    DependencyProvenance {
        key: key.to_owned(),
        value: value.to_string(),
    }
}

pub(crate) fn dependency_producer_diagnostic(
    path: &Path,
    producer: ProducerDiagnostic,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: match producer.severity {
            ProducerDiagnosticSeverity::Warning => DependencyPackDiagnosticSeverity::Warning,
            ProducerDiagnosticSeverity::Error => DependencyPackDiagnosticSeverity::Error,
        },
        code: producer.code,
        dependency_id: None,
        location: Some(path.to_string_lossy().into_owned()),
        message: producer.message,
    }
}

#[doc(hidden)]
pub fn dependency_diagnostic(
    code: &str,
    path: Option<&Path>,
    message: impl Into<String>,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: code.to_owned(),
        dependency_id: None,
        location: path.map(|value| value.to_string_lossy().into_owned()),
        message: message.into(),
    }
}

#[doc(hidden)]
pub fn require_non_empty_evidence_field(
    ecosystem: &str,
    code: &str,
    field: &str,
    value: &str,
) -> Result<(), DependencyPackDiagnostic> {
    if value.trim().is_empty() {
        return Err(dependency_diagnostic(
            code,
            None,
            format!("{ecosystem} dependency evidence field {field} must not be empty"),
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn cancelled_dependency_evidence_diagnostic(
    ecosystem: &str,
    code: &str,
    path: Option<&Path>,
) -> DependencyPackDiagnostic {
    dependency_diagnostic(
        code,
        path,
        format!("{ecosystem} dependency evidence decoding was cancelled"),
    )
}

#[doc(hidden)]
pub fn read_evidence_file_with_budget(
    ecosystem: &str,
    path: &Path,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<ExactArtifact, DependencyPackDiagnostic> {
    let remaining = limits
        .max_total_artifact_bytes
        .saturating_sub(*evidence_bytes_read);
    if remaining == 0 {
        return Err(dependency_diagnostic(
            "limit.total_artifact_bytes",
            Some(path),
            format!(
                "{ecosystem} dependency evidence exceeds the {} byte aggregate limit",
                limits.max_total_artifact_bytes
            ),
        ));
    }
    let producer_limits = ArtifactProducerLimits {
        max_artifact_bytes: limits.producer.max_artifact_bytes.min(remaining),
        ..limits.producer
    };
    let artifact = read_exact_artifact_while(path, &producer_limits, || {
        cancellation.is_some_and(CancellationToken::is_cancelled)
    })
    .map_err(|producer| {
        let mut diagnostic = dependency_producer_diagnostic(path, producer);
        if diagnostic.code == "limit.artifact_bytes"
            && remaining < limits.producer.max_artifact_bytes
        {
            diagnostic.code = "limit.total_artifact_bytes".to_owned();
            diagnostic.message = format!(
                "{ecosystem} dependency evidence exceeds the {} byte aggregate limit",
                limits.max_total_artifact_bytes
            );
        }
        diagnostic
    })?;
    *evidence_bytes_read = evidence_bytes_read.saturating_add(artifact.bytes().len() as u64);
    Ok(artifact)
}

#[doc(hidden)]
pub fn append_producer_diagnostics(
    bounded: &mut BoundedProducerDiagnostics,
    diagnostics: Vec<ProducerDiagnostic>,
) {
    bounded.absorb(diagnostics);
}

#[doc(hidden)]
pub fn failed_dependency_pack_production(code: &str, message: &str) -> DependencyPackProduction {
    DependencyPackProduction {
        pack: None,
        diagnostics: vec![ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            source_entry: None,
            code: code.to_owned(),
            location: None,
            declaration: None,
            message: message.to_owned(),
        }],
        suppressed_diagnostics: SuppressedDiagnostics::default(),
    }
}

#[doc(hidden)]
pub fn dependency_locator_path(locator: &Locator) -> &str {
    match locator {
        Locator::Source { path, .. }
        | Locator::Artifact { path, .. }
        | Locator::Interchange { path, .. } => path,
    }
}

#[doc(hidden)]
pub fn read_bounded_declaration_file(
    path: &Path,
    max_bytes: u64,
) -> Result<Option<String>, String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not inspect declaration file: {error}")),
    };
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(format!(
            "declaration file is not a regular file within {max_bytes} bytes"
        ));
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("could not read declaration file: {error}"))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{self, Cursor, Read};

    use super::{BoundedReadError, read_bounded_bytes};

    struct CountingReader<'a> {
        inner: Cursor<&'a [u8]>,
        bytes_read: &'a Cell<usize>,
    }

    impl Read for CountingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let bytes_read = self.inner.read(buffer)?;
            self.bytes_read
                .set(self.bytes_read.get().saturating_add(bytes_read));
            Ok(bytes_read)
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4271: Python metadata reads could exceed their configured byte limit"
    )]
    fn bounded_reader_stops_after_one_byte_over_limit() {
        let bytes_read = Cell::new(0);
        let reader = CountingReader {
            inner: Cursor::new(b"metadata"),
            bytes_read: &bytes_read,
        };

        assert!(matches!(
            read_bounded_bytes(reader, 3),
            Err(BoundedReadError::LimitExceeded)
        ));
        assert_eq!(bytes_read.get(), 4);
    }
}
