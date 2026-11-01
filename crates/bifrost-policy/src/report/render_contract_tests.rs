use std::io::{self, Write};

use super::PolicyReportDocument;
use crate::render::{PolicyRenderError, write_policy_json};
use crate::{
    PolicyDiagnosticSeverity, PolicyReportDiagnostic, PolicyReportDiagnosticCode,
    PolicySourceIdentity,
};

fn empty_report() -> PolicyReportDocument {
    PolicyReportDocument::try_new(vec![], vec![], vec![], false, 0, None).unwrap()
}

#[test]
fn canonical_report_rejects_future_schema_with_actual_version() {
    let report = empty_report();
    let mut bytes = Vec::new();
    write_policy_json(&report, &mut bytes, usize::MAX).unwrap();

    let mut future = report;
    future.schema_version = PolicyReportDocument::SCHEMA_VERSION + 1;
    assert!(matches!(
        write_policy_json(&future, Vec::new(), usize::MAX),
        Err(PolicyRenderError::UnsupportedSchemaVersion { actual })
            if actual == future.schema_version
    ));
}

#[test]
fn canonical_report_preserves_carriage_return_and_unicode() {
    let original = "\r\"\\\u{1F600}";
    let diagnostic = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "load failed",
        Some(PolicySourceIdentity::new(original)),
        None,
        vec![],
    )
    .unwrap();
    let report =
        PolicyReportDocument::try_new(vec![], vec![], vec![diagnostic], false, 0, None).unwrap();
    let mut bytes = Vec::new();
    write_policy_json(&report, &mut bytes, usize::MAX).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("\\u000D\\\"\\\\😀"));
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, serde_json::to_value(&report).unwrap());
}

struct StopsWriting {
    kind: io::ErrorKind,
    attempted: bool,
    bytes: Vec<u8>,
}

impl Write for StopsWriting {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.attempted {
            self.attempted = true;
            return if self.kind == io::ErrorKind::WriteZero {
                Ok(0)
            } else {
                Err(self.kind.into())
            };
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn canonical_report_retries_interrupted_output() {
    let mut sink = StopsWriting {
        kind: io::ErrorKind::Interrupted,
        attempted: false,
        bytes: Vec::new(),
    };
    let written = write_policy_json(&empty_report(), &mut sink, usize::MAX).unwrap();
    assert_eq!(written as usize, sink.bytes.len());
    assert!(serde_json::from_slice::<serde_json::Value>(&sink.bytes).is_ok());
}

#[test]
fn canonical_report_rejects_zero_byte_output() {
    let mut sink = StopsWriting {
        kind: io::ErrorKind::WriteZero,
        attempted: false,
        bytes: Vec::new(),
    };
    assert!(matches!(
        write_policy_json(&empty_report(), &mut sink, usize::MAX),
        Err(PolicyRenderError::Output(error)) if error.kind() == io::ErrorKind::WriteZero
    ));
}
