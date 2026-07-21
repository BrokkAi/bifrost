//! Bounded renderers for the canonical policy report document.
//!
//! Renderers in this module deliberately accept only [`PolicyReportDocument`].
//! Query rows and adapter-owned solver values must first pass through the
//! evaluator and report builder, which keeps all output formats on the same
//! canonical contract.

mod human;
mod sarif;

use std::fmt;
use std::io::{self, Write};

use serde::Serialize;
use serde_json::error::Category;
use serde_json::ser::{CharEscape, Formatter};

use super::PolicyReportDocument;

pub use human::{
    EscapedTerminalText, HumanRenderColor, HumanRenderDetail, HumanRenderOptions,
    escape_terminal_text, write_policy_human,
};
pub use sarif::{SarifToolIdentity, write_policy_sarif};

/// A policy report could not be rendered or written.
#[derive(Debug)]
pub enum PolicyRenderError {
    /// The report uses a schema version this renderer does not implement.
    UnsupportedSchemaVersion { actual: u32 },
    /// The next encoded write would exceed the configured output bound.
    SerializedReportLimit { max_serialized_bytes: usize },
    /// A canonical model value could not be encoded.
    Serialization(serde_json::Error),
    /// A renderer observed a relationship forbidden by canonical construction.
    InvalidCanonicalReport { detail: &'static str },
    /// The destination rejected an otherwise valid encoded report.
    Output(io::Error),
}

impl fmt::Display for PolicyRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { actual } => write!(
                formatter,
                "policy report schema version {actual} is not supported by this renderer"
            ),
            Self::SerializedReportLimit {
                max_serialized_bytes,
            } => write!(
                formatter,
                "serialized policy report exceeds the {max_serialized_bytes}-byte output limit"
            ),
            Self::Serialization(error) => {
                write!(formatter, "policy report encoding failed: {error}")
            }
            Self::InvalidCanonicalReport { detail } => {
                write!(formatter, "invalid canonical policy report: {detail}")
            }
            Self::Output(error) => write!(formatter, "policy report output failed: {error}"),
        }
    }
}

impl std::error::Error for PolicyRenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            Self::Output(error) => Some(error),
            Self::UnsupportedSchemaVersion { .. }
            | Self::SerializedReportLimit { .. }
            | Self::InvalidCanonicalReport { .. } => None,
        }
    }
}

/// Write the exact canonical report model as compact, deterministic JSON.
///
/// Control and bidirectional-control characters are always represented with
/// explicit `\\uXXXX` escapes. Serialization streams directly into the
/// bounded destination and never materializes a `serde_json::Value` or an
/// encoded report string.
pub fn write_policy_json<W: Write>(
    report: &PolicyReportDocument,
    output: W,
    max_serialized_bytes: usize,
) -> Result<u64, PolicyRenderError> {
    ensure_supported_schema(report)?;
    let mut output = BoundedWriter::new(output, max_serialized_bytes);
    let serialized = {
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut output, CanonicalJsonFormatter);
        report.serialize(&mut serializer)
    };
    if let Err(error) = serialized {
        if output.limit_exceeded() {
            return Err(PolicyRenderError::SerializedReportLimit {
                max_serialized_bytes,
            });
        }
        return Err(map_json_error(error, max_serialized_bytes));
    }
    output.flush().map_err(map_io_error)?;
    Ok(output.bytes_written())
}

pub(crate) fn ensure_supported_schema(
    report: &PolicyReportDocument,
) -> Result<(), PolicyRenderError> {
    if report.schema_version() != PolicyReportDocument::SCHEMA_VERSION {
        return Err(PolicyRenderError::UnsupportedSchemaVersion {
            actual: report.schema_version(),
        });
    }
    Ok(())
}

/// A writer that refuses an entire next write before it can cross its bound.
///
/// The byte count is the encoded byte count seen by the destination. In
/// particular, JSON and SARIF count bytes after string escaping.
pub(crate) struct BoundedWriter<W> {
    inner: W,
    max_serialized_bytes: usize,
    bytes_written: usize,
    limit_exceeded: bool,
}

impl<W> BoundedWriter<W> {
    pub(crate) const fn new(inner: W, max_serialized_bytes: usize) -> Self {
        Self {
            inner,
            max_serialized_bytes,
            bytes_written: 0,
            limit_exceeded: false,
        }
    }

    pub(crate) fn bytes_written(&self) -> u64 {
        u64::try_from(self.bytes_written).unwrap_or(u64::MAX)
    }

    pub(crate) const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }

    fn preflight(&mut self, byte_count: usize) -> io::Result<usize> {
        match self
            .bytes_written
            .checked_add(byte_count)
            .filter(|next| *next <= self.max_serialized_bytes)
        {
            Some(next) => Ok(next),
            None => {
                self.limit_exceeded = true;
                Err(serialized_limit_error(self.max_serialized_bytes))
            }
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.preflight(bytes.len())?;
        let written = self.inner.write(bytes)?;
        debug_assert!(written <= bytes.len());
        self.bytes_written = if written == bytes.len() {
            next
        } else {
            self.bytes_written.saturating_add(written)
        };
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.preflight(bytes.len())?;
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match self.inner.write(remaining) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => {
                    self.bytes_written = self.bytes_written.saturating_add(written);
                    remaining = &remaining[written..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SerializedLimitMarker {
    max_serialized_bytes: usize,
}

impl fmt::Display for SerializedLimitMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "serialized report exceeds {} bytes",
            self.max_serialized_bytes
        )
    }
}

impl std::error::Error for SerializedLimitMarker {}

fn serialized_limit_error(max_serialized_bytes: usize) -> io::Error {
    io::Error::other(SerializedLimitMarker {
        max_serialized_bytes,
    })
}

pub(crate) fn map_io_error(error: io::Error) -> PolicyRenderError {
    if let Some(marker) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<SerializedLimitMarker>())
    {
        PolicyRenderError::SerializedReportLimit {
            max_serialized_bytes: marker.max_serialized_bytes,
        }
    } else {
        PolicyRenderError::Output(error)
    }
}

pub(crate) fn map_json_error(
    error: serde_json::Error,
    max_serialized_bytes: usize,
) -> PolicyRenderError {
    if error_chain_has_serialized_limit(&error) {
        return PolicyRenderError::SerializedReportLimit {
            max_serialized_bytes,
        };
    }
    if error.classify() == Category::Io {
        PolicyRenderError::Output(error.into())
    } else {
        PolicyRenderError::Serialization(error)
    }
}

fn error_chain_has_serialized_limit(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(candidate) = current {
        if candidate.downcast_ref::<SerializedLimitMarker>().is_some()
            || candidate
                .downcast_ref::<io::Error>()
                .and_then(io::Error::get_ref)
                .is_some_and(|source| source.downcast_ref::<SerializedLimitMarker>().is_some())
        {
            return true;
        }
        current = candidate.source();
    }
    false
}

/// Compact JSON with explicit escapes for every terminal-control character.
pub(crate) struct CanonicalJsonFormatter;

impl Formatter for CanonicalJsonFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        let mut run_start = 0;
        for (index, character) in fragment.char_indices() {
            if should_escape_text_character(character) {
                writer.write_all(&fragment.as_bytes()[run_start..index])?;
                write_json_unicode_escape(writer, character)?;
                run_start = index + character.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[run_start..])
    }

    fn write_char_escape<W>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        match escape {
            CharEscape::Quote => writer.write_all(br#"\""#),
            CharEscape::ReverseSolidus => writer.write_all(br#"\\"#),
            CharEscape::Solidus => writer.write_all(br#"\/"#),
            CharEscape::Backspace => writer.write_all(br"\u0008"),
            CharEscape::FormFeed => writer.write_all(br"\u000C"),
            CharEscape::LineFeed => writer.write_all(br"\u000A"),
            CharEscape::CarriageReturn => writer.write_all(br"\u000D"),
            CharEscape::Tab => writer.write_all(br"\u0009"),
            CharEscape::AsciiControl(byte) => write_json_u16_escape(writer, u16::from(byte)),
        }
    }
}

fn write_json_unicode_escape<W: Write + ?Sized>(writer: &mut W, character: char) -> io::Result<()> {
    let value = u32::from(character);
    if let Ok(value) = u16::try_from(value) {
        return write_json_u16_escape(writer, value);
    }

    let scalar = value - 0x1_0000;
    let high = 0xD800 | u16::try_from(scalar >> 10).expect("high surrogate fits u16");
    let low = 0xDC00 | u16::try_from(scalar & 0x3FF).expect("low surrogate fits u16");
    write_json_u16_escape(writer, high)?;
    write_json_u16_escape(writer, low)
}

fn write_json_u16_escape<W: Write + ?Sized>(writer: &mut W, value: u16) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = [
        b'\\',
        b'u',
        HEX[usize::from((value >> 12) & 0xF)],
        HEX[usize::from((value >> 8) & 0xF)],
        HEX[usize::from((value >> 4) & 0xF)],
        HEX[usize::from(value & 0xF)],
    ];
    writer.write_all(&bytes)
}

pub(crate) fn should_escape_text_character(character: char) -> bool {
    character.is_control() || is_bidi_control(character)
}

pub(crate) const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::policy::{
        CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
        PolicyEvaluator, PolicyRegistry, PolicyRegistryLimits, PolicyReportDiagnostic,
        PolicyReportDiagnosticCode, PolicyRuleDescriptor, PolicyRunCompletion,
        PolicySourceIdentity, TaintCatalogRegistry,
    };
    use crate::analyzer::{Language, ProjectFile, TestProject, TypescriptAnalyzer};

    const MATCHING_POLICY: &str = r#"(policy
      :schema-version 1
      :id "test.render"
      :name "Render"
      :message "Avoid target"
      :severity warning
      :analysis (analysis :type match :selector
        (rql :schema-version 2 (language typescript (function :name "target")))))"#;

    fn evaluated_report(
        policy_source: &str,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> PolicyReportDocument {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "app.ts")
            .write(source)
            .expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

        let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        ));
        let mut registry =
            PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new("test:render-policy"),
                policy_source.as_bytes(),
            )
            .expect("valid policy");
        let policy = registry.policies().next().expect("one policy");
        let descriptor = PolicyRuleDescriptor::from_loaded(policy);
        let run = DefaultPolicyEvaluator::new()
            .evaluate(
                policy,
                &PolicyEvaluationContext {
                    analyzer: &analyzer,
                    cancellation,
                    cvss_overlays: &[],
                    organizational_risk: &[],
                },
                &mut PolicyBudget::default(),
            )
            .expect("policy evaluation");
        PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None)
            .expect("canonical report")
    }

    fn diagnostic_report(source: &str) -> PolicyReportDocument {
        let diagnostic = PolicyReportDiagnostic::try_new(
            PolicyReportDiagnosticCode::PolicyLoadFailed,
            super::super::PolicyDiagnosticSeverity::Error,
            "load failed",
            Some(PolicySourceIdentity::new(source)),
            None,
            Vec::new(),
        )
        .unwrap();
        PolicyReportDocument::try_new(Vec::new(), Vec::new(), vec![diagnostic], false, 0, None)
            .unwrap()
    }

    #[test]
    fn bounded_writer_rejects_the_next_write_without_crossing_the_limit() {
        let mut output = Vec::new();
        let mut writer = BoundedWriter::new(&mut output, 4);
        writer.write_all(b"1234").unwrap();
        let error = writer.write_all(b"5").unwrap_err();
        assert!(matches!(
            map_io_error(error),
            PolicyRenderError::SerializedReportLimit {
                max_serialized_bytes: 4
            }
        ));
        assert_eq!(writer.bytes_written(), 4);
        assert_eq!(output, b"1234");
    }

    #[test]
    fn bounded_writer_preserves_destination_failures() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let error = BoundedWriter::new(FailingWriter, 16)
            .write_all(b"report")
            .unwrap_err();
        assert!(matches!(
            map_io_error(error),
            PolicyRenderError::Output(error) if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn canonical_formatter_escapes_controls_and_bidi_without_touching_unicode_text() {
        #[derive(Serialize)]
        struct Text<'a> {
            value: &'a str,
        }

        let mut output = Vec::new();
        let mut serializer =
            serde_json::Serializer::with_formatter(&mut output, CanonicalJsonFormatter);
        Text {
            value: "line\n\t\u{001B}\u{007F}\u{0085}\u{202E}\u{2066} café",
        }
        .serialize(&mut serializer)
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            r#"{"value":"line\u000A\u0009\u001B\u007F\u0085\u202E\u2066 café"}"#
        );
    }

    #[test]
    fn canonical_json_is_deterministic_and_the_exact_encoded_size_is_the_bound() {
        let report = evaluated_report(
            MATCHING_POLICY,
            "export function target() { return 1; }\n",
            None,
        );
        let mut first = Vec::new();
        let exact = write_policy_json(&report, &mut first, usize::MAX).unwrap();
        let mut second = Vec::new();
        assert_eq!(
            write_policy_json(&report, &mut second, usize::MAX).unwrap(),
            exact
        );
        assert_eq!(first, second);
        assert_eq!(usize::try_from(exact).unwrap(), first.len());
        assert!(first.starts_with(br#"{"schema_version":1,"rules":["#));

        let limit = first.len() - 1;
        let mut bounded = Vec::new();
        let error = write_policy_json(&report, &mut bounded, limit).unwrap_err();
        assert!(
            matches!(
                &error,
                PolicyRenderError::SerializedReportLimit {
                    max_serialized_bytes
                } if *max_serialized_bytes == limit
            ),
            "unexpected limit error: {error:?}"
        );
        assert!(bounded.len() <= limit);
    }

    #[test]
    fn canonical_json_escapes_workspace_control_text_after_encoding() {
        let report = diagnostic_report("workspace:bad\n\u{001B}\u{007F}\u{0085}\u{202E}\u{2066}");
        let mut output = Vec::new();
        write_policy_json(&report, &mut output, usize::MAX).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"workspace:bad\u000A\u001B\u007F\u0085\u202E\u2066"#));
        assert!(!output.contains('\n'));
        assert!(!output.contains('\u{001B}'));
    }

    #[test]
    fn canonical_json_preserves_broken_pipe_as_an_output_error() {
        struct BrokenPipe;

        impl Write for BrokenPipe {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let report = diagnostic_report("workspace:policy.rqlp");
        assert!(matches!(
            write_policy_json(&report, BrokenPipe, usize::MAX),
            Err(PolicyRenderError::Output(error))
                if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn human_report_has_findings_clean_and_incomplete_summaries_without_ansi() {
        let finding = evaluated_report(
            MATCHING_POLICY,
            "export function target() { return 1; }\n",
            None,
        );
        let mut first = Vec::new();
        write_policy_human(
            &finding,
            &HumanRenderOptions::default(),
            &mut first,
            usize::MAX,
        )
        .unwrap();
        let mut second = Vec::new();
        write_policy_human(
            &finding,
            &HumanRenderOptions::default(),
            &mut second,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(first, second);
        let finding = String::from_utf8(first).unwrap();
        assert!(
            finding.starts_with("app.ts:1:8: [warning] test.render: Avoid target\n"),
            "unexpected human report:\n{finding}"
        );
        assert!(finding.contains("  evidence: structural_match function\n"));
        assert!(finding.contains("policy rule: test.render (Render)\n"));
        assert!(finding.contains("summary: 1 finding; 1 complete policy run\n"));
        assert!(!finding.contains('\u{001B}'));

        let clean = evaluated_report(
            MATCHING_POLICY,
            "export function other() { return 1; }\n",
            None,
        );
        let mut output = Vec::new();
        write_policy_human(
            &clean,
            &HumanRenderOptions::default(),
            &mut output,
            usize::MAX,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("policy rule: test.render (Render)\n"));
        assert!(output.ends_with("summary: 0 findings; 1 complete policy run; clean\n"));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let incomplete = evaluated_report(
            MATCHING_POLICY,
            "export function target() { return 1; }\n",
            Some(&cancellation),
        );
        assert!(matches!(
            incomplete.runs()[0].completion(),
            PolicyRunCompletion::Inconclusive { .. }
        ));
        let mut output = Vec::new();
        write_policy_human(
            &incomplete,
            &HumanRenderOptions::default(),
            &mut output,
            usize::MAX,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("policy test.render (Render): inconclusive (cancelled); non-clean")
        );
        assert!(output.ends_with("summary: 0 findings; 1 inconclusive policy run; non-clean\n"));
    }

    #[test]
    fn human_report_emits_one_concise_note_for_inferred_policy_and_rql_schemas() {
        let inferred = MATCHING_POLICY
            .replacen("\n      :schema-version 1", "", 1)
            .replacen("rql :schema-version 2", "rql", 1);
        let report = evaluated_report(&inferred, "export function other() { return 1; }\n", None);
        let mut output = Vec::new();
        write_policy_human(
            &report,
            &HumanRenderOptions::default(),
            &mut output,
            usize::MAX,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        let note = "note: policy test.render inferred policy schema 1 and RQL schema 2\n";
        assert!(output.starts_with(note));
        assert_eq!(output.matches(note).count(), 1);
        assert!(output.contains("policy rule: test.render (Render)\n"));
        assert!(output.ends_with("summary: 0 findings; 1 complete policy run; clean\n"));
    }

    #[test]
    fn human_output_escapes_report_source_text_and_respects_its_encoded_bound() {
        let report = diagnostic_report("workspace:bad\n\u{001B}[31m\u{202E}\u{2066}");
        let mut exact = Vec::new();
        let bytes = write_policy_human(
            &report,
            &HumanRenderOptions::default(),
            &mut exact,
            usize::MAX,
        )
        .unwrap();
        let rendered = String::from_utf8(exact).unwrap();
        assert!(rendered.contains(r#"workspace:bad\u{A}\u{1B}[31m\u{202E}\u{2066}"#));
        assert!(!rendered.contains('\u{001B}'));
        assert_eq!(usize::try_from(bytes).unwrap(), rendered.len());

        let limit = rendered.len() - 1;
        let mut bounded = Vec::new();
        assert!(matches!(
            write_policy_human(
                &report,
                &HumanRenderOptions::default(),
                &mut bounded,
                limit,
            ),
            Err(PolicyRenderError::SerializedReportLimit {
                max_serialized_bytes
            }) if max_serialized_bytes == limit
        ));
        assert!(bounded.len() <= limit);
    }
}
