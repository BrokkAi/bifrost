use std::cell::Cell;
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::rc::Rc;

use flate2::read::GzDecoder;

use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, ProducerDiagnostic, SuppressedDiagnostics,
};

const MAX_OUTER_ENTRIES: usize = 64;
const MIN_INNER_ENTRY_LIMIT: usize = 1_024;
const MAX_INNER_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RubyGemDeclarationKind {
    Rbs,
    Rbi,
    Ruby,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubyGemDeclarationEntry {
    pub path: String,
    pub kind: RubyGemDeclarationKind,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RubyGemArchiveOutcome {
    pub archive_sha256: String,
    pub entries: Vec<RubyGemDeclarationEntry>,
    pub diagnostics: Vec<ProducerDiagnostic>,
    pub suppressed_diagnostics: SuppressedDiagnostics,
    pub complete: bool,
    pub cancelled: bool,
}

pub(crate) fn read_gem_declaration_entries(
    archive_sha256: &str,
    bytes: &[u8],
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
) -> RubyGemArchiveOutcome {
    let mut diagnostics = BoundedProducerDiagnostics::new(limits);
    if cancelled(cancellation) {
        diagnostics.error(
            "ruby.gem.cancelled",
            None,
            "Ruby gem archive production was cancelled",
        );
        return finish(archive_sha256, Vec::new(), diagnostics, true, false);
    }

    let compressed_data = match read_compressed_data(bytes, limits, cancellation, &mut diagnostics)
    {
        Some(bytes) => bytes,
        None => {
            let was_cancelled = cancelled(cancellation);
            return finish(
                archive_sha256,
                Vec::new(),
                diagnostics,
                was_cancelled,
                false,
            );
        }
    };
    let entries = read_inner_entries(&compressed_data, limits, cancellation, &mut diagnostics);
    let was_cancelled = cancelled(cancellation);
    let complete = !was_cancelled && entries.is_some() && diagnostics.is_empty();
    finish(
        archive_sha256,
        entries.unwrap_or_default(),
        diagnostics,
        was_cancelled,
        complete,
    )
}

fn read_compressed_data(
    bytes: &[u8],
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<Vec<u8>> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let archive_entries = archive.entries().map_err(|error| {
        diagnostics.error(
            "ruby.gem.outer_archive",
            None,
            format!("could not read Ruby gem tar entries: {error}"),
        );
    });
    let Ok(archive_entries) = archive_entries else {
        return None;
    };
    let mut compressed_data = None;
    for (index, entry) in archive_entries.enumerate() {
        if cancelled(cancellation) {
            diagnostics.error(
                "ruby.gem.cancelled",
                None,
                "Ruby gem archive production was cancelled",
            );
            return None;
        }
        if index >= MAX_OUTER_ENTRIES {
            diagnostics.error(
                "limit.archive_entries",
                None,
                format!("Ruby gem outer archive exceeds {MAX_OUTER_ENTRIES} entries"),
            );
            return None;
        }
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                diagnostics.error(
                    "ruby.gem.outer_entry",
                    None,
                    format!("could not read Ruby gem outer entry: {error}"),
                );
                return None;
            }
        };
        let Some(path) = portable_archive_path(&entry, diagnostics) else {
            continue;
        };
        if path != "data.tar.gz" {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            diagnostics.error(
                "ruby.gem.data_not_file",
                Some(path),
                "Ruby gem data.tar.gz entry is not a regular file",
            );
            return None;
        }
        if compressed_data.is_some() {
            diagnostics.error(
                "ruby.gem.duplicate_data",
                Some(path),
                "Ruby gem contains more than one data.tar.gz entry",
            );
            return None;
        }
        if entry.size() > limits.max_artifact_bytes {
            diagnostics.error(
                "limit.archive_bytes",
                Some(path),
                "compressed Ruby gem data exceeds the artifact byte limit",
            );
            return None;
        }
        let mut data = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(limits.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut data)
            .is_err()
            || data.len() as u64 > limits.max_artifact_bytes
        {
            diagnostics.error(
                "ruby.gem.data_read",
                Some(path),
                "could not read bounded Ruby gem data.tar.gz bytes",
            );
            return None;
        }
        compressed_data = Some(data);
    }
    if compressed_data.is_none() {
        diagnostics.error(
            "ruby.gem.missing_data",
            None,
            "Ruby gem does not contain data.tar.gz",
        );
    }
    compressed_data
}

fn read_inner_entries(
    compressed_data: &[u8],
    limits: &ArtifactProducerLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<Vec<RubyGemDeclarationEntry>> {
    let state = Rc::new(BoundedReadState::default());
    let decoder = GzDecoder::new(Cursor::new(compressed_data));
    let reader = BoundedCancellationReader {
        inner: decoder,
        max_bytes: limits.max_artifact_bytes,
        cancellation,
        state: state.clone(),
    };
    let mut archive = tar::Archive::new(reader);
    let archive_entries = archive.entries().map_err(|error| {
        inner_archive_error(diagnostics, &state, error);
    });
    let Ok(archive_entries) = archive_entries else {
        return None;
    };
    let entry_limit = limits
        .max_records
        .saturating_mul(4)
        .clamp(MIN_INNER_ENTRY_LIMIT, MAX_INNER_ENTRIES);
    let mut total_bytes = 0_u64;
    let mut selected = Vec::new();
    for (index, entry) in archive_entries.enumerate() {
        if cancelled(cancellation) {
            diagnostics.error(
                "ruby.gem.cancelled",
                None,
                "Ruby gem archive production was cancelled",
            );
            return None;
        }
        if index >= entry_limit {
            diagnostics.error(
                "limit.archive_entries",
                None,
                format!("Ruby gem data archive exceeds {entry_limit} entries"),
            );
            return None;
        }
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                inner_archive_error(diagnostics, &state, error);
                return None;
            }
        };
        let Some(path) = portable_archive_path(&entry, diagnostics) else {
            continue;
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let Some(kind) = declaration_kind(Path::new(&path)) else {
            continue;
        };
        if selected.len() >= limits.max_records {
            diagnostics.error(
                "limit.records",
                Some(path),
                format!(
                    "Ruby gem declarations exceed the {} record limit",
                    limits.max_records
                ),
            );
            return None;
        }
        total_bytes = total_bytes.saturating_add(entry.size());
        if entry.size() > limits.max_artifact_bytes || total_bytes > limits.max_artifact_bytes {
            diagnostics.error(
                "limit.archive_bytes",
                Some(path),
                "expanded Ruby declaration bytes exceed the artifact byte limit",
            );
            return None;
        }
        let mut source = Vec::with_capacity(entry.size() as usize);
        if entry
            .by_ref()
            .take(limits.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut source)
            .is_err()
            || source.len() as u64 > limits.max_artifact_bytes
        {
            diagnostics.error(
                "ruby.gem.entry_read",
                Some(path),
                "could not read bounded Ruby declaration bytes",
            );
            return None;
        }
        match String::from_utf8(source) {
            Ok(source) => selected.push(RubyGemDeclarationEntry { path, kind, source }),
            Err(_) => diagnostics.warning(
                "ruby.gem.declaration_encoding",
                Some(path),
                "Ruby declaration entry is not valid UTF-8",
            ),
        }
    }
    selected.sort_by(|left, right| (&left.path, left.kind).cmp(&(&right.path, right.kind)));
    Some(selected)
}

#[derive(Default)]
struct BoundedReadState {
    consumed: Cell<u64>,
    limit_exceeded: Cell<bool>,
    cancelled: Cell<bool>,
}

struct BoundedCancellationReader<'a, R> {
    inner: R,
    max_bytes: u64,
    cancellation: Option<&'a CancellationToken>,
    state: Rc<BoundedReadState>,
}

impl<R: Read> Read for BoundedCancellationReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if cancelled(self.cancellation) {
            self.state.cancelled.set(true);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ruby gem archive production was cancelled",
            ));
        }
        let remaining = self.max_bytes.saturating_sub(self.state.consumed.get());
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            if self.inner.read(&mut probe)? == 0 {
                return Ok(0);
            }
            self.state.limit_exceeded.set(true);
            return Err(std::io::Error::other(
                "expanded Ruby gem data archive exceeds the artifact byte limit",
            ));
        }
        let bounded_len = buffer.len().min(remaining as usize);
        let read = self.inner.read(&mut buffer[..bounded_len])?;
        self.state
            .consumed
            .set(self.state.consumed.get().saturating_add(read as u64));
        Ok(read)
    }
}

fn inner_archive_error(
    diagnostics: &mut BoundedProducerDiagnostics,
    state: &BoundedReadState,
    error: std::io::Error,
) {
    if state.cancelled.get() {
        diagnostics.error(
            "ruby.gem.cancelled",
            None,
            "Ruby gem archive production was cancelled",
        );
    } else if state.limit_exceeded.get() {
        diagnostics.error(
            "limit.archive_bytes",
            None,
            "expanded Ruby gem data archive exceeds the artifact byte limit",
        );
    } else {
        diagnostics.error(
            "ruby.gem.data_archive",
            None,
            format!("could not read compressed Ruby gem data archive: {error}"),
        );
    }
}

fn portable_archive_path<R: Read>(
    entry: &tar::Entry<'_, R>,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<String> {
    let path = match entry.path() {
        Ok(path) => path,
        Err(error) => {
            diagnostics.warning(
                "ruby.gem.entry_path",
                None,
                format!("Ruby gem contains an invalid archive path: {error}"),
            );
            return None;
        }
    };
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    diagnostics.warning(
                        "ruby.gem.entry_path_encoding",
                        None,
                        "Ruby gem contains a non-UTF-8 archive path",
                    );
                    return None;
                };
                if part.contains('\\') || part.contains(':') {
                    diagnostics.warning(
                        "ruby.gem.nonportable_entry_path",
                        None,
                        "Ruby gem contains a platform-dependent archive path",
                    );
                    return None;
                }
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                diagnostics.warning(
                    "ruby.gem.unsafe_entry_path",
                    None,
                    "Ruby gem contains a non-portable archive path",
                );
                return None;
            }
        }
    }
    if parts.is_empty() {
        diagnostics.warning(
            "ruby.gem.empty_entry_path",
            None,
            "Ruby gem contains an empty archive path",
        );
        return None;
    }
    Some(parts.join("/"))
}

fn declaration_kind(path: &Path) -> Option<RubyGemDeclarationKind> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rbs") => Some(RubyGemDeclarationKind::Rbs),
        Some("rbi") => Some(RubyGemDeclarationKind::Rbi),
        Some("rb") => Some(RubyGemDeclarationKind::Ruby),
        _ => None,
    }
}

fn cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn finish(
    archive_sha256: &str,
    entries: Vec<RubyGemDeclarationEntry>,
    diagnostics: BoundedProducerDiagnostics,
    cancelled: bool,
    complete: bool,
) -> RubyGemArchiveOutcome {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    RubyGemArchiveOutcome {
        archive_sha256: archive_sha256.to_owned(),
        entries,
        diagnostics,
        suppressed_diagnostics,
        complete: complete && suppressed_diagnostics.total() == 0,
        cancelled,
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    #[test]
    fn nested_gem_archive_reads_only_sorted_declaration_files() {
        let bytes = gem_archive(&[
            ("lib/widget.rb", b"class Widget; end"),
            ("sig/widget.rbs", b"class Widget\nend"),
            ("README.md", b"not a declaration"),
            ("sorbet/rbi/widget.rbi", b"class Widget; end"),
        ]);
        let outcome = read_gem_declaration_entries(
            &"a".repeat(64),
            &bytes,
            &ArtifactProducerLimits::default(),
            None,
        );

        assert!(outcome.complete, "{:?}", outcome.diagnostics);
        assert_eq!(
            outcome
                .entries
                .iter()
                .map(|entry| (entry.path.as_str(), entry.kind))
                .collect::<Vec<_>>(),
            vec![
                ("lib/widget.rb", RubyGemDeclarationKind::Ruby),
                ("sig/widget.rbs", RubyGemDeclarationKind::Rbs),
                ("sorbet/rbi/widget.rbi", RubyGemDeclarationKind::Rbi),
            ]
        );
    }

    #[test]
    fn nested_gem_archive_is_cancellable_and_expansion_bounded() {
        let bytes = gem_archive(&[("sig/widget.rbs", b"class Widget\nend")]);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = read_gem_declaration_entries(
            &"a".repeat(64),
            &bytes,
            &ArtifactProducerLimits::default(),
            Some(&cancellation),
        );
        assert!(cancelled.cancelled);
        assert_eq!(cancelled.diagnostics[0].code, "ruby.gem.cancelled");

        let bounded = read_gem_declaration_entries(
            &"a".repeat(64),
            &bytes,
            &ArtifactProducerLimits {
                max_artifact_bytes: 8,
                ..ArtifactProducerLimits::default()
            },
            None,
        );
        assert!(!bounded.complete);
        assert_eq!(bounded.diagnostics[0].code, "limit.archive_bytes");

        let skipped_expansion = gem_archive(&[("README.md", &[0_u8; 8 * 1024])]);
        let bounded = read_gem_declaration_entries(
            &"a".repeat(64),
            &skipped_expansion,
            &ArtifactProducerLimits {
                max_artifact_bytes: 2 * 1024,
                ..ArtifactProducerLimits::default()
            },
            None,
        );
        assert!(!bounded.complete);
        assert_eq!(bounded.diagnostics[0].code, "limit.archive_bytes");
    }

    fn gem_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let encoder = GzEncoder::new(&mut compressed, Compression::default());
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
