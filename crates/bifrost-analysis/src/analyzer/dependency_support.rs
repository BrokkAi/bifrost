use std::cell::RefCell;
use std::io::{self, Read};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::CancellationToken;
use crate::analyzer::semantic_model::ExternalDiscoveryRead;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, BoundedProducerDiagnostics, DependencyPackDiagnostic,
    DependencyPackDiagnosticSeverity, DependencyPackLimits, DependencyPackProduction,
    DependencyProvenance, ExactArtifact, Locator, ProducerDiagnostic, ProducerDiagnosticSeverity,
    SuppressedDiagnostics, read_exact_artifact_while,
};

#[derive(Debug, Clone, Default)]
pub struct ExternalDiscoveryReads {
    pub keys: Vec<ExternalDiscoveryRead>,
    pub complete: bool,
    refused: bool,
}

impl ExternalDiscoveryReads {
    /// Mark the capture incomplete because the project-read ledger saw reads it
    /// could not name.
    pub fn refuse_unbounded_project_reads(&mut self) {
        self.refused = true;
        self.complete = false;
    }
}

thread_local! {
    static EXTERNAL_DISCOVERY_CAPTURE: RefCell<ExternalDiscoveryCapture> = const { RefCell::new(ExternalDiscoveryCapture { reads: None }) };
}

/// The external reads one discovery records. A capture is request scoped, not
/// thread scoped: a worker that serves the discovery installs a handle taken
/// on the capturing thread, as `ReadAttribution::for_request` transports
/// project reads. Reads reported on a thread with no installed handle belong
/// to no discovery and are dropped.
///
/// Each worker installs its own [`fork`](Self::fork) and the capturing thread
/// [`merge`](Self::merge)s the forks in a fixed order after joining them, so
/// the recorded order, and the identity hashed from it, does not depend on
/// which worker finished first.
#[derive(Clone, Default)]
pub struct ExternalDiscoveryCapture {
    reads: Option<Arc<Mutex<ExternalDiscoveryReads>>>,
}

/// Restores the previous capture on the installing thread.
pub struct ExternalDiscoveryCaptureGuard {
    previous: ExternalDiscoveryCapture,
    // Like MutexGuard: must drop on the thread that installed it.
    _thread: PhantomData<std::sync::MutexGuard<'static, ()>>,
}

impl Drop for ExternalDiscoveryCaptureGuard {
    fn drop(&mut self) {
        let previous = std::mem::take(&mut self.previous);
        EXTERNAL_DISCOVERY_CAPTURE.with(|slot| *slot.borrow_mut() = previous);
    }
}

impl ExternalDiscoveryCapture {
    /// The capture of the discovery running on this thread. Outside a
    /// capture the handle is inert: installing it and reporting through it
    /// record nothing, exactly as a report outside a capture records nothing.
    pub fn current() -> Self {
        EXTERNAL_DISCOVERY_CAPTURE.with(|slot| slot.borrow().clone())
    }

    /// An empty capture whose reads join this one at [`merge`](Self::merge).
    pub fn fork(&self) -> Self {
        Self {
            reads: self.reads.as_ref().map(|_| Arc::default()),
        }
    }

    /// Append a joined worker's reads, and its refusal, to this capture. A
    /// worker cannot declare the discovery complete; only the capturing
    /// thread can.
    pub fn merge(&self, fork: Self) {
        let (Some(reads), Some(fork)) = (&self.reads, fork.reads) else {
            return;
        };
        let fork = std::mem::take(&mut *lock(&fork));
        debug_assert!(
            !fork.complete,
            "a worker declared external discovery reads complete"
        );
        let mut reads = lock(reads);
        reads.keys.extend(fork.keys);
        if fork.refused {
            reads.refused = true;
            reads.complete = false;
        }
    }

    /// Route this thread's reports to this capture until the guard drops.
    pub fn install(&self) -> ExternalDiscoveryCaptureGuard {
        let previous = EXTERNAL_DISCOVERY_CAPTURE
            .with(|slot| std::mem::replace(&mut *slot.borrow_mut(), self.clone()));
        ExternalDiscoveryCaptureGuard {
            previous,
            _thread: PhantomData,
        }
    }

    fn with_reads(&self, f: impl FnOnce(&mut ExternalDiscoveryReads)) {
        if let Some(reads) = &self.reads {
            f(&mut lock(reads));
        }
    }
}

fn lock(
    reads: &Mutex<ExternalDiscoveryReads>,
) -> std::sync::MutexGuard<'_, ExternalDiscoveryReads> {
    // Reads are append-only; a panicking worker leaves them consistent.
    reads
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn with_current_reads(f: impl FnOnce(&mut ExternalDiscoveryReads)) {
    // Clone out of the slot: a report must never hold the slot borrowed while
    // it takes the reads lock.
    ExternalDiscoveryCapture::current().with_reads(f);
}

pub fn capture_external_discovery_reads<T>(f: impl FnOnce() -> T) -> (T, ExternalDiscoveryReads) {
    assert!(
        ExternalDiscoveryCapture::current().reads.is_none(),
        "nested external discovery capture"
    );
    let capture = ExternalDiscoveryCapture {
        reads: Some(Arc::default()),
    };
    let result = {
        let _installed = capture.install();
        f()
    };
    let reads = std::mem::take(&mut *lock(
        capture.reads.as_ref().expect("capture was just created"),
    ));
    (result, reads)
}

pub fn report_external_discovery_read(read: ExternalDiscoveryRead) {
    with_current_reads(|reads| reads.keys.push(read));
}

pub fn declare_external_discovery_reads_complete() {
    with_current_reads(|reads| reads.complete = !reads.refused);
}

/// Records the observation of `path` that `digest` summarizes. An unreadable
/// observation, or a relative path whose meaning depends on the process
/// directory, cannot be reproduced from a fixed input and refuses carry.
pub fn report_path_observation(
    path: &Path,
    op: crate::analyzer::semantic_model::PathObservationOp,
    digest: &io::Result<crate::analyzer::semantic::ids::StableDigest>,
) {
    match digest {
        Ok(digest) if path.is_absolute() => {
            report_external_discovery_read(ExternalDiscoveryRead::PathObservation {
                absolute_path: path.to_path_buf(),
                op,
                digest: *digest,
            })
        }
        _ => refuse_external_discovery_reads(),
    }
}

pub fn refuse_external_discovery_reads() {
    with_current_reads(|reads| {
        reads.refused = true;
        reads.complete = false;
    });
}

/// Read an external file under the existing artifact budget and record its bytes.
pub fn read_external_evidence_file_with_budget(
    ecosystem: &str,
    path: &Path,
    limits: &DependencyPackLimits,
    evidence_bytes_read: &mut u64,
    cancellation: Option<&CancellationToken>,
) -> Result<ExactArtifact, DependencyPackDiagnostic> {
    let result =
        read_evidence_file_with_budget(ecosystem, path, limits, evidence_bytes_read, cancellation);
    match &result {
        Ok(artifact) => {
            report_external_discovery_read(ExternalDiscoveryRead::file(path, artifact.bytes()))
        }
        Err(diagnostic)
            if diagnostic.code == "limit.artifact_bytes"
                || diagnostic.code == "limit.total_artifact_bytes" =>
        {
            if let Ok(metadata) = std::fs::metadata(path) {
                report_external_discovery_read(ExternalDiscoveryRead::OverBudgetFile {
                    absolute_path: path.to_path_buf(),
                    size: metadata.len(),
                });
            } else {
                refuse_external_discovery_reads();
            }
        }
        Err(diagnostic) if diagnostic.code == "artifact.metadata" && !path.exists() => {
            report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                absolute_path: path.to_path_buf(),
            });
        }
        Err(_) => refuse_external_discovery_reads(),
    }
    result
}

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
    let result = (|| {
        let file = match brokk_bifrost_core::content_digest::open_regular_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                    absolute_path: path.to_path_buf(),
                });
                return Ok(None);
            }
            Err(error) => return Err(format!("could not inspect declaration file: {error}")),
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect declaration file: {error}"))?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return Err(format!(
                "declaration file is not a regular file within {max_bytes} bytes"
            ));
        }
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read declaration file: {error}"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(format!(
                "declaration file is not a regular file within {max_bytes} bytes"
            ));
        }
        report_external_discovery_read(ExternalDiscoveryRead::file(path, &bytes));
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|error| format!("could not read declaration file: {error}"))
    })();
    if result.is_err() {
        refuse_external_discovery_reads();
    }
    result
}

/// Read the project files a files-only dependency producer interprets.
///
/// Every file for which `is_input` holds is read as one immutable snapshot,
/// within the pack limits' file count and byte budget. A listing or read
/// failure, a breached limit and cancellation are pushed onto `diagnostics`
/// under `code_prefix` (`rust`, `ruby`) and the shared `limit.*` codes, with
/// `ecosystem` naming the build tool in each message. Returns the snapshots,
/// the bytes they hold, and whether acquisition was cancelled.
#[doc(hidden)]
pub fn select_dependency_input_snapshots(
    project: &dyn crate::analyzer::Project,
    ecosystem: &str,
    code_prefix: &str,
    is_input: impl Fn(&Path) -> bool,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut crate::analyzer::semantic_model::BoundedDependencyDiagnostics,
) -> (
    Vec<(
        brokk_bifrost_core::analyzer::model::ProjectFile,
        brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot,
    )>,
    u64,
    bool,
) {
    let mut selected = Vec::new();
    let mut bytes = 0_u64;
    let files = match project.all_files_shared() {
        Ok(files) => files,
        Err(error) => {
            diagnostics.push(dependency_diagnostic(
                &format!("{code_prefix}.files.list"),
                None,
                error.to_string(),
            ));
            return (selected, bytes, false);
        }
    };
    for file in files.iter().filter(|file| is_input(file.rel_path())) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            diagnostics.push(dependency_diagnostic(
                &format!("{code_prefix}.evidence.cancelled"),
                None,
                format!("{ecosystem} file acquisition cancelled"),
            ));
            return (selected, bytes, true);
        }
        if selected.len() >= limits.max_source_files_per_artifact {
            diagnostics.push(dependency_diagnostic(
                "limit.dependency_input_files",
                None,
                format!("{ecosystem} file count exceeds the dependency evidence limit"),
            ));
            break;
        }
        let remaining = limits.max_total_artifact_bytes.saturating_sub(bytes);
        let cap = remaining
            .min(limits.producer.max_artifact_bytes)
            .min(usize::MAX as u64) as usize;
        if cap == 0 {
            diagnostics.push(dependency_diagnostic(
                "limit.total_artifact_bytes",
                Some(file.rel_path()),
                format!("{ecosystem} evidence byte budget exhausted"),
            ));
            break;
        }
        match project.read_source_snapshot_limited(file, cap) {
            Ok(Some(snapshot)) => {
                bytes += snapshot.source().len() as u64;
                selected.push((file.clone(), snapshot));
            }
            Ok(None) => diagnostics.push(dependency_diagnostic(
                "limit.artifact_bytes",
                Some(file.rel_path()),
                format!("selected {ecosystem} snapshot exceeds its byte limit"),
            )),
            Err(error) => diagnostics.push(dependency_diagnostic(
                &format!("{code_prefix}.files.read"),
                Some(file.rel_path()),
                error.to_string(),
            )),
        }
    }
    (selected, bytes, false)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{self, Cursor, Read};
    use std::path::Path;

    use super::{
        BoundedReadError, ExternalDiscoveryCapture, ExternalDiscoveryReads,
        capture_external_discovery_reads, declare_external_discovery_reads_complete,
        dependency_producer_diagnostic, read_bounded_bytes, read_bounded_declaration_file,
        refuse_external_discovery_reads, report_external_discovery_read,
        require_non_empty_evidence_field,
    };
    use crate::analyzer::semantic_model::ExternalDiscoveryRead;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn bounded_reads_accept_exact_and_zero_limits() {
        for limit in [0, 4] {
            for length in 0..=5 {
                let bytes = vec![b'x'; length];
                let result = read_bounded_bytes(Cursor::new(&bytes), limit);
                if length as u64 <= limit {
                    assert_eq!(result.unwrap(), bytes);
                } else {
                    assert!(matches!(result, Err(BoundedReadError::LimitExceeded)));
                }
            }
        }
    }

    #[test]
    fn evidence_reads_respect_artifact_and_remaining_budgets() {
        use crate::analyzer::semantic_model::DependencyPackLimits;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"1234").unwrap();
        for (artifact_limit, total_limit, code) in [
            (3, 10, "limit.artifact_bytes"),
            (10, 7, "limit.total_artifact_bytes"),
        ] {
            let mut limits = DependencyPackLimits {
                max_total_artifact_bytes: total_limit,
                ..Default::default()
            };
            limits.producer.max_artifact_bytes = artifact_limit;
            let mut used = if artifact_limit == 3 { 0 } else { 4 };
            let before = used;
            let error =
                super::read_evidence_file_with_budget("fixture", &path, &limits, &mut used, None)
                    .unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(used, before);
        }
        let limits = DependencyPackLimits {
            max_total_artifact_bytes: 7,
            ..Default::default()
        };
        let mut used = 0;
        let accepted =
            super::read_evidence_file_with_budget("fixture", &path, &limits, &mut used, None)
                .unwrap();
        assert_eq!(accepted.bytes(), b"1234");
        assert_eq!(used, 4);
        assert_eq!(
            super::read_evidence_file_with_budget("fixture", &path, &limits, &mut used, None)
                .unwrap_err()
                .code,
            "limit.total_artifact_bytes"
        );
        assert_eq!(used, 4);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "d92b993f1ef4: declaration files with underreported metadata escaped the byte cap"
    )]
    fn declaration_read_bounds_streams_with_underreported_metadata() {
        let path = Path::new("/proc/version");
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
        assert!(
            read_bounded_declaration_file(path, 1)
                .unwrap_err()
                .contains("within 1 bytes")
        );
    }

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
    fn dependency_evidence_boundaries_and_severities_are_preserved() {
        use crate::analyzer::semantic_model::{
            DependencyPackDiagnosticSeverity, ProducerDiagnostic, ProducerDiagnosticSeverity,
        };
        assert!(require_non_empty_evidence_field("maven", "bad", "coordinate", "   ").is_err());
        assert!(require_non_empty_evidence_field("maven", "bad", "coordinate", "x").is_ok());
        for (producer_severity, expected) in [
            (
                ProducerDiagnosticSeverity::Warning,
                DependencyPackDiagnosticSeverity::Warning,
            ),
            (
                ProducerDiagnosticSeverity::Error,
                DependencyPackDiagnosticSeverity::Error,
            ),
        ] {
            let diagnostic = dependency_producer_diagnostic(
                Path::new("pom.xml"),
                ProducerDiagnostic {
                    severity: producer_severity,
                    code: "x".into(),
                    location: None,
                    source_entry: None,
                    declaration: None,
                    message: "x".into(),
                },
            );
            assert_eq!(diagnostic.severity, expected);
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decl");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(
            read_bounded_declaration_file(&path, 4).unwrap().as_deref(),
            Some("1234")
        );
        assert!(read_bounded_declaration_file(&path, 3).is_err());
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

    #[hardwon(
        "#13517: Go reads reported on a scoped domain worker never reached the discovery capture"
    )]
    #[test]
    fn worker_reads_reach_the_capture_in_fork_order() {
        let read = |name: &str| ExternalDiscoveryRead::Environment {
            name: name.into(),
            value: None,
            working_directory: None,
        };
        let names = |reads: &ExternalDiscoveryReads| {
            reads
                .keys
                .iter()
                .map(|key| match key {
                    ExternalDiscoveryRead::Environment { name, .. } => name.to_string(),
                    other => panic!("unexpected read {other:?}"),
                })
                .collect::<Vec<_>>()
        };
        let barrier = std::sync::Barrier::new(2);
        let ((), reads) = capture_external_discovery_reads(|| {
            report_external_discovery_read(read("first"));
            let capture = ExternalDiscoveryCapture::current();
            let forks = [capture.fork(), capture.fork()];
            std::thread::scope(|scope| {
                // The second worker reports before the first can: completion
                // order must not decide the recorded order.
                for (index, fork) in forks.iter().enumerate() {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let _installed = fork.install();
                        if index == 0 {
                            barrier.wait();
                        }
                        report_external_discovery_read(read(["worker0", "worker1"][index]));
                        if index == 1 {
                            barrier.wait();
                            refuse_external_discovery_reads();
                        }
                    });
                }
                // A worker that installs nothing reports to no discovery.
                scope.spawn(|| report_external_discovery_read(read("dropped")));
            });
            for fork in forks {
                capture.merge(fork);
            }
            declare_external_discovery_reads_complete();
            report_external_discovery_read(read("last"));
        });
        assert_eq!(names(&reads), ["first", "worker0", "worker1", "last"]);
        assert!(
            !reads.complete,
            "a worker refusal must survive the parent's later completion declaration"
        );
    }

    #[test]
    fn capture_handle_is_inert_outside_a_capture_and_restores_the_previous_one() {
        let outside = ExternalDiscoveryCapture::current();
        let _installed = outside.install();
        report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
            absolute_path: "/nowhere".into(),
        });
        outside.merge(outside.fork());
        let ((), reads) = capture_external_discovery_reads(|| {
            let inner = ExternalDiscoveryCapture::current();
            drop(inner.install());
            report_external_discovery_read(ExternalDiscoveryRead::AbsentFile {
                absolute_path: "/kept".into(),
            });
        });
        assert_eq!(reads.keys.len(), 1);
    }
}
