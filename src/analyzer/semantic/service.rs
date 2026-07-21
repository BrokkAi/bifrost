//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

use std::mem::size_of;
use std::sync::Arc;

use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::tree_sitter_analyzer::{PreparedSourceOrigin, PreparedSyntaxTree};
use crate::analyzer::{LanguageAdapter, ProjectFile, TreeSitterAnalyzer};

use super::{
    AdapterSemanticsVersion, AllocationSite, BasicBlock, CaptureBinding, ConfigurationFingerprint,
    ContentIdentity, ControlEdge, DependencyFingerprint, Evidence, MemoryLocation,
    OverlaySnapshotId, ProcedureId, ProcedureSemantics, ProcedureSemanticsParts, ProgramPoint,
    SemanticArtifact, SemanticArtifactBuildError, SemanticArtifactKey, SemanticCallSite,
    SemanticCapabilities, SemanticEvent, SemanticGap, SemanticIrVersion, SemanticLocator,
    SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticValue, SemanticWork,
    SourceMapping, SourceRevision, WorkspaceMountId, WorkspaceRelativePath,
};

const DEFAULT_COMPLETE_CACHE_BYTES: u64 = 256 * 1024 * 1024 / 8;

/// Immutable complete-artifact cache shared by one concrete analyzer adapter.
///
/// Moka bounds retained bytes rather than entry count. Incomplete outcomes are
/// never presented to this type, so a lookup can always be treated as a fully
/// validated immutable artifact. The in-flight map serializes construction for
/// one exact artifact key without retaining completed work.
#[derive(Clone)]
pub(crate) struct CompleteSemanticArtifactCache {
    inner: CompleteValueCache<SemanticArtifactKey, SemanticArtifact>,
}

impl Default for CompleteSemanticArtifactCache {
    fn default() -> Self {
        Self::new(DEFAULT_COMPLETE_CACHE_BYTES)
    }
}

impl CompleteSemanticArtifactCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            inner: CompleteValueCache::new(max_retained_bytes, weigh_complete_artifact),
        }
    }

    #[cfg(test)]
    fn insert(&self, key: SemanticArtifactKey, artifact: Arc<SemanticArtifact>) {
        self.inner.insert_complete_for_test(key, artifact);
    }

    fn acquire(
        &self,
        key: &SemanticArtifactKey,
        cancellation: &super::CancellationToken,
    ) -> (
        CompleteValueAcquisition<SemanticArtifactKey, SemanticArtifact>,
        CompleteValueWait,
    ) {
        self.inner.acquire(key, cancellation)
    }

    #[cfg(test)]
    fn len(&self) -> u64 {
        self.inner.len_for_test()
    }

    #[cfg(test)]
    fn waiting_count(&self) -> usize {
        self.inner.waiting_count_for_test()
    }
}

/// Convert the artifact's exact retained-work census into a conservative byte
/// weight. Fixed rows use their concrete Rust size; nested entries reserve at
/// least twice a `SemanticLocator`, and owned text is doubled to cover the
/// independently cloned Moka key. Hash-map bucket and Arc allocation overhead
/// are included explicitly. Source bytes are intentionally absent: the prepared
/// source is not owned by `SemanticArtifact`.
fn retained_artifact_bytes(key: &SemanticArtifactKey, artifact: &SemanticArtifact) -> u64 {
    fn rows(count: usize, row_size: usize) -> u64 {
        (count as u64).saturating_mul(row_size as u64)
    }

    let work = artifact.work();
    let locator_index_entry = size_of::<SemanticLocator>()
        .saturating_add(size_of::<ProcedureId>())
        .saturating_add(size_of::<usize>() * 2);
    let mut bytes = (size_of::<Arc<SemanticArtifact>>()
        + size_of::<SemanticArtifact>()
        + size_of::<SemanticArtifactKey>()) as u64;
    bytes = bytes
        .saturating_add(rows(work.procedures, size_of::<ProcedureSemantics>()))
        .saturating_add(rows(work.procedures, locator_index_entry))
        .saturating_add(rows(work.blocks, size_of::<BasicBlock>()))
        .saturating_add(rows(work.program_points, size_of::<ProgramPoint>()))
        .saturating_add(rows(work.values, size_of::<SemanticValue>()))
        .saturating_add(rows(work.allocations, size_of::<AllocationSite>()))
        .saturating_add(rows(work.call_sites, size_of::<SemanticCallSite>()))
        .saturating_add(rows(work.memory_locations, size_of::<MemoryLocation>()))
        .saturating_add(rows(work.captures, size_of::<CaptureBinding>()))
        .saturating_add(rows(work.source_mappings, size_of::<SourceMapping>()))
        .saturating_add(rows(work.evidence, size_of::<Evidence>()))
        .saturating_add(rows(work.gaps, size_of::<SemanticGap>()))
        .saturating_add(rows(work.events, size_of::<SemanticEvent>()))
        .saturating_add(rows(work.control_edges, size_of::<ControlEdge>()))
        .saturating_add(rows(
            work.nested_entries,
            size_of::<SemanticLocator>().saturating_mul(2).max(64),
        ))
        .saturating_add((work.owned_text_bytes as u64).saturating_mul(2));

    // `key` is intentionally used here as an invariant check: the cache must
    // weigh the same immutable identity embedded in the artifact.
    debug_assert_eq!(key, artifact.key());
    bytes.max(1)
}

fn weigh_complete_artifact(key: &SemanticArtifactKey, artifact: &Arc<SemanticArtifact>) -> u32 {
    retained_artifact_bytes(key, artifact).min(u64::from(u32::MAX)) as u32
}

/// Snapshot-stable adapter identity. Only intrafile extraction inputs belong
/// here; workspace dispatch generations are ICFG state and deliberately absent.
#[derive(Debug, Clone)]
pub(crate) struct SemanticAdapterIdentity {
    pub(crate) adapter: AdapterSemanticsVersion,
    pub(crate) configuration: ConfigurationFingerprint,
    pub(crate) dependencies: DependencyFingerprint,
}

/// The private boundary implemented by one real language lowering adapter.
///
/// `work` in the returned outcome is prospective/observed work only. The
/// service merges it with the validated artifact's retained work at
/// publication, and only publication mutates the caller's budget.
pub(crate) trait ProgramSemanticsLowerer: Send + Sync {
    fn identity(&self) -> SemanticAdapterIdentity;

    fn capabilities(&self) -> SemanticCapabilities;

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &super::SemanticBudget,
        cancellation: &super::CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError>;
}

fn validate_semantic_file<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
) -> Result<(), SemanticProviderError> {
    if file.root() != analyzer.project().root() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file root `{}` does not match analyzer root `{}`",
            file.root().display(),
            analyzer.project().root().display()
        )));
    }
    let file_language = crate::analyzer::common::language_for_file(file);
    if file_language != analyzer.adapter().language() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file language {} does not match {} adapter",
            file_language.config_label(),
            analyzer.adapter().language().config_label()
        )));
    }
    Ok(())
}

/// Derive the current complete artifact identity from one atomic prepared
/// syntax snapshot. This deliberately does not consult the artifact cache,
/// lower procedures, or mutate a semantic budget.
pub(crate) fn current_artifact_key_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    max_source_bytes: usize,
) -> Result<Option<SemanticArtifactKey>, SemanticProviderError> {
    validate_semantic_file(analyzer, file)?;
    let prepared = match analyzer.prepared_syntax_limited(file, max_source_bytes) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            return Err(SemanticProviderError::source_access(format!(
                "could not prepare the current source snapshot for `{file}`"
            )));
        }
        Err(_) => return Ok(None),
    };
    semantic_artifact_key(file, &prepared, lowerer.identity()).map(Some)
}

/// Materialize against exactly one prepared syntax snapshot.
///
/// The content digest, source origin, dialect, tree, and source mappings all
/// come from `prepared_syntax`; no second source read can race key derivation.
pub(crate) fn materialize_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    validate_semantic_file(analyzer, file)?;

    let max_source_bytes = request.budget.remaining().source_bytes;
    let prepared = match analyzer.prepared_syntax_limited(file, max_source_bytes) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            return Err(SemanticProviderError::source_access(format!(
                "could not prepare the current source snapshot for `{file}`"
            )));
        }
        Err(limit) => {
            let work = SemanticWork {
                source_bytes: limit.minimum_source_bytes(),
                ..SemanticWork::default()
            };
            let exceeded = request.budget.check(work).map_or_else(
                |exceeded| exceeded,
                |_| {
                    unreachable!(
                        "a source snapshot larger than the remaining source budget must exceed it"
                    )
                },
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
    };
    let source_work = SemanticWork {
        source_bytes: prepared.source().len(),
        ..SemanticWork::default()
    };

    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }
    let mut staged_budget = request.budget.clone();
    if let Err(exceeded) = staged_budget.charge(source_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work,
        });
    }

    let identity = lowerer.identity();
    let key = semantic_artifact_key(file, &prepared, identity)?;
    let (acquisition, _cache_wait) = cache.acquire(&key, request.cancellation);
    let permit = match acquisition {
        CompleteValueAcquisition::Cached { value: artifact } => {
            return publish_cached(artifact, source_work, staged_budget, request);
        }
        CompleteValueAcquisition::Leader { permit } => permit,
        CompleteValueAcquisition::Cancelled => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: source_work,
            });
        }
    };

    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }

    let lowered = lowerer.lower(file, &prepared, &staged_budget, request.cancellation)?;
    if request.cancellation.is_cancelled() {
        if let SemanticOutcome::Cancelled {
            partial: Some(_), ..
        } = &lowered
        {
            // A lowerer-supplied partial still has to pass ordinary publication
            // below before it can be retained by a cancelled outcome.
        } else {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: source_work.component_max(lowered.work()),
            });
        }
    }

    let outcome = publish_lowered(
        key,
        lowerer.capabilities(),
        lowered,
        source_work,
        staged_budget,
        request,
    );
    if let Ok(SemanticOutcome::Complete { value, .. }) = &outcome {
        permit.publish_complete(Arc::clone(value));
    }
    outcome
}

fn publish_cached(
    artifact: Arc<SemanticArtifact>,
    source_work: SemanticWork,
    mut staged_budget: super::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    if let Err(exceeded) = staged_budget.charge(artifact.work()) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work.component_max(artifact.work()),
        });
    }
    let work = source_work.component_max(artifact.work());
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work,
        });
    }
    *request.budget = staged_budget;
    Ok(SemanticOutcome::Complete {
        value: artifact,
        work,
    })
}

fn semantic_artifact_key(
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    identity: SemanticAdapterIdentity,
) -> Result<SemanticArtifactKey, SemanticProviderError> {
    let path = WorkspaceRelativePath::try_from_path(file.rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let content = ContentIdentity::hash_bytes(prepared.source().as_bytes());
    let revision = match prepared.origin() {
        PreparedSourceOrigin::Disk => SourceRevision::Disk { content },
        PreparedSourceOrigin::Overlay => {
            let revision = prepared.overlay_revision().ok_or_else(|| {
                SemanticProviderError::internal(
                    "prepared overlay source is missing its atomic revision token",
                )
            })?;
            SourceRevision::Overlay {
                content,
                snapshot: OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()),
            }
        }
    };
    Ok(SemanticArtifactKey::new(
        WorkspaceMountId::from_root(file.root()),
        path,
        prepared.dialect(),
        revision,
        identity.adapter,
        SemanticIrVersion::current(),
        identity.configuration,
        identity.dependencies,
    ))
}

fn publish_lowered(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    lowered: SemanticOutcome<Vec<ProcedureSemanticsParts>>,
    source_work: SemanticWork,
    mut staged_budget: super::SemanticBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    macro_rules! publish_parts {
        ($parts:expr, $work:expr) => {{
            match publish(
                key.clone(),
                capabilities.clone(),
                $parts,
                &mut staged_budget,
            )? {
                Publication::Artifact(artifact) => artifact,
                Publication::Exceeded(exceeded) => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work: source_work.component_max($work),
                    });
                }
            }
        }};
    }

    macro_rules! commit_non_cancelled {
        ($work:expr, $outcome:expr) => {{
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: $work,
                });
            }
            *request.budget = staged_budget;
            $outcome
        }};
    }

    match lowered {
        SemanticOutcome::Complete { value, work } => {
            let artifact = publish_parts!(value, work);
            let total_work = source_work
                .component_max(work)
                .component_max(artifact.work());
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            *request.budget = staged_budget;
            Ok(SemanticOutcome::Complete {
                work: total_work,
                value: artifact,
            })
        }
        SemanticOutcome::Ambiguous { candidates, work } => {
            let candidates = publish_parts!(candidates, work);
            let total_work = source_work
                .component_max(work)
                .component_max(candidates.work());
            commit_non_cancelled!(
                total_work,
                Ok(SemanticOutcome::Ambiguous {
                    candidates,
                    work: total_work,
                })
            )
        }
        SemanticOutcome::Unknown { partial, work } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unknown {
                        partial: Some(partial),
                        work: total_work,
                    })
                ),
                None => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unknown {
                        partial: None,
                        work: total_work,
                    })
                ),
            }
        }
        SemanticOutcome::Unsupported {
            capability,
            partial,
            work,
        } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unsupported {
                        capability,
                        partial: Some(partial),
                        work: total_work,
                    })
                ),
                None => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::Unsupported {
                        capability,
                        partial: None,
                        work: total_work,
                    })
                ),
            }
        }
        SemanticOutcome::Unproven { partial, work } => {
            let partial = publish_parts!(partial, work);
            let total_work = source_work
                .component_max(work)
                .component_max(partial.work());
            commit_non_cancelled!(
                total_work,
                Ok(SemanticOutcome::Unproven {
                    partial,
                    work: total_work,
                })
            )
        }
        SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => commit_non_cancelled!(
                    total_work,
                    Ok(SemanticOutcome::ExceededBudget {
                        partial: Some(partial),
                        exceeded,
                        work: total_work,
                    })
                ),
                None if request.cancellation.is_cancelled() => Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                }),
                None => Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work: total_work,
                }),
            }
        }
        SemanticOutcome::Cancelled { partial, work } => {
            let partial = match partial {
                Some(partial) => Some(publish_parts!(partial, work)),
                None => None,
            };
            let artifact_work = partial
                .as_ref()
                .map_or(SemanticWork::default(), |artifact| artifact.work());
            let total_work = source_work.component_max(work).component_max(artifact_work);
            match partial {
                Some(partial) => {
                    *request.budget = staged_budget;
                    Ok(SemanticOutcome::Cancelled {
                        partial: Some(partial),
                        work: total_work,
                    })
                }
                None => Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                }),
            }
        }
    }
}

enum Publication {
    Artifact(Arc<SemanticArtifact>),
    Exceeded(super::SemanticBudgetExceeded),
}

fn publish(
    key: SemanticArtifactKey,
    capabilities: SemanticCapabilities,
    parts: Vec<ProcedureSemanticsParts>,
    budget: &mut super::SemanticBudget,
) -> Result<Publication, SemanticProviderError> {
    match SemanticArtifact::try_new_with_budget(key, capabilities, parts, budget) {
        Ok(artifact) => Ok(Publication::Artifact(Arc::new(artifact))),
        Err(SemanticArtifactBuildError::Invalid(error)) => {
            Err(SemanticProviderError::InvalidArtifact(error))
        }
        Err(SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
            Ok(Publication::Exceeded(exceeded))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Condvar, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::analyzer::semantic::SemanticBudget;
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::analyzer::{IAnalyzer, Language, OverlayProject, TestProject};

    #[derive(Clone, Copy)]
    enum FakeMode {
        Complete,
        PartialThenComplete,
        Cancel,
        CancelUnknownPartial,
        CancelWithPartial,
    }

    struct FakeLowerer {
        calls: AtomicUsize,
        mode: FakeMode,
    }

    impl FakeLowerer {
        fn new(mode: FakeMode) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                mode,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ProgramSemanticsLowerer for FakeLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("fake-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"fake-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"fake-dependencies"),
            }
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            match self.mode {
                FakeMode::Complete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete if call == 0 => Ok(SemanticOutcome::Unknown {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
                FakeMode::PartialThenComplete => Ok(SemanticOutcome::Complete {
                    value: Vec::new(),
                    work: SemanticWork::default(),
                }),
                FakeMode::Cancel => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Complete {
                        value: Vec::new(),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelUnknownPartial => {
                    cancellation.cancel();
                    Ok(SemanticOutcome::Unknown {
                        partial: Some(Vec::new()),
                        work: SemanticWork::default(),
                    })
                }
                FakeMode::CancelWithPartial => Ok(SemanticOutcome::Cancelled {
                    partial: Some(Vec::new()),
                    work: SemanticWork::default(),
                }),
            }
        }
    }

    struct IdentityOnlyLowerer(SemanticAdapterIdentity);

    impl ProgramSemanticsLowerer for IdentityOnlyLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            self.0.clone()
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            panic!("artifact-key lookup must not invoke semantic lowering")
        }
    }

    struct BlockingLowerer {
        calls: AtomicUsize,
        entered: mpsc::Sender<()>,
        released: Mutex<bool>,
        release: Condvar,
    }

    impl BlockingLowerer {
        fn new(entered: mpsc::Sender<()>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                entered,
                released: Mutex::new(false),
                release: Condvar::new(),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn release(&self) {
            *self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned") = true;
            self.release.notify_all();
        }
    }

    impl ProgramSemanticsLowerer for BlockingLowerer {
        fn identity(&self) -> SemanticAdapterIdentity {
            SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("blocking-typescript", b"v1")
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(b"blocking-config"),
                dependencies: DependencyFingerprint::hash_bytes(b"blocking-dependencies"),
            }
        }

        fn capabilities(&self) -> SemanticCapabilities {
            SemanticCapabilities::default()
        }

        fn lower(
            &self,
            _file: &ProjectFile,
            _prepared: &PreparedSyntaxTree,
            _budget: &SemanticBudget,
            _cancellation: &super::super::CancellationToken,
        ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.entered
                .send(())
                .expect("blocking lowerer entry receiver");
            let mut released = self
                .released
                .lock()
                .expect("blocking lowerer mutex poisoned");
            while !*released {
                released = self
                    .release
                    .wait(released)
                    .expect("blocking lowerer mutex poisoned while waiting");
            }
            Ok(SemanticOutcome::Complete {
                value: Vec::new(),
                work: SemanticWork::default(),
            })
        }
    }

    fn write_file(root: &std::path::Path, rel: &str, contents: &str) -> ProjectFile {
        let file = ProjectFile::new(root.to_path_buf(), rel);
        file.write(contents).expect("write fixture");
        file
    }

    fn analyzer(root: &std::path::Path) -> TreeSitterAnalyzer<TypescriptAdapter> {
        TreeSitterAnalyzer::new(
            Arc::new(TestProject::new(root.to_path_buf(), Language::TypeScript)),
            TypescriptAdapter,
        )
    }

    fn materialize(
        analyzer: &TreeSitterAnalyzer<TypescriptAdapter>,
        cache: &CompleteSemanticArtifactCache,
        lowerer: &dyn ProgramSemanticsLowerer,
        file: &ProjectFile,
        budget: &mut SemanticBudget,
        cancellation: &super::super::CancellationToken,
    ) -> SemanticOutcome<Arc<SemanticArtifact>> {
        materialize_with_lowerer(
            analyzer,
            cache,
            lowerer,
            file,
            &mut SemanticRequest::new(budget, cancellation),
        )
        .expect("materialization")
    }

    fn wait_for_waiter(cache: &CompleteSemanticArtifactCache) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count() == 0 {
            assert!(
                Instant::now() < deadline,
                "same-key request did not enter the single-flight wait"
            );
            thread::yield_now();
        }
    }

    fn assert_source_and_artifact_charged(
        budget: &SemanticBudget,
        file: &ProjectFile,
        artifact: &SemanticArtifact,
    ) {
        let mut retained = budget.used();
        assert_eq!(
            retained.source_bytes,
            file.read_to_string().expect("fixture source").len()
        );
        retained.source_bytes = 0;
        assert_eq!(retained, artifact.work());
    }

    #[test]
    fn current_artifact_key_tracks_source_adapter_and_configuration_without_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let identity = |adapter: &[u8], configuration: &[u8], dependencies: &[u8]| {
            IdentityOnlyLowerer(SemanticAdapterIdentity {
                adapter: AdapterSemanticsVersion::hash_bytes("identity-only", adapter)
                    .expect("adapter name"),
                configuration: ConfigurationFingerprint::hash_bytes(configuration),
                dependencies: DependencyFingerprint::hash_bytes(dependencies),
            })
        };

        let baseline_lowerer = identity(b"adapter-v1", b"config-v1", b"dependencies-v1");
        assert_eq!(
            current_artifact_key_with_lowerer(
                &analyzer,
                &baseline_lowerer,
                &file,
                "export const value = 1;\n".len() - 1,
            )
            .expect("bounded key lookup"),
            None
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let baseline =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("baseline key lookup")
                .expect("baseline key");
        let adapter_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v2", b"config-v1", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("adapter key lookup")
        .expect("adapter key");
        let configuration_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v2", b"dependencies-v1"),
            &file,
            usize::MAX,
        )
        .expect("configuration key lookup")
        .expect("configuration key");
        let dependencies_changed = current_artifact_key_with_lowerer(
            &analyzer,
            &identity(b"adapter-v1", b"config-v1", b"dependencies-v2"),
            &file,
            usize::MAX,
        )
        .expect("dependency key lookup")
        .expect("dependency key");

        assert_ne!(baseline, adapter_changed);
        assert_ne!(baseline, configuration_changed);
        assert_ne!(baseline, dependencies_changed);

        file.write("export const value = 2;\n")
            .expect("rewrite fixture");
        let source_changed =
            current_artifact_key_with_lowerer(&analyzer, &baseline_lowerer, &file, usize::MAX)
                .expect("updated source key lookup")
                .expect("updated source key");
        assert_ne!(baseline, source_changed);
    }

    #[test]
    fn current_artifact_key_matches_materialization_without_running_the_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let current = current_artifact_key_with_lowerer(&analyzer, &lowerer, &file, usize::MAX)
            .expect("current artifact key lookup")
            .expect("current artifact key");
        assert_eq!(lowerer.calls(), 0);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("complete artifact")
        };
        assert_eq!(value.key(), &current);
        assert_eq!(lowerer.calls(), 1);
    }

    #[test]
    fn complete_cache_reuses_arc_but_charges_each_request() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export function main() {}\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut first_budget = SemanticBudget::default();
        let first = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut first_budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: first, .. } = first else {
            panic!("first complete artifact")
        };
        assert_source_and_artifact_charged(&first_budget, &file, &first);

        let mut second_budget = SemanticBudget::default();
        let second = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut second_budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value: second, .. } = second else {
            panic!("cached complete artifact")
        };
        assert!(Arc::ptr_eq(&first, &second));
        assert_source_and_artifact_charged(&second_budget, &file, &second);
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn complete_cache_capacity_is_retained_bytes_not_entry_count() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let first_file = write_file(&root, "src/first.ts", "export const value = 1;\n");
        let second_file = write_file(&root, "src/other.ts", "export const value = 2;\n");
        let analyzer = analyzer(&root);
        let staging_cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &first_file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("first artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &staging_cache,
            &lowerer,
            &second_file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("second artifact")
        };

        let first_weight = retained_artifact_bytes(first.key(), &first);
        let second_weight = retained_artifact_bytes(second.key(), &second);
        assert_eq!(first_weight, second_weight, "equal-sized fixtures");
        assert!(first_weight > 1);
        let cache = CompleteSemanticArtifactCache::new(first_weight);
        cache.insert(first.key().clone(), Arc::clone(&first));
        cache.insert(second.key().clone(), Arc::clone(&second));

        assert_eq!(cache.len(), 1, "two byte-weighted entries exceed capacity");
    }

    #[test]
    fn analyzer_update_preserves_unchanged_content_keyed_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let unchanged = write_file(&root, "src/unchanged.ts", "export const stable = 1;\n");
        let changed = write_file(&root, "src/changed.ts", "export const changing = 1;\n");
        let analyzer = analyzer(&root);
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: before, .. } = analyzer
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("initial materialization")
        else {
            panic!("initial complete artifact")
        };

        changed
            .write("export const changing = 2;\n")
            .expect("update changed fixture");
        let updated = analyzer.update(&BTreeSet::from([changed]));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: after, .. } = updated
            .materialize_semantics_with_lowerer(
                &lowerer,
                &unchanged,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("post-update materialization")
        else {
            panic!("post-update complete artifact")
        };

        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(lowerer.calls(), 1);
    }

    #[test]
    fn concurrent_same_key_materialization_runs_one_lowerer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::new(1);
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });

        wait_for_waiter(&cache);
        assert_eq!(lowerer.calls(), 1);
        lowerer.release();
        let SemanticOutcome::Complete {
            value: first_value, ..
        } = first.join().expect("first materialization thread")
        else {
            panic!("first complete artifact")
        };
        let SemanticOutcome::Complete {
            value: second_value,
            ..
        } = second.join().expect("second materialization thread")
        else {
            panic!("second complete artifact")
        };
        assert!(Arc::ptr_eq(&first_value, &second_value));
        assert_eq!(lowerer.calls(), 1);
        assert_eq!(
            cache.len(),
            0,
            "an oversize artifact is shared with current waiters but not retained"
        );
    }

    #[test]
    fn cancelled_same_key_waiter_does_not_publish_or_lower() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let lowerer = Arc::new(BlockingLowerer::new(entered_tx));

        let first_analyzer = analyzer.clone();
        let first_cache = cache.clone();
        let first_file = file.clone();
        let first_lowerer = Arc::clone(&lowerer);
        let first = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            materialize(
                &first_analyzer,
                &first_cache,
                first_lowerer.as_ref(),
                &first_file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first lowerer entry");

        let cancellation = super::super::CancellationToken::default();
        let waiter_cancellation = cancellation.clone();
        let second_analyzer = analyzer.clone();
        let second_cache = cache.clone();
        let second_file = file.clone();
        let second_lowerer = Arc::clone(&lowerer);
        let second = thread::spawn(move || {
            let mut budget = SemanticBudget::default();
            let outcome = materialize(
                &second_analyzer,
                &second_cache,
                second_lowerer.as_ref(),
                &second_file,
                &mut budget,
                &waiter_cancellation,
            );
            (outcome, budget.used())
        });

        wait_for_waiter(&cache);
        cancellation.cancel();
        let (outcome, used) = second.join().expect("cancelled waiter thread");
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(used, SemanticWork::default());
        assert_eq!(lowerer.calls(), 1);

        lowerer.release();
        assert!(
            first
                .join()
                .expect("leader materialization thread")
                .is_complete()
        );
        assert_eq!(lowerer.calls(), 1);
    }

    #[test]
    fn dialect_and_source_origin_are_part_of_snapshot_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let source = "export const value = 1;\n";
        let ts = write_file(&root, "src/same.ts", source);
        let tsx = write_file(&root, "src/same.tsx", source);
        let base: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: disk, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("disk artifact")
        };
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: tsx_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &tsx,
            &mut budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("tsx artifact")
        };
        assert_ne!(disk.key().language(), tsx_artifact.key().language());

        assert!(overlay.set(ts.abs_path(), source.to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete {
            value: overlay_artifact,
            ..
        } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &ts,
            &mut budget,
            &super::super::CancellationToken::default(),
        )
        else {
            panic!("overlay artifact")
        };
        assert_ne!(disk.key(), overlay_artifact.key());
        assert!(matches!(disk.key().revision(), SourceRevision::Disk { .. }));
        assert!(matches!(
            overlay_artifact.key().revision(),
            SourceRevision::Overlay { .. }
        ));
    }

    #[test]
    fn adjacent_overlay_revisions_do_not_reuse_stale_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 0;\n");
        let base: Arc<dyn crate::analyzer::Project> =
            Arc::new(TestProject::new(root.clone(), Language::TypeScript));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer = TreeSitterAnalyzer::new(overlay.clone(), TypescriptAdapter);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);

        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: first, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "export const value = 2;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: second, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("second overlay")
        };

        assert_ne!(first.key().revision(), second.key().revision());
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(overlay.set(file.abs_path(), "export const value = 1;\n".to_string()));
        let mut budget = SemanticBudget::default();
        let SemanticOutcome::Complete { value: third, .. } = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        ) else {
            panic!("third overlay")
        };
        assert_ne!(first.key().revision(), third.key().revision());
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(lowerer.calls(), 3);
    }

    #[test]
    fn cancellation_discards_unpublished_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Cancel);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn independently_validated_cancelled_partial_is_charged_but_not_cached() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelWithPartial);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        let SemanticOutcome::Cancelled {
            partial: Some(partial),
            ..
        } = outcome
        else {
            panic!("validated lowerer partial should survive cancellation")
        };
        assert_source_and_artifact_charged(&budget, &file, &partial);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cancellation_discards_non_cancelled_partial_outcomes_without_charging() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::CancelUnknownPartial);
        let cancellation = super::super::CancellationToken::default();
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn source_limit_is_enforced_before_parsing_or_lowering() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = 8;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, work, .. }
                if work.source_bytes > 8
        ));
        assert_eq!(lowerer.calls(), 0);
        assert_eq!(budget.used(), SemanticWork::default());
    }

    #[test]
    fn empty_source_is_a_valid_exact_snapshot() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/empty.ts", "");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut budget = SemanticBudget::default();

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("empty TypeScript source should publish an empty complete artifact")
        };
        assert!(value.procedures().is_empty());
        assert_source_and_artifact_charged(&budget, &file, &value);
    }

    #[test]
    fn concrete_provider_rejects_foreign_roots_and_languages_before_source_access() {
        let first = tempfile::tempdir().expect("first temp dir");
        let second = tempfile::tempdir().expect("second temp dir");
        let root = first.path().canonicalize().expect("first root");
        let foreign_root = second.path().canonicalize().expect("second root");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let cancellation = super::super::CancellationToken::default();

        for file in [
            ProjectFile::new(foreign_root, "src/main.ts"),
            ProjectFile::new(root.clone(), "src/Main.java"),
        ] {
            let mut budget = SemanticBudget::default();
            let error = materialize_with_lowerer(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect_err("foreign file identity should be rejected");
            assert!(matches!(error, SemanticProviderError::InvalidIdentity(_)));
            assert_eq!(budget.used(), SemanticWork::default());
        }
        assert_eq!(lowerer.calls(), 0);
    }

    #[test]
    fn partial_artifacts_are_charged_once_but_never_cached_as_complete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::PartialThenComplete);

        let mut budget = SemanticBudget::default();
        let first = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        assert!(matches!(
            first,
            SemanticOutcome::Unknown {
                partial: Some(_),
                ..
            }
        ));
        assert_eq!(cache.len(), 0);

        let mut budget = SemanticBudget::default();
        assert!(
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
            .is_complete()
        );
        let mut budget = SemanticBudget::default();
        assert!(
            materialize(
                &analyzer,
                &cache,
                &lowerer,
                &file,
                &mut budget,
                &super::super::CancellationToken::default(),
            )
            .is_complete()
        );
        assert_eq!(lowerer.calls(), 2);
    }

    #[test]
    fn retained_payload_budget_failure_is_atomic() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("root");
        let file = write_file(&root, "src/main.ts", "export const value = 1;\n");
        let analyzer = analyzer(&root);
        let cache = CompleteSemanticArtifactCache::default();
        let lowerer = FakeLowerer::new(FakeMode::Complete);
        let mut limits = SemanticBudget::default().limits();
        limits.owned_text_bytes = 1;
        let mut budget = SemanticBudget::new(limits).expect("positive limits");

        let outcome = materialize(
            &analyzer,
            &cache,
            &lowerer,
            &file,
            &mut budget,
            &super::super::CancellationToken::default(),
        );
        assert!(matches!(
            outcome,
            SemanticOutcome::ExceededBudget { partial: None, .. }
        ));
        assert_eq!(budget.used(), SemanticWork::default());
        assert_eq!(cache.len(), 0);
    }
}
