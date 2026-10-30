//! Every workspace authority read names its inputs, including memo hits.
use super::read_ledger::{FactSubject, LookupKind, ReadKey, WorkspaceFactFamily};
use super::{IAnalyzer, Language, read_attribution_records_reads};
use crate::analyzer::semantic::ids::StableDigest;

/// The complete certificate for an authority answer.
pub enum AuthorityInputs<'a> {
    SourceOf(&'a [Language]),
    SourceAndFiles {
        languages: &'a [Language],
        /// Non-source inputs, including absent candidate paths.
        files: Arc<[ReadKey]>,
    },
    Fact {
        language: Language,
        subject: FactSubject,
        answer: StableDigest,
    },
    Unnamed,
}

use brokk_bifrost_core::analyzer::memo_attribution::{
    AuthorityRecorder, CapturedMemoReads, MemoAttribution, MemoCapability,
};
pub use brokk_bifrost_core::analyzer::memo_attribution::{
    CaptureIdentity, CaptureScopedMemo, PendingMemo, ReplayingMemo, ReplayingMemoEntry,
};
use std::sync::Arc;

pub type WorkspaceAuthorityMemo<M> =
    brokk_bifrost_core::analyzer::memo_attribution::WorkspaceAuthorityMemo<M, WorkspaceFactFamily>;

/// Bind core-only JS/TS configuration and receiver reads to this analyzer.
/// The resolver calls this on warm reads and after collecting new probes.
pub fn js_ts_configuration_read_recorder<A: super::LanguageAdapter>(
    analyzer: &super::TreeSitterAnalyzer<A>,
    language: Language,
) -> brokk_bifrost_js_ts::tsconfig::JsTsConfigurationReadRecorder {
    use brokk_bifrost_js_ts::tsconfig::JsTsReadAuthority;
    let analyzer: Arc<dyn IAnalyzer> = Arc::new(analyzer.clone_for_read_attribution());
    Arc::new(move |authority, paths| {
        let capability = memo_attribution(analyzer.as_ref());
        if !capability.is_capturing() {
            return;
        }
        if capability.capture_identity().is_none() {
            capability.record_unattributed();
        }
        if let JsTsReadAuthority::UnresolvedModulePaths { language, paths } = &authority {
            for file in paths {
                analyzer.record_read(ReadKey::path_absent(
                    *language,
                    brokk_bifrost_core::path_utils::rel_path_string(file),
                ));
            }
            return;
        }
        let precise = match &authority {
            JsTsReadAuthority::ModulePathCandidates {
                file,
                specifier,
                answer,
            } => Some((
                FactSubject::FileNamedMember {
                    rel_path: brokk_bifrost_core::path_utils::rel_path_string(file).into(),
                    owner: "".into(),
                    member: specifier.clone().into(),
                    environment: None,
                },
                *answer,
            )),
            JsTsReadAuthority::LibrarySelection { file, answer } => Some((
                FactSubject::File {
                    rel_path: brokk_bifrost_core::path_utils::rel_path_string(file).into(),
                },
                *answer,
            )),
            _ => None,
        };
        if let Some((subject, answer)) = precise {
            let inputs = match answer {
                Some(answer) => AuthorityInputs::Fact {
                    language,
                    subject,
                    answer: StableDigest::from_array(answer),
                },
                None => AuthorityInputs::Unnamed,
            };
            record_workspace_authority_read(
                analyzer.as_ref(),
                WorkspaceFactFamily::JsTsModulePaths,
                inputs,
            );
            return;
        }
        let family = match authority {
            JsTsReadAuthority::UnresolvedModulePaths { .. }
            | JsTsReadAuthority::ModulePaths
            | JsTsReadAuthority::ModulePathCandidates { .. }
            | JsTsReadAuthority::LibrarySelection { .. } => WorkspaceFactFamily::JsTsModulePaths,
            JsTsReadAuthority::WorkspacePackages { .. } => {
                WorkspaceFactFamily::JsTsWorkspacePackages
            }
            JsTsReadAuthority::ReceiverMembers => WorkspaceFactFamily::JsTsReceiverMembers,
            JsTsReadAuthority::JsxPropsOwners => WorkspaceFactFamily::JsTsJsxPropsOwners,
            JsTsReadAuthority::JsxComponentOwners => WorkspaceFactFamily::JsTsJsxComponentOwners,
        };
        if let JsTsReadAuthority::WorkspacePackages { answer } = authority {
            record_workspace_authority_read(
                analyzer.as_ref(),
                family,
                AuthorityInputs::Fact {
                    language,
                    subject: FactSubject::Whole,
                    answer: StableDigest::from_array(answer),
                },
            );
            return;
        }
        let root = analyzer.project().root().to_path_buf();
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        let files = paths
            .iter()
            .filter_map(|path| {
                // Escaping extends candidates are refused before their contents can
                // influence resolution. Their external paths are not workspace inputs.
                let relative = path
                    .strip_prefix(&root)
                    .or_else(|_| path.strip_prefix(&canonical_root))
                    .ok()?;
                let rel_path = crate::path_utils::workspace_relative_slash_path(relative);
                if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 1024 * 1024) {
                    // Resolution rejects oversized configuration inputs too. Refuse
                    // publication without allocating their unbounded contents.
                    capability.record_unattributed();
                    return None;
                }
                match std::fs::read(path) {
                    Ok(bytes) => Some(ReadKey::file(
                        language,
                        rel_path,
                        git2::Oid::hash_object(git2::ObjectType::Blob, &bytes)
                            .expect("hashing configuration bytes"),
                    )),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Some(ReadKey::path_absent(language, rel_path))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => {
                        Some(ReadKey::path_absent(language, rel_path))
                    }
                    Err(_) => {
                        capability.record_unattributed();
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        record_workspace_authority_read(
            analyzer.as_ref(),
            family,
            AuthorityInputs::SourceAndFiles {
                languages: &[Language::JavaScript, Language::TypeScript],
                files: files.into(),
            },
        );
    })
}

/// The only implementation of the core attribution backend.
pub struct AnalyzerMemoAttribution<'a> {
    analyzer: &'a dyn IAnalyzer,
}

/// Refuse a wrapper's no-op ledger defaults instead of silently losing reads.
/// Check the thread ledger directly: calling the broken wrapper to record the
/// refusal would lose that refusal too. Healthy reads need no ledger clone.
fn checked_read_ledger_attachment(analyzer: &dyn IAnalyzer) -> bool {
    let attached = analyzer.read_ledger_attached();
    if !analyzer.records_query_reads() {
        let thread_ledger = super::i_analyzer::innermost_read_ledger();
        if attached || thread_ledger.is_some() {
            if let Some(ledger) = thread_ledger {
                ledger.record_unattributed();
            } else {
                analyzer.record_unattributed_read();
            }
            debug_assert!(
                analyzer.records_query_reads(),
                "an analyzer used under capture must forward query read-ledger operations"
            );
        }
    }
    attached
}

pub fn memo_attribution(analyzer: &dyn IAnalyzer) -> MemoCapability<AnalyzerMemoAttribution<'_>> {
    checked_read_ledger_attachment(analyzer);
    MemoCapability::new(AnalyzerMemoAttribution { analyzer })
}

/// An owned recording view of the query's analyzer. This never uses an
/// ordinary analyzer clone, whose active-query registry would be empty.
#[derive(Clone)]
pub struct OwnedMemoCapability {
    analyzer: Arc<dyn IAnalyzer>,
}

impl std::fmt::Debug for OwnedMemoCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // IAnalyzer is not Debug. Identify the recording destination and its
        // current capture instead of requiring every language adapter to be Debug.
        f.debug_struct("OwnedMemoCapability")
            .field("analyzer", &Arc::as_ptr(&self.analyzer))
            .field("capture", &self.capability().capture_identity())
            .finish()
    }
}

pub fn owned_memo_attribution(analyzer: Arc<dyn IAnalyzer>) -> OwnedMemoCapability {
    OwnedMemoCapability { analyzer }
}

/// A recording-only view shares query registration with this exact generation.
pub fn workspace_memo_attribution(workspace: &super::WorkspaceAnalyzer) -> OwnedMemoCapability {
    owned_memo_attribution(recording_view(workspace))
}

/// Ordinary workspace clones open a fresh registry. A recording view must
/// share the original registry so broadcast and helper-thread reads survive.
fn recording_view(workspace: &super::WorkspaceAnalyzer) -> Arc<dyn IAnalyzer> {
    match workspace {
        super::WorkspaceAnalyzer::Multi(analyzer) => {
            Arc::new(analyzer.clone_for_read_attribution())
        }
        super::WorkspaceAnalyzer::Empty(analyzer) => {
            Arc::new(analyzer.clone_for_read_attribution())
        }
    }
}

impl OwnedMemoCapability {
    pub fn capability(&self) -> MemoCapability<AnalyzerMemoAttribution<'_>> {
        memo_attribution(self.analyzer.as_ref())
    }

    pub fn analyzer(&self) -> &dyn IAnalyzer {
        checked_read_ledger_attachment(self.analyzer.as_ref());
        self.analyzer.as_ref()
    }
}

impl MemoAttribution for AnalyzerMemoAttribution<'_> {
    type Key = ReadKey;
    fn is_capturing(&self) -> bool {
        let attached = checked_read_ledger_attachment(self.analyzer);
        read_attribution_records_reads(|| attached)
    }
    fn capture_identity(&self) -> Option<CaptureIdentity> {
        checked_read_ledger_attachment(self.analyzer);
        super::i_analyzer::innermost_read_ledger().map(|ledger| ledger.capture_identity())
    }
    fn record_unattributed(&self) {
        checked_read_ledger_attachment(self.analyzer);
        self.analyzer.record_unattributed_read();
    }
    fn capture<T>(
        &self,
        build: impl FnOnce() -> T,
    ) -> (T, CapturedMemoReads<ReadKey>, Option<CaptureIdentity>) {
        let forwarded_to =
            super::i_analyzer::innermost_read_ledger().map(|ledger| ledger.capture_identity());
        let (value, reads) = super::capture_query_reads(self.analyzer, || {
            // Even a cold build with no outer capture opens its own capture.
            checked_read_ledger_attachment(self.analyzer);
            build()
        });
        (
            value,
            CapturedMemoReads {
                keys: Arc::from(reads.unordered_keys()),
                unattributed_reads: reads.unattributed_reads(),
                execution_dependences: reads.execution_dependences(),
            },
            forwarded_to,
        )
    }
    fn capture_authority<T>(&self, build: impl FnOnce() -> T) -> (T, CapturedMemoReads<ReadKey>) {
        let enclosing = super::i_analyzer::innermost_read_ledger();
        let (value, reads) = super::i_analyzer::capture_with_read_ledger_scope(
            self.analyzer,
            enclosing.as_ref(),
            || {
                checked_read_ledger_attachment(self.analyzer);
                build()
            },
        );
        (
            value,
            CapturedMemoReads {
                keys: Arc::from(reads.unordered_keys()),
                unattributed_reads: reads.unattributed_reads(),
                execution_dependences: reads.execution_dependences(),
            },
        )
    }
    fn replay(&self, reads: &CapturedMemoReads<ReadKey>) {
        checked_read_ledger_attachment(self.analyzer);
        super::i_analyzer::replay_shared_query_read_receipt(
            self.analyzer,
            &reads.keys,
            reads.unattributed_reads,
            reads.execution_dependences,
        );
    }
}
impl<'a> AuthorityRecorder<WorkspaceFactFamily, AuthorityInputs<'a>>
    for AnalyzerMemoAttribution<'_>
{
    fn record_authority(
        &self,
        family: &WorkspaceFactFamily,
        inputs: AuthorityInputs<'a>,
        reads: CapturedMemoReads<ReadKey>,
    ) {
        if matches!(&inputs, AuthorityInputs::Fact { .. }) {
            super::i_analyzer::replay_query_read_receipt(
                self.analyzer,
                [],
                reads.unattributed_reads,
                reads.execution_dependences,
            );
        } else {
            self.replay(&reads);
        }
        record_workspace_authority_read(self.analyzer, *family, inputs);
    }
}

/// Name one raw project-file input, including an absent candidate path.
/// Read failures other than absence refuse the enclosing authority certificate.
pub fn workspace_authority_file_input(
    analyzer: &dyn IAnalyzer,
    language: Language,
    rel_path: &str,
) -> Option<ReadKey> {
    let file = super::ProjectFile::new(analyzer.project().root().to_path_buf(), rel_path);
    match analyzer.project().read_source_snapshot(&file) {
        Ok(snapshot) => Some(ReadKey::file(language, rel_path, snapshot.oid())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Some(ReadKey::path_absent(language, rel_path))
        }
        Err(error) => {
            analyzer.record_query_failure(super::store::StoreError::new(format!(
                "reading authority input {file:?}: {error}"
            )));
            None
        }
    }
}

/// Certificate funnel for workspace authorities without a memo wrapper.
pub fn record_workspace_authority_read(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    inputs: AuthorityInputs<'_>,
) {
    let attached = checked_read_ledger_attachment(analyzer);
    if !read_attribution_records_reads(|| attached) {
        return;
    }
    match inputs {
        AuthorityInputs::SourceOf(languages) => {
            analyzer.record_read(analyzer.workspace_scope_read_key(languages));
        }
        AuthorityInputs::SourceAndFiles { languages, files } => {
            analyzer.record_read(analyzer.workspace_scope_read_key(languages));
            for key in files.iter() {
                assert!(
                    matches!(key, ReadKey::File { .. } | ReadKey::PathAbsent { .. }),
                    "non-source authority inputs must name files or absent paths"
                );
                analyzer.record_read(key.clone());
            }
        }
        AuthorityInputs::Fact {
            language,
            subject,
            answer,
        } => {
            analyzer.record_read(ReadKey::lookup(
                LookupKind::WorkspaceFact,
                super::LookupQuestion::WorkspaceFact {
                    family,
                    language,
                    subject,
                },
                answer,
            ));
        }
        AuthorityInputs::Unnamed => analyzer.record_unattributed_read(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{MultiAnalyzer, capture_query_reads};
    use std::convert::Infallible;
    use std::sync::OnceLock;

    #[test]
    fn owned_memo_reads_reach_the_owner_on_untransported_helper_threads() {
        let analyzer = Arc::new(MultiAnalyzer::default());
        let attribution = owned_memo_attribution(analyzer.clone());
        let memo = ReplayingMemo::new(OnceLock::new());
        let key = ReadKey::Configuration(StableDigest::sha256(b"owned memo input"));
        let read = || {
            let result = memo
                .read(&attribution.capability(), |cell, capture| {
                    Ok::<_, Infallible>(Arc::clone(cell.get_or_init(|| {
                        Arc::new(capture.build(|| {
                            analyzer.record_read(key.clone());
                            17
                        }))
                    })))
                })
                .unwrap();
            assert_eq!(*result, 17);
        };
        let (_, fill_reads) = capture_query_reads(analyzer.as_ref(), read);
        assert_eq!(fill_reads.keys(), vec![key.clone()]);
        assert_eq!(fill_reads.unattributed_reads(), 0);
        let (_, hit_reads) = capture_query_reads(analyzer.as_ref(), || {
            std::thread::scope(|threads| {
                threads.spawn(read).join().expect("memo reader panicked");
            });
        });
        assert_eq!(hit_reads.keys(), vec![key]);
        // This thread has no transported capture identity. The owned analyzer
        // still reaches the consumer and refuses to certify that detached hit.
        assert_eq!(hit_reads.unattributed_reads(), 1);
    }

    #[test]
    fn memo_reads_replay_after_an_uncaptured_build() {
        let analyzer = MultiAnalyzer::default();
        let attribution = memo_attribution(&analyzer);
        let memo = ReplayingMemo::new(OnceLock::new());
        let key = ReadKey::Configuration(StableDigest::sha256(b"memo input"));
        let read = || {
            let result = memo
                .read(&attribution, |cell, capture| {
                    Ok::<_, Infallible>(Arc::clone(cell.get_or_init(|| {
                        Arc::new(capture.build(|| {
                            analyzer.record_read(key.clone());
                            for _ in 0..3 {
                                analyzer.record_unattributed_read();
                                analyzer.mark_execution_dependent();
                            }
                            17
                        }))
                    })))
                })
                .unwrap();
            assert_eq!(*result, 17);
        };
        assert!(!analyzer.read_ledger_attached());
        read();
        assert!(!analyzer.read_ledger_attached());
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, read);
            assert_eq!(reads.keys(), vec![key.clone()]);
            assert_eq!(reads.unattributed_reads(), 3);
            assert_eq!(reads.execution_dependences(), 3);
        }
        // A build on an ordinary helper thread has no transported parent
        // frame. Its keys must reach the capture when the selected entry returns.
        let threaded = ReplayingMemo::new(OnceLock::new());
        let (_, reads) = capture_query_reads(&analyzer, || {
            let result = threaded
                .read(&attribution, |cell, capture| {
                    std::thread::scope(|threads| {
                        threads
                            .spawn(|| {
                                Ok::<_, Infallible>(Arc::clone(cell.get_or_init(|| {
                                    Arc::new(capture.build(|| {
                                        analyzer.record_read(key.clone());
                                        analyzer.record_unattributed_read();
                                        19
                                    }))
                                })))
                            })
                            .join()
                            .expect("memo build helper panicked")
                    })
                })
                .unwrap();
            assert_eq!(*result, 19);
        });
        assert_eq!(reads.keys(), vec![key.clone()]);
        assert_eq!(reads.unattributed_reads(), 1);
        let mut mutable = ReplayingMemo::default();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, || {
                let result = mutable
                    .read_mut(&attribution, |slot: &mut Option<Arc<_>>, capture| {
                        Ok::<_, Infallible>(Arc::clone(slot.get_or_insert_with(|| {
                            Arc::new(capture.build(|| {
                                analyzer.record_read(key.clone());
                                analyzer.record_unattributed_read();
                                29
                            }))
                        })))
                    })
                    .unwrap();
                assert_eq!(*result, 29);
            });
            assert_eq!(reads.keys(), vec![key.clone()]);
            assert_eq!(reads.unattributed_reads(), 1);
        }
        assert_eq!(
            mutable.clone().account(|slot| usize::from(slot.is_some())),
            1
        );
        let mut pending: PendingMemo<Vec<usize>> = PendingMemo::default();
        let (_, reads) = capture_query_reads(&analyzer, || {
            pending.read_mut(&attribution, |values| values.push(31));
            pending.read(&attribution, |values| assert_eq!(values, &[31]));
        });
        assert_eq!(reads.unattributed_reads(), 2);
        assert_eq!(pending.clone().account(Vec::len), 1);
        let mut authority =
            WorkspaceAuthorityMemo::new(WorkspaceFactFamily::FieldSlots, Vec::new());
        let (_, reads) = capture_query_reads(&analyzer, || {
            authority.read_mut(
                &attribution,
                |values| {
                    values.push(37);
                    analyzer.record_read(key.clone());
                    analyzer.record_unattributed_read();
                },
                |_| AuthorityInputs::Fact {
                    language: Language::Python,
                    subject: FactSubject::Whole,
                    answer: StableDigest::sha256(b"authority answer"),
                },
            );
        });
        assert_eq!(reads.unattributed_reads(), 1);
        assert!(
            !reads.keys().contains(&key),
            "Fact suppresses implementation keys"
        );
        assert_eq!(reads.keys().len(), 1);
        assert_eq!(authority.clone().account(Vec::len), 1);
        // Neither construction nor a byte census outside capture taints a memo.
        let mut scoped: CaptureScopedMemo<Vec<usize>> = CaptureScopedMemo::default();
        assert_eq!(scoped.account(Vec::len), 0);
        let (_, first) = capture_query_reads(&analyzer, || {
            scoped.read_mut(&attribution, |values| values.push(41));
            scoped
                .clone()
                .read(&attribution, |values| assert_eq!(values, &[41]));
        });
        assert_eq!(first.unattributed_reads(), 0);
        let tainted = CaptureScopedMemo::new(OnceLock::new());
        tainted.read(&attribution, |cell| {
            cell.get_or_init(|| 43);
        });
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, || {
                tainted.read(&attribution, |cell| assert_eq!(cell.get(), Some(&43)));
            });
            assert_eq!(reads.unattributed_reads(), 1);
        }
        let scoped = CaptureScopedMemo::new(OnceLock::new());
        let (_, outer) = capture_query_reads(&analyzer, || {
            scoped.read(&attribution, |cell| {
                cell.get_or_init(|| 23);
            });
            let (_, sibling) = capture_query_reads(&analyzer, || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    scoped.read(&attribution, |cell| cell.get().copied())
                }));
                assert_eq!(result.is_err(), cfg!(debug_assertions));
            });
            assert_eq!(sibling.unattributed_reads(), 1);
            // A foreign write could have happened in release: C cannot trust it again.
            scoped.read(&attribution, |cell| assert_eq!(cell.get(), Some(&23)));
        });
        assert_eq!(outer.unattributed_reads(), 2);
    }
}

/// Two scalar answers from the same complete raw listing. No file collection
/// or source bytes survive this build.
#[derive(Clone, Copy, Debug)]
pub struct WorkspaceFileSetAnswers {
    pub listing: StableDigest,
    pub inventory: StableDigest,
}

pub fn workspace_file_set_answers(
    project: &dyn super::Project,
) -> std::io::Result<WorkspaceFileSetAnswers> {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        let listed = project.all_files_shared()?;
        let receipt =
            brokk_bifrost_core::analyzer::project_reads::file_set_receipt(project, &listed)?;
        Ok(WorkspaceFileSetAnswers {
            listing: StableDigest::from_array(
                receipt
                    .listing
                    .expect("complete file set has a listing digest"),
            ),
            inventory: StableDigest::from_array(
                receipt
                    .inventory
                    .expect("complete file set has an inventory digest"),
            ),
        })
    })
}

pub fn workspace_file_listing_answer(
    project: &dyn super::Project,
) -> std::io::Result<StableDigest> {
    workspace_file_set_answers(project).map(|answers| answers.listing)
}
pub fn workspace_file_inventory_answer(
    project: &dyn super::Project,
) -> std::io::Result<StableDigest> {
    workspace_file_set_answers(project).map(|answers| answers.inventory)
}
pub fn workspace_ignore_rules_answer(
    project: &dyn super::Project,
) -> std::io::Result<StableDigest> {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        project.ignore_rules_digest().map(StableDigest::from_array)
    })
}
fn overlay_set_digest(
    overlays: Option<&brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent>,
) -> StableDigest {
    let mut paths: Vec<_> = overlays
        .into_iter()
        .flat_map(|overlays| {
            overlays
                .entries()
                .iter()
                .map(|(file, _)| crate::path_utils::rel_path_string(file))
        })
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-workspace-overlay-set:v1",
    );
    hash.sequence("paths", &paths, |hash, path| {
        hash.field("rel_path", path.as_bytes())
    });
    StableDigest::from_array(hash.finish())
}

pub fn workspace_overlay_set_answer(project: &dyn super::Project) -> StableDigest {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        overlay_set_digest(project.overlay_content().as_deref())
    })
}

pub fn workspace_overlay_membership_answer(
    project: &dyn super::Project,
    rel_path: &str,
) -> StableDigest {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        let file = super::ProjectFile::new(project.root(), std::path::Path::new(rel_path));
        overlay_membership_digest(project.has_overlay(&file))
    })
}

fn overlay_membership_digest(present: bool) -> StableDigest {
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-workspace-overlay-membership:v1",
    );
    hash.field("present", &[u8::from(present)]);
    StableDigest::from_array(hash.finish())
}

pub fn workspace_analyzer_languages_answer(project: &dyn super::Project) -> StableDigest {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        StableDigest::from_array(
            brokk_bifrost_core::analyzer::project_reads::workspace_analyzer_languages_digest(
                &project.analyzer_languages(),
            ),
        )
    })
}

pub fn workspace_path_kind_answer(project: &dyn super::Project, rel_path: &str) -> StableDigest {
    StableDigest::from_array(
        brokk_bifrost_core::analyzer::project_reads::workspace_path_kind_digest(
            &project.root().join(rel_path),
        ),
    )
}

fn workspace_directory_digest(exists: bool) -> StableDigest {
    let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
        b"bifrost-workspace-directory:v1",
    );
    hash.field("exists", &[u8::from(exists)]);
    StableDigest::from_array(hash.finish())
}

pub fn workspace_directory_answer(project: &dyn super::Project, rel_path: &str) -> StableDigest {
    brokk_bifrost_core::analyzer::project_reads::without_project_reads(|| {
        workspace_directory_digest(project.has_directory(std::path::Path::new(rel_path)))
    })
}

pub use brokk_bifrost_core::analyzer::project_reads::{
    ErasedMemoAttribution, OpaqueReadReceipt, ReadCapability,
};

/// Takes the exact analyzer owner, preserving its query registry.
pub fn erased_read_capability(analyzer: Arc<dyn IAnalyzer>) -> ReadCapability {
    checked_read_ledger_attachment(analyzer.as_ref());
    ReadCapability::new(OwnedReadAttribution { analyzer })
}

/// The erased form of [`workspace_memo_attribution`], for crates below analysis.
pub fn workspace_read_capability(workspace: &super::WorkspaceAnalyzer) -> ReadCapability {
    erased_read_capability(recording_view(workspace))
}

struct OwnedReadAttribution {
    analyzer: Arc<dyn IAnalyzer>,
}
impl brokk_bifrost_core::analyzer::project_reads::ErasedReadAttribution for OwnedReadAttribution {
    fn is_live(&self) -> bool {
        true
    }
    fn is_capturing(&self) -> bool {
        memo_attribution(self.analyzer.as_ref()).is_capturing()
    }
    fn capture_identity(&self) -> Option<CaptureIdentity> {
        memo_attribution(self.analyzer.as_ref()).capture_identity()
    }
    fn record_unattributed(&self) {
        memo_attribution(self.analyzer.as_ref()).record_unattributed();
    }
    fn capture(
        &self,
        build: &mut dyn FnMut(),
    ) -> brokk_bifrost_core::analyzer::project_reads::ErasedCapturedReads {
        let ((), reads, forwarded_to) = AnalyzerMemoAttribution {
            analyzer: self.analyzer.as_ref(),
        }
        .capture(build);
        erased_memo_receipt(reads, forwarded_to)
    }
    fn capture_authority(
        &self,
        build: &mut dyn FnMut(),
    ) -> brokk_bifrost_core::analyzer::project_reads::ErasedCapturedReads {
        let ((), reads) = AnalyzerMemoAttribution {
            analyzer: self.analyzer.as_ref(),
        }
        .capture_authority(build);
        erased_memo_receipt(reads, None)
    }
    fn replay(
        &self,
        receipts: &[OpaqueReadReceipt],
        unattributed_reads: usize,
        execution_dependences: usize,
    ) {
        checked_read_ledger_attachment(self.analyzer.as_ref());
        for receipt in receipts {
            let keys = receipt
                .downcast_ref::<CapturedMemoReads<ReadKey>>()
                .expect("only analysis constructs read receipts");
            self.analyzer.record_read_receipt(&keys.keys);
        }
        super::i_analyzer::replay_query_read_receipt(
            self.analyzer.as_ref(),
            [],
            unattributed_reads,
            execution_dependences,
        );
    }
    fn record(
        &self,
        project: &dyn super::Project,
        read: brokk_bifrost_core::analyzer::project_reads::ProjectRead<'_>,
        receipt: brokk_bifrost_core::analyzer::project_reads::ProjectReadReceipt,
    ) {
        match project_read_keys(project, self.analyzer.project().root(), read, receipt) {
            Ok(keys) => {
                for key in keys {
                    self.analyzer.record_read(key);
                }
            }
            Err(_) => self.analyzer.record_unattributed_read(),
        }
    }
}

pub fn workspace_fact_key(
    family: WorkspaceFactFamily,
    subject: FactSubject,
    answer: StableDigest,
) -> ReadKey {
    ReadKey::lookup(
        LookupKind::WorkspaceFact,
        super::LookupQuestion::WorkspaceFact {
            family,
            language: Language::None,
            subject,
        },
        answer,
    )
}
pub fn workspace_file_listing_key(answer: StableDigest) -> ReadKey {
    workspace_fact_key(
        WorkspaceFactFamily::WorkspaceFileListing,
        FactSubject::Whole,
        answer,
    )
}

fn erased_memo_receipt(
    reads: CapturedMemoReads<ReadKey>,
    forwarded_to: Option<CaptureIdentity>,
) -> brokk_bifrost_core::analyzer::project_reads::ErasedCapturedReads {
    // Debug expands strings and every collection, so its size plus the key
    // storage conservatively accounts for the keys' retained allocations.
    let retained_bytes = std::mem::size_of_val(reads.keys.as_ref())
        + reads
            .keys
            .iter()
            .map(|key| format!("{key:?}").len())
            .sum::<usize>();
    brokk_bifrost_core::analyzer::project_reads::ErasedCapturedReads {
        unattributed_reads: reads.unattributed_reads,
        execution_dependences: reads.execution_dependences,
        receipt: OpaqueReadReceipt::new(
            Arc::new(reads),
            retained_bytes + std::mem::size_of::<CapturedMemoReads<ReadKey>>(),
        ),
        forwarded_to,
    }
}
pub(super) fn erased_captured_reads(
    reads: &super::ReadLedger,
    forwarded_to: Option<CaptureIdentity>,
) -> brokk_bifrost_core::analyzer::project_reads::ErasedCapturedReads {
    erased_memo_receipt(
        CapturedMemoReads {
            keys: Arc::from(reads.unordered_keys()),
            unattributed_reads: reads.unattributed_reads(),
            execution_dependences: reads.execution_dependences(),
        },
        forwarded_to,
    )
}
pub(super) fn replay_erased_reads(
    contexts: &[Arc<super::AnalyzerQueryContext>],
    receipts: &[OpaqueReadReceipt],
    unattributed_reads: usize,
    execution_dependences: usize,
) {
    for receipt in receipts {
        let reads = receipt
            .downcast_ref::<CapturedMemoReads<ReadKey>>()
            .expect("only analysis constructs read receipts");
        super::i_analyzer::record_receipt_on_active_ledgers(contexts, &reads.keys);
    }

    super::i_analyzer::replay_read_channels(
        [],
        unattributed_reads,
        execution_dependences,
        |key| super::i_analyzer::record_read_on_active_ledgers(contexts, key),
        |count| super::i_analyzer::record_unattributed_on_active_ledgers(contexts, count),
        |count| super::i_analyzer::record_execution_dependence_on_active_ledgers(contexts, count),
    );
}

pub(super) fn project_read_keys(
    project: &dyn super::Project,
    workspace_root: &std::path::Path,
    read: brokk_bifrost_core::analyzer::project_reads::ProjectRead<'_>,
    receipt: brokk_bifrost_core::analyzer::project_reads::ProjectReadReceipt,
) -> std::io::Result<Vec<ReadKey>> {
    use brokk_bifrost_core::analyzer::project_reads::{ProjectRead, without_project_reads};
    without_project_reads(|| {
        if project.root() != workspace_root
            && matches!(
                read,
                ProjectRead::Listing
                    | ProjectRead::AnalyzerLanguages { .. }
                    | ProjectRead::Inventory
                    | ProjectRead::IgnoreRules
                    | ProjectRead::Overlays
                    | ProjectRead::GitIgnore { .. }
            )
        {
            return Err(std::io::Error::other(
                "a whole-workspace fact cannot certify a different Project root",
            ));
        }
        let path_in_workspace = |path: &std::path::Path| -> std::io::Result<String> {
            path.strip_prefix(workspace_root)
                .map(crate::path_utils::workspace_relative_slash_path)
                .map_err(std::io::Error::other)
        };
        match read {
            ProjectRead::AnalyzerLanguages { languages } => Ok(vec![workspace_fact_key(
                WorkspaceFactFamily::WorkspaceAnalyzerLanguages, FactSubject::Whole,
                StableDigest::from_array(brokk_bifrost_core::analyzer::project_reads::workspace_analyzer_languages_digest(languages)),
            )]),
            ProjectRead::Listing => Ok(vec![workspace_file_listing_key(
                receipt
                    .listing
                    .map(StableDigest::from_array)
                    .ok_or_else(|| std::io::Error::other("listing getter omitted its receipt"))?,
            )]),
            ProjectRead::Inventory => Ok(vec![workspace_fact_key(
                WorkspaceFactFamily::WorkspaceFileInventory,
                FactSubject::Whole,
                receipt
                    .inventory
                    .map(StableDigest::from_array)
                    .ok_or_else(|| std::io::Error::other("inventory getter omitted its receipt"))?,
            )]),
            ProjectRead::GitIgnore { rel_path } => {
                let mut keys = if receipt.inventory.is_some() {
                    project_read_keys(project, workspace_root, ProjectRead::Inventory, receipt.clone())?
                } else if receipt.git_ignore_presence_only {
                    Vec::new()
                } else {
                    return Err(std::io::Error::other(
                        "git ignore getter omitted its inventory receipt",
                    ));
                };
                keys.extend(project_read_keys(
                    project,
                    workspace_root,
                    ProjectRead::Path { rel_path },
                    receipt,
                )?);
                Ok(keys)
            }
            ProjectRead::IgnoreRules => Ok(vec![workspace_fact_key(
                WorkspaceFactFamily::WorkspaceIgnoreRules,
                FactSubject::Whole,
                receipt
                    .ignore_rules
                    .map(StableDigest::from_array)
                    .ok_or_else(|| std::io::Error::other("ignore getter omitted its receipt"))?,
            )]),
            ProjectRead::OverlayMembership { rel_path } => {
                let path = path_in_workspace(&project.root().join(rel_path))?;
                Ok(vec![workspace_fact_key(
                    WorkspaceFactFamily::WorkspaceOverlayMembership,
                    FactSubject::File {
                        rel_path: path.into(),
                    },
                    overlay_membership_digest(receipt.overlay_membership.ok_or_else(|| std::io::Error::other("overlay getter omitted its receipt"))?),
                )])
            }
            ProjectRead::Directory { rel_path } => {
                let name = path_in_workspace(&project.root().join(rel_path))?;
                Ok(vec![workspace_fact_key(
                    WorkspaceFactFamily::WorkspaceDirectory,
                    FactSubject::File {
                        rel_path: name.into(),
                    },
                    workspace_directory_digest(receipt.directory.ok_or_else(|| {
                        std::io::Error::other("directory getter omitted its receipt")
                    })?),
                )])
            }
            ProjectRead::AbsolutePath { abs_path } => match abs_path.strip_prefix(project.root()) {
                Ok(rel_path) => project_read_keys(
                    project,
                    workspace_root,
                    ProjectRead::Path { rel_path },
                    receipt,
                ),
                Err(_) => Ok(Vec::new()), // Outside the root is a pure path rejection.
            },
            ProjectRead::Path { rel_path } => {
                let path = path_in_workspace(&project.root().join(rel_path))?;
                let mut keys = vec![workspace_fact_key(
                    WorkspaceFactFamily::WorkspacePathKind,
                    FactSubject::File {
                        rel_path: path.into(),
                    },
                    StableDigest::from_array(brokk_bifrost_core::analyzer::project_reads::observed_path_kind_digest(receipt.path_kind.ok_or_else(|| std::io::Error::other("path getter omitted its receipt"))?)),
                )];
                let mut membership_receipt = receipt.clone();
                membership_receipt.overlay_membership = receipt.path_overlay_membership;
                keys.extend(project_read_keys(
                    project,
                    workspace_root,
                    ProjectRead::OverlayMembership { rel_path },
                    membership_receipt,
                )?);
                // Fixed/subset projects also consult their own stored membership.
                // Physical projects leave this empty and need only the path kind.
                if receipt.inventory.is_some() {
                    keys.extend(project_read_keys(
                        project,
                        workspace_root,
                        ProjectRead::Inventory,
                        receipt,
                    )?);
                }
                Ok(keys)
            }

            ProjectRead::Overlays => {
                let overlays = receipt.overlays.ok_or_else(|| std::io::Error::other("overlay getter omitted its receipt"))?;
                let mut keys = vec![workspace_fact_key(
                    WorkspaceFactFamily::WorkspaceOverlayMembership,
                    FactSubject::Whole,
                    overlay_set_digest(overlays.as_deref()),
                )];
                if let Some(overlays) = overlays {
                    for (file, _, blob) in overlays.entries_with_blob_ids() {
                        keys.push(ReadKey::file(
                            file.language(),
                            path_in_workspace(&file.abs_path())?,
                            blob,
                        ));
                    }
                }
                Ok(keys)
            }
            ProjectRead::Content {
                file,
                blob: Some(blob),
            } => Ok(vec![ReadKey::file(
                file.language(),
                path_in_workspace(&file.abs_path())?,
                blob,
            )]),
            ProjectRead::Content { file, blob: None } => Ok(vec![ReadKey::path_absent(
                file.language(),
                path_in_workspace(&file.abs_path())?,
            )]),
            ProjectRead::Unattributed => Err(std::io::Error::other(
                "project source could not name its exact input",
            )),
        }
    })
}
