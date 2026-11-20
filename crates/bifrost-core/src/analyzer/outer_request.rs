//! State shared by one outer analyzer request and its nested work.
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::external_selection::{SelectionRefused, VerifiedSelection};
use super::project::{Project, ProjectViewStamp};

/// Additional request entry variants are added by later milestones.
// The JVM key carries both admitted selections by value for exact request identity.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestEntryKey {
    /// One capture-safe value-flow registration authority per outer request.
    ValueFlowRetention,
    /// One budget-bound selected-source factory for this outer request.
    SelectedSourceEntries,
    /// This request's disk checks of the published Python runtime
    /// environments (#13725).
    PythonRuntimeVerification,
    /// This request's Python definition answers, one per selected site
    /// (#13847).
    PythonDefinitionAnswers,
    /// The source allocation is retained by the entry's value, so its address
    /// cannot be reused while this request owns its selection.
    WorkspaceSelection {
        owner: usize,
    },
    JvmCatalogReader(JvmCatalogReaderKey),
    JvmReaderDerivation {
        activation: String,
        view: [u8; 32],
        excluded: [u8; 32],
        questions: [u8; 32],
        view_stamp: Option<ProjectViewStamp>,
        generation: u64,
    },
    /// An activation by its model-set hash and the digest of its request-owned
    /// active shards: the hash ignores which physical shards were selected.
    JvmCatalogActivation {
        activation: String,
        view: [u8; 32],
    },
    ExternalSelection {
        question_digest: [u8; 32],
        view_stamp: ProjectViewStamp,
    },
}

/// A selection as a request admitted it. The flags mean different things and
/// must not stand in for each other.
///
/// `certified` is `complete && verified`: the authority's answer is a
/// deterministic snapshot that a later run can ask for again and compare, and it
/// proves absence.
///
/// `complete` is the only basis for proving absence.
///
/// `replayable` is the only reuse predicate (`VerifiedSelection::replayable`).
/// A selection that is not complete is replayable when it is verified and its
/// only incompleteness is a gap that is fixed for unchanged inputs: a pack's
/// partial coverage, or a declared coordinate with no local artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdmittedSelection {
    pub certified: bool,
    pub complete: bool,
    pub replayable: bool,
    pub question_digest: [u8; 32],
    pub view_stamp: Option<ProjectViewStamp>,
    /// What this request is bound to: the authority's answer together with any
    /// gaps folded in at bind.
    pub answer_digest: [u8; 32],
    /// What the authority itself answers for the question. A later run asks
    /// the authority again, so a persisted read key names this digest, never
    /// `answer_digest` when gaps were folded in.
    pub authority_answer_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JvmCatalogReaderKey {
    pub dependencies: AdmittedSelection,
    pub jdk: AdmittedSelection,
    pub curated: [u8; 32],
    /// The activation's request-owned active shards. A handle narrows its
    /// pinned view to them, so activations with different views in one
    /// request open separate handles.
    pub view: [u8; 32],
    pub rules: [u8; 32],
    pub generation: u64,
}

pub trait RequestResource: Any + Send + Sync {
    fn close(&self);
}

#[derive(Debug, PartialEq, Eq)]
pub enum RequestResourceError<E> {
    Closed,
    Open(E),
}

type ResourceSlot = Arc<dyn Any + Send + Sync>;
type ResourceCloser = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Resources {
    closed: bool,
    slots: HashMap<RequestEntryKey, (ResourceSlot, ResourceCloser)>,
}

/// State owned by one caller-visible request, shared by nested scopes and workers.
#[doc(hidden)]
pub struct OuterRequest {
    id: u64,
    entries: Mutex<HashMap<RequestEntryKey, Arc<dyn Any + Send + Sync>>>,
    resources: Mutex<Resources>,
}

/// A borrow of one initialized entry in its original request.
///
/// This carries data provenance, not SQL permission. Consumers can project a
/// field without supplying another request identity or source key. Only Core
/// constructs the handle; it has no Default, Clone or Copy implementation.
///
/// Fields cannot be constructed outside Core:
///
/// ```compile_fail
/// use brokk_bifrost_core::analyzer::outer_request::{OuterRequest, WorkspaceEntry};
/// let request = OuterRequest::new();
/// let entry = WorkspaceEntry { request: &request, source: 1, value: &42_u8 };
/// ```
///
/// An entry, including a projection, cannot escape its callback:
///
/// ```compile_fail
/// use brokk_bifrost_core::analyzer::outer_request::{OuterRequest, WorkspaceEntryBinding};
/// struct Selection(u8);
/// impl WorkspaceEntryBinding for Selection {
///     type Binding = u8;
///     fn binding(&self) -> &u8 { &self.0 }
/// }
/// let request = OuterRequest::new();
/// request.bind_workspace_selection(1, || Selection(42));
/// let escaped = request.with_workspace_selection::<Selection, _>(1, |entry| entry.project());
/// ```
///
/// A caller cannot substitute another binding with a projection closure:
///
/// ```compile_fail
/// use brokk_bifrost_core::analyzer::outer_request::{OuterRequest, WorkspaceEntryBinding};
/// struct Selection(u8);
/// impl WorkspaceEntryBinding for Selection {
///     type Binding = u8;
///     fn binding(&self) -> &u8 { &self.0 }
/// }
/// #[brokk_bifrost_test_macros::hardwon(
///     "#10979: a projection closure could relabel another source's binding"
/// )]
/// fn cannot_substitute_a_foreign_binding() {
///     static OTHER_SOURCE: u8 = 99;
///     let request = OuterRequest::new();
///     request.bind_workspace_selection(1, || Selection(41));
///     request.with_workspace_selection::<Selection, _>(1, |entry| {
///         entry.project(|_| &OTHER_SOURCE);
///     });
/// }
/// ```
///
/// Borrowing does not create a clonable handle:
///
/// ```compile_fail
/// use brokk_bifrost_core::analyzer::outer_request::WorkspaceEntry;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<WorkspaceEntry<'_, u8>>();
/// ```
#[doc(hidden)]
pub struct WorkspaceEntry<'a, T: ?Sized> {
    request: &'a Arc<OuterRequest>,
    source: usize,
    value: &'a T,
}

impl<'a, T: ?Sized> WorkspaceEntry<'a, T> {
    pub fn request(&self) -> &Arc<OuterRequest> {
        self.request
    }

    pub fn source(&self) -> usize {
        self.source
    }

    pub fn value(&self) -> &T {
        self.value
    }

    /// Borrow the original owner's binding without a caller-selected value.
    pub fn project(self) -> WorkspaceEntry<'a, T::Binding>
    where
        T: WorkspaceEntryBinding,
    {
        WorkspaceEntry {
            request: self.request,
            source: self.source,
            value: self.value.binding(),
        }
    }
}

/// The trusted request entry owner defines its one immutable binding.
///
/// Analysis's private request workspace selection supplies the production
/// implementation. Readers consume that entry; they must not implement this
/// trait to substitute data. The associated type keeps Core independent of
/// Store and Analysis. A private Core supertrait cannot seal an implementation
/// in the downstream Analysis crate, and Core cannot name its private type.
/// The owner's implementation is the single reviewed binding extraction point.
#[doc(hidden)]
pub trait WorkspaceEntryBinding {
    type Binding: ?Sized;

    fn binding(&self) -> &Self::Binding;
}

impl std::fmt::Debug for OuterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OuterRequest")
            .field("id", &self.id)
            .finish()
    }
}

impl OuterRequest {
    #[doc(hidden)]
    pub fn new() -> Arc<Self> {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT_ID
            .try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |id| id.checked_add(1),
            )
            .expect("outer request identity exhausted");
        Arc::new(Self {
            id,
            entries: Mutex::new(HashMap::new()),
            resources: Mutex::new(Resources::default()),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Capture an immutable workspace selection once, when its query opens.
    /// The concrete selection belongs to analysis; core only owns its lifetime.
    pub fn bind_workspace_selection<T: Any + Send + Sync>(
        &self,
        owner: usize,
        capture: impl FnOnce() -> T,
    ) {
        let slot = {
            let mut entries = self.entries.lock().expect("outer request map poisoned");
            Arc::clone(
                entries
                    .entry(RequestEntryKey::WorkspaceSelection { owner })
                    .or_insert_with(|| Arc::new(OnceLock::<Arc<T>>::new())),
            )
        };
        let slot = Arc::downcast::<OnceLock<Arc<T>>>(slot)
            .expect("workspace selection owner has one answer type");
        // A source capture may consume another source or SQL. Never hold the
        // request map while it runs. Competing first captures share this slot.
        slot.get_or_init(|| Arc::new(capture()));
    }

    /// Read already captured data without opening or waiting for a selector.
    pub fn workspace_selection<T: Any + Send + Sync>(&self, owner: usize) -> Option<Arc<T>> {
        let slot = {
            let entries = self.entries.lock().expect("outer request map poisoned");
            Arc::clone(entries.get(&RequestEntryKey::WorkspaceSelection { owner })?)
        };
        let slot = Arc::downcast::<OnceLock<Arc<T>>>(slot)
            .expect("workspace selection owner has one answer type");
        slot.get().cloned()
    }

    /// Borrow the actual initialized entry, retaining its original identity.
    /// The callback cannot return the borrowed entry or a projected handle.
    pub fn with_workspace_selection<T: Any + Send + Sync, R>(
        self: &Arc<Self>,
        owner: usize,
        consume: impl FnOnce(WorkspaceEntry<'_, T>) -> R,
    ) -> Option<R> {
        let selection = self.workspace_selection::<T>(owner)?;
        Some(consume(WorkspaceEntry {
            request: self,
            source: owner,
            value: selection.as_ref(),
        }))
    }

    /// Borrow an already opened resource without allocating a slot or invoking
    /// its constructor. Match resource()'s lock order and closed-request gate.
    pub fn resource_if_present<R: RequestResource>(&self, key: &RequestEntryKey) -> Option<Arc<R>> {
        let slot = {
            let resources = self.resources.lock().expect("request resources poisoned");
            if resources.closed {
                return None;
            }
            Arc::clone(&resources.slots.get(key)?.0)
        };
        let slot =
            Arc::downcast::<Mutex<Option<Arc<R>>>>(slot).expect("resource key has one answer type");
        let resource = slot.lock().expect("resource slot poisoned").clone()?;
        if self.is_closed() {
            None
        } else {
            Some(resource)
        }
    }

    pub fn resource<R: RequestResource, E>(
        &self,
        key: RequestEntryKey,
        open: impl FnOnce() -> Result<Arc<R>, E>,
    ) -> Result<Arc<R>, RequestResourceError<E>> {
        let slot = {
            let mut resources = self.resources.lock().expect("request resources poisoned");
            if resources.closed {
                return Err(RequestResourceError::Closed);
            }
            Arc::clone(
                &resources
                    .slots
                    .entry(key)
                    .or_insert_with(|| {
                        let slot = Arc::new(Mutex::<Option<Arc<R>>>::new(None));
                        let closer_slot = Arc::clone(&slot);
                        let closer: ResourceCloser = Arc::new(move || {
                            let resource =
                                closer_slot.lock().expect("resource slot poisoned").clone();
                            if let Some(resource) = resource {
                                resource.close();
                            }
                        });
                        (slot as ResourceSlot, closer)
                    })
                    .0,
            )
        };
        let slot =
            Arc::downcast::<Mutex<Option<Arc<R>>>>(slot).expect("resource key has one answer type");
        let mut guard = slot.lock().expect("resource slot poisoned");
        let resource = if let Some(resource) = guard.as_ref() {
            Arc::clone(resource)
        } else {
            let resource = open().map_err(RequestResourceError::Open)?;
            *guard = Some(Arc::clone(&resource));
            resource
        };
        drop(guard);
        if self
            .resources
            .lock()
            .expect("request resources poisoned")
            .closed
        {
            return Err(RequestResourceError::Closed);
        }
        Ok(resource)
    }

    /// The activation binding is request-local and records only the reader key.
    pub fn jvm_catalog_binding(
        &self,
        activation: &str,
        view: [u8; 32],
    ) -> Option<JvmCatalogReaderKey> {
        self.entries
            .lock()
            .expect("outer request map poisoned")
            .get(&RequestEntryKey::JvmCatalogActivation {
                activation: activation.to_owned(),
                view,
            })
            .map(|entry| {
                Arc::downcast::<JvmCatalogReaderKey>(Arc::clone(entry))
                    .expect("JVM activation binding has one answer type")
                    .as_ref()
                    .clone()
            })
    }

    pub fn bind_jvm_catalog(&self, activation: String, view: [u8; 32], key: JvmCatalogReaderKey) {
        let mut entries = self.entries.lock().expect("outer request map poisoned");
        let entry = entries
            .entry(RequestEntryKey::JvmCatalogActivation { activation, view })
            .or_insert_with(|| Arc::new(key.clone()));
        assert_eq!(
            Arc::downcast::<JvmCatalogReaderKey>(Arc::clone(entry))
                .expect("JVM activation binding has one answer type")
                .as_ref(),
            &key,
            "one activation has one admitted catalog reader in a request"
        );
    }

    pub fn is_closed(&self) -> bool {
        self.resources
            .lock()
            .expect("request resources poisoned")
            .closed
    }

    pub fn close(&self) {
        let closers = {
            let mut resources = self.resources.lock().expect("request resources poisoned");
            if resources.closed {
                return;
            }
            resources.closed = true;
            resources
                .slots
                .values()
                .map(|(_, close)| Arc::clone(close))
                .collect::<Vec<_>>()
        };
        for close in closers {
            close();
        }
    }

    /// Share one fill for a question and a stamped view in this request.
    ///
    /// Within one request and one view stamp, the first verified selection
    /// stands: later consumers in the request reuse it without validating
    /// the disk again. The fill validated its capture against a fresh walk
    /// and fresh manifest reads when it completed, but no atomic filesystem
    /// snapshot is claimed, so a disk edit that advances no stamp becomes
    /// visible to the next request, not to this one.
    pub fn external_selection(
        &self,
        project: &dyn Project,
        question_digest: [u8; 32],
        fill: impl FnOnce() -> Result<VerifiedSelection, SelectionRefused>,
    ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
        let Some(stamp) = project.view_stamp() else {
            let answer = Arc::new(fill()?);
            assert_eq!(answer.question_digest, question_digest);
            assert!(!answer.verified, "unstamped views cannot verify selections");
            assert!(answer.view_stamp.is_none());
            return Ok(answer);
        };
        let key = RequestEntryKey::ExternalSelection {
            question_digest,
            view_stamp: stamp.clone(),
        };
        let slot = {
            let mut entries = self.entries.lock().expect("outer request map poisoned");
            Arc::clone(entries.entry(key.clone()).or_insert_with(|| {
                Arc::new(Mutex::<Option<Arc<VerifiedSelection>>>::new(None))
                    as Arc<dyn Any + Send + Sync>
            }))
        };
        let slot = Arc::downcast::<Mutex<Option<Arc<VerifiedSelection>>>>(slot)
            .expect("external selection key has one answer type");
        let answer = {
            let mut guard = slot.lock().expect("external selection slot poisoned");
            if let Some(answer) = guard.as_ref() {
                Arc::clone(answer)
            } else {
                let answer = Arc::new(fill()?);
                // Only an answer captured under this key's stamp fills its slot.
                if answer.view_stamp.as_ref() == Some(&stamp) {
                    *guard = Some(Arc::clone(&answer));
                }
                answer
            }
        };
        assert_eq!(answer.question_digest, question_digest);
        debug_assert_eq!(answer.certified, answer.complete && answer.verified);
        let Some(answer_stamp) = answer.view_stamp.clone() else {
            panic!("a stamped view's fill returns a stamped answer");
        };
        let (answer, answer_key) = if answer_stamp == stamp {
            (answer, key)
        } else {
            // The fill's own retry settled on a later stable view. Record the
            // answer under the stamp it was captured at, and leave the
            // earlier key empty.
            let settled_key = RequestEntryKey::ExternalSelection {
                question_digest,
                view_stamp: answer_stamp.clone(),
            };
            let mut entries = self.entries.lock().expect("outer request map poisoned");
            entries.remove(&key);
            let settled = Arc::clone(entries.entry(settled_key.clone()).or_insert_with(|| {
                Arc::new(Mutex::new(Some(Arc::clone(&answer)))) as Arc<dyn Any + Send + Sync>
            }));
            drop(entries);
            let settled = Arc::downcast::<Mutex<Option<Arc<VerifiedSelection>>>>(settled)
                .expect("external selection key has one answer type");
            let mut guard = settled.lock().expect("external selection slot poisoned");
            (Arc::clone(guard.get_or_insert(answer)), settled_key)
        };
        // Handing the answer out binds the consumer to the current view, so
        // the view is compared after every wait for a slot. A view that moved
        // since the answer's capture is a miss, never a relabelled entry.
        if project.view_stamp().as_ref() != Some(&answer_stamp) {
            self.entries
                .lock()
                .expect("outer request map poisoned")
                .remove(&answer_key);
            return Err(SelectionRefused::Stale);
        }
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::model::Language;
    use crate::analyzer::project::{FilesystemProject, TestProject};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn answer(digest: [u8; 32], project: &dyn Project) -> VerifiedSelection {
        VerifiedSelection {
            question_digest: digest,
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            verified: project.view_stamp().is_some(),
            certified: project.view_stamp().is_some(),
            complete: true,
            only_replayable_gaps: false,
            records: Arc::new(()),
        }
    }

    struct TestResource(AtomicUsize);

    impl RequestResource for TestResource {
        fn close(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn resource_key(n: u8) -> RequestEntryKey {
        RequestEntryKey::JvmCatalogReader(JvmCatalogReaderKey {
            dependencies: AdmittedSelection {
                certified: true,
                complete: true,
                replayable: true,
                question_digest: [n; 32],
                view_stamp: None,
                answer_digest: [n; 32],
                authority_answer_digest: [n; 32],
            },
            jdk: AdmittedSelection {
                certified: true,
                complete: true,
                replayable: true,
                question_digest: [n; 32],
                view_stamp: None,
                answer_digest: [n; 32],
                authority_answer_digest: [n; 32],
            },
            curated: [n; 32],
            view: [n; 32],
            rules: [n; 32],
            generation: n as u64,
        })
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13536: capturing one source while reading another bound entry deadlocks the request map"
    )]
    fn workspace_capture_can_read_another_bound_entry() {
        let request = OuterRequest::new();
        request.bind_workspace_selection(1, || 41_u8);
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            request
                .bind_workspace_selection(2, || *request.workspace_selection::<u8>(1).unwrap() + 1);
            send.send(*request.workspace_selection::<u8>(2).unwrap())
                .unwrap();
        });
        assert_eq!(
            receive.recv_timeout(std::time::Duration::from_secs(5)),
            Ok(42),
            "entry capture must not hold the request map while reading another source"
        );
        worker.join().unwrap();
    }

    #[test]
    fn workspace_projection_preserves_the_original_request_and_source() {
        struct Selection {
            value: u8,
        }
        impl WorkspaceEntryBinding for Selection {
            type Binding = u8;

            fn binding(&self) -> &u8 {
                &self.value
            }
        }
        let first = OuterRequest::new();
        let second = OuterRequest::new();
        first.bind_workspace_selection(11, || Selection { value: 41 });
        first.bind_workspace_selection(22, || Selection { value: 99 });
        second.bind_workspace_selection(11, || Selection { value: 17 });
        let observed = |request: &Arc<OuterRequest>, source| {
            request.with_workspace_selection::<Selection, _>(source, |entry| {
                let field = entry.project();
                (field.request().id(), field.source(), *field.value())
            })
        };
        assert_eq!(observed(&first, 11), Some((first.id(), 11, 41)));
        assert_eq!(observed(&first, 22), Some((first.id(), 22, 99)));
        assert_eq!(observed(&second, 11), Some((second.id(), 11, 17)));
        assert_eq!(observed(&first, 33), None, "lookup cannot capture a source");
        first.bind_workspace_selection::<Selection>(11, || {
            panic!("an original entry cannot be rebound")
        });
        assert_eq!(observed(&first, 11), Some((first.id(), 11, 41)));
    }

    #[test]
    fn workspace_first_capture_initializes_once_without_blocking_readers() {
        use std::sync::{Barrier, mpsc};
        let request = OuterRequest::new();
        let fills = AtomicUsize::new(0);
        let release = Barrier::new(2);
        let (entered, wait_for_entry) = mpsc::channel();
        std::thread::scope(|threads| {
            let first = threads.spawn(|| {
                request.bind_workspace_selection(1, || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    entered.send(()).unwrap();
                    release.wait();
                    42_u8
                });
            });
            wait_for_entry.recv().unwrap();
            assert!(request.workspace_selection::<u8>(1).is_none());
            assert!(
                request
                    .with_workspace_selection::<u8, _>(1, |_| panic!("not yet initialized"))
                    .is_none()
            );
            let second = threads.spawn(|| {
                request.bind_workspace_selection(1, || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    99_u8
                });
            });
            release.wait();
            first.join().unwrap();
            second.join().unwrap();
        });
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let first = request.workspace_selection::<u8>(1).unwrap();
        let second = request.workspace_selection::<u8>(1).unwrap();
        assert_eq!(*first, 42);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn resources_share_fills_retry_failures_and_close_once() {
        let request = OuterRequest::new();
        assert!(
            request
                .resource_if_present::<TestResource>(&resource_key(1))
                .is_none()
        );
        assert!(request.resources.lock().unwrap().slots.is_empty());
        let fills = AtomicUsize::new(0);
        std::thread::scope(|threads| {
            let first = threads.spawn(|| {
                request.resource(resource_key(1), || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(Arc::new(TestResource(AtomicUsize::new(0))))
                })
            });
            let second = threads.spawn(|| {
                request.resource(resource_key(1), || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(Arc::new(TestResource(AtomicUsize::new(0))))
                })
            });
            let a = first.join().unwrap().unwrap();
            let b = second.join().unwrap().unwrap();
            assert!(Arc::ptr_eq(
                &a,
                &request
                    .resource_if_present::<TestResource>(&resource_key(1))
                    .unwrap()
            ));
            assert!(Arc::ptr_eq(&a, &b));
            assert_eq!(fills.load(Ordering::SeqCst), 1);
            assert!(matches!(
                request.resource::<TestResource, ()>(resource_key(2), || Err(())),
                Err(RequestResourceError::Open(()))
            ));
            let retried = request
                .resource(resource_key(2), || {
                    Ok::<_, ()>(Arc::new(TestResource(AtomicUsize::new(0))))
                })
                .unwrap();
            assert!(
                request
                    .resource_if_present::<TestResource>(&resource_key(2))
                    .is_some()
            );
            request.close();
            request.close();
            assert!(
                request
                    .resource_if_present::<TestResource>(&resource_key(1))
                    .is_none()
            );
            assert_eq!(a.0.load(Ordering::SeqCst), 1);
            assert_eq!(retried.0.load(Ordering::SeqCst), 1);
            assert!(matches!(
                request.resource::<TestResource, ()>(resource_key(3), || panic!(
                    "closed request opened resource"
                )),
                Err(RequestResourceError::Closed)
            ));
        });
    }

    #[test]
    fn failed_fill_is_not_cached() {
        let temp = tempfile::tempdir().unwrap();
        let project = FilesystemProject::new(temp.path()).unwrap();
        let request = OuterRequest::new();
        let digest = [9; 32];
        assert!(matches!(
            request.external_selection(&project, digest, || Err(SelectionRefused::Stale)),
            Err(SelectionRefused::Stale)
        ));
        assert!(
            request
                .external_selection(&project, digest, || Ok(answer(digest, &project)))
                .is_ok()
        );
    }

    #[test]
    fn a_fill_that_settles_on_a_later_view_is_recorded_under_it() {
        let temp = tempfile::tempdir().unwrap();
        let project = FilesystemProject::new(temp.path()).unwrap();
        let request = OuterRequest::new();
        let digest = [5; 32];
        // The verifier's own retry captured a stable view after the stamp
        // moved, as a cold listing's first walk does.
        let first = request
            .external_selection(&project, digest, || {
                project.invalidate_cached_file_listing();
                Ok(answer(digest, &project))
            })
            .unwrap();
        let second = request
            .external_selection(&project, digest, || panic!("the settled entry is shared"))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn selection_entry_shares_fill_across_request_threads_and_rejects_crossing() {
        let temp = tempfile::tempdir().unwrap();
        let project = FilesystemProject::new(temp.path()).unwrap();
        let request = OuterRequest::new();
        let fills = AtomicUsize::new(0);
        let digest = [7; 32];
        std::thread::scope(|threads| {
            let first = threads.spawn(|| {
                request.external_selection(&project, digest, || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(digest, &project))
                })
            });
            let second = threads.spawn(|| {
                request.external_selection(&project, digest, || {
                    fills.fetch_add(1, Ordering::SeqCst);
                    Ok(answer(digest, &project))
                })
            });
            assert!(Arc::ptr_eq(
                &first.join().unwrap().unwrap(),
                &second.join().unwrap().unwrap()
            ));
        });
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let crossed = request.external_selection(&project, [8; 32], || {
            let answer = answer([8; 32], &project);
            project.invalidate_cached_file_listing();
            Ok(answer)
        });
        assert!(matches!(crossed, Err(SelectionRefused::Stale)));
        let fresh = request.external_selection(&project, [8; 32], || Ok(answer([8; 32], &project)));
        assert!(fresh.is_ok());

        let unstamped = TestProject::new(temp.path(), Language::Java);
        assert!(unstamped.view_stamp().is_none());
        let first = request
            .external_selection(&unstamped, digest, || Ok(answer(digest, &unstamped)))
            .unwrap();
        let second = request
            .external_selection(&unstamped, digest, || Ok(answer(digest, &unstamped)))
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
    }
}
