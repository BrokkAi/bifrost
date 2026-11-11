//! State shared by one outer analyzer request and its nested work.
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::external_selection::{SelectionRefused, VerifiedSelection};
use super::project::{Project, ProjectViewStamp};

/// Additional request entry variants are added by later milestones.
// The JVM key carries both admitted selections by value for exact request identity.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestEntryKey {
    JvmCatalogReader(JvmCatalogReaderKey),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdmittedSelection {
    pub certified: bool,
    pub complete: bool,
    pub question_digest: [u8; 32],
    pub view_stamp: Option<ProjectViewStamp>,
    pub answer_digest: [u8; 32],
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
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_ne!(id, 0, "outer request identity exhausted");
        Arc::new(Self {
            id,
            entries: Mutex::new(HashMap::new()),
            resources: Mutex::new(Resources::default()),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
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
            assert!(
                !answer.certified,
                "unstamped views cannot certify selections"
            );
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
            certified: project.view_stamp().is_some(),
            complete: true,
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
                question_digest: [n; 32],
                view_stamp: None,
                answer_digest: [n; 32],
            },
            jdk: AdmittedSelection {
                certified: true,
                complete: true,
                question_digest: [n; 32],
                view_stamp: None,
                answer_digest: [n; 32],
            },
            curated: [n; 32],
            view: [n; 32],
            rules: [n; 32],
            generation: n as u64,
        })
    }

    #[test]
    fn resources_share_fills_retry_failures_and_close_once() {
        let request = OuterRequest::new();
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
            request.close();
            request.close();
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
