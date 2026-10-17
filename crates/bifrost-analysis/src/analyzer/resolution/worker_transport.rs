//! Query-owned worker operations and canonical answer transport.
//!
//! Each worker opens and finishes its own reader from the parent's captured
//! authority. Answers contain owned checked evidence, never reader handles or
//! supplemental catalogs. Runtime aliases cross with their content digests;
//! the parent re-interns those digests in deterministic caller-supplied order.

use super::SpliceMount;
use super::{
    BindingFragmentId, BindingNodeId, FactResolutionAnswer, PartialPathId, ResolutionCompletion,
    ResolutionIdentityDigestKey as Key, ResolutionIdentityTranslation, SemanticId,
    SharedNameInterner, StackVariableId,
};
use crate::CancellationToken;
use crate::analyzer::store::resolution_operation::{
    CapturedSelectedResolutionInput, SelectedResolutionOperation,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::{AnalyzerStore, Result};
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;

/// A checked answer must visit every identity when translating and preserve
/// its stable locators, verdicts and other non-identity fields.
pub(crate) trait WorkerAnswer: Sized + Send {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self;
}

struct IdentityTranslation<F>(F);

impl<F: Fn(Key) -> Key> ResolutionIdentityTranslation for IdentityTranslation<F> {
    fn semantic(&self, value: SemanticId) -> SemanticId {
        let Key::Semantic(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn node(&self, value: BindingNodeId) -> BindingNodeId {
        let Key::Node(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn path(&self, value: PartialPathId) -> PartialPathId {
        let Key::Path(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn fragment(&self, value: BindingFragmentId) -> BindingFragmentId {
        let Key::Fragment(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn stack_variable(&self, _: StackVariableId) -> StackVariableId {
        unreachable!("checked worker evidence contains no stack variables")
    }
}

/// One answer's complete, query-local identity authority.
pub(crate) struct TransportedAnswer<A> {
    answer: A,
    digests: Vec<(Key, [u8; 32])>,
}

impl<A: WorkerAnswer> TransportedAnswer<A> {
    pub(crate) fn answer(&self) -> &A {
        &self.answer
    }

    pub(crate) fn capture(
        selected: &SelectedResolutionOperation<'_, '_>,
        answer: A,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let keys = RefCell::new(HashSet::default());
        let answer = answer.translate(&IdentityTranslation(|key| {
            keys.borrow_mut().insert(key);
            key
        }));
        let mut digests = keys
            .into_inner()
            .into_iter()
            .map(|key| Ok((key, selected.identity_content_digest(key, cancellation)?)))
            .collect::<Result<Vec<_>>>()?;
        digests.sort_unstable_by_key(|(key, digest)| {
            (
                *digest,
                match key {
                    Key::Semantic(_) => 0,
                    Key::Node(_) => 1,
                    Key::Path(_) => 2,
                    Key::Fragment(_) => 3,
                },
            )
        });
        Ok(Self { answer, digests })
    }

    /// Stable locators supply any parent anchors. All other runtime numbers
    /// are freshly interned aliases; worker completion order transfers no ids.
    pub(crate) fn reintern(
        self,
        selected: &SelectedResolutionOperation<'_, '_>,
        anchors: impl IntoIterator<Item = (Key, Key)>,
        cancellation: &CancellationToken,
    ) -> Result<A> {
        let Self { answer, digests } = self;
        let mut aliases = HashMap::default();
        for (worker, parent) in anchors {
            if let Some(previous) = aliases.insert(worker, parent) {
                assert_eq!(previous, parent, "one worker alias has one parent anchor");
            }
        }
        for (key, digest) in digests {
            if let Some(parent) = aliases.get(&key).copied() {
                assert_eq!(
                    selected.identity_content_digest(parent, cancellation)?,
                    digest,
                    "a stable source locator identifies the same selected content"
                );
                continue;
            }
            let mapped = match key {
                Key::Semantic(id) if id.shared_name_id().is_some() => Key::Semantic(
                    SemanticId::shared_name(selected.worker_shared_names().intern(digest)),
                ),
                Key::Fragment(_) => {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Semantic(id)
                    if id.local_key().is_some_and(|key| {
                        i64::from(key) < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                    }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Node(id)
                    if id == BindingNodeId::universal_root()
                        || id.local_key().is_some_and(|key| {
                            i64::from(key)
                                < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                        }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Path(id)
                    if id.local_key().is_some_and(|key| {
                        i64::from(key) < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                    }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                _ if key.operation_number().is_some() => {
                    let number = selected.worker_demand_state().intern_identity(digest);
                    match key {
                        Key::Semantic(_) => Key::Semantic(SemanticId::operation_local(number)),
                        Key::Node(_) => Key::Node(BindingNodeId::operation_local(number)),
                        Key::Path(_) => Key::Path(PartialPathId::operation_local(number)),
                        Key::Fragment(_) => unreachable!("fragments are selected content"),
                    }
                }
                Key::Semantic(_) => {
                    Key::Semantic(selected.worker_context_identities().semantic(digest))
                }
                Key::Node(_) => Key::Node(selected.worker_context_identities().node(digest)),
                Key::Path(_) => Key::Path(selected.worker_context_identities().path(digest)),
            };
            assert!(aliases.insert(key, mapped).is_none());
        }

        Ok(answer.translate(&IdentityTranslation(|key| {
            *aliases
                .get(&key)
                .expect("every checked identity carries its canonical digest")
        })))
    }
}

/// Called on the worker thread. The reader stays here through answer capture
/// and open/finish validation, including generation and overlay checks.
///
/// A callback's single-flight dependencies must build inline or independently
/// of the calling pool. Waiting here for work queued on this same bounded pool
/// can starve its builder. Selected forward resolution uses operation-owned
/// SQL reads and synchronous context construction, not whole-snapshot builders.
pub(crate) fn run_selected_worker<'store, 'project, A: WorkerAnswer>(
    store: &'store AnalyzerStore,
    input: &CapturedSelectedResolutionInput<'project>,
    cancellation: &CancellationToken,
    work: impl FnOnce(
        &mut SelectedResolutionOperation<'store, 'project>,
    ) -> Result<SelectedResolutionOperationOutcome<A>>,
) -> Result<SelectedResolutionOperationOutcome<TransportedAnswer<A>>> {
    assert!(
        !store.uses_single_connection_reads(),
        "workers require independent readers"
    );
    let mut selected =
        match store.open_selected_resolution_operation(input.input(), cancellation)? {
            SelectedResolutionOperationOpenOutcome::Ready(selected) => *selected,
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    super::cancelled_completion(),
                ));
            }
        };
    match work(&mut selected)? {
        SelectedResolutionOperationOutcome::Native(answer) => {
            let answer = TransportedAnswer::capture(&selected, answer, cancellation)?;
            selected.finish_worker_answer(answer, cancellation)
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            Ok(SelectedResolutionOperationOutcome::Unavailable(reason))
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            Ok(SelectedResolutionOperationOutcome::Stale(reason))
        }
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            Ok(SelectedResolutionOperationOutcome::Cancelled(completion))
        }
    }
}

/// Capture leaf authority before a forward stage is cleaned up. The selected
/// owner keeps these bounded digests in its query-owned authority memo.
pub(crate) fn forward_identity_digests(
    operation: &super::FactResolutionOperation<'_>,
    answer: &FactResolutionAnswer,
    enumeration: &ResolutionCompletion,
) -> Result<Vec<(Key, [u8; 32])>> {
    let keys = RefCell::new(HashSet::default());
    let translation = IdentityTranslation(|key| {
        keys.borrow_mut().insert(key);
        key
    });
    // A rich incoming worker transports the whole forward answer, including
    // typed projections. Preserve every identity's authority before cleanup.
    drop(answer.clone().translate(&translation));
    drop(enumeration.splice(&translation));
    keys.into_inner()
        .into_iter()
        .map(|key| Ok((key, operation.identity_content_digest(key)?)))
        .collect()
}
