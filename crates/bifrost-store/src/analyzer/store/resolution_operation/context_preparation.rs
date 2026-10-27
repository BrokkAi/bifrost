//! Derived context state owned by exactly one selected request.
//!
//! Keys include the selected scope and staged revision wherever those can
//! change during a request. Values are typed derivations, including language
//! metadata and inventory certificates; they are never a replacement for SQL
//! membership. Compilation does not grant publication authority, and failed
//! registration charges do not advance the ledger. Nothing survives the owner.

use super::*;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

/// A language supplies its complete preparation identity and typed metadata.
/// Missing or interrupted preparations are not negative-cached. The derivation
/// observes its existing cancellation and budget boundaries before returning.
pub(super) struct RequestContextMemo<K: Eq + Hash, V> {
    entries: RefCell<ExactReadMemo<K, V>>,
}

impl<K: Eq + Hash, V> Default for RequestContextMemo<K, V> {
    fn default() -> Self {
        Self {
            entries: RefCell::default(),
        }
    }
}

impl<K: Eq + Hash, V: Clone> RequestContextMemo<K, V> {
    pub(super) fn clear(&self) {
        self.entries.replace(ExactReadMemo::default());
    }

    /// Read only an already admitted preparation. Publication must never
    /// derive on a miss or convert a promised ready value into a cached miss.
    pub(super) fn get(&self, key: &K) -> Option<V> {
        self.entries.borrow().get(key).cloned()
    }

    /// Attach a request-owned projection to an existing admitted preparation.
    /// Absence is an invariant failure, never permission to derive again.
    pub(super) fn update(&self, key: &K, update: impl FnOnce(&mut V)) {
        update(
            self.entries
                .borrow_mut()
                .get_mut(key)
                .expect("a projection belongs to an admitted request preparation"),
        );
    }

    /// A completed derivation is still returned when cancellation arrives at
    /// the admission boundary, but it must not be retained for another demand.
    pub(super) fn prepare(
        &self,
        key: K,
        cancellation: &CancellationToken,
        derive: impl FnOnce() -> Result<Option<V>>,
    ) -> Result<Option<V>> {
        if let Some(value) = self.entries.borrow().get(&key) {
            return Ok(Some(value.clone()));
        }
        let value = derive()?;
        if let Some(value) = value.as_ref().filter(|_| !cancellation.is_cancelled()) {
            self.entries.borrow_mut().insert(key, value.clone());
        }
        Ok(value)
    }

    pub(super) fn read(
        &self,
        key: K,
        derive: impl FnOnce(&K) -> Result<Option<V>>,
    ) -> Result<Option<V>> {
        if let Some(value) = self.entries.borrow().get(&key) {
            return Ok(Some(value.clone()));
        }
        let value = derive(&key)?;
        if let Some(value) = &value {
            self.entries.borrow_mut().insert(key, value.clone());
        }
        Ok(value)
    }
}

/// Per-file lazy plans can travel with an owned preparation. Locks cover only
/// a memo access, never a language derivation, SQL read, or session observation.
pub(super) struct ContextPlanMemo<K, V> {
    entries: Mutex<HashMap<K, V>>,
}

impl<K, V> Default for ContextPlanMemo<K, V> {
    fn default() -> Self {
        Self {
            entries: Mutex::default(),
        }
    }
}

impl<K: Eq + Hash, V: Clone> ContextPlanMemo<K, V> {
    pub(super) fn clear(&self) {
        self.entries
            .lock()
            .expect("context plan memo is not poisoned")
            .clear();
    }

    pub(super) fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("context plan memo is not poisoned")
            .len()
    }

    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.entries
            .lock()
            .expect("context plan memo is not poisoned")
            .contains_key(key)
    }

    pub(super) fn get(&self, key: &K) -> Option<V> {
        self.entries
            .lock()
            .expect("context plan memo is not poisoned")
            .get(key)
            .cloned()
    }

    pub(super) fn insert(&self, key: K, value: V) {
        self.entries
            .lock()
            .expect("context plan memo is not poisoned")
            .insert(key, value);
    }
}

/// One lazy invariant has no demand key and needs no allocated map.
pub(super) struct ContextPlanCell<V> {
    value: Mutex<Option<V>>,
}

impl<V> Default for ContextPlanCell<V> {
    fn default() -> Self {
        Self {
            value: Mutex::default(),
        }
    }
}

impl<V: Clone> ContextPlanCell<V> {
    pub(super) fn get(&self) -> Option<V> {
        self.value
            .lock()
            .expect("context plan cell is not poisoned")
            .clone()
    }

    pub(super) fn set(&self, value: V) {
        *self
            .value
            .lock()
            .expect("context plan cell is not poisoned") = Some(value);
    }
}

/// Derivations with equal descriptors are reusable only under equal selected
/// rows. The descriptor may include language-specific authority and evidence.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct ContextProjectionKey<T> {
    pub(super) derivation: T,
    pub(super) scope: [u8; 32],
    pub(super) stage_epoch: (u64, u64),
}

struct PublishedProjection<V> {
    value: Arc<V>,
    published: Option<crate::analyzer::resolution::SelectedContextPathToken>,
}

pub(super) struct ContextProjectionMemo<K, V> {
    entries: RefCell<HashMap<K, PublishedProjection<V>>>,
}

impl<K, V> Default for ContextProjectionMemo<K, V> {
    fn default() -> Self {
        Self {
            entries: RefCell::default(),
        }
    }
}

impl<K: Clone + Eq + Hash, V> ContextProjectionMemo<K, V> {
    pub(super) fn project(
        &self,
        key: &K,
        compile: impl FnOnce() -> Result<Option<V>>,
    ) -> Result<Option<SelectedContextCellProjection<Arc<V>>>> {
        if let Some(projected) = self.entries.borrow().get(key) {
            return Ok(Some(SelectedContextCellProjection {
                value: Arc::clone(&projected.value),
                published: projected.published,
            }));
        }
        let Some(value) = compile()? else {
            return Ok(None);
        };
        let value = Arc::new(value);
        self.entries.borrow_mut().insert(
            key.clone(),
            PublishedProjection {
                value: Arc::clone(&value),
                published: None,
            },
        );
        Ok(Some(SelectedContextCellProjection {
            value,
            published: None,
        }))
    }

    pub(super) fn publish(
        &self,
        keys: impl IntoIterator<Item = K>,
        token: crate::analyzer::resolution::SelectedContextPathToken,
    ) {
        let mut entries = self.entries.borrow_mut();
        for key in keys {
            entries
                .get_mut(&key)
                .expect("compiled context projection exists")
                .published
                .get_or_insert(token);
        }
    }
}

/// Provider identity deliberately excludes the demanded name. New named cells
/// are charged as deltas against that provider, once per request. Languages
/// supply the key (including role/authority when relevant) and visibility time.
pub(super) struct ContextRegistrationMemo<K> {
    providers: HashMap<K, RegisteredContextCells>,
}

impl<K> Default for ContextRegistrationMemo<K> {
    fn default() -> Self {
        Self {
            providers: HashMap::default(),
        }
    }
}

#[derive(Default)]
struct RegisteredContextCells {
    shared: HashSet<ResolutionSemanticIdentity>,
    boundaries: HashSet<BindingNodeId>,
    gaps: BTreeSet<SemanticId>,
}

impl<K: Eq + Hash> ContextRegistrationMemo<K> {
    pub(super) fn register(
        &mut self,
        key: K,
        blueprint: &SelectedFactOperationBlueprint,
        charge: impl FnOnce(SelectedContextRegistrationCells<'_>) -> Result<ContextRegistrationOutcome>,
    ) -> Result<ContextRegistrationOutcome> {
        let registered = self.providers.entry(key).or_default();
        let shared = blueprint
            .shared_semantic_identities()
            .iter()
            .copied()
            .filter(|identity| !registered.shared.contains(identity))
            .collect::<Vec<_>>();
        let boundaries = blueprint
            .boundary_nodes()
            .iter()
            .copied()
            .filter(|node| !registered.boundaries.contains(node))
            .collect::<Vec<_>>();
        let gaps = blueprint
            .context_owned_gap_identities()
            .difference(&registered.gaps)
            .copied()
            .collect::<BTreeSet<_>>();
        let outcome = charge(SelectedContextRegistrationCells {
            shared: &shared,
            boundaries: &boundaries,
            gaps: &gaps,
        })?;
        if matches!(outcome, ContextRegistrationOutcome::Cancelled) {
            return Ok(outcome);
        }
        registered.shared.extend(shared);
        registered.boundaries.extend(boundaries);
        registered.gaps.extend(gaps);
        Ok(outcome)
    }
}
