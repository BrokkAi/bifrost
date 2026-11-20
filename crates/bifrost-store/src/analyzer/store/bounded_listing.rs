//! The bounded-tree listing record of a Rust listing certificate, and the
//! process-local registry that lets a store-side reader reach the resolver of
//! a live bounded image.
//!
//! A bounded revision image records that it left files of a Git tree out as
//! one typed [`BoundedTreeOmission`] (see `brokk_bifrost_core::analyzer::project`).
//! The certificate persists it as plain data: the tree id, a digest of the
//! materialized path set, and the paths as rows. The resolver that answers
//! membership questions needs a Git handle, so it is never persisted: the
//! image registers it here for as long as the image lives, and a reader that
//! finds no resolver treats the listing as unknown.

use super::WorkspaceSnapshotId;
use brokk_bifrost_core::analyzer::project::{BoundedListingResolver, BoundedTreeOmission};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

/// The persisted form of a [`BoundedTreeOmission`]: plain data, no resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTreeRecord {
    /// The raw id bytes of the endpoint's Git tree.
    pub tree: Vec<u8>,
    /// Digest of the materialized path set (`BoundedTreeOmission::digest_of`).
    pub digest: [u8; 32],
    /// The materialized paths, sorted and unique.
    pub materialized: Vec<String>,
    /// A working-tree endpoint's overlay on the tree (see `BoundedTreeOmission`):
    /// paths it holds that the tree lacks or changed, and tree paths it
    /// deleted. Sorted and unique; empty for a commit endpoint.
    pub overlay_present: Vec<String>,
    pub overlay_absent: Vec<String>,
}

impl BoundedTreeRecord {
    /// The `(tree, digest)` pair two records are equal by.
    pub fn key(&self) -> (&[u8], [u8; 32]) {
        (&self.tree, self.digest)
    }
}

impl From<&BoundedTreeOmission> for BoundedTreeRecord {
    fn from(omission: &BoundedTreeOmission) -> Self {
        Self {
            tree: omission.tree().as_bytes().to_vec(),
            digest: omission.digest(),
            materialized: omission.materialized().to_vec(),
            overlay_present: omission.overlay_present().to_vec(),
            overlay_absent: omission.overlay_absent().to_vec(),
        }
    }
}

type RegistryKey = (String, String, i64, i64);

struct RegisteredResolver {
    token: u64,
    resolver: Arc<dyn BoundedListingResolver>,
}

#[derive(Default)]
struct Registry {
    next_token: u64,
    resolvers: HashMap<RegistryKey, RegisteredResolver>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(Mutex::default);

fn registry_key(snapshot: &WorkspaceSnapshotId) -> RegistryKey {
    (
        snapshot.workspace_id.0.clone(),
        snapshot.lang.clone(),
        snapshot.generation.0,
        snapshot.revision,
    )
}

/// Keeps one registration alive. Dropping it removes the entry, unless a later
/// registration for the same snapshot replaced it.
#[must_use = "the registration ends when the guard drops"]
pub struct BoundedListingRegistration {
    key: RegistryKey,
    token: u64,
}

impl Drop for BoundedListingRegistration {
    fn drop(&mut self) {
        let mut registry = REGISTRY.lock().expect("bounded listing registry poisoned");
        if registry
            .resolvers
            .get(&self.key)
            .is_some_and(|registered| registered.token == self.token)
        {
            registry.resolvers.remove(&self.key);
        }
    }
}

/// Make `resolver` answer for `snapshot` until the returned guard drops. The
/// bounded image owns the guard, so the entry disappears with the image. The
/// entry is a handle to the image's Git tree access, not copied data.
pub fn register_bounded_listing_resolver(
    snapshot: WorkspaceSnapshotId,
    resolver: Arc<dyn BoundedListingResolver>,
) -> BoundedListingRegistration {
    let key = registry_key(&snapshot);
    let mut registry = REGISTRY.lock().expect("bounded listing registry poisoned");
    registry.next_token += 1;
    let token = registry.next_token;
    registry
        .resolvers
        .insert(key.clone(), RegisteredResolver { token, resolver });
    BoundedListingRegistration { key, token }
}

/// The resolver of the live bounded image that holds `snapshot`. `None` means
/// no image registered one, and the caller treats the listing as root
/// `Unknown`.
pub fn bounded_listing_resolver(
    snapshot: &WorkspaceSnapshotId,
) -> Option<Arc<dyn BoundedListingResolver>> {
    REGISTRY
        .lock()
        .expect("bounded listing registry poisoned")
        .resolvers
        .get(&registry_key(snapshot))
        .map(|registered| Arc::clone(&registered.resolver))
}
