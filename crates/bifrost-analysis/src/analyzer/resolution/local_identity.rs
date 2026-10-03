//! Content-local identities for immutable resolution facts.
//!
//! Source lowering uses opaque mounted IDs because the in-memory evaluator
//! must distinguish the same blob mounted at different workspace paths.
//! Persistence stores the recipes below instead. A selected reader can then
//! mount one immutable blob interior without storing a workspace identity in
//! the content-owned rows.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionNamespace, ResolutionScopeId, ResolutionSiteId,
};

use crate::CancellationToken;
use crate::hash::{HashMap, HashSet};

use super::fact_lowering::LoweredSemanticRole;
use super::model::{
    BindingFragmentId, BindingNodeId, MOUNT_ORDINAL_LIMIT, PartialPathId, PrecedenceStep,
    SemanticId, SharedNameId, StackVariableId, UNMOUNTED_ORDINAL,
};

/// Derive the content key of one exact selected workspace mount.
///
/// This used to be the mount's `BindingFragmentId`, and every identity mounted
/// on it carried the first eight bytes of this digest. A `BindingFragmentId`
/// is the mount ordinal now, so what this returns is the mount's *content*:
/// the selection fingerprint hashes it, `selected_resolution_mounts` stores
/// it, and the interior cache keys on it, which is what keeps one interior
/// shared by every selection that mounts the same content.
///
/// `workspace_digest` is the parsed lower-hex workspace identity and
/// `persisted_relative_path` is the slash-stable relative string already stored
/// by the workspace projection. Path parsing and normalization belong at that
/// persistence boundary, not in this content-identity helper. Semantic language
/// is deliberately absent: storage language selects the persisted projection,
/// while the sealed interior digest already commits to its semantic-language
/// payload.
pub(crate) fn selected_resolution_fragment_id(
    workspace_digest: [u8; 32],
    storage_language: &str,
    persisted_relative_path: &str,
    projection_digest: [u8; 32],
    interior_digest: [u8; 32],
) -> SelectedResolutionFragmentDigest {
    assert!(
        !storage_language.is_empty(),
        "a selected resolution mount needs a storage language"
    );
    assert!(
        !persisted_relative_path.is_empty(),
        "a selected resolution mount needs a persisted relative path"
    );
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-selected-fragment:v1");
    hasher.field("workspace_id", &workspace_digest);
    hasher.field("storage_language", storage_language.as_bytes());
    hasher.field("relative_path", persisted_relative_path.as_bytes());
    hasher.field("projection_digest", &projection_digest);
    hasher.field("interior_digest", &interior_digest);
    SelectedResolutionFragmentDigest(hasher.finish())
}

/// The content key of one selected mount: what `BindingFragmentId` used to be
/// before it became the mount ordinal.
///
/// It is a value, not an identity. Nothing in the engine compares it; the
/// selection fingerprint, the mount record and the interior cache key are its
/// only readers, and content addressing is exactly what each of them wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SelectedResolutionFragmentDigest([u8; 32]);

impl SelectedResolutionFragmentDigest {
    pub(crate) const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A source-site address that can be resolved before any opaque runtime ID
/// exists for the selected mount.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SelectedSemanticLocator {
    storage_language: String,
    relative_path: String,
    address: SelectedSemanticAddress,
    role: LoweredSemanticRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SelectedSemanticAddress {
    SourceSite(ResolutionSiteId),
    ReferenceRange { start_byte: usize, end_byte: usize },
    DeclarationRange { start_byte: usize, end_byte: usize },
}

impl SelectedSemanticLocator {
    pub(crate) fn new(
        storage_language: impl Into<String>,
        relative_path: impl Into<String>,
        source_site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> Self {
        let storage_language = storage_language.into();
        let relative_path = relative_path.into();
        assert!(
            !storage_language.is_empty(),
            "a selected semantic locator needs a storage language"
        );
        assert!(
            !relative_path.is_empty(),
            "a selected semantic locator needs a persisted relative path"
        );
        Self {
            storage_language,
            relative_path,
            address: SelectedSemanticAddress::SourceSite(source_site),
            role,
        }
    }

    /// Address one exact selected reference by the syntax range available to
    /// production consumers. Producer-local site ids stay behind the selected
    /// store boundary.
    pub(crate) fn for_reference_range(
        storage_language: impl Into<String>,
        relative_path: impl Into<String>,
        start_byte: usize,
        end_byte: usize,
    ) -> Self {
        assert!(
            start_byte <= end_byte,
            "a selected reference locator needs an ordered byte range"
        );
        let storage_language = storage_language.into();
        let relative_path = relative_path.into();
        assert!(
            !storage_language.is_empty(),
            "a selected semantic locator needs a storage language"
        );
        assert!(
            !relative_path.is_empty(),
            "a selected semantic locator needs a persisted relative path"
        );
        Self {
            storage_language,
            relative_path,
            address: SelectedSemanticAddress::ReferenceRange {
                start_byte,
                end_byte,
            },
            role: LoweredSemanticRole::Reference,
        }
    }

    /// Address the name of a native declaration, independently of references.
    pub(crate) fn for_declaration_range(
        storage_language: impl Into<String>,
        relative_path: impl Into<String>,
        start_byte: usize,
        end_byte: usize,
    ) -> Self {
        assert!(start_byte <= end_byte, "a declaration range is ordered");
        let storage_language = storage_language.into();
        let relative_path = relative_path.into();
        assert!(!storage_language.is_empty());
        assert!(!relative_path.is_empty());
        Self {
            storage_language,
            relative_path,
            address: SelectedSemanticAddress::DeclarationRange {
                start_byte,
                end_byte,
            },
            role: LoweredSemanticRole::Definition,
        }
    }

    pub(crate) const fn declaration_range(&self) -> Option<(usize, usize)> {
        match self.address {
            SelectedSemanticAddress::DeclarationRange {
                start_byte,
                end_byte,
            } => Some((start_byte, end_byte)),
            _ => None,
        }
    }

    pub(crate) fn storage_language(&self) -> &str {
        &self.storage_language
    }

    pub(crate) fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub(crate) const fn source_site(&self) -> Option<ResolutionSiteId> {
        match self.address {
            SelectedSemanticAddress::SourceSite(site) => Some(site),
            SelectedSemanticAddress::ReferenceRange { .. }
            | SelectedSemanticAddress::DeclarationRange { .. } => None,
        }
    }

    pub(crate) const fn reference_range(&self) -> Option<(usize, usize)> {
        match self.address {
            SelectedSemanticAddress::SourceSite(_)
            | SelectedSemanticAddress::DeclarationRange { .. } => None,
            SelectedSemanticAddress::ReferenceRange {
                start_byte,
                end_byte,
            } => Some((start_byte, end_byte)),
        }
    }

    pub(crate) const fn role(&self) -> LoweredSemanticRole {
        self.role
    }
}

/// Connection-local ordinal for one exact selected mount.
///
/// `pub` because it names the mount scope of the public batch source trait's
/// root readers; the module itself is private, so the crate is still the only
/// place that can spell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectedResolutionMountOrdinal(u32);

impl SelectedResolutionMountOrdinal {
    pub(crate) const fn new(value: u32) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }
}

/// Nonnegative blob-local key from one persisted identity dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionLocalKey(i64);

impl ResolutionLocalKey {
    pub(crate) fn new(value: i64) -> Self {
        assert!(value >= 0, "a resolution local key cannot be negative");
        Self(value)
    }

    pub(crate) const fn get(self) -> i64 {
        self.0
    }
}

/// One mount of this selection.
///
/// It used to carry its content-derived `BindingFragmentId` beside its ordinal,
/// because the two were independent and every runtime id named the fragment.
/// A `BindingFragmentId` is the ordinal now, so the mount is the ordinal and
/// the fragment is read off it; the mount's *content* key lives on the mount
/// record, which is where the selection fingerprint and the interior cache
/// want it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SelectedResolutionMount {
    ordinal: SelectedResolutionMountOrdinal,
}

impl SelectedResolutionMount {
    /// Construct the scalar handle after the caller proves selected row membership.
    pub(crate) const fn from_ordinal(ordinal: SelectedResolutionMountOrdinal) -> Self {
        Self { ordinal }
    }

    pub(crate) const fn ordinal(self) -> SelectedResolutionMountOrdinal {
        self.ordinal
    }

    pub(crate) fn fragment(self) -> BindingFragmentId {
        BindingFragmentId::at_ordinal(self.ordinal.get())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectedLocalIdentityProvenance<Identity> {
    mount: SelectedResolutionMount,
    local_key: ResolutionLocalKey,
    identity: Identity,
}

impl<Identity: Copy> SelectedLocalIdentityProvenance<Identity> {
    pub(crate) const fn mount(self) -> SelectedResolutionMount {
        self.mount
    }

    pub(crate) const fn local_key(self) -> ResolutionLocalKey {
        self.local_key
    }

    pub(crate) const fn identity(self) -> Identity {
        self.identity
    }
}

/// An active-stage identity belongs to a selected host but has no ordinary
/// blob-local coordinate. Its caller keeps the original full runtime ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectedStageIdentityProvenance<Identity> {
    mount: SelectedResolutionMount,
    identity: Identity,
}

impl<Identity: Copy> SelectedStageIdentityProvenance<Identity> {
    pub(crate) const fn mount(self) -> SelectedResolutionMount {
        self.mount
    }

    pub(crate) const fn identity(self) -> Identity {
        self.identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedSemanticProvenance {
    FragmentLocal(SelectedLocalIdentityProvenance<ResolutionSemanticIdentity>),
    Stage(SelectedStageIdentityProvenance<ResolutionSemanticIdentity>),
    Shared(ResolutionSemanticIdentity),
}

impl SelectedSemanticProvenance {
    pub(crate) const fn stage(
        mount: SelectedResolutionMount,
        identity: ResolutionSemanticIdentity,
    ) -> Self {
        Self::Stage(SelectedStageIdentityProvenance { mount, identity })
    }

    /// One fragment-local semantic decoded from its mount's identity catalog.
    pub(crate) const fn fragment_local(
        mount: SelectedResolutionMount,
        local_key: ResolutionLocalKey,
        identity: ResolutionSemanticIdentity,
    ) -> Self {
        Self::FragmentLocal(SelectedLocalIdentityProvenance {
            mount,
            local_key,
            identity,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedNodeProvenance {
    FragmentLocal(SelectedLocalIdentityProvenance<ResolutionNodeIdentity>),
    Stage(SelectedStageIdentityProvenance<ResolutionNodeIdentity>),
    UniversalRoot,
    ContextBoundary,
}

impl SelectedNodeProvenance {
    pub(crate) const fn stage(
        mount: SelectedResolutionMount,
        identity: ResolutionNodeIdentity,
    ) -> Self {
        Self::Stage(SelectedStageIdentityProvenance { mount, identity })
    }

    /// One fragment-local node decoded from its mount's identity catalog.
    pub(crate) const fn fragment_local(
        mount: SelectedResolutionMount,
        local_key: ResolutionLocalKey,
        identity: ResolutionNodeIdentity,
    ) -> Self {
        Self::FragmentLocal(SelectedLocalIdentityProvenance {
            mount,
            local_key,
            identity,
        })
    }
}

/// The first storage-local key an operation may mint for an identity that a
/// selected blob does not own.
///
/// A prepared blob keys its identities by their dense catalog positions, so a
/// key at or above this base cannot collide with one however large the blob
/// is. The macro overlay needs exactly that guarantee: it reuses the blob's
/// own key for an identity the blob already has and mints a fresh one for an
/// identity only the overlay introduces.
///
/// It was `1 << 40` while a key was the tail of a 32-byte digest and had the
/// room. A local identity's key is the low 32 bits of a `u64` now, so the
/// base is bit 31: keys below it are catalog positions and keys at or above
/// it are the operation's own supplemental ones for that mount. Tract's
/// largest blob holds far fewer than 2^31 catalog entries -- 3,034,115
/// semantics over 891 blobs -- so the split costs nothing either side.
pub(crate) const SUPPLEMENTAL_LOCAL_KEY_BASE: i64 = 1 << 31;

/// Where one runtime semantic ID lives, read from the ID itself.
///
/// A local ID carries its mount ordinal and its catalog position; a shared
/// name carries its interned id and belongs to no mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedSemanticMount {
    FragmentLocal(SelectedResolutionMount),
    Shared(ResolutionSemanticIdentity),
}

/// What one runtime node ID names, read from the ID's own bytes plus the
/// operation's own registrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedNodeMount {
    FragmentLocal(SelectedResolutionMount),
    UniversalRoot,
    ContextBoundary,
}

/// Checked operation-local correspondence between selected storage coordinates
/// and the opaque runtime IDs consumed by the resolution engine.
///
/// A fragment-local runtime ID names its own mount in bytes 0..8, so the only
/// map a persisted mount needs here is the prefix-to-ordinal entry that
/// `register_mount` writes. The identity maps below hold exactly the three
/// kinds of identity whose provenance no interior can restate: a transient
/// mount's, lowered from replacement content; the operation's own supplemental
/// identities, minted above `SUPPLEMENTAL_LOCAL_KEY_BASE`; and the selected
/// context's shared recipes and boundary nodes. Everything else is read out of
/// the id: a local id is a mount ordinal and the catalog position that is its
/// storage-local key, so neither the mount nor the key costs a lookup.
///
/// The maps are intentionally not persisted. A new selected operation rebuilds
/// only the identities it registers, while reverse lookup can recover exact
/// mount provenance for every issued fragment-local ID.
#[derive(Clone, Debug)]
pub(crate) struct MountRebaser {
    /// The ordinals this selection has registered.
    ///
    /// This used to be three maps: ordinal to fragment, fragment to ordinal,
    /// and the 8-byte fragment prefix to ordinal, which is what a runtime id
    /// had to be decoded through. A local id carries its ordinal now, so the
    /// only question left is whether an ordinal is one of this selection's.
    persisted_mount_count: u32,
    mounts: HashSet<SelectedResolutionMountOrdinal>,
    semantics_by_runtime: HashMap<SemanticId, SelectedSemanticProvenance>,
    nodes_by_runtime: HashMap<BindingNodeId, SelectedNodeProvenance>,
    paths_by_runtime:
        HashMap<PartialPathId, SelectedLocalIdentityProvenance<ResolutionPathIdentity>>,
    variables_by_runtime:
        HashMap<StackVariableId, SelectedLocalIdentityProvenance<ResolutionStackVariableIdentity>>,
    /// The next supplemental key of each kind for the mounts that have minted
    /// one. Absent means the mount has minted none and starts at the base.
    supplemental_keys: HashMap<SelectedResolutionMountOrdinal, [i64; 4]>,
    /// The runtime id this operation already gave one identity at one mount.
    ///
    /// A mounted id used to be a pure function of the identity and the
    /// fragment, so "have I already minted this one" was answered by computing
    /// it and looking it up. A mounted id is a catalog position now and an
    /// operation's own identities have no position until it gives them one, so
    /// the question has to be asked of the identity. This is what answers it.
    /// It holds exactly what the maps beside it hold -- a transient mount's
    /// identities and the operation's own supplemental ones -- so it is
    /// bounded the same way and dropped by the same `retain`.
    supplemental_paths:
        HashMap<(SelectedResolutionMountOrdinal, ResolutionPathIdentity), PartialPathId>,
    supplemental_nodes:
        HashMap<(SelectedResolutionMountOrdinal, ResolutionNodeIdentity), BindingNodeId>,
    supplemental_semantics:
        HashMap<(SelectedResolutionMountOrdinal, ResolutionSemanticIdentity), SemanticId>,
    /// Open registration scope, when a caller is registering a batch of
    /// identities it intends to take back.
    ///
    /// The macro overlay is that caller: its capsules' facts live only in its
    /// own service, so an identity it registers is answerable only while the
    /// overlay is in hand, and the overlay is rebuilt per crate stage. Only a
    /// registration that was new is recorded, so taking the scope back cannot
    /// remove an identity that was already here.
    scope: Option<Vec<MountRebaserRegistration>>,
}

/// One registration a scope can take back.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MountRebaserRegistration {
    Semantic(
        SelectedResolutionMountOrdinal,
        ResolutionSemanticIdentity,
        SemanticId,
    ),
    Node(
        SelectedResolutionMountOrdinal,
        ResolutionNodeIdentity,
        BindingNodeId,
    ),
    Path(
        SelectedResolutionMountOrdinal,
        ResolutionPathIdentity,
        PartialPathId,
    ),
    StackVariable(StackVariableId),
}

impl Default for MountRebaser {
    fn default() -> Self {
        let mut nodes_by_runtime = HashMap::default();
        assert!(
            nodes_by_runtime
                .insert(
                    BindingNodeId::universal_root(),
                    SelectedNodeProvenance::UniversalRoot,
                )
                .is_none()
        );
        Self {
            persisted_mount_count: 0,
            mounts: HashSet::default(),
            semantics_by_runtime: HashMap::default(),
            nodes_by_runtime,
            paths_by_runtime: HashMap::default(),
            variables_by_runtime: HashMap::default(),
            supplemental_keys: HashMap::default(),
            supplemental_paths: HashMap::default(),
            supplemental_nodes: HashMap::default(),
            supplemental_semantics: HashMap::default(),
            scope: None,
        }
    }
}

impl MountRebaser {
    /// Recognize the dense persisted ordinals already validated by SQL staging.
    /// Explicit transient registrations and supplemental identities stay local
    /// to this request and do not allocate entries for persisted membership.
    pub(crate) fn for_persisted_mount_count(count: usize) -> Self {
        let count = u32::try_from(count).expect("persisted mount count fits u32");
        assert!(count <= UNMOUNTED_ORDINAL);
        Self {
            persisted_mount_count: count,
            ..Self::default()
        }
    }

    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Start recording the registrations a scoped caller makes.
    ///
    /// Scopes do not nest: the macro overlay is the one caller, and a second
    /// open scope would mean one batch's registrations were recorded against
    /// another's.
    pub(crate) fn begin_scope(&mut self) {
        assert!(
            self.scope.is_none(),
            "one registration scope is open at a time"
        );
        self.scope = Some(Vec::new());
    }

    /// Stop recording, and hand back what the scope registered.
    pub(crate) fn end_scope(&mut self) -> Vec<MountRebaserRegistration> {
        self.scope
            .take()
            .expect("a registration scope is open when it ends")
    }

    /// Take back what a scope registered.
    ///
    /// Every entry was new when it was recorded, so this cannot remove an
    /// identity that was registered before the scope opened. The supplemental
    /// key counters are deliberately not rewound: a later scope mints fresh
    /// keys rather than reusing a number an answer may still name.
    pub(crate) fn forget_scope(&mut self, registrations: &[MountRebaserRegistration]) {
        for registration in registrations {
            match *registration {
                MountRebaserRegistration::Semantic(ordinal, identity, runtime) => {
                    self.semantics_by_runtime.remove(&runtime);
                    self.supplemental_semantics.remove(&(ordinal, identity));
                }
                MountRebaserRegistration::Node(ordinal, identity, runtime) => {
                    assert_ne!(
                        runtime,
                        BindingNodeId::universal_root(),
                        "the universal root is not a scoped registration"
                    );
                    self.nodes_by_runtime.remove(&runtime);
                    self.supplemental_nodes.remove(&(ordinal, identity));
                }
                MountRebaserRegistration::Path(ordinal, identity, runtime) => {
                    self.paths_by_runtime.remove(&runtime);
                    self.supplemental_paths.remove(&(ordinal, identity));
                }
                MountRebaserRegistration::StackVariable(runtime) => {
                    self.variables_by_runtime.remove(&runtime);
                }
            }
        }
        self.semantics_by_runtime.shrink_to_fit();
        self.nodes_by_runtime.shrink_to_fit();
        self.paths_by_runtime.shrink_to_fit();
        self.variables_by_runtime.shrink_to_fit();
        self.supplemental_semantics.shrink_to_fit();
        self.supplemental_nodes.shrink_to_fit();
        self.supplemental_paths.shrink_to_fit();
    }

    /// The fragment-local identities this rebaser holds, by kind: semantics,
    /// nodes, paths, stack variables.
    ///
    /// This is the quantity that used to grow with every mount a query
    /// opened. RM-2 measured it on one tract reverse frontier at 1,974,097
    /// semantics, 394,894 nodes, 432,242 paths and 156,273 stack variables,
    /// holding 1.24 GiB of live heap. Only a transient mount's identities and
    /// the operation's own supplemental ones belong here now.
    pub(crate) fn fragment_local_identity_entries(&self) -> [usize; 4] {
        [
            self.semantics_by_runtime
                .values()
                .filter(|provenance| {
                    matches!(provenance, SelectedSemanticProvenance::FragmentLocal(_))
                })
                .count(),
            self.nodes_by_runtime
                .values()
                .filter(|provenance| matches!(provenance, SelectedNodeProvenance::FragmentLocal(_)))
                .count(),
            self.paths_by_runtime.len(),
            self.variables_by_runtime.len(),
        ]
    }

    /// How many selected mounts this rebaser knows.
    pub(crate) fn mount_count(&self) -> usize {
        self.persisted_mount_count as usize + self.mounts.len()
    }

    pub(crate) fn clone_work(&self) -> usize {
        [
            self.mounts.len(),
            self.semantics_by_runtime.len(),
            self.nodes_by_runtime.len(),
            self.paths_by_runtime.len(),
            self.variables_by_runtime.len(),
            self.supplemental_keys.len(),
            self.supplemental_paths.len(),
            self.supplemental_nodes.len(),
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .expect("selected identity rebaser clone work must fit usize")
    }

    /// Register one mount of this selection by its ordinal.
    ///
    /// The ordinal is the whole of a mount's runtime identity now: it is the
    /// mount's `BindingFragmentId` and it is the top 29 bits of every local id
    /// the mount owns. `UNMOUNTED_ORDINAL` is what a lowering mints under
    /// before its artifact is mounted anywhere, so a mount that took it would
    /// make an unmounted id look like one of this selection's; that is what
    /// the prefix assertions this replaces were for, and it is one comparison
    /// now instead of two digest compares and a map.
    pub(crate) fn register_mount(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> SelectedResolutionMount {
        assert_ne!(
            ordinal.get(),
            UNMOUNTED_ORDINAL,
            "a selected resolution mount cannot take the unmounted ordinal"
        );
        assert!(
            ordinal.get() < MOUNT_ORDINAL_LIMIT,
            "a mount ordinal fits the 29 bits milestone 4's layout gives it: {}",
            ordinal.get()
        );
        if ordinal.get() >= self.persisted_mount_count {
            self.mounts.insert(ordinal);
        }
        SelectedResolutionMount { ordinal }
    }

    /// The next supplemental local key of each kind for one mount: semantics,
    /// nodes, paths, stack variables.
    ///
    /// A blob's own identities keep the dense catalog positions the preparer
    /// gave them, so an identity only this operation introduces starts above
    /// every one of them at `SUPPLEMENTAL_LOCAL_KEY_BASE` and the counter
    /// advances as keys are registered. Scanning a coordinate map for the
    /// highest key in use, which is how this used to answer, made the cost of
    /// one macro overlay grow with every identity the whole query had seen.
    pub(crate) fn next_supplemental_local_keys(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> [i64; 4] {
        self.supplemental_keys
            .get(&ordinal)
            .copied()
            .unwrap_or([SUPPLEMENTAL_LOCAL_KEY_BASE; 4])
    }

    /// Advance one mount's supplemental counter past a key it just issued.
    fn observe_local_key(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        kind: usize,
        local_key: ResolutionLocalKey,
    ) {
        if local_key.get() < SUPPLEMENTAL_LOCAL_KEY_BASE {
            return;
        }
        let next = local_key
            .get()
            .checked_add(1)
            .expect("a supplemental local key fits i64");
        let keys = self
            .supplemental_keys
            .entry(ordinal)
            .or_insert([SUPPLEMENTAL_LOCAL_KEY_BASE; 4]);
        keys[kind] = keys[kind].max(next);
    }

    /// Register one complete transient catalog against an already registered
    /// operation-local mount. The caller stages this mutation on a cloned
    /// rebaser and swaps it into the selected inventory only after `true`.
    ///
    /// Only a transient mount reaches this. A persisted mount's catalog is
    /// read from its own interior where a key is wanted, so walking it here
    /// would rewrite the whole blob's identities into these maps for nothing:
    /// on one tract reverse frontier that walk taught the rebaser 1,974,097
    /// semantics, 432,242 paths, 394,894 nodes and 156,273 stack variables and
    /// held 1.24 GiB of live heap.
    pub(crate) fn register_identity_catalog(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        catalog: &ResolutionIdentityCatalog,
        cancellation: &CancellationToken,
    ) -> bool {
        assert_eq!(
            self.registered_mount(ordinal).fragment(),
            catalog.fragment(),
            "transient identity catalog must have its exact selected mount owner"
        );
        for (index, &(runtime, identity)) in catalog.semantics().iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            assert_eq!(
                self.register_semantic(
                    ordinal,
                    ResolutionLocalKey::new(i64::try_from(index).expect("semantic index fits i64")),
                    identity,
                ),
                runtime,
                "transient semantic catalog must round-trip its mounted ID"
            );
        }
        for (index, &(runtime, identity)) in catalog.nodes().iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            assert_eq!(
                self.register_node(
                    ordinal,
                    ResolutionLocalKey::new(i64::try_from(index).expect("node index fits i64")),
                    identity,
                ),
                runtime,
                "transient node catalog must round-trip its mounted ID"
            );
        }
        for (index, &(runtime, identity)) in catalog.paths().iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            assert_eq!(
                self.register_path(
                    ordinal,
                    ResolutionLocalKey::new(i64::try_from(index).expect("path index fits i64")),
                    identity,
                ),
                runtime,
                "transient path catalog must round-trip its mounted ID"
            );
        }
        for (index, &(runtime, identity)) in catalog.stack_variables().iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            assert_eq!(
                self.register_stack_variable(
                    ordinal,
                    ResolutionLocalKey::new(i64::try_from(index).expect("variable index fits i64")),
                    identity,
                ),
                runtime,
                "transient variable catalog must round-trip its mounted ID"
            );
        }
        !cancellation.is_cancelled()
    }

    pub(crate) fn mount(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Option<SelectedResolutionMount> {
        (ordinal.get() < self.persisted_mount_count || self.mounts.contains(&ordinal))
            .then_some(SelectedResolutionMount { ordinal })
    }

    pub(crate) fn mount_for_fragment(
        &self,
        fragment: BindingFragmentId,
    ) -> Option<SelectedResolutionMount> {
        self.mount(SelectedResolutionMountOrdinal::new(fragment.ordinal()))
    }

    /// The mount one local runtime id names, or `None` when the id belongs to
    /// no file or to no mount of this selection.
    ///
    /// This is what the fragment-prefix lookup was: it took the eight bytes a
    /// fragment-local id carried and looked the mount up in a map. A local id
    /// carries the ordinal itself now, so the question is answered from the id
    /// and one set membership, and an id that belongs to no file has no
    /// ordinal to offer.
    pub(crate) fn mount_for_ordinal(
        &self,
        ordinal: Option<u32>,
    ) -> Option<SelectedResolutionMount> {
        self.mount(SelectedResolutionMountOrdinal::new(ordinal?))
    }

    pub(crate) fn register_semantic(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        local_key: ResolutionLocalKey,
        identity: ResolutionSemanticIdentity,
    ) -> SemanticId {
        let mount = self.registered_mount(ordinal);
        let runtime = identity.mounted(mount.ordinal.get(), local_key_u32(local_key));
        let provenance = match identity.space() {
            ResolutionSemanticIdentitySpace::FragmentLocal => {
                SelectedSemanticProvenance::FragmentLocal(SelectedLocalIdentityProvenance {
                    mount,
                    local_key,
                    identity,
                })
            }
            ResolutionSemanticIdentitySpace::Shared => SelectedSemanticProvenance::Shared(identity),
        };
        let fresh = register_runtime(
            &mut self.semantics_by_runtime,
            runtime,
            provenance,
            "semantic",
        );
        self.observe_local_key(ordinal, 0, local_key);
        self.supplemental_semantics
            .insert((ordinal, identity), runtime);
        if fresh && let Some(scope) = self.scope.as_mut() {
            scope.push(MountRebaserRegistration::Semantic(
                ordinal, identity, runtime,
            ));
        }
        runtime
    }

    /// The runtime semantic this operation already gave one identity at one
    /// mount, if it registered one.
    ///
    /// A transient mount's identities and the operation's own supplemental
    /// ones live only here; a persisted mount's live in its interior's
    /// catalog, which answers the same question with
    /// `ResolutionIdentityCatalog::semantic_for_identity`.
    pub(crate) fn supplemental_semantic(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        identity: ResolutionSemanticIdentity,
    ) -> Option<SemanticId> {
        self.supplemental_semantics
            .get(&(ordinal, identity))
            .copied()
    }

    /// Register one selected-context semantic that has no blob-local storage
    /// coordinate.
    ///
    /// Root bridges are operation-local, but their route and lookup cells use
    /// the same Shared recipes as persisted paths. Keeping this entry out of
    /// `semantics_by_coordinate` prevents selected context from inventing a
    /// local row while still giving the root candidate reader exact runtime
    /// provenance.
    pub(crate) fn register_shared_semantic(
        &mut self,
        identity: ResolutionSemanticIdentity,
    ) -> SemanticId {
        let name = identity
            .shared_name()
            .expect("a coordinate-free selected semantic must use Shared identity");
        let runtime = SemanticId::shared_name(name);
        register_runtime(
            &mut self.semantics_by_runtime,
            runtime,
            SelectedSemanticProvenance::Shared(identity),
            "semantic",
        );
        runtime
    }

    pub(crate) fn register_node(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        local_key: ResolutionLocalKey,
        identity: ResolutionNodeIdentity,
    ) -> BindingNodeId {
        let mount = self.registered_mount(ordinal);
        let runtime = identity.mounted(mount.ordinal.get(), local_key_u32(local_key));
        let provenance = SelectedNodeProvenance::FragmentLocal(SelectedLocalIdentityProvenance {
            mount,
            local_key,
            identity,
        });
        let fresh = register_runtime(
            &mut self.nodes_by_runtime,
            runtime,
            provenance,
            "binding node",
        );
        self.observe_local_key(ordinal, 1, local_key);
        self.supplemental_nodes.insert((ordinal, identity), runtime);
        if fresh && let Some(scope) = self.scope.as_mut() {
            scope.push(MountRebaserRegistration::Node(ordinal, identity, runtime));
        }
        runtime
    }

    pub(crate) fn register_path(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        local_key: ResolutionLocalKey,
        identity: ResolutionPathIdentity,
    ) -> PartialPathId {
        let mount = self.registered_mount(ordinal);
        let runtime = identity.mounted(mount.ordinal.get(), local_key_u32(local_key));
        let provenance = SelectedLocalIdentityProvenance {
            mount,
            local_key,
            identity,
        };
        let fresh = register_runtime(
            &mut self.paths_by_runtime,
            runtime,
            provenance,
            "partial path",
        );
        self.observe_local_key(ordinal, 2, local_key);
        self.supplemental_paths.insert((ordinal, identity), runtime);
        if fresh && let Some(scope) = self.scope.as_mut() {
            scope.push(MountRebaserRegistration::Path(ordinal, identity, runtime));
        }
        runtime
    }

    pub(crate) fn register_stack_variable(
        &mut self,
        ordinal: SelectedResolutionMountOrdinal,
        local_key: ResolutionLocalKey,
        identity: ResolutionStackVariableIdentity,
    ) -> StackVariableId {
        let mount = self.registered_mount(ordinal);
        let runtime = identity.mounted(mount.ordinal.get(), local_key_u32(local_key));
        let provenance = SelectedLocalIdentityProvenance {
            mount,
            local_key,
            identity,
        };
        let fresh = register_runtime(
            &mut self.variables_by_runtime,
            runtime,
            provenance,
            "stack variable",
        );
        self.observe_local_key(ordinal, 3, local_key);
        if fresh && let Some(scope) = self.scope.as_mut() {
            scope.push(MountRebaserRegistration::StackVariable(runtime));
        }
        runtime
    }

    /// Register one gap reason the selected context itself minted.
    ///
    /// The reason belongs to no blob, so nothing can decode a mount from it,
    /// and it has to keep the runtime value the completion already carries.
    /// Its id comes from the caller's per-request range, so it names no
    /// `resolution_identities` row and every keyed read it reaches matches
    /// nothing, which is what a reason minted by the context should do.
    pub(crate) fn register_context_owned_semantic(
        &mut self,
        semantic: SemanticId,
        names: &dyn SharedNameInterner,
    ) {
        // The interner keys on a 32-byte digest, which is what a shared name
        // is interned by. A context-owned reason is not a name any blob
        // published, so what it needs is a key no blob's name can collide
        // with; its own eight bytes in an otherwise zero digest are that.
        let mut key = [0; 32];
        key[24..].copy_from_slice(&semantic.as_bytes());
        let name = names.intern(key);
        assert!(
            !name.is_interned(),
            "a context-owned gap reason is not a name any blob published: {semantic}"
        );
        register_runtime(
            &mut self.semantics_by_runtime,
            semantic,
            SelectedSemanticProvenance::Shared(ResolutionSemanticIdentity::shared(name)),
            "semantic",
        );
    }

    pub(crate) fn register_context_boundary(&mut self, node: BindingNodeId) {
        assert_ne!(
            node,
            BindingNodeId::universal_root(),
            "a Java placement boundary cannot replace the universal root"
        );
        register_runtime(
            &mut self.nodes_by_runtime,
            node,
            SelectedNodeProvenance::ContextBoundary,
            "binding node",
        );
    }

    /// The mount one runtime semantic belongs to, or the shared identity it is.
    ///
    /// This is total and opens nothing: the operation's own registrations
    /// answer first, then the ID's prefix names its mount, and an ID whose
    /// prefix names no selected mount is a whole digest, which is exactly what
    /// a shared identity is.
    pub(crate) fn semantic_mount(&self, semantic: SemanticId) -> SelectedSemanticMount {
        match self.semantics_by_runtime.get(&semantic) {
            Some(SelectedSemanticProvenance::FragmentLocal(local)) => {
                SelectedSemanticMount::FragmentLocal(local.mount)
            }
            Some(SelectedSemanticProvenance::Stage(stage)) => {
                SelectedSemanticMount::FragmentLocal(stage.mount())
            }
            Some(SelectedSemanticProvenance::Shared(identity)) => {
                SelectedSemanticMount::Shared(*identity)
            }
            None => match semantic.shared_name_id() {
                Some(name) => {
                    SelectedSemanticMount::Shared(ResolutionSemanticIdentity::shared(name))
                }
                None => SelectedSemanticMount::FragmentLocal(
                    self.mount_for_ordinal(semantic.ordinal())
                        .unwrap_or_else(|| {
                            panic!(
                                "a runtime semantic is a shared name or is mounted on a \
                                 selected fragment: {semantic}"
                            )
                        }),
                ),
            },
        }
    }

    /// What one runtime node names, or `None` when its prefix names no
    /// selected mount and the operation never registered it.
    pub(crate) fn node_mount(&self, node: BindingNodeId) -> Option<SelectedNodeMount> {
        match self.nodes_by_runtime.get(&node) {
            Some(SelectedNodeProvenance::FragmentLocal(local)) => {
                Some(SelectedNodeMount::FragmentLocal(local.mount))
            }
            Some(SelectedNodeProvenance::Stage(stage)) => {
                Some(SelectedNodeMount::FragmentLocal(stage.mount()))
            }
            Some(SelectedNodeProvenance::UniversalRoot) => Some(SelectedNodeMount::UniversalRoot),
            Some(SelectedNodeProvenance::ContextBoundary) => {
                Some(SelectedNodeMount::ContextBoundary)
            }
            None => self
                .mount_for_ordinal(node.ordinal())
                .map(SelectedNodeMount::FragmentLocal),
        }
    }

    /// Whether this operation issued one runtime semantic: the rebaser holds
    /// it, or its own prefix names a selected mount.
    ///
    /// A whole-digest shared identity is not issued by anyone in particular,
    /// so it answers false, which is what the callers of this want: they are
    /// asking whether an arbitrary symbol or reason can name one of this
    /// selection's fragment-local anchors.
    pub(crate) fn issued_semantic(&self, semantic: SemanticId) -> bool {
        self.semantics_by_runtime.contains_key(&semantic)
            || self.mount_for_ordinal(semantic.ordinal()).is_some()
    }

    /// One semantic's provenance when the operation registered it: a transient
    /// mount's identity, a supplemental identity, or a selected-context shared
    /// recipe. A persisted mount's own semantic is not here; its key is the
    /// position it occupies in the mount's interior identity catalog.
    pub(crate) fn registered_semantic_provenance(
        &self,
        semantic: SemanticId,
    ) -> Option<SelectedSemanticProvenance> {
        self.semantics_by_runtime.get(&semantic).copied()
    }

    /// One node's provenance, when this operation registered it and can state
    /// it without opening anything.
    ///
    /// **It no longer answers for a persisted node.** It used to: a persisted
    /// node's id ended in sixteen zero bytes and its dense key, so
    /// `decode_persisted_local_key` read the key out of the id and
    /// `persisted_node_identity` *invented* an identity equal to that key,
    /// which was right only because `rekey_dense` had overwritten the real
    /// identity with the same value. One representation means nothing
    /// translates, so that invention is gone, and with it the discrimination
    /// it rested on: every local id carries its key in the clear now and no id
    /// says whether its mount's catalog holds it.
    ///
    /// That last question is the one the caller actually asks, and only the
    /// mount's catalog can answer it, so
    /// `SelectedResolutionAuthority::node_catalog_provenance` reads the keyed
    /// catalog row where this returns `None`. `BindingNodeId::local_key`
    /// supplies the key; the row establishes actual selected membership.
    pub(crate) fn node_provenance(&self, node: BindingNodeId) -> Option<SelectedNodeProvenance> {
        self.nodes_by_runtime.get(&node).copied()
    }

    /// See [`Self::node_provenance`]: this answers for what the operation
    /// registered and leaves a persisted path to its mount's catalog.
    pub(crate) fn path_provenance(
        &self,
        path: PartialPathId,
    ) -> Option<SelectedLocalIdentityProvenance<ResolutionPathIdentity>> {
        self.paths_by_runtime.get(&path).copied()
    }

    /// See [`Self::node_provenance`]: this answers for what the operation
    /// registered and leaves a persisted variable to its mount's catalog.
    pub(crate) fn stack_variable_provenance(
        &self,
        variable: StackVariableId,
    ) -> Option<SelectedLocalIdentityProvenance<ResolutionStackVariableIdentity>> {
        self.variables_by_runtime.get(&variable).copied()
    }

    /// The runtime path this operation already gave one identity at one mount,
    /// or `None` when it has given it none.
    ///
    /// This is what recomputing the mounted id used to answer. An operation's
    /// own identity has no catalog position until the operation gives it one,
    /// so it cannot be recomputed, and asking the identity is the only way to
    /// keep one bridge from being minted twice under two keys.
    pub(crate) fn supplemental_path(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        identity: ResolutionPathIdentity,
    ) -> Option<PartialPathId> {
        self.supplemental_paths.get(&(ordinal, identity)).copied()
    }

    /// See [`Self::supplemental_path`].
    pub(crate) fn supplemental_node(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        identity: ResolutionNodeIdentity,
    ) -> Option<BindingNodeId> {
        self.supplemental_nodes.get(&(ordinal, identity)).copied()
    }

    fn registered_mount(&self, ordinal: SelectedResolutionMountOrdinal) -> SelectedResolutionMount {
        self.mount(ordinal).unwrap_or_else(|| {
            panic!(
                "resolution identity names unregistered selected mount ordinal {}",
                ordinal.get()
            )
        })
    }
}

/// One storage-local key as the 32 bits a runtime identity carries it in.
///
/// A key is a catalog position or one of an operation's supplemental keys, and
/// `MountedIdentities::new` already asserts a blob's catalog fits `u32`; the
/// supplemental range starts at `SUPPLEMENTAL_LOCAL_KEY_BASE`, which is inside
/// it. The conversion is written once so that a key that does not fit fails
/// here rather than silently truncating into an identity.
fn local_key_u32(local_key: ResolutionLocalKey) -> u32 {
    u32::try_from(local_key.get())
        .unwrap_or_else(|_| panic!("a storage-local key fits u32: {}", local_key.get()))
}

fn register_bijection<Left, Right>(
    by_left: &mut HashMap<Left, Right>,
    by_right: &mut HashMap<Right, Left>,
    left: Left,
    right: Right,
    label: &str,
) where
    Left: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    Right: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    if let Some(previous) = by_left.insert(left, right) {
        assert_eq!(
            previous, right,
            "{label} left identity has conflicting right identities: {left:?}"
        );
    }
    if let Some(previous) = by_right.insert(right, left) {
        assert_eq!(
            previous, left,
            "{label} right identity has conflicting left identities: {right:?}"
        );
    }
}

/// Returns whether the runtime id was not registered before.
fn register_runtime<Runtime, Provenance>(
    by_runtime: &mut HashMap<Runtime, Provenance>,
    runtime: Runtime,
    provenance: Provenance,
    label: &str,
) -> bool
where
    Runtime: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    Provenance: Copy + std::fmt::Debug + Eq,
{
    match by_runtime.insert(runtime, provenance) {
        Some(previous) => {
            assert_eq!(
                previous, provenance,
                "mounted resolution {label} has conflicting selected provenance: {runtime:?}"
            );
            false
        }
        None => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolutionSemanticIdentitySpace {
    FragmentLocal,
    Shared,
}

/// One semantic's content identity: a fragment-local digest, or a shared
/// name's interned id.
///
/// A fragment-local semantic is a digest of a producer-stable local key, and
/// stays one: it is local to a blob and means nothing outside it. A shared
/// name belongs to no file, so it is an integer interned once per store
/// (`resolution_identities.id`) instead of a digest every blob recomputes.
/// The name's own digest is how the writer finds or creates that row; it is a
/// property of the store's interning table, not of the identity, and the
/// catalog carries it for the preparer through
/// [`ResolutionIdentityCatalog::shared_name_digest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolutionSemanticIdentity {
    FragmentLocal([u8; 32]),
    Shared(SharedNameId),
    /// A gap reason: fragment-local like `FragmentLocal`, but it occupies a
    /// runtime position without a `resolution_semantic_catalog` row (#3737).
    /// Nothing reads a reason by catalog digest, and a row per reason was
    /// 9,126 of one Go file's 83,742 catalog rows. Reasons sort after every
    /// other identity, so the rows that are written stay dense from zero.
    GapReason([u8; 32]),
}

impl ResolutionSemanticIdentity {
    pub(crate) const fn fragment_local(digest: [u8; 32]) -> Self {
        Self::FragmentLocal(digest)
    }

    pub(crate) const fn gap_reason(digest: [u8; 32]) -> Self {
        Self::GapReason(digest)
    }

    pub(crate) const fn shared(name: SharedNameId) -> Self {
        Self::Shared(name)
    }

    /// Whether this identity has a persisted catalog row.
    pub(crate) const fn has_catalog_row(self) -> bool {
        !matches!(self, Self::GapReason(_))
    }

    /// This identity with another digest, in the same variant.
    pub(crate) fn with_fragment_local_digest(self, digest: [u8; 32]) -> Self {
        match self {
            Self::FragmentLocal(_) => Self::FragmentLocal(digest),
            Self::GapReason(_) => Self::GapReason(digest),
            Self::Shared(name) => {
                panic!("a shared name has no fragment-local digest to replace: {name}")
            }
        }
    }

    pub(crate) const fn space(self) -> ResolutionSemanticIdentitySpace {
        match self {
            Self::FragmentLocal(_) | Self::GapReason(_) => {
                ResolutionSemanticIdentitySpace::FragmentLocal
            }
            Self::Shared(_) => ResolutionSemanticIdentitySpace::Shared,
        }
    }

    /// The producer-stable digest of one fragment-local semantic.
    pub(crate) fn fragment_local_digest(self) -> [u8; 32] {
        match self {
            Self::FragmentLocal(digest) | Self::GapReason(digest) => digest,
            Self::Shared(name) => {
                panic!("a shared name has an interned id, not a fragment-local digest: {name}")
            }
        }
    }

    /// The shared name this identity is, or `None` when it is fragment-local.
    pub(crate) const fn shared_name(self) -> Option<SharedNameId> {
        match self {
            Self::FragmentLocal(_) | Self::GapReason(_) => None,
            Self::Shared(name) => Some(name),
        }
    }

    /// This identity as the runtime semantic one mount meets it by.
    ///
    /// A fragment-local identity is its mount's ordinal and the catalog
    /// position it occupies there, so unlike the digest splice this replaces,
    /// it is not a function of the identity alone: the position is known only
    /// once `ResolutionIdentityCatalogBuilder::finish` has put the catalog in
    /// canonical order, and the ordinal only once a selection mounts it. A
    /// shared name belongs to no mount and ignores both.
    pub(crate) fn mounted(self, ordinal: u32, local_key: u32) -> SemanticId {
        match self {
            Self::FragmentLocal(_) | Self::GapReason(_) => SemanticId::local(ordinal, local_key),
            Self::Shared(name) => SemanticId::shared_name(name),
        }
    }
}

/// One interner for a whole test binary.
///
/// Production interning is per store: an id is a row of that store's
/// `resolution_identities`, and two stores may give one name two ids. Most
/// fixtures have no store behind them and compare artifacts lowered
/// separately, which a content digest used to give them for free. One table
/// for the process gives that property back without pretending any of these
/// ids is a store fact: every one of them is in the per-request range.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn test_shared_names() -> &'static dyn SharedNameInterner {
    static NAMES: std::sync::OnceLock<TestSharedNames> = std::sync::OnceLock::new();
    NAMES.get_or_init(TestSharedNames::default)
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub(crate) struct TestSharedNames {
    ids: std::sync::Mutex<HashMap<[u8; 32], SharedNameId>>,
}

#[cfg(any(test, feature = "test-support"))]
impl SharedNameInterner for TestSharedNames {
    fn intern(&self, digest: [u8; 32]) -> SharedNameId {
        let mut ids = self
            .ids
            .lock()
            .expect("the test shared-name table is not poisoned");
        let next =
            u32::try_from(ids.len()).expect("a test binary mints fewer names than u32 holds");
        *ids.entry(digest)
            .or_insert_with(|| SharedNameId::per_request(next))
    }
}

/// Where one shared name's id comes from.
///
/// A shared name is minted by language-neutral lowering, which has no store in
/// hand, so the id is handed to it. The single writer's connection answers
/// with `resolution_identities.id`; a read-only request answers from the store
/// where a row exists and from its own per-request range where none does; a
/// preparation that will write its rows as digests answers from its own range
/// and never claims a store fact.
/// `pub` because it names a parameter of the public lowering entry points;
/// the module itself is private, so the crate is still the only place that can
/// spell it, as `SelectedResolutionMountOrdinal` above is.
pub trait SharedNameInterner: std::fmt::Debug {
    /// The id of one shared name, by the 32-byte digest that names it.
    fn intern(&self, digest: [u8; 32]) -> SharedNameId;

    /// Decode a stored name into the request's established identity.
    ///
    /// Admission may associate a newly persisted name with an ID already used
    /// by this request. This conversion performs no SQL and never interns a
    /// missing name. Its input must name a committed store identity.
    #[allow(clippy::wrong_self_convention)]
    fn from_persisted(&self, stored: SharedNameId) -> SharedNameId {
        assert!(
            stored.is_interned(),
            "a persisted shared name must be interned"
        );
        stored
    }

    /// Bind a request name to a durable key, if it has a stored correspondence.
    ///
    /// Request-only names, including synthetic context reasons, remain unmapped.
    /// This conversion performs no SQL and never publishes a missing name.
    fn to_persisted(&self, request: SharedNameId) -> Option<SharedNameId> {
        request.is_interned().then_some(request)
    }
}

/// One interner with no store behind it: every name gets a per-request id and
/// the digests are kept so that the preparer can still write them.
///
/// This is what index-time preparation uses. Its ids never leave the
/// artifact: the rows the preparer writes carry the digest, the writer interns
/// it, and the artifact is dropped. `is_interned` is false for every id it
/// mints, which is what says so.
#[derive(Debug, Default)]
pub struct PerRequestSharedNames {
    names: std::cell::RefCell<HashMap<[u8; 32], SharedNameId>>,
    digests: std::cell::RefCell<Vec<[u8; 32]>>,
}

impl PerRequestSharedNames {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every name this table minted an id for, in id order.
    pub(crate) fn digests(&self) -> Vec<(SharedNameId, [u8; 32])> {
        self.digests
            .borrow()
            .iter()
            .enumerate()
            .map(|(ordinal, digest)| {
                (
                    SharedNameId::per_request(
                        u32::try_from(ordinal).expect("a per-request shared name ordinal fits u32"),
                    ),
                    *digest,
                )
            })
            .collect()
    }
}

impl SharedNameInterner for PerRequestSharedNames {
    fn intern(&self, digest: [u8; 32]) -> SharedNameId {
        if let Some(&id) = self.names.borrow().get(&digest) {
            return id;
        }
        let mut digests = self.digests.borrow_mut();
        let id = SharedNameId::per_request(
            u32::try_from(digests.len()).expect("a per-request shared name ordinal fits u32"),
        );
        digests.push(digest);
        self.names.borrow_mut().insert(digest, id);
        id
    }
}

/// The canonical source recipe for one effective lookup semantic.
///
/// The semantic language is the analyzer's stable configuration label, not a
/// storage-language or parser-dialect key. The recipe therefore survives
/// remounting and can be written directly to the normalized lookup-recipe
/// relation without trying to invert an opaque semantic digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ResolutionLookupSemanticRecipe {
    semantic_language: String,
    namespace: ResolutionNamespace,
    spelling: String,
}

impl ResolutionLookupSemanticRecipe {
    /// The heap this recipe owns beyond its own inline size.
    pub(crate) fn owned_bytes(&self) -> usize {
        let Self {
            semantic_language,
            namespace: _,
            spelling,
        } = self;
        semantic_language
            .capacity()
            .saturating_add(spelling.capacity())
    }

    pub(crate) fn new(language: Language, namespace: ResolutionNamespace, spelling: &str) -> Self {
        assert_ne!(
            language,
            Language::None,
            "a resolution lookup recipe needs a semantic language"
        );
        assert!(
            matches!(
                namespace,
                ResolutionNamespace::Type
                    | ResolutionNamespace::Value
                    | ResolutionNamespace::Callable
                    | ResolutionNamespace::Constructor
                    | ResolutionNamespace::Macro
                    | ResolutionNamespace::Constant
                    | ResolutionNamespace::Package
            ),
            "a resolution lookup recipe needs one effective namespace: {namespace:?}"
        );
        assert!(
            !spelling.is_empty(),
            "a resolution lookup recipe needs a nonempty spelling"
        );
        Self {
            semantic_language: language.config_label().to_owned(),
            namespace,
            spelling: spelling.to_owned(),
        }
    }

    pub(crate) fn semantic_language(&self) -> &str {
        &self.semantic_language
    }

    pub(crate) const fn namespace(&self) -> ResolutionNamespace {
        self.namespace
    }

    pub(crate) fn spelling(&self) -> &str {
        &self.spelling
    }

    /// The 32-byte digest that names this recipe in `resolution_identities`.
    ///
    /// This is the interning key, not the identity: it is how a store finds or
    /// creates the row whose id the recipe then is.
    pub(crate) fn name_digest(&self) -> [u8; 32] {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-effective-lookup-key:v1");
        hasher.field("language", self.semantic_language.as_bytes());
        hasher.field("namespace", self.namespace.identity_label().as_bytes());
        hasher.field("spelling", self.spelling.as_bytes());
        hasher.finish()
    }

    pub(crate) fn identity(&self, names: &dyn SharedNameInterner) -> ResolutionSemanticIdentity {
        ResolutionSemanticIdentity::shared(names.intern(self.name_digest()))
    }

    pub(crate) fn semantic(&self, names: &dyn SharedNameInterner) -> SemanticId {
        SemanticId::shared_name(names.intern(self.name_digest()))
    }
}

macro_rules! local_identity {
    ($name:ident, $mounted:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn new(digest: [u8; 32]) -> Self {
                Self(digest)
            }

            pub(crate) const fn digest(self) -> [u8; 32] {
                self.0
            }

            /// This identity as the runtime id one mount meets it by: the
            /// mount's ordinal and the catalog position it occupies there.
            ///
            /// The position is not a function of the identity, so unlike the
            /// digest splice this replaces, an identity cannot mount itself
            /// until `ResolutionIdentityCatalogBuilder::finish` has ordered
            /// the catalog. The identity itself is unchanged: it is still the
            /// producer-stable local descriptor the catalog is ordered by.
            pub(crate) fn mounted(self, ordinal: u32, local_key: u32) -> $mounted {
                <$mounted>::local(ordinal, local_key)
            }
        }
    };
}

local_identity!(ResolutionNodeIdentity, BindingNodeId);
local_identity!(ResolutionPathIdentity, PartialPathId);
local_identity!(ResolutionStackVariableIdentity, StackVariableId);

/// One catalog index as the position a mounted id carries.
fn catalog_position(index: usize) -> u32 {
    u32::try_from(index).expect("a blob's identity catalog fits u32")
}

/// One catalog position as the storage-local key it is.
fn catalog_local_key(position: u32) -> ResolutionLocalKey {
    ResolutionLocalKey::new(i64::from(position))
}

/// Explicit Go spelling-scope choice coverage, separate from effective namespace
/// precedence. A missing spelling must be covered in all four namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoSpellingChoiceAuthority {
    pub(crate) scope: ResolutionScopeId,
    pub(crate) activation_start: Option<usize>,
}

pub(crate) const GO_SPELLING_NAMESPACES: [ResolutionNamespace; 4] = [
    ResolutionNamespace::Type,
    ResolutionNamespace::Value,
    ResolutionNamespace::Callable,
    ResolutionNamespace::Package,
];

#[derive(Debug)]
pub(crate) struct ResolutionIdentityCatalogBuilder<'a> {
    fragment: BindingFragmentId,
    /// Where a shared name's id comes from. A shared name belongs to no file,
    /// so the lowering cannot mint one; it asks this.
    names: &'a dyn SharedNameInterner,
    /// The digest that names each shared name this blob mentions. The identity
    /// is the id; the digest is what the writer interns by, and the preparer
    /// is its only reader.
    shared_name_digests: HashMap<SharedNameId, [u8; 32]>,
    semantics: HashMap<SemanticId, ResolutionSemanticIdentity>,
    semantics_by_identity: HashMap<ResolutionSemanticIdentity, SemanticId>,
    lookup_recipes: HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
    lookup_semantics_by_recipe: HashMap<ResolutionLookupSemanticRecipe, SemanticId>,
    precedence_namespaces: HashMap<PrecedenceStep, ResolutionNamespace>,
    go_spelling_choices: HashMap<PrecedenceStep, GoSpellingChoiceAuthority>,
    nodes: HashMap<BindingNodeId, ResolutionNodeIdentity>,
    nodes_by_identity: HashMap<ResolutionNodeIdentity, BindingNodeId>,
    source_site_nodes: HashSet<BindingNodeId>,
    /// The semantic and the node of each site that has them. Their catalog
    /// positions are the site's own number (`finish`).
    site_semantics: HashMap<ResolutionSiteId, SemanticId>,
    site_nodes: HashMap<ResolutionSiteId, BindingNodeId>,
    source_scope_ordinals: HashMap<BindingNodeId, ResolutionScopeId>,
    paths: HashMap<PartialPathId, ResolutionPathIdentity>,
    paths_by_identity: HashMap<ResolutionPathIdentity, PartialPathId>,
    stack_variables: HashMap<StackVariableId, ResolutionStackVariableIdentity>,
    stack_variables_by_identity: HashMap<ResolutionStackVariableIdentity, StackVariableId>,
    /// The next provisional key of each kind: semantics, nodes, paths, stack
    /// variables.
    ///
    /// A mounted id is a mount ordinal and a catalog position now, and neither
    /// is known while the lowering runs: the position only after `finish` has
    /// ordered the catalog, the ordinal only when a selection mounts the
    /// artifact. So the lowering mints under [`UNMOUNTED_ORDINAL`] from these
    /// counters and `rekey_dense` translates every one of them to the position
    /// it ended up at. That is why `rekey_dense`'s translation is total in this
    /// stage where it used to be partial.
    provisional: [u32; 4],
}

impl<'a> ResolutionIdentityCatalogBuilder<'a> {
    pub(crate) fn new(fragment: BindingFragmentId, names: &'a dyn SharedNameInterner) -> Self {
        Self {
            fragment,
            names,
            shared_name_digests: HashMap::default(),
            semantics: HashMap::default(),
            semantics_by_identity: HashMap::default(),
            lookup_recipes: HashMap::default(),
            lookup_semantics_by_recipe: HashMap::default(),
            precedence_namespaces: HashMap::default(),
            go_spelling_choices: HashMap::default(),
            nodes: HashMap::default(),
            nodes_by_identity: HashMap::default(),
            source_site_nodes: HashSet::default(),
            site_semantics: HashMap::default(),
            site_nodes: HashMap::default(),
            source_scope_ordinals: HashMap::default(),
            paths: HashMap::default(),
            paths_by_identity: HashMap::default(),
            stack_variables: HashMap::default(),
            stack_variables_by_identity: HashMap::default(),
            provisional: [0; 4],
        }
    }

    /// The next provisional key of one kind: semantics 0, nodes 1, paths 2,
    /// stack variables 3.
    fn next_provisional(&mut self, kind: usize) -> u32 {
        let key = self.provisional[kind];
        self.provisional[kind] = key
            .checked_add(1)
            .unwrap_or_else(|| panic!("a blob's identity catalog fits u32: {key}"));
        key
    }

    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub(crate) fn semantic(&mut self, identity: ResolutionSemanticIdentity) -> SemanticId {
        if let Some(name) = identity.shared_name() {
            assert!(
                self.shared_name_digests.contains_key(&name),
                "a shared name enters the catalog through `shared_name`, which is where \
                 its interning digest is recorded: {name}"
            );
        }
        // A lowering asks for one identity more than once -- the same
        // declaration's semantic from two paths, the same shared name from two
        // sites -- and the answer has to be one id. `identity.mount(fragment)`
        // gave that for free because it was a pure function; a provisional
        // number is a counter, so the memo is what gives it back, and without
        // it the second ask mints a second id and the catalog's own bijection
        // assertion fires.
        if let Some(mounted) = self.semantics_by_identity.get(&identity) {
            return *mounted;
        }
        let mounted = identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(0));
        register_identity(
            &mut self.semantics,
            &mut self.semantics_by_identity,
            mounted,
            identity,
            "semantic",
        );
        mounted
    }

    /// The digest that names one shared name this blob mentions.
    pub(crate) fn shared_name_digest(&self, name: SharedNameId) -> [u8; 32] {
        self.shared_name_digests
            .get(&name)
            .copied()
            .unwrap_or_else(|| {
                panic!("a shared name this blob mentions carries its digest: {name}")
            })
    }

    /// The bytes one registered semantic identity contributes to a lowered
    /// digest.
    ///
    /// A fragment-local identity contributes its own digest. A shared name
    /// contributes the digest it is interned by, not its id: the id is a
    /// property of one store's interning table, and a lowered digest that
    /// moved with it would differ between two caches holding the same file.
    pub(crate) fn identity_hash_bytes(&self, identity: ResolutionSemanticIdentity) -> [u8; 32] {
        match identity {
            ResolutionSemanticIdentity::FragmentLocal(digest)
            | ResolutionSemanticIdentity::GapReason(digest) => digest,
            ResolutionSemanticIdentity::Shared(name) => self.shared_name_digest(name),
        }
    }

    /// One shared name, interned, as the semantic every mount meets it by.
    pub(crate) fn shared_name(&mut self, digest: [u8; 32]) -> SemanticId {
        let name = self.names.intern(digest);
        if let Some(previous) = self.shared_name_digests.insert(name, digest) {
            assert_eq!(
                previous, digest,
                "one shared name id names one digest: {name}"
            );
        }
        self.semantic(ResolutionSemanticIdentity::shared(name))
    }

    pub(crate) fn lookup_semantic(
        &mut self,
        language: Language,
        namespace: ResolutionNamespace,
        spelling: &str,
    ) -> SemanticId {
        let recipe = ResolutionLookupSemanticRecipe::new(language, namespace, spelling);
        let semantic = self.shared_name(recipe.name_digest());
        register_lookup_recipe(
            &mut self.lookup_recipes,
            &mut self.lookup_semantics_by_recipe,
            semantic,
            recipe,
        );
        semantic
    }

    pub(crate) fn register_precedence_namespace(
        &mut self,
        step: PrecedenceStep,
        namespace: ResolutionNamespace,
    ) -> PrecedenceStep {
        assert!(
            !self.go_spelling_choices.contains_key(&step),
            "a Go spelling choice is not a singleton namespace choice"
        );
        assert_ne!(
            namespace,
            ResolutionNamespace::TypeOrValue,
            "a precedence step needs an effective namespace"
        );
        if let Some(previous) = self.precedence_namespaces.insert(step, namespace) {
            assert_eq!(
                previous, namespace,
                "precedence step has conflicting effective namespaces: {step:?}"
            );
        }
        step
    }

    pub(crate) fn register_go_spelling_choice(
        &mut self,
        step: PrecedenceStep,
        authority: GoSpellingChoiceAuthority,
    ) -> PrecedenceStep {
        assert!(
            !self.precedence_namespaces.contains_key(&step),
            "a singleton namespace choice cannot become a Go spelling choice"
        );
        if let Some(previous) = self.go_spelling_choices.insert(step, authority) {
            assert_eq!(
                previous, authority,
                "Go spelling choice has conflicting positional authority"
            );
        }
        step
    }

    pub(crate) fn node(&mut self, identity: ResolutionNodeIdentity) -> BindingNodeId {
        // One identity, one id. See `Self::semantic`.
        if let Some(mounted) = self.nodes_by_identity.get(&identity) {
            return *mounted;
        }
        let mounted = identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(1));
        register_identity(
            &mut self.nodes,
            &mut self.nodes_by_identity,
            mounted,
            identity,
            "node",
        );
        mounted
    }

    pub(crate) fn source_scope_node(&mut self, scope: ResolutionScopeId) -> BindingNodeId {
        let mounted = self.node(super::fact_lowering::scope_head_node_identity(scope));
        if let Some(previous) = self.source_scope_ordinals.insert(mounted, scope) {
            assert_eq!(previous, scope, "source scope node has one ordinal");
        }
        mounted
    }

    /// The semantic of one reference site. Every registration of a site's
    /// semantic goes through this or [`Self::source_definition_semantic`], so
    /// that `finish` can give the site its own catalog position.
    pub(crate) fn source_reference_semantic(&mut self, site: ResolutionSiteId) -> SemanticId {
        let mounted = self.semantic(super::fact_lowering::reference_semantic_identity(site));
        self.record_site_semantic(site, mounted);
        mounted
    }

    /// The semantic of one definition site. See
    /// [`Self::source_reference_semantic`].
    pub(crate) fn source_definition_semantic(&mut self, site: ResolutionSiteId) -> SemanticId {
        let mounted = self.semantic(super::fact_lowering::definition_semantic_identity(site));
        self.record_site_semantic(site, mounted);
        mounted
    }

    fn record_site_semantic(&mut self, site: ResolutionSiteId, semantic: SemanticId) {
        if let Some(previous) = self.site_semantics.insert(site, semantic) {
            assert_eq!(
                previous, semantic,
                "a resolution site has one semantic, so that its site, semantic \
                 and node can share one number: {site:?}"
            );
        }
    }

    fn record_site_node(&mut self, site: ResolutionSiteId, node: BindingNodeId) {
        self.source_site_nodes.insert(node);
        if let Some(previous) = self.site_nodes.insert(site, node) {
            assert_eq!(
                previous, node,
                "a resolution site has one node, so that its site, semantic and \
                 node can share one number: {site:?}"
            );
        }
    }

    pub(crate) fn source_reference_node(&mut self, site: ResolutionSiteId) -> BindingNodeId {
        let mounted = self.node(super::fact_lowering::reference_node_identity(site));
        self.record_site_node(site, mounted);
        mounted
    }

    pub(crate) fn source_definition_node(&mut self, site: ResolutionSiteId) -> BindingNodeId {
        let mounted = self.node(super::fact_lowering::definition_node_identity(site));
        self.record_site_node(site, mounted);
        mounted
    }

    pub(crate) fn path(&mut self, identity: ResolutionPathIdentity) -> PartialPathId {
        // One identity, one id. See `Self::semantic`.
        if let Some(mounted) = self.paths_by_identity.get(&identity) {
            return *mounted;
        }
        let mounted = identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(2));
        register_identity(
            &mut self.paths,
            &mut self.paths_by_identity,
            mounted,
            identity,
            "path",
        );
        mounted
    }

    pub(crate) fn stack_variable(
        &mut self,
        identity: ResolutionStackVariableIdentity,
    ) -> StackVariableId {
        // One identity, one id. See `Self::semantic`.
        if let Some(mounted) = self.stack_variables_by_identity.get(&identity) {
            return *mounted;
        }
        let mounted = identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(3));
        register_identity(
            &mut self.stack_variables,
            &mut self.stack_variables_by_identity,
            mounted,
            identity,
            "stack variable",
        );
        mounted
    }

    pub(crate) fn semantic_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<ResolutionSemanticIdentity> {
        self.semantics.get(&semantic).copied()
    }

    pub(crate) fn path_identity(&self, path: PartialPathId) -> Option<ResolutionPathIdentity> {
        self.paths.get(&path).copied()
    }

    pub(crate) fn node_identity(&self, node: BindingNodeId) -> Option<ResolutionNodeIdentity> {
        self.nodes.get(&node).copied()
    }

    pub(crate) fn finish(mut self) -> ResolutionIdentityCatalog {
        for (&semantic, recipe) in &self.lookup_recipes {
            let identity = self
                .semantics
                .get(&semantic)
                .copied()
                .expect("lookup recipe semantic must be registered in the identity catalog");
            let name = identity.shared_name().unwrap_or_else(|| {
                panic!("lookup recipe semantic must be a shared name: {recipe:?}")
            });
            assert_eq!(
                self.shared_name_digests.get(&name).copied(),
                Some(recipe.name_digest()),
                "lookup recipe does not derive its registered shared name: {recipe:?}"
            );
        }
        for step in self
            .precedence_namespaces
            .keys()
            .chain(self.go_spelling_choices.keys())
        {
            assert!(
                self.semantics.contains_key(&step.semantic),
                "precedence step semantic must be registered in the identity catalog: {step:?}"
            );
        }
        // Site `n`, its semantic and its node carry one number, for every
        // language: position `n` of the semantic catalog and position `n` of
        // the node catalog belong to site `n`, and everything else is numbered
        // above the sites. A persisted local key is the catalog position
        // (`ResolutionLocalKeys`), so this numbering is what lets the schema's
        // sites table hold one b-tree entry per site instead of three
        // (`.agents/docs/stack-graph-schema-draft-2026-09-18.md`, section 3).
        // About a quarter of a blob's sites mint neither a semantic nor a node
        // (expression sites with no positioned identifier); their positions are
        // held by fillers so that every other site is still its own number.
        let site_span = self
            .site_semantics
            .keys()
            .chain(self.site_nodes.keys())
            .map(|site| site.index() + 1)
            .max()
            .unwrap_or(0);
        let mut reserved_semantics = Vec::with_capacity(site_span);
        let mut reserved_nodes = Vec::with_capacity(site_span);
        for index in 0..site_span {
            let site = ResolutionSiteId::try_from_index(index).expect("a site ordinal fits its id");
            reserved_semantics.push(match self.site_semantics.get(&site) {
                Some(&mounted) => (
                    mounted,
                    self.semantics
                        .remove(&mounted)
                        .expect("a site semantic is registered in the identity catalog"),
                ),
                None => {
                    for identity in [
                        super::fact_lowering::reference_semantic_identity(site),
                        super::fact_lowering::definition_semantic_identity(site),
                    ] {
                        assert!(
                            !self.semantics_by_identity.contains_key(&identity),
                            "a site semantic is registered through source_reference_semantic \
                             or source_definition_semantic, so that site {site:?} keeps its \
                             own catalog position {index}"
                        );
                    }
                    let identity = super::fact_lowering::site_filler_semantic_identity(site);
                    (
                        identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(0)),
                        identity,
                    )
                }
            });
            reserved_nodes.push(match self.site_nodes.get(&site) {
                Some(&mounted) => (
                    mounted,
                    self.nodes
                        .remove(&mounted)
                        .expect("a site node is registered in the identity catalog"),
                ),
                None => {
                    for identity in [
                        super::fact_lowering::reference_node_identity(site),
                        super::fact_lowering::definition_node_identity(site),
                    ] {
                        assert!(
                            !self.nodes_by_identity.contains_key(&identity),
                            "a site node is registered through source_reference_node or \
                             source_definition_node, so that site {site:?} keeps its own \
                             catalog position {index}"
                        );
                    }
                    let identity = super::fact_lowering::site_filler_node_identity(site);
                    (
                        identity.mounted(UNMOUNTED_ORDINAL, self.next_provisional(1)),
                        identity,
                    )
                }
            });
        }
        let semantics = site_first_entries(
            reserved_semantics,
            canonical_semantic_entries(self.semantics, &self.shared_name_digests),
        );
        let nodes = site_first_entries(reserved_nodes, canonical_entries(self.nodes));
        for (site, semantic) in &self.site_semantics {
            assert_eq!(
                semantics[site.index()].0,
                *semantic,
                "a site numbers its own semantic: {site:?}"
            );
        }
        for (site, node) in &self.site_nodes {
            assert_eq!(
                nodes[site.index()].0,
                *node,
                "a site numbers its own node: {site:?}"
            );
        }
        ResolutionIdentityCatalog {
            fragment: self.fragment,
            site_span,
            shared_name_digests: self.shared_name_digests,
            semantics: MountedIdentities::new(semantics),
            lookup_recipes: MountedIdentities::new(canonical_recipe_entries(self.lookup_recipes)),
            precedence_namespaces: self.precedence_namespaces,
            go_spelling_choices: self.go_spelling_choices,
            nodes: MountedIdentities::new(nodes),
            source_site_nodes: self.source_site_nodes,
            source_scope_ordinals: self.source_scope_ordinals,
            paths: MountedIdentities::new(canonical_entries(self.paths)),
            stack_variables: MountedIdentities::new(canonical_entries(self.stack_variables)),
        }
    }
}

fn register_lookup_recipe(
    by_semantic: &mut HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
    by_recipe: &mut HashMap<ResolutionLookupSemanticRecipe, SemanticId>,
    semantic: SemanticId,
    recipe: ResolutionLookupSemanticRecipe,
) {
    if let Some(previous) = by_semantic.get(&semantic) {
        assert_eq!(
            previous, &recipe,
            "shared lookup semantic has conflicting canonical recipes: {semantic}"
        );
    }
    if let Some(previous) = by_recipe.get(&recipe) {
        assert_eq!(
            *previous, semantic,
            "canonical lookup recipe has conflicting shared semantics: {recipe:?}"
        );
    }
    by_semantic.insert(semantic, recipe.clone());
    by_recipe.insert(recipe, semantic);
}

fn register_identity<Mounted, Identity>(
    by_mounted: &mut HashMap<Mounted, Identity>,
    by_identity: &mut HashMap<Identity, Mounted>,
    mounted: Mounted,
    identity: Identity,
    label: &str,
) where
    Mounted: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    Identity: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    if let Some(previous) = by_mounted.insert(mounted, identity) {
        assert_eq!(
            previous, identity,
            "mounted resolution {label} has conflicting local identities: {mounted:?}"
        );
    }
    if let Some(previous) = by_identity.insert(identity, mounted) {
        assert_eq!(
            previous, mounted,
            "resolution {label} local identity has conflicting mounted values: {identity:?}"
        );
    }
}

fn canonical_entries<Mounted, Identity>(
    entries: HashMap<Mounted, Identity>,
) -> Vec<(Mounted, Identity)>
where
    Mounted: Copy + Ord,
    Identity: Copy + Ord,
{
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(mounted, identity)| (*identity, *mounted));
    entries
}

/// One catalog in site order: position `n` belongs to site `n`, and whatever
/// the sites do not claim follows in the order the caller canonicalized.
fn site_first_entries<Mounted, Identity>(
    mut reserved: Vec<(Mounted, Identity)>,
    mut rest: Vec<(Mounted, Identity)>,
) -> Vec<(Mounted, Identity)> {
    reserved.append(&mut rest);
    reserved
}

/// The semantic catalog's canonical order, which a catalog position and so
/// every persisted local key depends on.
///
/// It orders by content and never by an interned id. A shared name's id is a
/// property of one store's `resolution_identities` table, so ordering by it
/// would give two caches holding the same file different local keys and
/// therefore a different interior digest, and a byte-identical replacement
/// would stop meeting the persisted blob it replaces. The name's interning
/// digest is the content that stands in for it.
fn canonical_semantic_entries(
    entries: HashMap<SemanticId, ResolutionSemanticIdentity>,
    shared_name_digests: &HashMap<SharedNameId, [u8; 32]>,
) -> Vec<(SemanticId, ResolutionSemanticIdentity)> {
    let order = |identity: &ResolutionSemanticIdentity| match identity {
        ResolutionSemanticIdentity::FragmentLocal(digest) => (0_u8, *digest),
        ResolutionSemanticIdentity::Shared(name) => (
            1,
            *shared_name_digests.get(name).unwrap_or_else(|| {
                panic!("a shared name this blob mentions carries its digest: {name}")
            }),
        ),
        ResolutionSemanticIdentity::GapReason(digest) => (2, *digest),
    };
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(_, identity)| order(identity));
    entries
}

fn canonical_recipe_entries(
    entries: HashMap<SemanticId, ResolutionLookupSemanticRecipe>,
) -> Vec<(SemanticId, ResolutionLookupSemanticRecipe)> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(semantic_a, recipe_a), (semantic_b, recipe_b)| {
        (recipe_a, semantic_a).cmp(&(recipe_b, semantic_b))
    });
    entries
}

/// A mounted id that may carry the catalog position it occupies.
///
/// A local runtime id is a mount ordinal and a catalog position, so an id in
/// the catalog that numbered it answers "which entry am I" out of its own
/// bits. The ids that do not are the ones that belong to no blob -- a shared
/// name in the semantic catalog, whose id is its `resolution_identities` id --
/// and the ids of a catalog whose order is not the position they carry, which
/// is the lookup-recipe catalog, ordered by recipe.
pub(crate) trait CarriesCatalogPosition: Copy + Ord + std::fmt::Debug {
    /// The catalog position this id carries, if it carries one.
    fn carried_position(self) -> Option<usize>;
}

macro_rules! carries_catalog_position {
    ($($name:ty),* $(,)?) => {
        $(impl CarriesCatalogPosition for $name {
            fn carried_position(self) -> Option<usize> {
                self.local_key().map(|key| {
                    usize::try_from(key).expect("a catalog position fits usize")
                })
            }
        })*
    };
}

carries_catalog_position!(SemanticId, BindingNodeId, PartialPathId, StackVariableId);

/// One identity catalog: canonical entries plus an index over the mounted ids
/// that do not name their own entry.
///
/// `entries` is in the mount-independent order its position stands for: the
/// sites first, each at its own number, then the canonical (identity, mounted)
/// order of everything else (`ResolutionIdentityCatalogBuilder::finish`). That
/// position is the storage-local key that preparation, persistence and
/// remounting all read. A question about one mounted id
/// therefore cannot binary search `entries` directly, and answering it by
/// scanning them made a blob's preparation quadratic in its own size: with
/// one scan per emitted artifact, `assert_lookup_recipes_reach_emitted_artifact`
/// alone was 37 percent of the release CPU of preparing this repository's
/// `store/mod.rs`, and the whole lowering phase grew as size^1.6 (R9.3).
///
/// `by_mounted` was that index over every entry. Since milestone 4 gave a
/// local id its catalog position in the clear, most entries answer from the id
/// itself and are not in the index at all: `entries[key]` is the entry, and
/// the equality check beside it is what says so. What is left in the index is
/// the semantic catalog's shared names, whose ids are interned names rather
/// than positions, and the lookup-recipe catalog, which is ordered by recipe
/// and whose positions are therefore not the semantics' own.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountedIdentities<Mounted, Identity> {
    entries: Vec<(Mounted, Identity)>,
    /// Positions of the entries `entries[id.carried_position()]` does not
    /// find, ordered by their mounted id.
    by_mounted: Vec<u32>,
}

impl<Mounted: CarriesCatalogPosition, Identity> MountedIdentities<Mounted, Identity> {
    fn new(entries: Vec<(Mounted, Identity)>) -> Self {
        let mut by_mounted = Vec::new();
        for position in 0..u32::try_from(entries.len()).expect("a blob's identity catalog fits u32")
        {
            let mounted = entries[position as usize].0;
            if mounted.carried_position() != Some(position as usize) {
                by_mounted.push(position);
            }
        }
        by_mounted.sort_unstable_by_key(|&position| entries[position as usize].0);
        assert!(
            by_mounted
                .windows(2)
                .all(|pair| entries[pair[0] as usize].0 != entries[pair[1] as usize].0),
            "a mounted identity names exactly one catalog entry"
        );
        assert!(
            by_mounted.iter().all(|&position| {
                let mounted = entries[position as usize].0;
                mounted
                    .carried_position()
                    .and_then(|carried| entries.get(carried))
                    .is_none_or(|(carried, _)| *carried != mounted)
            }),
            "a mounted identity names exactly one catalog entry"
        );
        by_mounted.shrink_to_fit();
        Self {
            entries,
            by_mounted,
        }
    }

    fn get(&self, mounted: Mounted) -> Option<&Identity> {
        self.entry(mounted).map(|(_, identity)| identity)
    }

    /// The catalog position one mounted id occupies, with its identity.
    ///
    /// The position is the storage-local key: preparation writes the entries
    /// in this order and keys every row by the index. A reader that holds a
    /// runtime ID and this blob's interior therefore has its coordinate
    /// without any operation-lifetime map from ID to key.
    fn entry(&self, mounted: Mounted) -> Option<(u32, &Identity)> {
        if let Some(position) = mounted.carried_position()
            && let Some((carried, identity)) = self.entries.get(position)
            && *carried == mounted
        {
            return Some((
                u32::try_from(position).expect("a blob's identity catalog fits u32"),
                identity,
            ));
        }
        self.by_mounted
            .binary_search_by_key(&mounted, |&position| self.entries[position as usize].0)
            .ok()
            .map(|index| {
                let position = self.by_mounted[index];
                (position, &self.entries[position as usize].1)
            })
    }

    fn entries(&self) -> &[(Mounted, Identity)] {
        &self.entries
    }

    /// The entry one identity occupies among the positions at or above
    /// `content_ordered_from`, which `finish` leaves in identity order.
    ///
    /// This is the direction `entry` does not answer, and it needs no index:
    /// the catalog's own canonical order *is* identity order above the sites
    /// (`canonical_entries`, `canonical_semantic_entries`), so the search is
    /// logarithmic over the entries themselves. The leading site positions are
    /// in site order instead, and an identity a site numbers is found by its
    /// site number rather than here.
    fn entry_by_identity<Key: Ord>(
        &self,
        content_ordered_from: usize,
        key: Key,
        order: impl Fn(&Identity) -> Key,
    ) -> Option<(u32, &Mounted)> {
        let tail = &self.entries[content_ordered_from..];
        let index = tail
            .binary_search_by(|(_, identity)| order(identity).cmp(&key))
            .ok()?;
        let position = u32::try_from(content_ordered_from + index)
            .expect("a blob's identity catalog fits u32");
        Some((position, &tail[index].0))
    }

    /// The slots both vectors allocated, plus whatever each identity owns.
    fn estimated_retained_bytes(&self, owned: impl Fn(&Identity) -> usize) -> usize {
        let Self {
            entries,
            by_mounted,
        } = self;
        entries.iter().map(|(_, identity)| owned(identity)).fold(
            brokk_bifrost_core::hash::vec_slot_bytes(entries)
                .saturating_add(brokk_bifrost_core::hash::vec_slot_bytes(by_mounted)),
            usize::saturating_add,
        )
    }

    fn into_entries(self) -> Vec<(Mounted, Identity)> {
        self.entries
    }

    /// The identities, rewritable in place. Mounted ids stay as they are, so
    /// the index remains correct.
    fn identities_mut(&mut self) -> impl Iterator<Item = (Mounted, &mut Identity)> {
        self.entries
            .iter_mut()
            .map(|(mounted, identity)| (*mounted, identity))
    }

    fn push(&mut self, mounted: Mounted, identity: Identity) {
        let position =
            u32::try_from(self.entries.len()).expect("a blob's identity catalog fits u32");
        assert!(
            self.entry(mounted).is_none(),
            "a mounted identity is registered once: {mounted:?}"
        );
        let index = self
            .by_mounted
            .binary_search_by_key(&mounted, |&position| self.entries[position as usize].0)
            .expect_err("a mounted identity is registered once");
        self.entries.push((mounted, identity));
        if mounted.carried_position() != Some(position as usize) {
            self.by_mounted.insert(index, position);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolutionIdentityCatalog {
    fragment: BindingFragmentId,
    /// How many leading catalog positions belong to sites.
    ///
    /// `ResolutionIdentityCatalogBuilder::finish` gives site `n` position `n`
    /// in both the semantic and the node catalog and orders everything above
    /// the sites by identity. Recording where the sites end is what lets a
    /// question about an identity be a binary search instead of an index.
    site_span: usize,
    /// The interning digest of every shared name this blob mentions. Written
    /// rows carry the digest, because interning is a store fact the per-blob
    /// producer cannot know; everything in the heap carries the id.
    shared_name_digests: HashMap<SharedNameId, [u8; 32]>,
    semantics: MountedIdentities<SemanticId, ResolutionSemanticIdentity>,
    lookup_recipes: MountedIdentities<SemanticId, ResolutionLookupSemanticRecipe>,
    precedence_namespaces: HashMap<PrecedenceStep, ResolutionNamespace>,
    go_spelling_choices: HashMap<PrecedenceStep, GoSpellingChoiceAuthority>,
    nodes: MountedIdentities<BindingNodeId, ResolutionNodeIdentity>,
    source_site_nodes: HashSet<BindingNodeId>,
    source_scope_ordinals: HashMap<BindingNodeId, ResolutionScopeId>,
    paths: MountedIdentities<PartialPathId, ResolutionPathIdentity>,
    stack_variables: MountedIdentities<StackVariableId, ResolutionStackVariableIdentity>,
}

/// One total runtime-identity translation, as the deep walks in `remount.rs`
/// consume it.
///
/// Two translations exist and they are not variants of one structure. A
/// remount reads a catalog and answers from maps built out of it; a mount
/// splice rewrites the mount ordinal of every identity that crosses between
/// an unmounted interior and the engine, with nothing to look up. The walks
/// over paths, completions and typed rows are the same walks either way, so
/// they are written once and take whichever translation the caller has.
pub(crate) trait ResolutionIdentityTranslation {
    fn semantic(&self, semantic: SemanticId) -> SemanticId;

    fn node(&self, node: BindingNodeId) -> BindingNodeId;

    fn path(&self, path: PartialPathId) -> PartialPathId;

    fn stack_variable(&self, variable: StackVariableId) -> StackVariableId;

    /// The fragment a value belongs to after this translation.
    fn fragment(&self, fragment: BindingFragmentId) -> BindingFragmentId;

    /// This translation's answer for one incompleteness reason an operation
    /// minted rather than a producer.
    ///
    /// A lowered artifact cannot carry one, so the remount treats it as an
    /// invariant failure; a value crossing the mount seam can, so the splice
    /// translates the identity inside it.
    fn operation_local_reason(
        &self,
        reason: &super::model::ResolutionIncompleteReason,
    ) -> super::model::ResolutionIncompleteReason;
}

/// The ids one operation assigned to the identities of an artifact it
/// registered, as a translation the remount walks can take.
///
/// A macro capsule is lowered onto its host's mount and its ids are its own
/// catalog's positions, which collide with the host blob's. The operation
/// gives each of its identities a key instead -- the host's own key where the
/// host holds the identity, a supplemental key where it does not -- and the
/// artifact is remounted onto those. That is what an identity digest used to
/// do for free: a capsule identity the host also held hashed to the host's id,
/// and one only the capsule held hashed to something the host could not name.
#[derive(Debug, Default)]
pub(crate) struct ResolutionRegisteredIdentities {
    semantics: HashMap<SemanticId, SemanticId>,
    nodes: HashMap<BindingNodeId, BindingNodeId>,
    paths: HashMap<PartialPathId, PartialPathId>,
    stack_variables: HashMap<StackVariableId, StackVariableId>,
    fragment: Option<BindingFragmentId>,
}

impl ResolutionRegisteredIdentities {
    pub(crate) fn new(fragment: BindingFragmentId) -> Self {
        Self {
            fragment: Some(fragment),
            ..Self::default()
        }
    }

    pub(crate) fn assign_semantic(&mut self, from: SemanticId, to: SemanticId) {
        assert!(
            self.semantics
                .insert(from, to)
                .is_none_or(|prior| prior == to)
        );
    }

    pub(crate) fn assign_node(&mut self, from: BindingNodeId, to: BindingNodeId) {
        assert!(self.nodes.insert(from, to).is_none_or(|prior| prior == to));
    }

    pub(crate) fn assign_path(&mut self, from: PartialPathId, to: PartialPathId) {
        assert!(self.paths.insert(from, to).is_none_or(|prior| prior == to));
    }

    pub(crate) fn assign_stack_variable(&mut self, from: StackVariableId, to: StackVariableId) {
        assert!(
            self.stack_variables
                .insert(from, to)
                .is_none_or(|prior| prior == to)
        );
    }
}

impl ResolutionIdentityTranslation for ResolutionRegisteredIdentities {
    fn fragment(&self, fragment: BindingFragmentId) -> BindingFragmentId {
        self.fragment.unwrap_or(fragment)
    }

    fn semantic(&self, semantic: SemanticId) -> SemanticId {
        self.semantics
            .get(&semantic)
            .copied()
            .unwrap_or_else(|| panic!("semantic {semantic} was not registered for this overlay"))
    }

    fn node(&self, node: BindingNodeId) -> BindingNodeId {
        if node == BindingNodeId::universal_root() {
            return node;
        }
        self.nodes
            .get(&node)
            .copied()
            .unwrap_or_else(|| panic!("node {node} was not registered for this overlay"))
    }

    fn path(&self, path: PartialPathId) -> PartialPathId {
        self.paths
            .get(&path)
            .copied()
            .unwrap_or_else(|| panic!("path {path} was not registered for this overlay"))
    }

    fn stack_variable(&self, variable: StackVariableId) -> StackVariableId {
        self.stack_variables
            .get(&variable)
            .copied()
            .unwrap_or_else(|| {
                panic!("stack variable {variable} was not registered for this overlay")
            })
    }

    fn operation_local_reason(
        &self,
        reason: &super::model::ResolutionIncompleteReason,
    ) -> super::model::ResolutionIncompleteReason {
        panic!("a lowered overlay cannot carry an operation-local reason: {reason:?}")
    }
}

/// Complete runtime-ID translation for one lowered artifact remount.
///
/// The maps are derived only from producer-stable local identity descriptors.
/// Callers must not manufacture a missing translation from a display path or
/// source-local helper; absence means the lowered artifact and its catalog
/// disagree and is therefore an invariant violation.
pub(super) struct ResolutionMountTranslation {
    /// The fragment the remounted artifact belongs to, which is what every
    /// fragment inside a remounted value becomes.
    fragment: BindingFragmentId,
    semantics: HashMap<SemanticId, SemanticId>,
    nodes: HashMap<BindingNodeId, BindingNodeId>,
    paths: HashMap<PartialPathId, PartialPathId>,
    stack_variables: HashMap<StackVariableId, StackVariableId>,
}

impl ResolutionIdentityTranslation for ResolutionMountTranslation {
    fn fragment(&self, _fragment: BindingFragmentId) -> BindingFragmentId {
        self.fragment
    }

    fn semantic(&self, semantic: SemanticId) -> SemanticId {
        self.semantics
            .get(&semantic)
            .copied()
            .unwrap_or_else(|| panic!("semantic {semantic} is missing from the remount catalog"))
    }

    fn node(&self, node: BindingNodeId) -> BindingNodeId {
        if node == BindingNodeId::universal_root() {
            return node;
        }
        self.nodes
            .get(&node)
            .copied()
            .unwrap_or_else(|| panic!("node {node} is missing from the remount catalog"))
    }

    fn path(&self, path: PartialPathId) -> PartialPathId {
        self.paths
            .get(&path)
            .copied()
            .unwrap_or_else(|| panic!("path {path} is missing from the remount catalog"))
    }

    fn stack_variable(&self, variable: StackVariableId) -> StackVariableId {
        self.stack_variables
            .get(&variable)
            .copied()
            .unwrap_or_else(|| {
                panic!("stack variable {variable} is missing from the remount catalog")
            })
    }

    /// Each of these three reasons is minted while one operation runs, against
    /// values no producer published, so a lowered artifact can never carry one
    /// and this catalog does not hold the identity inside it.
    fn operation_local_reason(
        &self,
        reason: &super::model::ResolutionIncompleteReason,
    ) -> super::model::ResolutionIncompleteReason {
        panic!("an operation-local reason cannot appear in a lowered artifact: {reason:?}")
    }
}

impl ResolutionIdentityCatalog {
    /// Conservative retained-byte estimate for cache admission.
    ///
    /// Rust cannot report an allocation's real size, so this charges the slots
    /// every collection allocated plus the heap each entry owns. The fields are
    /// destructured exhaustively so a new one cannot silently leave the weight
    /// behind.
    pub(crate) fn estimated_retained_bytes(&self) -> usize {
        let Self {
            fragment: _,
            site_span: _,
            shared_name_digests,
            semantics,
            lookup_recipes,
            precedence_namespaces,
            go_spelling_choices,
            nodes,
            source_site_nodes,
            source_scope_ordinals,
            paths,
            stack_variables,
        } = self;
        semantics
            .estimated_retained_bytes(|_| 0)
            .saturating_add(lookup_recipes.estimated_retained_bytes(|recipe| recipe.owned_bytes()))
            .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                precedence_namespaces,
            ))
            .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                go_spelling_choices,
            ))
            .saturating_add(nodes.estimated_retained_bytes(|_| 0))
            .saturating_add(brokk_bifrost_core::hash::set_slot_bytes(source_site_nodes))
            .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                source_scope_ordinals,
            ))
            .saturating_add(paths.estimated_retained_bytes(|_| 0))
            .saturating_add(stack_variables.estimated_retained_bytes(|_| 0))
            .saturating_add(brokk_bifrost_core::hash::map_slot_bytes(
                shared_name_digests,
            ))
    }

    /// Give every identity this blob owns the catalog position that is its
    /// storage-local key, and return the translation from what the lowering
    /// minted to what the catalog holds.
    ///
    /// **The translation is total now, where it used to be partial.** It could
    /// be partial while a mounted id was `in_fragment(fragment, digest)`, a
    /// pure function of the identity: a semantic kept the id its digest gave
    /// it, and a source node kept the id its producer identity gave it, so
    /// only the dense nodes, paths and variables moved. A mounted id is
    /// `(ordinal, catalog position)` now and no identity can mount itself, so
    /// the lowering minted every one of them from a counter under
    /// `UNMOUNTED_ORDINAL` and every one of them moves here.
    ///
    /// That is what makes the rule at the head of `remount.rs` load-bearing
    /// rather than advisory: a collection keyed or ordered by a mounted id has
    /// to be rebuilt, because every mounted id in the artifact changes.
    ///
    /// The identities themselves do not change. They used to: a dense node's
    /// producer identity was overwritten with a digest of its own key, so that
    /// the rebaser could invent it back from an id. Nothing translates any
    /// more, so each entry keeps the producer-stable descriptor the catalog is
    /// ordered by, and the key lives in the id where the reader can see it.
    pub(super) fn rekey_dense(self) -> (Self, ResolutionMountTranslation) {
        let Self {
            fragment,
            site_span,
            shared_name_digests,
            semantics,
            lookup_recipes,
            precedence_namespaces,
            go_spelling_choices,
            nodes,
            source_site_nodes,
            source_scope_ordinals,
            paths,
            stack_variables,
        } = self;
        let ordinal = fragment.ordinal();
        let mut semantic_translation = HashMap::default();
        let semantics = semantics
            .into_entries()
            .into_iter()
            .enumerate()
            .map(|(index, (mounted, identity))| {
                let rekeyed = identity.mounted(ordinal, catalog_position(index));
                assert!(semantic_translation.insert(mounted, rekeyed).is_none());
                (rekeyed, identity)
            })
            .collect::<Vec<_>>();
        // A lookup recipe's semantic is a shared name, whose id is the name
        // and not a position, so the translation leaves it where it is. The
        // catalog builder asserts that every recipe semantic is shared; this
        // is the other end of that assertion and it is why the recipe catalog
        // needs no rebuild.
        let lookup_recipes = lookup_recipes
            .into_entries()
            .into_iter()
            .map(|(mounted, recipe)| {
                let translated = semantic_translation
                    .get(&mounted)
                    .copied()
                    .unwrap_or(mounted);
                assert_eq!(
                    translated, mounted,
                    "a lookup recipe's semantic is a shared name and keeps its id: {recipe:?}"
                );
                (mounted, recipe)
            })
            .collect::<Vec<_>>();
        let precedence_namespaces = precedence_namespaces
            .into_iter()
            .map(|(step, namespace)| {
                (
                    PrecedenceStep {
                        semantic: semantic_translation[&step.semantic],
                        ..step
                    },
                    namespace,
                )
            })
            .collect();
        let go_spelling_choices = go_spelling_choices
            .into_iter()
            .map(|(step, authority)| {
                (
                    PrecedenceStep {
                        semantic: semantic_translation[&step.semantic],
                        ..step
                    },
                    authority,
                )
            })
            .collect();
        let mut node_translation = HashMap::default();
        let nodes = nodes
            .into_entries()
            .into_iter()
            .enumerate()
            .map(|(index, (mounted, identity))| {
                let rekeyed = identity.mounted(ordinal, catalog_position(index));
                assert!(node_translation.insert(mounted, rekeyed).is_none());
                (rekeyed, identity)
            })
            .collect::<Vec<_>>();
        let source_site_nodes = source_site_nodes
            .into_iter()
            .map(|node| node_translation[&node])
            .collect();
        let source_scope_ordinals = source_scope_ordinals
            .into_iter()
            .map(|(node, scope)| (node_translation[&node], scope))
            .collect();
        let mut path_translation = HashMap::default();
        let paths = paths
            .into_entries()
            .into_iter()
            .enumerate()
            .map(|(index, (mounted, identity))| {
                let rekeyed = identity.mounted(ordinal, catalog_position(index));
                assert!(path_translation.insert(mounted, rekeyed).is_none());
                (rekeyed, identity)
            })
            .collect::<Vec<_>>();
        let mut stack_variable_translation = HashMap::default();
        let stack_variables = stack_variables
            .into_entries()
            .into_iter()
            .enumerate()
            .map(|(index, (mounted, identity))| {
                let rekeyed = identity.mounted(ordinal, catalog_position(index));
                assert!(
                    stack_variable_translation
                        .insert(mounted, rekeyed)
                        .is_none()
                );
                (rekeyed, identity)
            })
            .collect::<Vec<_>>();
        (
            Self {
                fragment,
                site_span,
                shared_name_digests,
                semantics: MountedIdentities::new(semantics),
                lookup_recipes: MountedIdentities::new(lookup_recipes),
                precedence_namespaces,
                go_spelling_choices,
                nodes: MountedIdentities::new(nodes),
                source_site_nodes,
                source_scope_ordinals,
                paths: MountedIdentities::new(paths),
                stack_variables: MountedIdentities::new(stack_variables),
            },
            ResolutionMountTranslation {
                fragment: BindingFragmentId::at_ordinal(ordinal),
                semantics: semantic_translation,
                nodes: node_translation,
                paths: path_translation,
                stack_variables: stack_variable_translation,
            },
        )
    }

    pub(crate) const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    pub(crate) fn semantic_identity(
        &self,
        semantic: SemanticId,
    ) -> Option<ResolutionSemanticIdentity> {
        self.semantics.get(semantic).copied()
    }

    /// The storage-local key and recipe this blob gives one runtime semantic.
    ///
    /// This is what replaces the operation-lifetime `(mount, key)` map for a
    /// fragment-local semantic: the mounted ID names this catalog through its
    /// own prefix, and the catalog is owned by the byte-capped interior cache,
    /// one per blob.
    /// The runtime semantic this blob gives one producer identity.
    ///
    /// This is the direction a mounted id used to make free: an id was a
    /// digest of `(fragment, identity)`, so anything holding an identity could
    /// state the id. A local id is a catalog position now, so only the blob's
    /// own catalog can, and this is where it answers. An identity a site
    /// numbers is not searched here; `mounted_site_semantic` reads it from the
    /// site number directly.
    pub(crate) fn semantic_for_identity(
        &self,
        identity: ResolutionSemanticIdentity,
    ) -> Option<SemanticId> {
        let order = |identity: &ResolutionSemanticIdentity| match identity {
            ResolutionSemanticIdentity::FragmentLocal(digest) => (0_u8, *digest),
            ResolutionSemanticIdentity::Shared(name) => (
                1,
                *self.shared_name_digests.get(name).unwrap_or_else(|| {
                    panic!("a shared name this blob mentions carries its digest: {name}")
                }),
            ),
            ResolutionSemanticIdentity::GapReason(digest) => (2, *digest),
        };
        self.semantics
            .entry_by_identity(self.site_span, order(&identity), order)
            .map(|(_, mounted)| *mounted)
    }

    /// This catalog with every runtime id replaced by the one an operation
    /// assigned it. The identities and their order are untouched: what moves
    /// is only which id names each of them.
    pub(crate) fn retargeted(self, assigned: &ResolutionRegisteredIdentities) -> Self {
        let Self {
            fragment,
            site_span,
            shared_name_digests,
            semantics,
            lookup_recipes,
            precedence_namespaces,
            go_spelling_choices,
            nodes,
            source_site_nodes,
            source_scope_ordinals,
            paths,
            stack_variables,
        } = self;
        Self {
            fragment: assigned.fragment(fragment),
            site_span,
            shared_name_digests,
            semantics: MountedIdentities::new(
                semantics
                    .into_entries()
                    .into_iter()
                    .map(|(mounted, identity)| (assigned.semantic(mounted), identity))
                    .collect(),
            ),
            lookup_recipes: MountedIdentities::new(
                lookup_recipes
                    .into_entries()
                    .into_iter()
                    .map(|(mounted, recipe)| (assigned.semantic(mounted), recipe))
                    .collect(),
            ),
            precedence_namespaces: precedence_namespaces
                .into_iter()
                .map(|(step, namespace)| {
                    (
                        PrecedenceStep {
                            semantic: assigned.semantic(step.semantic),
                            ..step
                        },
                        namespace,
                    )
                })
                .collect(),
            go_spelling_choices: go_spelling_choices
                .into_iter()
                .map(|(step, authority)| {
                    (
                        PrecedenceStep {
                            semantic: assigned.semantic(step.semantic),
                            ..step
                        },
                        authority,
                    )
                })
                .collect(),
            nodes: MountedIdentities::new(
                nodes
                    .into_entries()
                    .into_iter()
                    .map(|(mounted, identity)| (assigned.node(mounted), identity))
                    .collect(),
            ),
            source_site_nodes: source_site_nodes
                .into_iter()
                .map(|node| assigned.node(node))
                .collect(),
            source_scope_ordinals: source_scope_ordinals
                .into_iter()
                .map(|(node, scope)| (assigned.node(node), scope))
                .collect(),
            paths: MountedIdentities::new(
                paths
                    .into_entries()
                    .into_iter()
                    .map(|(mounted, identity)| (assigned.path(mounted), identity))
                    .collect(),
            ),
            stack_variables: MountedIdentities::new(
                stack_variables
                    .into_entries()
                    .into_iter()
                    .map(|(mounted, identity)| (assigned.stack_variable(mounted), identity))
                    .collect(),
            ),
        }
    }

    /// The runtime path this blob gives one producer identity. See
    /// [`Self::semantic_for_identity`].
    pub(crate) fn path_for_identity(
        &self,
        identity: ResolutionPathIdentity,
    ) -> Option<PartialPathId> {
        // The path and stack-variable catalogs have no site prefix: only the
        // semantic and node catalogs reserve their leading positions for the
        // sites (`site_first_entries`), so a path's entries are in identity
        // order from zero.
        self.paths
            .entry_by_identity(0, identity, |identity| *identity)
            .map(|(_, mounted)| *mounted)
    }

    /// The runtime node this blob gives one producer identity. See
    /// [`Self::semantic_for_identity`].
    pub(crate) fn node_for_identity(
        &self,
        identity: ResolutionNodeIdentity,
    ) -> Option<BindingNodeId> {
        self.nodes
            .entry_by_identity(self.site_span, identity, |identity| *identity)
            .map(|(_, mounted)| *mounted)
    }

    pub(crate) fn semantic_coordinate(
        &self,
        semantic: SemanticId,
    ) -> Option<(ResolutionLocalKey, ResolutionSemanticIdentity)> {
        self.semantics
            .entry(semantic)
            .map(|(position, identity)| (catalog_local_key(position), *identity))
    }

    /// The storage-local key and producer identity this blob gives one runtime
    /// node, including the source nodes whose identity is not their key.
    pub(crate) fn node_coordinate(
        &self,
        node: BindingNodeId,
    ) -> Option<(ResolutionLocalKey, ResolutionNodeIdentity)> {
        self.nodes
            .entry(node)
            .map(|(position, identity)| (catalog_local_key(position), *identity))
    }

    /// The bytes one registered semantic identity contributes to a lowered
    /// digest. See [`ResolutionIdentityCatalogBuilder::identity_hash_bytes`].
    pub(crate) fn identity_hash_bytes(&self, identity: ResolutionSemanticIdentity) -> [u8; 32] {
        match identity {
            ResolutionSemanticIdentity::FragmentLocal(digest)
            | ResolutionSemanticIdentity::GapReason(digest) => digest,
            ResolutionSemanticIdentity::Shared(name) => self.shared_name_digest(name),
        }
    }

    /// Every shared name this blob mentions, as the digests the store interns
    /// them by, in a canonical order.
    ///
    /// The writer interns all of them, not only the ones its header families
    /// name, so that an interior produced for this blob later can assert that
    /// every shared id it holds is a store fact. An interior is cached across
    /// requests, so an id minted for one request must never enter one.
    pub(crate) fn shared_names(&self) -> Vec<[u8; 32]> {
        let mut digests = self
            .shared_name_digests
            .values()
            .copied()
            .collect::<Vec<_>>();
        digests.sort_unstable();
        digests
    }

    /// The digest that names one shared name in `resolution_identities`.
    pub(crate) fn shared_name_digest(&self, name: SharedNameId) -> [u8; 32] {
        self.shared_name_digests
            .get(&name)
            .copied()
            .unwrap_or_else(|| {
                panic!("a shared name this blob mentions carries its digest: {name}")
            })
    }

    pub(crate) fn lookup_recipe(
        &self,
        semantic: SemanticId,
    ) -> Option<&ResolutionLookupSemanticRecipe> {
        self.lookup_recipes.get(semantic)
    }

    pub(crate) const fn go_spelling_choices(
        &self,
    ) -> &HashMap<PrecedenceStep, GoSpellingChoiceAuthority> {
        &self.go_spelling_choices
    }

    pub(crate) fn precedence_namespace(&self, step: PrecedenceStep) -> Option<ResolutionNamespace> {
        self.precedence_namespaces.get(&step).copied()
    }

    pub(crate) const fn precedence_namespaces(
        &self,
    ) -> &HashMap<PrecedenceStep, ResolutionNamespace> {
        &self.precedence_namespaces
    }

    pub(crate) fn node_identity(&self, node: BindingNodeId) -> Option<ResolutionNodeIdentity> {
        self.nodes.get(node).copied()
    }

    pub(crate) fn path_identity(&self, path: PartialPathId) -> Option<ResolutionPathIdentity> {
        self.paths.get(path).copied()
    }

    pub(crate) fn stack_variable_identity(
        &self,
        variable: StackVariableId,
    ) -> Option<ResolutionStackVariableIdentity> {
        self.stack_variables.get(variable).copied()
    }

    pub(crate) fn semantics(&self) -> &[(SemanticId, ResolutionSemanticIdentity)] {
        self.semantics.entries()
    }

    pub(crate) fn lookup_recipes(&self) -> &[(SemanticId, ResolutionLookupSemanticRecipe)] {
        self.lookup_recipes.entries()
    }

    pub(crate) fn nodes(&self) -> &[(BindingNodeId, ResolutionNodeIdentity)] {
        self.nodes.entries()
    }

    pub(crate) fn source_scope_ordinals(&self) -> &HashMap<BindingNodeId, ResolutionScopeId> {
        &self.source_scope_ordinals
    }

    pub(crate) fn paths(&self) -> &[(PartialPathId, ResolutionPathIdentity)] {
        self.paths.entries()
    }

    pub(crate) fn stack_variables(&self) -> &[(StackVariableId, ResolutionStackVariableIdentity)] {
        self.stack_variables.entries()
    }

    pub(super) fn register_macro_module_node(
        &mut self,
        scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
    ) -> BindingNodeId {
        let identity = super::fact_lowering::scope_head_node_identity(scope);
        // The dedup used to be a computed id and a binary search, because a
        // mounted id was a pure function of its identity. It is a catalog
        // position now, so the question "does this catalog already hold this
        // identity" has to be asked of the identities. It is asked by walking
        // them, and that needs neither a per-operation map nor a reverse index
        // on the page: the only caller is one macro instantiation, which has
        // just remounted this whole artifact, so one more linear pass over the
        // node catalog is inside the work it has already done. A structure
        // that made this logarithmic would be per-blob state bought for a
        // constant factor on a path that is already linear.
        let runtime = match self
            .nodes
            .entries()
            .iter()
            .find(|(_, held)| *held == identity)
        {
            Some((mounted, _)) => *mounted,
            None => {
                let runtime = identity.mounted(
                    self.fragment.ordinal(),
                    catalog_position(self.nodes.entries().len()),
                );
                self.nodes.push(runtime, identity);
                runtime
            }
        };
        if let Some(previous) = self.source_scope_ordinals.insert(runtime, scope) {
            assert_eq!(previous, scope, "macro module scope node has one ordinal");
        }
        runtime
    }

    /// Give a selected macro capsule its own identities while retaining the
    /// caller's lexical checkpoint and module-root lookup tokens.
    pub(super) fn specialize_macro_input(
        &mut self,
        invocation_digest: [u8; 32],
        checkpoint: ResolutionNodeIdentity,
        module_scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
    ) {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
        let digest = |identity: [u8; 32]| {
            let mut hasher = CanonicalHasher::new(b"bifrost-selected-macro-input:v1");
            hasher.field("invocation", &invocation_digest);
            hasher.field("identity", &identity);
            hasher.finish()
        };
        self.source_site_nodes.clear();
        self.source_scope_ordinals.clear();
        // The artifact's own root scope head, read from this catalog rather
        // than computed: a node id is the position it occupies here now.
        let root = self
            .node_for_identity(super::fact_lowering::scope_head_node_identity(
                ResolutionScopeId::new(0),
            ))
            .expect("a lowered artifact's catalog holds its root scope head");
        self.source_site_nodes.insert(root);
        for (runtime, identity) in self.nodes.identities_mut() {
            *identity = if runtime == root {
                checkpoint
            } else {
                ResolutionNodeIdentity::new(digest(identity.digest()))
            };
        }
        for (_, identity) in self.semantics.identities_mut() {
            if identity.space() == ResolutionSemanticIdentitySpace::Shared {
                continue;
            }
            if [
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor::Lexical,
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor::Absolute,
            ].into_iter().any(|anchor| *identity == super::fact_lowering::root_import_anchor_semantic_identity(anchor)) {
                continue;
            }
            let root_namespace = [
                ResolutionNamespace::Type,
                ResolutionNamespace::Value,
                ResolutionNamespace::Callable,
                ResolutionNamespace::Constructor,
                ResolutionNamespace::Macro,
                ResolutionNamespace::Constant,
            ]
            .into_iter()
            .find(|namespace| {
                *identity
                    == super::fact_lowering::root_export_token_identity(
                        ResolutionScopeId::new(0),
                        *namespace,
                    )
            });
            *identity = root_namespace.map_or_else(
                || identity.with_fragment_local_digest(digest(identity.fragment_local_digest())),
                |namespace| {
                    super::fact_lowering::root_export_token_identity(module_scope, namespace)
                },
            );
        }
        for (_, identity) in self.paths.identities_mut() {
            *identity = ResolutionPathIdentity::new(digest(identity.digest()));
        }
        for (_, identity) in self.stack_variables.identities_mut() {
            *identity = ResolutionStackVariableIdentity::new(digest(identity.digest()));
        }
    }

    pub(super) fn remount(
        self,
        fragment: BindingFragmentId,
        cancellation: &CancellationToken,
    ) -> Option<(Self, ResolutionMountTranslation)> {
        let Self {
            site_span,
            shared_name_digests,
            semantics,
            lookup_recipes,
            precedence_namespaces,
            go_spelling_choices,
            nodes,
            source_site_nodes,
            source_scope_ordinals,
            paths,
            stack_variables,
            ..
        } = self;

        let mut semantic_translation = HashMap::default();
        let mut remounted_semantics = Vec::with_capacity(semantics.entries().len());
        let mut mounted_semantics = HashSet::default();
        for (index, (mounted, identity)) in semantics.into_entries().into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            let remounted = identity.mounted(fragment.ordinal(), catalog_position(index));
            assert!(
                semantic_translation.insert(mounted, remounted).is_none(),
                "resolution semantic catalog must be a bijection"
            );
            assert!(
                mounted_semantics.insert(remounted),
                "remounted resolution semantic identities must remain unique"
            );
            remounted_semantics.push((remounted, identity));
        }

        let mut node_translation = HashMap::default();
        let mut remounted_nodes = Vec::with_capacity(nodes.entries().len());
        let mut mounted_nodes = HashSet::default();
        for (index, (mounted, identity)) in nodes.into_entries().into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            let remounted = identity.mounted(fragment.ordinal(), catalog_position(index));
            assert!(
                node_translation.insert(mounted, remounted).is_none(),
                "resolution node catalog must be a bijection"
            );
            assert!(
                mounted_nodes.insert(remounted),
                "remounted resolution node identities must remain unique"
            );
            remounted_nodes.push((remounted, identity));
        }
        let source_scope_ordinals = source_scope_ordinals
            .into_iter()
            .map(|(node, scope)| (node_translation[&node], scope))
            .collect();
        let source_site_nodes = source_site_nodes
            .into_iter()
            .map(|node| node_translation[&node])
            .collect();

        let mut path_translation = HashMap::default();
        let mut remounted_paths = Vec::with_capacity(paths.entries().len());
        let mut mounted_paths = HashSet::default();
        for (index, (mounted, identity)) in paths.into_entries().into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            let remounted = identity.mounted(fragment.ordinal(), catalog_position(index));
            assert!(
                path_translation.insert(mounted, remounted).is_none(),
                "resolution path catalog must be a bijection"
            );
            assert!(
                mounted_paths.insert(remounted),
                "remounted resolution path identities must remain unique"
            );
            remounted_paths.push((remounted, identity));
        }

        let mut stack_variable_translation = HashMap::default();
        let mut remounted_stack_variables = Vec::with_capacity(stack_variables.entries().len());
        let mut mounted_stack_variables = HashSet::default();
        for (index, (mounted, identity)) in stack_variables.into_entries().into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            let remounted = identity.mounted(fragment.ordinal(), catalog_position(index));
            assert!(
                stack_variable_translation
                    .insert(mounted, remounted)
                    .is_none(),
                "resolution stack-variable catalog must be a bijection"
            );
            assert!(
                mounted_stack_variables.insert(remounted),
                "remounted resolution stack-variable identities must remain unique"
            );
            remounted_stack_variables.push((remounted, identity));
        }

        let translation = ResolutionMountTranslation {
            fragment,
            semantics: semantic_translation,
            nodes: node_translation,
            paths: path_translation,
            stack_variables: stack_variable_translation,
        };
        let mut remounted_lookup_recipes = Vec::with_capacity(lookup_recipes.entries().len());
        for (semantic, recipe) in lookup_recipes.into_entries() {
            if cancellation.is_cancelled() {
                return None;
            }
            let remounted = translation.semantic(semantic);
            assert_eq!(
                remounted, semantic,
                "a shared lookup recipe must be unchanged by remounting: {recipe:?}"
            );
            let semantic = remounted;
            remounted_lookup_recipes.push((semantic, recipe));
        }
        let mut remounted_precedence_namespaces = HashMap::default();
        for (step, namespace) in precedence_namespaces {
            if cancellation.is_cancelled() {
                return None;
            }
            let step = PrecedenceStep {
                semantic: translation.semantic(step.semantic),
                ..step
            };
            assert!(
                remounted_precedence_namespaces
                    .insert(step, namespace)
                    .is_none(),
                "remounted precedence steps must remain unique"
            );
        }

        let mut remounted_go_spelling_choices = HashMap::default();
        for (step, authority) in go_spelling_choices {
            if cancellation.is_cancelled() {
                return None;
            }
            let step = PrecedenceStep {
                semantic: translation.semantic(step.semantic),
                ..step
            };
            assert!(
                remounted_go_spelling_choices
                    .insert(step, authority)
                    .is_none()
            );
        }

        Some((
            Self {
                fragment,
                site_span,
                shared_name_digests,
                semantics: MountedIdentities::new(remounted_semantics),
                lookup_recipes: MountedIdentities::new(remounted_lookup_recipes),
                precedence_namespaces: remounted_precedence_namespaces,
                go_spelling_choices: remounted_go_spelling_choices,
                nodes: MountedIdentities::new(remounted_nodes),
                source_site_nodes,
                source_scope_ordinals,
                paths: MountedIdentities::new(remounted_paths),
                stack_variables: MountedIdentities::new(remounted_stack_variables),
            },
            translation,
        ))
    }
}

#[cfg(test)]
impl ResolutionIdentityCatalog {
    pub(super) fn register_variable_for_publication_test(&mut self) -> StackVariableId {
        let identity = ResolutionStackVariableIdentity::new([0x73; 32]);
        assert!(
            self.stack_variables
                .entries()
                .iter()
                .all(|(_, value)| *value != identity)
        );
        let variable = identity.mounted(
            self.fragment.ordinal(),
            catalog_position(self.stack_variables.entries().len()),
        );
        let mut entries = self.stack_variables.entries().to_vec();
        entries.push((variable, identity));
        entries.sort_unstable_by_key(|(_, identity)| *identity);
        self.stack_variables = MountedIdentities::new(entries);
        variable
    }

    pub(super) fn register_node_for_publication_test(&mut self, label: u8) -> BindingNodeId {
        let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-publication-generic-node-fixture:v1",
        );
        hash.field("node", &[label]);
        let identity = ResolutionNodeIdentity::new(hash.finish());
        assert!(
            self.nodes
                .entries()
                .iter()
                .all(|(_, existing)| *existing != identity)
        );
        let node = identity.mounted(
            self.fragment.ordinal(),
            catalog_position(self.nodes.entries().len()),
        );
        let mut entries = self.nodes.entries().to_vec();
        entries.push((node, identity));
        entries[self.site_span..].sort_unstable_by_key(|(_, identity)| *identity);
        self.nodes = MountedIdentities::new(entries);
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_persisted_membership_and_request_registrations_are_exact() {
        for count in [0_usize, 1, 2048] {
            let mut first = MountRebaser::for_persisted_mount_count(count);
            let second = MountRebaser::for_persisted_mount_count(count);
            for raw in 0..u32::try_from(count + 2).unwrap() {
                let ordinal = SelectedResolutionMountOrdinal::new(raw);
                assert_eq!(first.mount(ordinal).is_some(), (raw as usize) < count);
                assert_eq!(
                    first
                        .mount_for_fragment(BindingFragmentId::at_ordinal(raw))
                        .is_some(),
                    (raw as usize) < count
                );
            }
            let transient = SelectedResolutionMountOrdinal::new(u32::try_from(count + 1).unwrap());
            assert_eq!(first.register_mount(transient).ordinal(), transient);
            assert_eq!(first.register_mount(transient).ordinal(), transient);
            assert_eq!(first.mount_count(), count + 1);
            assert!(
                second.mount(transient).is_none(),
                "another request never inherits registrations"
            );
            assert!(
                first
                    .mount(SelectedResolutionMountOrdinal::new(UNMOUNTED_ORDINAL))
                    .is_none()
            );
        }
    }

    fn fragment(label: &[u8]) -> BindingFragmentId {
        BindingFragmentId::for_test(label)
    }

    /// A catalog position is a persisted local key, so it cannot depend on an
    /// interned id.
    ///
    /// This is the pin for the bug stage 1a shipped and a fixture caught: the
    /// semantic catalog was ordered by identity, a shared identity became an
    /// id, and the order followed the order this store happened to intern
    /// names in. Every local key moved, the interior digest moved with them,
    /// and a byte-identical replacement stopped meeting the persisted blob it
    /// replaces. Two caches would have disagreed the same way.
    ///
    /// Lowering the same file twice in one process would not catch it: one
    /// interner gives one answer. Nor would two interners that meet the same
    /// names in the same order, because their ids then differ by a constant
    /// and sort the same way. Two interners that meet them in *opposite*
    /// orders is what two caches built from different workspaces are, and that
    /// is what this builds.
    #[test]
    fn a_catalog_position_does_not_depend_on_an_interned_id() {
        let names = ["alpha", "beta", "gamma", "delta"].map(|name| {
            let mut digest = [0; 32];
            digest[..name.len()].copy_from_slice(name.as_bytes());
            digest
        });
        let ascending = PerRequestSharedNames::new();
        let descending = PerRequestSharedNames::new();
        for name in names.iter().rev() {
            descending.intern(*name);
        }

        let positions = [&ascending, &descending].map(|interner| {
            let mut builder =
                ResolutionIdentityCatalogBuilder::new(fragment(b"catalog-position"), interner);
            for (index, name) in names.iter().enumerate() {
                builder.shared_name(*name);
                builder.semantic(ResolutionSemanticIdentity::fragment_local(
                    [u8::try_from(index).expect("four identities fit u8"); 32],
                ));
            }
            let catalog = builder.finish();
            catalog
                .semantics()
                .iter()
                .map(|(_, identity)| match identity {
                    ResolutionSemanticIdentity::FragmentLocal(digest)
                    | ResolutionSemanticIdentity::GapReason(digest) => *digest,
                    ResolutionSemanticIdentity::Shared(name) => catalog.shared_name_digest(*name),
                })
                .collect::<Vec<_>>()
        });

        let ids = [&ascending, &descending].map(|interner| {
            names
                .iter()
                .map(|name| interner.intern(*name))
                .collect::<Vec<_>>()
        });
        // The precondition this pin rests on: the two interners put these
        // names in opposite id order, so a catalog ordered by id would sort
        // them two different ways.
        let by_id = ids.each_ref().map(|ids| {
            let mut order = (0..names.len()).collect::<Vec<_>>();
            order.sort_by_key(|&index| ids[index]);
            order
        });
        assert_ne!(
            by_id[0], by_id[1],
            "the two interners must order these names differently for this pin to mean anything"
        );
        assert_eq!(
            positions[0], positions[1],
            "a catalog position is a persisted local key and cannot depend on an interned id"
        );
    }

    #[test]
    fn canonical_catalog_order_depends_on_local_recipes_not_mounts() {
        let first = ResolutionSemanticIdentity::fragment_local([1; 32]);
        let second = ResolutionSemanticIdentity::fragment_local([2; 32]);
        let shared_digest = [3; 32];
        let shared = ResolutionSemanticIdentity::shared(
            crate::analyzer::resolution::test_shared_names().intern(shared_digest),
        );
        let fragments = [fragment(b"catalog-a"), fragment(b"catalog-b")];
        let catalogs = fragments.map(|fragment| {
            let mut builder = ResolutionIdentityCatalogBuilder::new(
                fragment,
                crate::analyzer::resolution::test_shared_names(),
            );
            builder.semantic(second);
            builder.shared_name(shared_digest);
            builder.semantic(first);
            builder.semantic(first);
            builder.finish()
        });

        let recipes = catalogs.each_ref().map(|catalog| {
            catalog
                .semantics()
                .iter()
                .map(|&(_, identity)| identity)
                .collect::<Vec<_>>()
        });
        assert_eq!(recipes[0], vec![first, second, shared]);
        assert_eq!(
            recipes[0], recipes[1],
            "a catalog's order is its recipes' order and nothing about its mount"
        );
        // A local identity occupies the same position in both catalogs and
        // gets the same number from both, because a builder mints unmounted;
        // it becomes a different runtime id in each when it is spliced into
        // that catalog's mount, because a local id is the ordinal and the
        // position. A shared name is the same id in both and stays the same
        // through either mount: it belongs to no mount.
        let local_positions = catalogs.each_ref().map(|catalog| {
            catalog
                .semantics()
                .iter()
                .position(|&(_, identity)| identity == first)
                .expect("the catalog holds the identity it was given")
        });
        assert_eq!(local_positions[0], local_positions[1]);
        assert_eq!(
            catalogs[0].semantics()[local_positions[0]].0,
            catalogs[1].semantics()[local_positions[1]].0
        );
        assert_ne!(
            catalogs[0].semantics()[local_positions[0]]
                .0
                .at_ordinal(fragments[0].ordinal()),
            catalogs[1].semantics()[local_positions[1]]
                .0
                .at_ordinal(fragments[1].ordinal())
        );
        let shared_ids = catalogs.each_ref().map(|catalog| {
            catalog
                .semantics()
                .iter()
                .find(|&&(_, identity)| identity == shared)
                .expect("the catalog holds the shared name it was given")
                .0
        });
        assert_eq!(shared_ids[0], shared_ids[1]);
        for catalog in &catalogs {
            for &(mounted, identity) in catalog.semantics() {
                assert_eq!(catalog.semantic_identity(mounted), Some(identity));
            }
        }
    }

    #[test]
    fn lookup_recipe_fields_are_separate_and_canonically_ordered() {
        let recipes = [
            (Language::Java, ResolutionNamespace::Type, "Name"),
            (Language::Go, ResolutionNamespace::Type, "Name"),
            (Language::Java, ResolutionNamespace::Value, "Name"),
            (Language::Java, ResolutionNamespace::Type, "Other"),
        ];
        let mut builder = ResolutionIdentityCatalogBuilder::new(
            fragment(b"lookup-recipes"),
            crate::analyzer::resolution::test_shared_names(),
        );
        let semantics = recipes.map(|(language, namespace, spelling)| {
            builder.lookup_semantic(language, namespace, spelling)
        });
        builder.lookup_semantic(Language::Java, ResolutionNamespace::Type, "Name");
        let catalog = builder.finish();

        assert_eq!(
            semantics
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(catalog.lookup_recipes().len(), 4);
        assert!(catalog.lookup_recipes().windows(2).all(|pair| {
            let (semantic_a, recipe_a) = &pair[0];
            let (semantic_b, recipe_b) = &pair[1];
            (recipe_a, semantic_a) < (recipe_b, semantic_b)
        }));
        for &(semantic, ref recipe) in catalog.lookup_recipes() {
            assert_eq!(
                recipe.semantic(crate::analyzer::resolution::test_shared_names()),
                semantic
            );
            assert_eq!(catalog.lookup_recipe(semantic), Some(recipe));
            assert_eq!(
                catalog.semantic_identity(semantic),
                Some(recipe.identity(crate::analyzer::resolution::test_shared_names()))
            );
        }
    }

    #[test]
    fn lookup_recipes_are_permutation_stable_and_mount_independent() {
        let recipes = [
            (Language::Java, ResolutionNamespace::Callable, "run"),
            (Language::Java, ResolutionNamespace::Type, "Widget"),
            (Language::Java, ResolutionNamespace::Value, "field"),
        ];
        let fragments = [fragment(b"lookup-mount-a"), fragment(b"lookup-mount-b")];
        let mut first = ResolutionIdentityCatalogBuilder::new(
            fragments[0],
            crate::analyzer::resolution::test_shared_names(),
        );
        for (language, namespace, spelling) in recipes {
            first.lookup_semantic(language, namespace, spelling);
        }
        let mut second = ResolutionIdentityCatalogBuilder::new(
            fragments[1],
            crate::analyzer::resolution::test_shared_names(),
        );
        for (language, namespace, spelling) in recipes.into_iter().rev() {
            second.lookup_semantic(language, namespace, spelling);
        }
        let catalogs = [first.finish(), second.finish()];

        assert_eq!(catalogs[0].lookup_recipes(), catalogs[1].lookup_recipes());
        for &(semantic, ref recipe) in catalogs[0].lookup_recipes() {
            assert_eq!(recipe.semantic_language(), "java");
            assert_eq!(
                recipe.semantic(crate::analyzer::resolution::test_shared_names()),
                semantic
            );
            for catalog in &catalogs {
                assert_eq!(
                    catalog.semantic_for_identity(
                        recipe.identity(crate::analyzer::resolution::test_shared_names())
                    ),
                    Some(semantic),
                    "a shared name is the same id in every catalog that holds it"
                );
            }
        }
    }

    #[test]
    fn every_local_identity_kind_rebases_from_its_recipe() {
        let fragment_a = fragment(b"local-identity-a");
        let fragment_b = fragment(b"local-identity-b");
        let node = ResolutionNodeIdentity::new([4; 32]);
        let path = ResolutionPathIdentity::new([5; 32]);
        let variable = ResolutionStackVariableIdentity::new([6; 32]);
        let mut builder = ResolutionIdentityCatalogBuilder::new(
            fragment_a,
            crate::analyzer::resolution::test_shared_names(),
        );
        let mounted_node = builder.node(node);
        let mounted_path = builder.path(path);
        let mounted_variable = builder.stack_variable(variable);
        let catalog = builder.finish();

        assert_eq!(catalog.node_identity(mounted_node), Some(node));
        assert_eq!(catalog.path_identity(mounted_path), Some(path));
        assert_eq!(
            catalog.stack_variable_identity(mounted_variable),
            Some(variable)
        );
        // The reverse direction too: an identity finds the position it
        // occupies, which is what a runtime id is.
        assert_eq!(catalog.node_for_identity(node), Some(mounted_node));
        // A builder mints unmounted: the mount arrives as a splice, and the
        // splice changes the ordinal and keeps the position, which is the
        // whole of what a remount does.
        assert_eq!(mounted_node.ordinal(), Some(UNMOUNTED_ORDINAL));
        assert_eq!(
            mounted_node.at_ordinal(fragment_a.ordinal()).ordinal(),
            Some(fragment_a.ordinal())
        );
        assert_eq!(
            mounted_node.at_ordinal(fragment_b.ordinal()).local_key(),
            mounted_node.local_key()
        );
        assert_ne!(
            mounted_node.at_ordinal(fragment_a.ordinal()),
            mounted_node.at_ordinal(fragment_b.ordinal())
        );
    }

    #[test]
    fn a_local_runtime_id_is_its_mount_ordinal_and_its_catalog_position() {
        // This replaces the pin on the representation it succeeds. A runtime
        // id used to be a 32-byte digest whose first eight bytes were its
        // mount's prefix and whose tail was its identity's; the mount was
        // recovered by comparing prefixes and the key by decoding the tail.
        // It is `(ordinal, catalog position)` in one u64 now, and both halves
        // are read back rather than decoded.
        let first = 3_u32;
        let second = 4_u32;
        macro_rules! pin_local_layout {
            ($name:ident) => {{
                let id = $name::local(first, 7);
                let other = $name::local(second, 7);
                assert_eq!(
                    id.kind(),
                    super::super::model::ResolutionIdentityKind::Local
                );
                assert_eq!(id.ordinal(), Some(first));
                assert_eq!(id.local_key(), Some(7));
                assert_ne!(id, other, "the ordinal separates two mounts of one key");
                assert_eq!(other.ordinal(), Some(second));
                assert_eq!(id.at_ordinal(second), other, "a splice is the ordinal");
            }};
        }
        pin_local_layout!(BindingNodeId);
        pin_local_layout!(PartialPathId);
        pin_local_layout!(StackVariableId);
        pin_local_layout!(SemanticId);
        assert_ne!(
            SemanticId::local(first, 7),
            SemanticId::local(first, 8),
            "the catalog position separates two identities of one mount"
        );

        // An identity that belongs to no file has no ordinal and no position.
        let operation = SemanticId::operation_local(5);
        assert_eq!(
            operation.kind(),
            super::super::model::ResolutionIdentityKind::Operation
        );
        assert_eq!(operation.ordinal(), None);
        assert_eq!(operation.local_key(), None);
        assert!(!operation.is_context_local());
        let context = SemanticId::context_local(5);
        assert!(context.is_context_local());
        assert_ne!(
            operation, context,
            "an operation and a context number from disjoint halves"
        );
    }

    #[test]
    fn shared_name_default_conversions_preserve_only_stored_correspondence() {
        let names = PerRequestSharedNames::new();
        let request = names.intern([17; 32]);
        let stored = SharedNameId::interned(19);
        assert_eq!(names.to_persisted(request), None);
        assert_eq!(names.to_persisted(stored), Some(stored));
        assert_eq!(names.from_persisted(stored), stored);
        assert_eq!(names.intern([17; 32]), request);
    }

    #[test]
    #[should_panic(expected = "a persisted shared name must be interned")]
    fn shared_name_default_decode_rejects_request_domain_input() {
        PerRequestSharedNames::new().from_persisted(SharedNameId::per_request(0));
    }

    #[test]
    fn shared_semantics_are_their_interned_id_on_every_mount() {
        let name = SharedNameId::per_request(46);
        let mounted = ResolutionSemanticIdentity::shared(name).mounted(3, 11);

        assert_eq!(mounted, SemanticId::shared_name(name));
        assert_eq!(mounted.shared_name_id(), Some(name));
        assert_eq!(
            mounted,
            ResolutionSemanticIdentity::shared(name).mounted(4, 12),
            "a shared name belongs to no mount, so neither the ordinal nor \
             the position it was offered changes it"
        );
    }

    #[test]
    fn a_persisted_local_key_is_the_runtime_id_and_needs_no_decoding() {
        // The three `persisted_*_identity` helpers and
        // `decode_persisted_local_key` are gone with this pin's predecessor.
        // A row's storage-local key is the position its identity occupies in
        // its blob's catalog, and a local runtime id is the mount ordinal and
        // that position, so the key *is* the id and there is nothing to
        // invent and nothing to decode.
        let ordinal = 9_u32;
        for key in [0_u32, 1, 7, 4096, u32::MAX] {
            assert_eq!(BindingNodeId::local(ordinal, key).local_key(), Some(key));
            assert_eq!(PartialPathId::local(ordinal, key).local_key(), Some(key));
            assert_eq!(StackVariableId::local(ordinal, key).local_key(), Some(key));
            assert_eq!(SemanticId::local(ordinal, key).local_key(), Some(key));
            assert_eq!(BindingNodeId::local(ordinal, key).ordinal(), Some(ordinal));
        }
    }

    #[test]
    fn selected_mount_identity_is_stable_and_separates_every_contextual_input() {
        let workspace = [11; 32];
        let projection = [12; 32];
        let interior = [13; 32];
        let selected = || {
            selected_resolution_fragment_id(
                workspace,
                "typescript:tsx",
                "src/component.tsx",
                projection,
                interior,
            )
        };

        let first_a = selected();
        let branch_b = selected_resolution_fragment_id(
            workspace,
            "typescript:tsx",
            "src/component.tsx",
            [15; 32],
            [16; 32],
        );
        let restored_a = selected();
        assert_ne!(first_a, branch_b, "the intervening B mount must differ");
        assert_eq!(first_a, restored_a, "A -> B -> A must restore identity");
        assert_ne!(
            selected(),
            selected_resolution_fragment_id(
                workspace,
                "typescript:tsx",
                "src/duplicate.tsx",
                projection,
                interior,
            ),
            "duplicate mounts of one blob must remain distinct"
        );
        assert_ne!(
            selected(),
            selected_resolution_fragment_id(
                [14; 32],
                "typescript:tsx",
                "src/component.tsx",
                projection,
                interior,
            ),
            "linked worktrees must remain isolated"
        );
        assert_ne!(
            selected(),
            selected_resolution_fragment_id(
                workspace,
                "typescript",
                "src/component.tsx",
                projection,
                interior,
            ),
            "storage-language projections must remain distinct"
        );
        assert_ne!(
            selected(),
            selected_resolution_fragment_id(
                workspace,
                "typescript:tsx",
                "src/component.tsx",
                [15; 32],
                interior,
            ),
            "workspace projection changes must remount the fragment"
        );
        assert_ne!(
            selected(),
            selected_resolution_fragment_id(
                workspace,
                "typescript:tsx",
                "src/component.tsx",
                projection,
                [16; 32],
            ),
            "interior changes must remount the fragment"
        );

        let locator = SelectedSemanticLocator::new(
            "typescript:tsx",
            "src/component.tsx",
            ResolutionSiteId::new(17),
            LoweredSemanticRole::Reference,
        );
        assert_eq!(locator.storage_language(), "typescript:tsx");
        assert_eq!(locator.relative_path(), "src/component.tsx");
        assert_eq!(locator.source_site(), Some(ResolutionSiteId::new(17)));
        assert_eq!(locator.reference_range(), None);
        assert_eq!(locator.role(), LoweredSemanticRole::Reference);

        let range_locator = SelectedSemanticLocator::for_reference_range(
            "typescript:tsx",
            "src/component.tsx",
            21,
            29,
        );
        assert_eq!(range_locator.source_site(), None);
        assert_eq!(range_locator.reference_range(), Some((21, 29)));
        assert_eq!(range_locator.role(), LoweredSemanticRole::Reference);
    }

    #[test]
    fn mount_rebaser_tracks_local_shared_root_and_operation_boundaries() {
        let first_fragment = selected_resolution_fragment_id(
            [20; 32],
            "java",
            "src/a/Name.java",
            [21; 32],
            [22; 32],
        );
        let second_fragment = selected_resolution_fragment_id(
            [20; 32],
            "java",
            "src/b/Name.java",
            [21; 32],
            [22; 32],
        );
        let first_ordinal = SelectedResolutionMountOrdinal::new(0);
        let second_ordinal = SelectedResolutionMountOrdinal::new(1);
        let mut rebaser = MountRebaser::new();
        let first_mount = rebaser.register_mount(first_ordinal);
        let second_mount = rebaser.register_mount(second_ordinal);
        assert_eq!(first_mount.ordinal().get(), 0);
        assert_ne!(
            first_fragment, second_fragment,
            "two files have two content keys, which the mount record carries"
        );
        assert_eq!(rebaser.mount(second_ordinal), Some(second_mount));

        let local_semantic = ResolutionSemanticIdentity::fragment_local([23; 32]);
        let shared_semantic = ResolutionSemanticIdentity::shared(SharedNameId::per_request(24));
        let first_semantic =
            rebaser.register_semantic(first_ordinal, ResolutionLocalKey::new(2), local_semantic);
        let second_semantic =
            rebaser.register_semantic(second_ordinal, ResolutionLocalKey::new(2), local_semantic);
        assert_ne!(first_semantic, second_semantic);
        let SelectedSemanticProvenance::FragmentLocal(first_provenance) = rebaser
            .registered_semantic_provenance(first_semantic)
            .expect("registered semantic")
        else {
            panic!("fragment-local semantic retained shared provenance")
        };
        assert_eq!(first_provenance.mount(), first_mount);
        assert_eq!(first_provenance.local_key().get(), 2);
        assert_eq!(first_provenance.identity(), local_semantic);

        let first_shared =
            rebaser.register_semantic(first_ordinal, ResolutionLocalKey::new(3), shared_semantic);
        let second_shared =
            rebaser.register_semantic(second_ordinal, ResolutionLocalKey::new(8), shared_semantic);
        assert_eq!(first_shared, second_shared);
        assert_eq!(
            rebaser.registered_semantic_provenance(first_shared),
            Some(SelectedSemanticProvenance::Shared(shared_semantic))
        );
        assert_eq!(
            rebaser.register_shared_semantic(shared_semantic),
            first_shared,
            "selected context may idempotently register the same Shared recipe"
        );

        let node_identity = ResolutionNodeIdentity::new([25; 32]);
        let path_identity = ResolutionPathIdentity::new([26; 32]);
        let variable_identity = ResolutionStackVariableIdentity::new([27; 32]);
        let mounted_node =
            rebaser.register_node(first_ordinal, ResolutionLocalKey::new(4), node_identity);
        let mounted_path =
            rebaser.register_path(first_ordinal, ResolutionLocalKey::new(5), path_identity);
        let mounted_variable = rebaser.register_stack_variable(
            first_ordinal,
            ResolutionLocalKey::new(6),
            variable_identity,
        );
        let Some(SelectedNodeProvenance::FragmentLocal(node_provenance)) =
            rebaser.node_provenance(mounted_node)
        else {
            panic!("registered node lost fragment provenance")
        };
        assert_eq!(node_provenance.identity(), node_identity);
        assert_eq!(
            rebaser
                .path_provenance(mounted_path)
                .map(|row| row.identity()),
            Some(path_identity)
        );
        assert_eq!(
            rebaser
                .stack_variable_provenance(mounted_variable)
                .map(|row| row.identity()),
            Some(variable_identity)
        );

        assert_eq!(
            rebaser.node_provenance(BindingNodeId::universal_root()),
            Some(SelectedNodeProvenance::UniversalRoot)
        );
        assert_eq!(BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY, 0);
        assert_ne!(
            BindingNodeId::universal_root(),
            BindingNodeId::local(first_ordinal.get(), 0),
            "a fragment-local Java root scope head is not the persisted universal boundary"
        );
        let java_boundary = BindingNodeId::for_test(b"operation-local-java-boundary");
        assert_ne!(
            BindingNodeId::universal_root(),
            java_boundary,
            "an arbitrary preload boundary is not the persisted universal boundary"
        );
        rebaser.register_context_boundary(java_boundary);
        assert_eq!(
            rebaser.node_provenance(java_boundary),
            Some(SelectedNodeProvenance::ContextBoundary)
        );
        assert_eq!(
            rebaser.node_provenance(BindingNodeId::for_test(b"unknown-node")),
            None,
            "unknown opaque IDs must not manufacture absence provenance"
        );
    }

    // `mount_rebaser_looks_up_a_mount_from_a_prefix_alone`,
    // `mount_rebaser_rejects_two_fragments_that_share_a_prefix`,
    // `mount_rebaser_rejects_one_ordinal_for_two_fragments` and
    // `mount_rebaser_rejects_one_fragment_at_two_ordinals` were here. All four
    // pinned the fragment prefix: a mount was a content digest, a runtime id
    // carried its first eight bytes, and the rebaser recovered the mount by
    // comparing them, so a prefix collision and a fragment registered twice
    // were both failures worth a test. A mount is an ordinal now and a local
    // id carries it outright, so none of the four is statable: there is no
    // prefix, nothing to collide, and `register_mount` takes only the ordinal.

    #[test]
    #[should_panic(expected = "cannot replace the universal root")]
    fn mount_rebaser_rejects_reclassifying_the_universal_root() {
        MountRebaser::new().register_context_boundary(BindingNodeId::universal_root());
    }

    #[test]
    #[should_panic(expected = "conflicting local identities")]
    fn conflicting_mounted_identity_fails_closed() {
        let mut forward = HashMap::default();
        let mut reverse = HashMap::default();
        register_identity(&mut forward, &mut reverse, 1_u8, 2_u8, "test");
        register_identity(&mut forward, &mut reverse, 1_u8, 3_u8, "test");
    }

    #[test]
    #[should_panic(expected = "conflicting mounted values")]
    fn conflicting_recipe_identity_fails_closed() {
        let mut forward = HashMap::default();
        let mut reverse = HashMap::default();
        register_identity(&mut forward, &mut reverse, 1_u8, 2_u8, "test");
        register_identity(&mut forward, &mut reverse, 3_u8, 2_u8, "test");
    }

    #[test]
    #[should_panic(expected = "conflicting canonical recipes")]
    fn same_lookup_digest_with_different_recipe_fails_closed() {
        let mut by_semantic = HashMap::default();
        let mut by_recipe = HashMap::default();
        let semantic = SemanticId::for_test(b"digest-7");
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name"),
        );
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Value, "Name"),
        );
    }

    #[test]
    #[should_panic(expected = "conflicting shared semantics")]
    fn same_lookup_recipe_with_different_digest_fails_closed() {
        let mut by_semantic = HashMap::default();
        let mut by_recipe = HashMap::default();
        let recipe =
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name");
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            SemanticId::for_test(b"digest-8"),
            recipe.clone(),
        );
        register_lookup_recipe(
            &mut by_semantic,
            &mut by_recipe,
            SemanticId::for_test(b"digest-9"),
            recipe,
        );
    }

    #[test]
    #[should_panic(expected = "does not derive its registered shared name")]
    fn catalog_completion_rejects_forged_lookup_recipe_identity() {
        let mut builder = ResolutionIdentityCatalogBuilder::new(
            fragment(b"forged-recipe"),
            crate::analyzer::resolution::test_shared_names(),
        );
        // A shared name that is not the recipe's own, which is what `finish`
        // rejects.
        let semantic = builder.shared_name([10; 32]);
        register_lookup_recipe(
            &mut builder.lookup_recipes,
            &mut builder.lookup_semantics_by_recipe,
            semantic,
            ResolutionLookupSemanticRecipe::new(Language::Java, ResolutionNamespace::Type, "Name"),
        );
        builder.finish();
    }
}
