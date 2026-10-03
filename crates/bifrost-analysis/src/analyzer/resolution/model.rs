//! Immutable algebra values for compositional name resolution.

use std::collections::BTreeSet;
use std::fmt;
use std::hash::Hash;

use brokk_bifrost_core::analyzer::canonical_hash::{
    CanonicalHasher, hash_domain_bytes, write_lower_hex,
};

use crate::analyzer::structural::{
    BoundaryStatus, CandidateOutcome, PrecedenceTier, ResolutionCompletionKind,
    ResolutionCompletionReasonKind, ResolutionWitnessKind,
};
use crate::hash::{HashMap, HashSet};

use super::completion_reasons::{CompletionReasonUnion, CompletionReasons};
use super::never_cancelled;

/// Which of the four spaces one runtime identity's payload lives in, read
/// from the identity's own top three bits.
///
/// A runtime identity used to be a 32-byte digest whose first eight bytes were
/// its mount's prefix, so "which space is this" was a byte compare against a
/// reserved prefix. It is a number now and the kind bits say it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolutionIdentityKind {
    /// One blob's own identity: a mount ordinal and a catalog position.
    Local = 0,
    /// One interned shared name. `SemanticId` only.
    Shared = 1,
    /// A number one operation minted for itself and drops with itself.
    Operation = 2,
    /// `BindingNodeId` only, payload zero: the universal root boundary.
    Reserved = 3,
}

impl ResolutionIdentityKind {
    fn from_bits(bits: u64) -> Self {
        match bits {
            0 => Self::Local,
            1 => Self::Shared,
            2 => Self::Operation,
            3 => Self::Reserved,
            other => panic!("a runtime identity kind is one of four values: {other}"),
        }
    }
}

/// The bit the kind starts at; everything below it is the payload.
const IDENTITY_KIND_SHIFT: u32 = 61;
const IDENTITY_PAYLOAD_MASK: u64 = (1 << IDENTITY_KIND_SHIFT) - 1;

/// The bit a `Local` identity's mount ordinal starts at; everything below it
/// is the catalog position that is the identity's storage-local key.
const LOCAL_ORDINAL_SHIFT: u32 = 32;
const LOCAL_KEY_MASK: u64 = (1 << LOCAL_ORDINAL_SHIFT) - 1;

/// One past the highest mount ordinal a `Local` identity can name.
///
/// `SelectedResolutionMountOrdinal` is a `u32` and tract selects about 900
/// persisted mounts, so 29 bits is four orders of magnitude of headroom. What
/// it buys is the 32 bits below it for the catalog position, which is the
/// range `MountedIdentities::new` already asserts a blob's catalog fits.
pub(crate) const MOUNT_ORDINAL_LIMIT: u32 = 1 << 29;

/// The ordinal a lowering mints its identities under, before its artifact is
/// mounted anywhere.
///
/// A lowered artifact's catalog positions are known only after `finish`, and
/// the ordinal it will be mounted at only when a selection mounts it, so the
/// lowering mints under this value and the mount splices its own ordinal in.
/// `MountRebaser::register_mount` asserts no mount takes it, so an unmounted
/// identity that escapes is a panic rather than an identity attributed to the
/// wrong blob.
pub(crate) const UNMOUNTED_ORDINAL: u32 = MOUNT_ORDINAL_LIMIT - 1;

/// The first `Operation` payload that belongs to a selected context rather
/// than to the operation that reads it.
///
/// Both mint `Operation` identities from a digest-to-number table, and the two
/// tables cannot share a numbering: a selected context is built before any
/// operation exists and may be attached to more than one operation over a
/// retained selection, so an operation's counter and a context's counter both
/// start at zero and would hand the same number to two different structures.
/// Bit 60 of the payload is what separates them, which leaves each side 2^60
/// distinct identities. An operation's number is asserted below this base
/// where it is minted, a context's is asserted below it and then offset by it,
/// and `SelectedResolutionContextSet` asserts at attachment that nothing it
/// carries lands in the operation's half.
pub(crate) const CONTEXT_OPERATION_BASE: u64 = 1 << 60;

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            fn of_kind(kind: ResolutionIdentityKind, payload: u64) -> Self {
                assert!(
                    payload <= IDENTITY_PAYLOAD_MASK,
                    "a runtime identity payload fits the 61 bits milestone 4's layout \
                     gives it: {payload}"
                );
                Self(((kind as u64) << IDENTITY_KIND_SHIFT) | payload)
            }

            pub(crate) fn kind(self) -> ResolutionIdentityKind {
                ResolutionIdentityKind::from_bits(self.0 >> IDENTITY_KIND_SHIFT)
            }

            const fn payload(self) -> u64 {
                self.0 & IDENTITY_PAYLOAD_MASK
            }

            /// One identity a blob owns, at a mount ordinal and the catalog
            /// position that is its storage-local key.
            pub(crate) fn local(ordinal: u32, local_key: u32) -> Self {
                assert!(
                    ordinal < MOUNT_ORDINAL_LIMIT,
                    "a mount ordinal fits the 29 bits milestone 4's layout gives it: \
                     {ordinal}"
                );
                Self::of_kind(
                    ResolutionIdentityKind::Local,
                    (u64::from(ordinal) << LOCAL_ORDINAL_SHIFT) | u64::from(local_key),
                )
            }

            /// The mount this identity belongs to, or `None` when it belongs
            /// to no file.
            pub(crate) fn ordinal(self) -> Option<u32> {
                match self.kind() {
                    ResolutionIdentityKind::Local => Some(
                        u32::try_from(self.payload() >> LOCAL_ORDINAL_SHIFT)
                            .expect("a 29-bit mount ordinal fits u32"),
                    ),
                    _ => None,
                }
            }

            /// The catalog position this identity occupies in its mount, or
            /// `None` when it belongs to no file.
            pub(crate) fn local_key(self) -> Option<u32> {
                match self.kind() {
                    ResolutionIdentityKind::Local => Some(
                        u32::try_from(self.payload() & LOCAL_KEY_MASK)
                            .expect("a 32-bit catalog position fits u32"),
                    ),
                    _ => None,
                }
            }

            /// This identity mounted at another ordinal.
            ///
            /// An interior is produced under [`UNMOUNTED_ORDINAL`] and shared
            /// by every mounting of that content, so the mount's own ordinal
            /// is spliced where a value crosses from the interior to the
            /// engine.
            pub(crate) fn at_ordinal(self, ordinal: u32) -> Self {
                let local_key = self
                    .local_key()
                    .unwrap_or_else(|| panic!("only an identity a blob owns is mounted: {self}"));
                Self::local(ordinal, local_key)
            }

            /// One number this operation minted for itself.
            pub(crate) fn operation_local(number: u64) -> Self {
                assert!(
                    number < CONTEXT_OPERATION_BASE,
                    "an operation's own identity number is below the selected \
                     context's range: {number}"
                );
                Self::of_kind(ResolutionIdentityKind::Operation, number)
            }

            /// One number a selected context minted, in the half of the
            /// `Operation` space that no operation can reach.
            pub(crate) fn context_local(number: u64) -> Self {
                assert!(
                    number < CONTEXT_OPERATION_BASE,
                    "a selected context's identity number fits its half of the \
                     operation space: {number}"
                );
                Self::of_kind(
                    ResolutionIdentityKind::Operation,
                    number | CONTEXT_OPERATION_BASE,
                )
            }

            /// Whether this identity was minted by a selected context rather
            /// than by the operation reading it.
            pub(crate) fn is_context_local(self) -> bool {
                matches!(self.kind(), ResolutionIdentityKind::Operation)
                    && self.payload() >= CONTEXT_OPERATION_BASE
            }

            /// The number this identity carries when an operation or a context
            /// minted it.
            pub(crate) fn operation_local_number(self) -> Option<u64> {
                matches!(self.kind(), ResolutionIdentityKind::Operation).then(|| self.payload())
            }

            pub(crate) const fn get(self) -> u64 {
                self.0
            }

            /// One identity for a fixture, minted from a label.
            ///
            /// Production has no `hash_bytes` left: an identity is a catalog
            /// position, an interned shared name, or a number its operation
            /// minted. A fixture has neither a catalog nor an operation, so it
            /// takes its number from a table that lives for the test binary,
            /// in the `Operation` kind, which is exactly what "belongs to no
            /// file" means in this layout. It is deterministic within a
            /// process, two labels cannot collide, and each fixture's
            /// `b"alpha"` stays readable where a bare counter would not.
            #[cfg(any(test, feature = "test-support"))]
            pub(crate) fn for_test(label: impl AsRef<[u8]>) -> Self {
                Self::operation_local(test_label_number(label.as_ref()))
            }

            /// This identity's own bytes, big-endian.
            ///
            /// It is eight bytes now rather than thirty-two, and it is still
            /// the whole of the identity: a hash that used to mix in a digest
            /// mixes in the number that replaced it, and a reason built from
            /// one identity is as distinct from another's as the identities
            /// are. Nothing decodes these bytes; the accessors above are how
            /// an identity is read.
            pub(crate) const fn as_bytes(self) -> [u8; 8] {
                self.0.to_be_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.kind() {
                    ResolutionIdentityKind::Local => write!(
                        formatter,
                        "{}#{}:{}",
                        stringify!($name),
                        self.payload() >> LOCAL_ORDINAL_SHIFT,
                        self.payload() & LOCAL_KEY_MASK
                    ),
                    ResolutionIdentityKind::Shared => {
                        write!(formatter, "{}#shared:{}", stringify!($name), self.payload())
                    }
                    ResolutionIdentityKind::Operation => {
                        write!(formatter, "{}#op:{}", stringify!($name), self.payload())
                    }
                    ResolutionIdentityKind::Reserved => {
                        write!(
                            formatter,
                            "{}#reserved:{}",
                            stringify!($name),
                            self.payload()
                        )
                    }
                }
            }
        }
    };
}

/// One number per distinct fixture label, for the whole test binary.
///
/// Shared by the four runtime identities and by `BindingFragmentId`: they are
/// different types, so one label naming one number in each of them is what a
/// fixture wants, and a fixture that needs two distinct values writes two
/// labels.
#[cfg(any(test, feature = "test-support"))]
fn test_label_number(label: &[u8]) -> u64 {
    static LABELS: std::sync::OnceLock<std::sync::Mutex<HashMap<Vec<u8>, u64>>> =
        std::sync::OnceLock::new();
    let mut labels = LABELS
        .get_or_init(|| std::sync::Mutex::new(HashMap::default()))
        .lock()
        .expect("the fixture label table is not poisoned");
    let next =
        u64::try_from(labels.len()).expect("a test binary mints fewer labels than u64 holds");
    *labels.entry(label.to_vec()).or_insert(next)
}

numeric_id!(BindingNodeId);
numeric_id!(PartialPathId);
numeric_id!(SemanticId);
numeric_id!(StackVariableId);

/// One derivation key: the canonical digest of how a value was derived.
///
/// This is not an identity and it is deliberately not one of the five. It
/// names no mount, no row and no catalog entry, and nothing ever looks one up
/// or writes one down; it exists so that two derivations of the same thing can
/// be recognised as the same derivation, and it is only ever compared with
/// other keys of its own kind. `SeededPartialPath` already said so in its own
/// words: its key is "never looked up in, hydrated from, or persisted to the
/// fragment source".
///
/// It keeps the whole digest. Three sites used to fold one of these into a
/// `PartialPathId`, which was identity-by-hashing -- the thing milestone 4
/// removes -- and truncating the digest into the sixty-one payload bits would
/// have been the same mistake in a smaller space. A value that is a content
/// key is a content key, with its own type, and then no part of the identity
/// layout has to make room for it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationKey([u8; 32]);

impl DerivationKey {
    pub(crate) const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for DerivationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "derivation#")?;
        write_lower_hex(&self.0, formatter)
    }
}

impl fmt::Display for DerivationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

/// One mounted binding fragment, which is its mount ordinal and nothing else.
///
/// It used to be a content digest whose first eight bytes every identity
/// mounted on it carried. The ordinal is inside the identity now, so this
/// names the mount directly; the mount's content digest stays in the mount
/// record, which is what the selection fingerprint and
/// `selected_resolution_mounts` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingFragmentId(u32);

impl BindingFragmentId {
    pub(crate) fn at_ordinal(ordinal: u32) -> Self {
        assert!(
            ordinal < MOUNT_ORDINAL_LIMIT,
            "a mount ordinal fits the 29 bits milestone 4's layout gives it: {ordinal}"
        );
        Self(ordinal)
    }

    /// The fragment a lowering mints under before its artifact is mounted.
    pub(crate) const fn unmounted() -> Self {
        Self(UNMOUNTED_ORDINAL)
    }

    /// One mount ordinal for a fixture, minted from a label. See
    /// `SemanticId::for_test`.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test(label: impl AsRef<[u8]>) -> Self {
        let ordinal = u32::try_from(test_label_number(label.as_ref()))
            .expect("a test binary mints fewer labels than u32 holds");
        assert!(
            ordinal < UNMOUNTED_ORDINAL,
            "a fixture's mount ordinal stays below the unmounted one: {ordinal}"
        );
        Self(ordinal)
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.0
    }

    /// This fragment's own bytes, big-endian. A hash that used to mix in the
    /// mount's content digest mixes in its ordinal now.
    pub(crate) const fn as_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for BindingFragmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fragment#{}", self.0)
    }
}

/// One shared name's id.
///
/// A shared name (a lookup recipe, an intrinsic type) belongs to no file, so
/// its identity is an integer interned once per store rather than a digest
/// recomputed per blob. Ids below [`SharedNameId::PER_REQUEST_BASE`] are
/// `resolution_identities.id`; ids at or above it were minted for one request
/// or one preparation, for a name the store has not interned, and are dropped
/// with it. One bit test tells them apart, so nothing consults a table to know
/// whether an id is a store fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SharedNameId(u32);

impl SharedNameId {
    /// The first id that names no `resolution_identities` row.
    pub(crate) const PER_REQUEST_BASE: u32 = 1 << 31;

    /// One `resolution_identities.id`, as the writer minted it.
    pub(crate) fn interned(id: i64) -> Self {
        let id = u32::try_from(id)
            .unwrap_or_else(|_| panic!("an interned shared name id fits u32: {id}"));
        assert!(
            id < Self::PER_REQUEST_BASE,
            "an interned shared name id is below the per-request base: {id}"
        );
        Self(id)
    }

    /// One id for a name the store has not interned, minted by the request or
    /// the preparation that met it and dropped with it.
    pub(crate) fn per_request(ordinal: u32) -> Self {
        let id = ordinal
            .checked_add(Self::PER_REQUEST_BASE)
            .unwrap_or_else(|| panic!("a per-request shared name ordinal fits u32: {ordinal}"));
        Self(id)
    }

    pub(crate) const fn get(self) -> u32 {
        self.0
    }

    /// Whether this id is a `resolution_identities` row and may therefore be
    /// written or compared across requests.
    pub(crate) const fn is_interned(self) -> bool {
        self.0 < Self::PER_REQUEST_BASE
    }
}

impl fmt::Display for SharedNameId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "shared#{}", self.0)
    }
}

pub type StackVariable = StackVariableId;

impl BindingNodeId {
    /// The canonical key for the one mount-independent root boundary.
    pub(crate) const UNIVERSAL_ROOT_BOUNDARY_KEY: i64 = 0;

    /// The one mount-independent root boundary shared by every selected
    /// resolution fragment.
    ///
    /// Persistent interiors refer to this node through boundary key zero. It
    /// is deliberately outside every fragment-local identity space, so equal
    /// content mounted at different workspace paths still meets at the same
    /// universal boundary. That is what the `Reserved` kind is for, and it is
    /// the only value in it.
    pub(crate) fn universal_root() -> Self {
        Self::of_kind(
            ResolutionIdentityKind::Reserved,
            u64::try_from(Self::UNIVERSAL_ROOT_BOUNDARY_KEY)
                .expect("the universal root boundary key is zero"),
        )
    }
}

impl SemanticId {
    /// One shared name as the runtime semantic every mount meets it by.
    pub(crate) fn shared_name(id: SharedNameId) -> Self {
        Self::of_kind(ResolutionIdentityKind::Shared, u64::from(id.get()))
    }

    /// The shared name this runtime semantic carries, or `None` when it is not
    /// a shared name.
    pub(crate) fn shared_name_id(self) -> Option<SharedNameId> {
        matches!(self.kind(), ResolutionIdentityKind::Shared).then(|| {
            SharedNameId(u32::try_from(self.payload()).expect("a shared name id fits u32"))
        })
    }
}

/// One alpha renaming in progress.
///
/// A renamed variable has to be distinct from every variable in the path it is
/// about to be composed with, and from every other variable in its own path.
/// Numbering from one past that path's highest operation-local variable gives
/// both at once: the two sides' operation-local numbers cannot meet, and a
/// fragment-local variable is a different kind of value, so it cannot be
/// mistaken for one either.
///
/// This is why the composition no longer carries a renaming identity. That
/// identity was a SHA-256 of the derivation chain, one per composition step
/// plus one per variable renamed, and it existed only to give a rename its own
/// namespace. A namespace computed from the path it is composing against is
/// the same guarantee without the hash, and the renaming's value never entered
/// a termination test: the cycle certifier keys on a stack effect whose
/// variables `AlphaNormalizer` has already renumbered from zero.
#[derive(Debug)]
struct AlphaRenaming {
    next: u64,
    /// The variables this rename has already numbered, scanned linearly.
    ///
    /// A path holds a handful of distinct stack variables, so the scan is
    /// shorter than a hash of the key would be and it allocates nothing until
    /// the first variable is renamed. This is the hot inner loop of
    /// composition and a map here was measurably worse than the SHA-256 it
    /// replaced.
    assigned: Vec<(StackVariableId, StackVariableId)>,
}

impl AlphaRenaming {
    /// A renaming whose numbers are fresh against `other`.
    fn after(other: &PartialPath) -> Self {
        Self {
            next: other.variable_ceiling,
            assigned: Vec::new(),
        }
    }

    fn rename(&mut self, variable: StackVariableId) -> StackVariableId {
        if let Some(&(_, renamed)) = self.assigned.iter().find(|(known, _)| *known == variable) {
            return renamed;
        }
        let renamed = StackVariableId::operation_local(self.next);
        self.next = self
            .next
            .checked_add(1)
            .expect("an alpha renaming mints fewer variables than u64 holds");
        self.assigned.push((variable, renamed));
        renamed
    }
}

/// Source-declared effective namespaces for one Go lexical definition.
/// This nonzero scalar is present only for an eligible lexical binder; it is
/// not inferred from a declaration's primary namespace or its syntax kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoDefinitionNamespaces(u8);

impl GoDefinitionNamespaces {
    pub const fn from_bits(bits: u8) -> Self {
        assert!(
            bits > 0 && bits <= 15,
            "Go lexical namespaces use Type=1, Value=2, Callable=4, Package=8"
        );
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) fn admits(
        self,
        namespace: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        package_qualifier: bool,
    ) -> bool {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        assert!(!package_qualifier || namespace == ResolutionNamespace::TypeOrValue);
        let requested = match namespace {
            ResolutionNamespace::Type => 1,
            ResolutionNamespace::Value => 2,
            ResolutionNamespace::Callable => 4,
            ResolutionNamespace::TypeOrValue => {
                if package_qualifier {
                    11
                } else {
                    3
                }
            }
            _ => panic!("unsupported Go spelling namespace: {namespace:?}"),
        };
        self.0 & requested != 0
    }
}

/// Whether a completed lexical binding is admissible for the requested namespace.
/// A blocker retains its real declaration identity and participates in precedence,
/// but cannot be published as an affirmative resolution target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingCandidateAdmission {
    Target,
    WrongNamespaceBlocker,
}

/// The stack effect or semantic endpoint represented by one graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingNodeKind {
    Root,
    Scope,
    PushSymbol(SemanticId),
    PopSymbol(SemanticId),
    /// Push a symbol together with the scope stack at traversal time.
    PushScopedSymbol(SemanticId),
    PopScopedSymbol(SemanticId),
    DropScopes,
    JumpToScope(BindingNodeId),
    Reference(SemanticId),
    Definition(SemanticId),
}

/// A top-first fixed stack prefix followed by an optional remainder variable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StackPattern<T> {
    fixed: Box<[T]>,
    tail: Option<StackVariableId>,
}

impl<T> StackPattern<T> {
    pub fn new(fixed: impl Into<Box<[T]>>, tail: Option<StackVariableId>) -> Self {
        Self {
            fixed: fixed.into(),
            tail,
        }
    }

    pub fn closed(fixed: impl Into<Box<[T]>>) -> Self {
        Self::new(fixed, None)
    }

    pub fn open(fixed: impl Into<Box<[T]>>, tail: StackVariableId) -> Self {
        Self::new(fixed, Some(tail))
    }

    pub fn fixed(&self) -> &[T] {
        &self.fixed
    }

    pub const fn tail(&self) -> Option<StackVariableId> {
        self.tail
    }
}

impl<T: Clone> StackPattern<T> {
    fn alpha_renamed(&self, renaming: &mut AlphaRenaming) -> Self {
        Self {
            fixed: self.fixed.clone(),
            tail: self.tail.map(|variable| renaming.rename(variable)),
        }
    }
}

/// One symbol-stack cell. Scoped symbols carry the partial scope stack that
/// was current when the symbol was pushed.
///
/// Keeping the attached scopes in the algebra is essential: two occurrences
/// of the same textual symbol are not interchangeable when they close over
/// different lexical scopes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialScopedSymbol {
    symbol: SemanticId,
    scopes: Option<StackPattern<BindingNodeId>>,
}

impl PartialScopedSymbol {
    pub const fn unscoped(symbol: SemanticId) -> Self {
        Self {
            symbol,
            scopes: None,
        }
    }

    pub fn scoped(symbol: SemanticId, scopes: StackPattern<BindingNodeId>) -> Self {
        Self {
            symbol,
            scopes: Some(scopes),
        }
    }

    pub const fn symbol(&self) -> SemanticId {
        self.symbol
    }

    pub fn scopes(&self) -> Option<&StackPattern<BindingNodeId>> {
        self.scopes.as_ref()
    }
}

pub type SymbolStackPattern = StackPattern<PartialScopedSymbol>;
pub type ScopeStackPattern = StackPattern<BindingNodeId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackUnificationError {
    FixedCellMismatch { index: usize },
    ClosedStackLengthMismatch,
    RecursiveVariableBinding(StackVariableId),
}

impl fmt::Display for StackUnificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedCellMismatch { index } => {
                write!(formatter, "stack cells differ at index {index}")
            }
            Self::ClosedStackLengthMismatch => {
                formatter.write_str("a closed stack cannot absorb the remaining cells")
            }
            Self::RecursiveVariableBinding(variable) => {
                write!(formatter, "stack variable {variable} would contain itself")
            }
        }
    }
}

impl std::error::Error for StackUnificationError {}

/// One finite substitution produced by unifying stack patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSubstitution<T> {
    bindings: HashMap<StackVariableId, StackPattern<T>>,
}

impl<T> Default for StackSubstitution<T> {
    fn default() -> Self {
        Self {
            bindings: HashMap::default(),
        }
    }
}

impl<T> StackSubstitution<T> {
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn binding(&self, variable: StackVariableId) -> Option<&StackPattern<T>> {
        self.bindings.get(&variable)
    }
}

impl<T: Clone + Eq> StackSubstitution<T> {
    /// Add one equality to an existing substitution. Applying existing
    /// bindings first is what makes repeated occurrences of a tail variable
    /// constrain, rather than overwrite, its earlier binding.
    fn unify_patterns_with_poll<P, C>(
        &mut self,
        left: &StackPattern<T>,
        right: &StackPattern<T>,
        clone_cell: &mut C,
        cancelled: &mut P,
    ) -> Option<Result<(), StackUnificationError>>
    where
        P: FnMut() -> bool,
        C: FnMut(&T, &mut P) -> Option<T>,
    {
        let left = match self.apply_with_poll(left, clone_cell, cancelled)? {
            Ok(left) => left,
            Err(error) => return Some(Err(error)),
        };
        let right = match self.apply_with_poll(right, clone_cell, cancelled)? {
            Ok(right) => right,
            Err(error) => return Some(Err(error)),
        };
        let shared = left.fixed.len().min(right.fixed.len());
        for index in 0..shared {
            if cancelled() {
                return None;
            }
            if left.fixed[index] != right.fixed[index] {
                return Some(Err(StackUnificationError::FixedCellMismatch { index }));
            }
        }

        let left_remainder = &left.fixed[shared..];
        let right_remainder = &right.fixed[shared..];
        debug_assert!(left_remainder.is_empty() || right_remainder.is_empty());

        match (left_remainder.is_empty(), right_remainder.is_empty()) {
            (true, true) => match (left.tail, right.tail) {
                (None, None) => {}
                (Some(variable), None) | (None, Some(variable)) => {
                    if let Err(error) = self.bind(variable, StackPattern::closed(Vec::new())) {
                        return Some(Err(error));
                    }
                }
                (Some(left_variable), Some(right_variable)) if left_variable != right_variable => {
                    if let Err(error) = self.bind(
                        left_variable,
                        StackPattern::open(Vec::new(), right_variable),
                    ) {
                        return Some(Err(error));
                    }
                }
                (Some(_), Some(_)) => {}
            },
            (true, false) => {
                let Some(variable) = left.tail else {
                    return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
                };
                let fixed = clone_cells_with_poll(right_remainder, clone_cell, cancelled)?;
                if let Err(error) = self.bind(variable, StackPattern::new(fixed, right.tail)) {
                    return Some(Err(error));
                }
            }
            (false, true) => {
                let Some(variable) = right.tail else {
                    return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
                };
                let fixed = clone_cells_with_poll(left_remainder, clone_cell, cancelled)?;
                if let Err(error) = self.bind(variable, StackPattern::new(fixed, left.tail)) {
                    return Some(Err(error));
                }
            }
            (false, false) => unreachable!("one fixed prefix must end first"),
        }
        Some(Ok(()))
    }
}

impl<T: Clone> StackSubstitution<T> {
    fn bind(
        &mut self,
        variable: StackVariableId,
        pattern: StackPattern<T>,
    ) -> Result<(), StackUnificationError> {
        if pattern.tail == Some(variable) {
            if pattern.fixed.is_empty() {
                return Ok(());
            }
            return Err(StackUnificationError::RecursiveVariableBinding(variable));
        }
        self.bindings.insert(variable, pattern);
        Ok(())
    }

    fn apply_with_poll<P, C>(
        &self,
        pattern: &StackPattern<T>,
        clone_cell: &mut C,
        cancelled: &mut P,
    ) -> Option<Result<StackPattern<T>, StackUnificationError>>
    where
        P: FnMut() -> bool,
        C: FnMut(&T, &mut P) -> Option<T>,
    {
        let mut fixed = clone_cells_with_poll(&pattern.fixed, clone_cell, cancelled)?;
        let mut tail = pattern.tail;
        let mut visited = HashSet::default();
        while let Some(variable) = tail {
            if cancelled() {
                return None;
            }
            let Some(binding) = self.bindings.get(&variable) else {
                break;
            };
            if !visited.insert(variable) {
                return Some(Err(StackUnificationError::RecursiveVariableBinding(
                    variable,
                )));
            }
            fixed.extend(clone_cells_with_poll(
                &binding.fixed,
                clone_cell,
                cancelled,
            )?);
            tail = binding.tail;
        }
        Some(Ok(StackPattern::new(fixed, tail)))
    }
}

fn clone_cells_with_poll<T, P, C>(
    values: &[T],
    clone_cell: &mut C,
    cancelled: &mut P,
) -> Option<Vec<T>>
where
    P: FnMut() -> bool,
    C: FnMut(&T, &mut P) -> Option<T>,
{
    let mut cloned = Vec::new();
    for value in values {
        cloned.push(clone_cell(value, cancelled)?);
    }
    Some(cloned)
}

fn clone_scope_stack_with_poll<P>(
    pattern: &ScopeStackPattern,
    cancelled: &mut P,
) -> Option<ScopeStackPattern>
where
    P: FnMut() -> bool,
{
    let mut clone_node = |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
    let fixed = clone_cells_with_poll(&pattern.fixed, &mut clone_node, cancelled)?;
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(fixed, pattern.tail))
}

fn alpha_rename_scope_stack_with_poll<P>(
    pattern: &ScopeStackPattern,
    renaming: &mut AlphaRenaming,
    cancelled: &mut P,
) -> Option<ScopeStackPattern>
where
    P: FnMut() -> bool,
{
    let mut cloned = clone_scope_stack_with_poll(pattern, cancelled)?;
    cloned.tail = cloned.tail.map(|variable| renaming.rename(variable));
    Some(cloned)
}

fn clone_scoped_symbol_with_poll<P>(
    symbol: &PartialScopedSymbol,
    cancelled: &mut P,
) -> Option<PartialScopedSymbol>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    Some(PartialScopedSymbol {
        symbol: symbol.symbol,
        scopes: match &symbol.scopes {
            Some(scopes) => Some(clone_scope_stack_with_poll(scopes, cancelled)?),
            None => None,
        },
    })
}

fn alpha_rename_scoped_symbol_with_poll<P>(
    symbol: &PartialScopedSymbol,
    renaming: &mut AlphaRenaming,
    cancelled: &mut P,
) -> Option<PartialScopedSymbol>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    Some(PartialScopedSymbol {
        symbol: symbol.symbol,
        scopes: match &symbol.scopes {
            Some(scopes) => Some(alpha_rename_scope_stack_with_poll(
                scopes, renaming, cancelled,
            )?),
            None => None,
        },
    })
}

fn alpha_rename_symbol_stack_with_poll<P>(
    pattern: &SymbolStackPattern,
    renaming: &mut AlphaRenaming,
    cancelled: &mut P,
) -> Option<SymbolStackPattern>
where
    P: FnMut() -> bool,
{
    // The fixed cells are renamed one at a time rather than through
    // `clone_cells_with_poll`, because each one needs the renaming, which is
    // `&mut` and cannot be captured by the shared closure that helper takes.
    let mut fixed = Vec::with_capacity(pattern.fixed.len());
    for symbol in &pattern.fixed {
        fixed.push(alpha_rename_scoped_symbol_with_poll(
            symbol, renaming, cancelled,
        )?);
    }
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(
        fixed,
        pattern.tail.map(|variable| renaming.rename(variable)),
    ))
}

fn clone_symbol_stack_with_poll<P>(
    pattern: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<SymbolStackPattern>
where
    P: FnMut() -> bool,
{
    let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
        clone_scoped_symbol_with_poll(symbol, cancelled)
    };
    let fixed = clone_cells_with_poll(&pattern.fixed, &mut clone_symbol, cancelled)?;
    if cancelled() {
        return None;
    }
    Some(StackPattern::new(fixed, pattern.tail))
}

fn apply_symbol_stack_with_poll<P>(
    symbols: &StackSubstitution<PartialScopedSymbol>,
    scopes: &StackSubstitution<BindingNodeId>,
    pattern: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<Result<SymbolStackPattern, StackUnificationError>>
where
    P: FnMut() -> bool,
{
    let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
        clone_scoped_symbol_with_poll(symbol, cancelled)
    };
    let outer = match symbols.apply_with_poll(pattern, &mut clone_symbol, cancelled)? {
        Ok(outer) => outer,
        Err(error) => return Some(Err(error)),
    };
    let mut fixed = Vec::with_capacity(outer.fixed.len());
    for symbol in outer.fixed.iter() {
        if cancelled() {
            return None;
        }
        let substituted_scopes = match &symbol.scopes {
            Some(pattern) => {
                let mut clone_node =
                    |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
                match scopes.apply_with_poll(pattern, &mut clone_node, cancelled)? {
                    Ok(scopes) => Some(scopes),
                    Err(error) => return Some(Err(error)),
                }
            }
            None => None,
        };
        fixed.push(PartialScopedSymbol {
            symbol: symbol.symbol,
            scopes: substituted_scopes,
        });
    }
    Some(Ok(StackPattern::new(fixed, outer.tail)))
}

fn unify_symbol_stacks_with_poll<P>(
    symbols: &mut StackSubstitution<PartialScopedSymbol>,
    scopes: &mut StackSubstitution<BindingNodeId>,
    left: &SymbolStackPattern,
    right: &SymbolStackPattern,
    cancelled: &mut P,
) -> Option<Result<(), StackUnificationError>>
where
    P: FnMut() -> bool,
{
    let left = match apply_symbol_stack_with_poll(symbols, scopes, left, cancelled)? {
        Ok(left) => left,
        Err(error) => return Some(Err(error)),
    };
    let right = match apply_symbol_stack_with_poll(symbols, scopes, right, cancelled)? {
        Ok(right) => right,
        Err(error) => return Some(Err(error)),
    };
    let shared = left.fixed.len().min(right.fixed.len());
    for index in 0..shared {
        if cancelled() {
            return None;
        }
        let left_symbol = &left.fixed[index];
        let right_symbol = &right.fixed[index];
        if left_symbol.symbol != right_symbol.symbol {
            return Some(Err(StackUnificationError::FixedCellMismatch { index }));
        }
        match (&left_symbol.scopes, &right_symbol.scopes) {
            (None, None) => {}
            (Some(left_scopes), Some(right_scopes)) => {
                let mut clone_node =
                    |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
                match scopes.unify_patterns_with_poll(
                    left_scopes,
                    right_scopes,
                    &mut clone_node,
                    cancelled,
                )? {
                    Ok(()) => {}
                    Err(_) => {
                        return Some(Err(StackUnificationError::FixedCellMismatch { index }));
                    }
                }
            }
            (None, Some(_)) | (Some(_), None) => {
                return Some(Err(StackUnificationError::FixedCellMismatch { index }));
            }
        }
    }

    let left_remainder = &left.fixed[shared..];
    let right_remainder = &right.fixed[shared..];
    debug_assert!(left_remainder.is_empty() || right_remainder.is_empty());
    match (left_remainder.is_empty(), right_remainder.is_empty()) {
        (true, true) => match (left.tail, right.tail) {
            (None, None) => {}
            (Some(variable), None) | (None, Some(variable)) => {
                if let Err(error) = symbols.bind(variable, StackPattern::closed(Vec::new())) {
                    return Some(Err(error));
                }
            }
            (Some(left_variable), Some(right_variable)) if left_variable != right_variable => {
                if let Err(error) = symbols.bind(
                    left_variable,
                    StackPattern::open(Vec::new(), right_variable),
                ) {
                    return Some(Err(error));
                }
            }
            (Some(_), Some(_)) => {}
        },
        (true, false) => {
            let Some(variable) = left.tail else {
                return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
            };
            let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
                clone_scoped_symbol_with_poll(symbol, cancelled)
            };
            let fixed = clone_cells_with_poll(right_remainder, &mut clone_symbol, cancelled)?;
            if let Err(error) = symbols.bind(variable, StackPattern::new(fixed, right.tail)) {
                return Some(Err(error));
            }
        }
        (false, true) => {
            let Some(variable) = right.tail else {
                return Some(Err(StackUnificationError::ClosedStackLengthMismatch));
            };
            let mut clone_symbol = |symbol: &PartialScopedSymbol, cancelled: &mut P| {
                clone_scoped_symbol_with_poll(symbol, cancelled)
            };
            let fixed = clone_cells_with_poll(left_remainder, &mut clone_symbol, cancelled)?;
            if let Err(error) = symbols.bind(variable, StackPattern::new(fixed, left.tail)) {
                return Some(Err(error));
            }
        }
        (false, false) => unreachable!("one fixed prefix must end first"),
    }
    Some(Ok(()))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointSignature {
    node: BindingNodeId,
    symbols: SymbolStackPattern,
    scopes: ScopeStackPattern,
}

impl EndpointSignature {
    pub fn new(
        node: BindingNodeId,
        symbols: StackPattern<SemanticId>,
        scopes: ScopeStackPattern,
    ) -> Self {
        Self::new_scoped(
            node,
            StackPattern::new(
                symbols
                    .fixed
                    .iter()
                    .copied()
                    .map(PartialScopedSymbol::unscoped)
                    .collect::<Vec<_>>(),
                symbols.tail,
            ),
            scopes,
        )
    }

    pub fn new_scoped(
        node: BindingNodeId,
        symbols: SymbolStackPattern,
        scopes: ScopeStackPattern,
    ) -> Self {
        Self {
            node,
            symbols,
            scopes,
        }
    }

    pub const fn node(&self) -> BindingNodeId {
        self.node
    }

    pub fn symbols(&self) -> &SymbolStackPattern {
        &self.symbols
    }

    pub fn scopes(&self) -> &ScopeStackPattern {
        &self.scopes
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        Some(Self::new_scoped(
            self.node,
            clone_symbol_stack_with_poll(&self.symbols, cancelled)?,
            clone_scope_stack_with_poll(&self.scopes, cancelled)?,
        ))
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if self.node != other.node
            || self.symbols.tail != other.symbols.tail
            || self.symbols.fixed.len() != other.symbols.fixed.len()
            || self.scopes.tail != other.scopes.tail
            || self.scopes.fixed.len() != other.scopes.fixed.len()
        {
            return Some(false);
        }
        for (left, right) in self.symbols.fixed.iter().zip(other.symbols.fixed.iter()) {
            if cancelled() {
                return None;
            }
            if left.symbol != right.symbol {
                return Some(false);
            }
            match (left.scopes.as_ref(), right.scopes.as_ref()) {
                (None, None) => {}
                (Some(left), Some(right)) => {
                    if !scope_patterns_equal_with_poll(left, right, cancelled)? {
                        return Some(false);
                    }
                }
                (None, Some(_)) | (Some(_), None) => return Some(false),
            }
        }
        scope_patterns_equal_with_poll(&self.scopes, &other.scopes, cancelled)
    }

    /// Test the exact middle-endpoint join used by path concatenation without
    /// materializing either outer endpoint or semantic evidence.
    pub(crate) fn can_concatenate_with_poll<P>(
        &self,
        next: &Self,
        cancelled: &mut P,
    ) -> Option<Result<(), PathCompositionError>>
    where
        P: FnMut() -> bool,
    {
        let next = if next.holds_a_variable() {
            let mut renaming = AlphaRenaming {
                next: self.operation_local_variable_ceiling(),
                assigned: Vec::new(),
            };
            next.alpha_renamed_with_poll(&mut renaming, cancelled)?
        } else {
            next.clone_with_poll(cancelled)?
        };
        match unify_middle_endpoints_with_poll(self, &next, cancelled)? {
            Ok(_) => Some(Ok(())),
            Err(error) => Some(Err(error)),
        }
    }

    fn alpha_renamed_with_poll<P>(
        &self,
        renaming: &mut AlphaRenaming,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        Some(Self::new_scoped(
            self.node,
            alpha_rename_symbol_stack_with_poll(&self.symbols, renaming, cancelled)?,
            alpha_rename_scope_stack_with_poll(&self.scopes, renaming, cancelled)?,
        ))
    }

    /// Whether this endpoint holds any stack variable at all.
    fn holds_a_variable(&self) -> bool {
        self.symbols.tail().is_some()
            || self.scopes.tail().is_some()
            || self.symbols.fixed().iter().any(|symbol| {
                symbol
                    .scopes
                    .as_ref()
                    .is_some_and(|scopes| scopes.tail().is_some())
            })
    }

    /// One past the highest operation-local variable number this endpoint
    /// holds, which is where a renaming composing against it may start.
    ///
    /// A variable a *selected context* minted is skipped, and must be: its
    /// number is offset by [`CONTEXT_OPERATION_BASE`], so counting it would
    /// raise the ceiling past that base and the next rename would assert. It
    /// is also unnecessary. The two halves of the `Operation` range are
    /// disjoint by bit 60, so a renamed variable numbered in the operation's
    /// half cannot equal a context's however high the context has counted.
    /// That disjointness is what the base is for, and this is the one place
    /// that would otherwise have to know both numberings at once.
    fn operation_local_variable_ceiling(&self) -> u64 {
        let mut ceiling = 0;
        let mut raise = |variable: Option<StackVariableId>| {
            if let Some(number) = variable
                .filter(|variable| !variable.is_context_local())
                .and_then(StackVariableId::operation_local_number)
            {
                ceiling = ceiling.max(
                    number
                        .checked_add(1)
                        .expect("an operation-local variable number is below u64::MAX"),
                );
            }
        };
        raise(self.symbols.tail());
        raise(self.scopes.tail());
        for symbol in self.symbols.fixed() {
            if let Some(scopes) = &symbol.scopes {
                raise(scopes.tail());
            }
        }
        ceiling
    }

    fn substituted_with_poll<P>(
        &self,
        symbols: &StackSubstitution<PartialScopedSymbol>,
        scopes: &StackSubstitution<BindingNodeId>,
        cancelled: &mut P,
    ) -> Option<Result<Self, StackUnificationError>>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let symbols = match apply_symbol_stack_with_poll(symbols, scopes, &self.symbols, cancelled)?
        {
            Ok(symbols) => symbols,
            Err(error) => return Some(Err(error)),
        };
        let mut clone_node =
            |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
        let scopes = match scopes.apply_with_poll(&self.scopes, &mut clone_node, cancelled)? {
            Ok(scopes) => scopes,
            Err(error) => return Some(Err(error)),
        };
        Some(Ok(Self::new_scoped(self.node, symbols, scopes)))
    }
}

fn scope_patterns_equal_with_poll<P>(
    left: &ScopeStackPattern,
    right: &ScopeStackPattern,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.tail != right.tail || left.fixed.len() != right.fixed.len() {
        return Some(false);
    }
    for (left, right) in left.fixed.iter().zip(right.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrecedenceStep {
    pub tier: PrecedenceTier,
    pub ordinal: u32,
    pub semantic: SemanticId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WitnessStep {
    Node(BindingNodeId),
    Candidate {
        semantic: SemanticId,
        outcome: CandidateOutcome,
    },
    Boundary {
        semantic: SemanticId,
        status: BoundaryStatus,
    },
}

impl WitnessStep {
    pub const fn kind(self) -> ResolutionWitnessKind {
        match self {
            Self::Node(_) => ResolutionWitnessKind::Node,
            Self::Candidate { .. } => ResolutionWitnessKind::Candidate,
            Self::Boundary { .. } => ResolutionWitnessKind::Boundary,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionIncompleteReason {
    Cancelled,
    CyclicExpansion(PartialPathId),
    /// One demanded root could not be answered because the finite dependency
    /// graph between root evaluations and endpoint relations closed a cycle.
    ///
    /// This is operation-local evidence, like `Cancelled`. The scheduler
    /// publishes no relation for a cyclic component, so no candidate path and
    /// no persisted coverage row can carry it; it exists so a site whose
    /// prefix depends on itself returns an honest incomplete answer named for
    /// its cause instead of an anonymous unsupported one.
    CyclicPrefixDependency(SemanticId),
    /// Candidate precedence does not induce a strict order: the traces form a
    /// cycle, or the language itself refuses to order candidates at one
    /// precedence (Rust's E0034, two in-scope traits a type implements that
    /// both supply the called member). The engine preserves every candidate
    /// rather than manufacturing an empty answer, but cannot call that
    /// conservative ambiguity exact.
    InconsistentPrecedence(SemanticId),
    OpenBoundary {
        semantic: SemanticId,
        status: BoundaryStatus,
    },
    UnsupportedSemantic(SemanticId),
    /// One candidate blob's receiver analysis stopped on its declared budget.
    ///
    /// This is operation-local evidence, like `Cancelled` and
    /// `CyclicPrefixDependency`. A budget is a property of the request that
    /// declared it, not of the blob, so no candidate path and no persisted
    /// coverage row can carry it; it exists so a reverse site whose
    /// confirmation ran out of steps says which definition it was confirming
    /// and why it stopped, instead of borrowing `UnsupportedSemantic` from the
    /// unknown-activation and type-bound-receiver paths and becoming
    /// indistinguishable from them.
    ReceiverBudgetExhausted(SemanticId),
    /// The request's non-cancelling soft deadline stopped reverse confirmation.
    ///
    /// This is operation-local evidence. The request may publish already
    /// confirmed blobs, but no persisted completion row can carry the budget
    /// of the request that produced it.
    TimeBudgetExceeded(SemanticId),
    /// One route left a Rust file that no Cargo target's module tree reaches.
    ///
    /// Such a file is published as its own `detached` crate topology whose
    /// `crate` root holds that file and nothing else, so every `crate::`,
    /// `self::` and `super::` route out of it is answered by a module tree
    /// Cargo never described. A route that dies there has not proved an
    /// absence; it has run out of the only crate the file was given. The
    /// reason names the fragment so a consumer can say which file it is
    /// about, and it is deliberately not an `OpenBoundary`: nothing crossed
    /// out of the workspace, the workspace failed to mount a file that is in
    /// it.
    ///
    /// This is operation-local evidence, like `Cancelled`. The crate route
    /// mints it from one selection's live crate rows; no lowered artifact
    /// carries it and no persisted completion-reason kind names it.
    UnmountedFile {
        fragment: BindingFragmentId,
    },
}

impl ResolutionIncompleteReason {
    pub const fn kind(self) -> ResolutionCompletionReasonKind {
        match self {
            Self::Cancelled => {
                panic!("operation-local cancellation has no persisted completion-reason kind")
            }
            Self::CyclicPrefixDependency(_) => {
                panic!("an unpublished cyclic prefix dependency has no persisted kind")
            }
            Self::ReceiverBudgetExhausted(_) => {
                panic!("an operation-local receiver budget stop has no persisted kind")
            }
            Self::TimeBudgetExceeded(_) => {
                panic!("an operation-local time budget stop has no persisted kind")
            }
            Self::UnmountedFile { .. } => {
                panic!("an operation-local unmounted-file route has no persisted kind")
            }
            Self::CyclicExpansion(_) => ResolutionCompletionReasonKind::CyclicExpansion,
            Self::InconsistentPrecedence(_) => {
                ResolutionCompletionReasonKind::InconsistentPrecedence
            }
            Self::OpenBoundary { .. } => ResolutionCompletionReasonKind::OpenBoundary,
            Self::UnsupportedSemantic(_) => ResolutionCompletionReasonKind::UnsupportedSemantic,
        }
    }
}

pub type CompletionReason = ResolutionIncompleteReason;

#[derive(Debug, Clone)]
pub enum ResolutionCompletion {
    Complete,
    Incomplete(CompletionReasons),
}

/// Canonical evidence union for source readers. Unlike exact operand ledgers,
/// this treats an empty raw incomplete value as contributing no reasons.
/// Local raw reasons accumulate in a set; source-wide bases remain shared.
#[derive(Debug, Default)]
pub(crate) struct ResolutionCompletionAccumulator {
    reasons: BTreeSet<ResolutionIncompleteReason>,
    shared: Option<CompletionReasonUnion>,
}

impl ResolutionCompletionAccumulator {
    pub(crate) fn include(&mut self, completion: &ResolutionCompletion) {
        let ResolutionCompletion::Incomplete(incoming) = completion else {
            return;
        };
        if let Some(shared) = &mut self.shared {
            shared
                .include_with_poll(incoming, &mut never_cancelled)
                .expect("non-cancellable source evidence union cannot abort");
        } else if incoming.is_shared() {
            let mut shared =
                CompletionReasonUnion::from_shared_with_poll(incoming, &mut never_cancelled)
                    .expect("non-cancellable source evidence construction cannot abort");
            for reason in std::mem::take(&mut self.reasons) {
                shared
                    .include_reason_with_poll(reason, &mut never_cancelled)
                    .expect("non-cancellable source evidence union cannot abort");
            }
            self.shared = Some(shared);
        } else {
            self.reasons.extend(incoming.iter().copied());
        }
    }

    pub(crate) fn finish(self) -> ResolutionCompletion {
        if let Some(shared) = self.shared {
            debug_assert!(self.reasons.is_empty());
            return ResolutionCompletion::Incomplete(
                shared
                    .finish_with_poll(&mut never_cancelled)
                    .expect("non-cancellable source evidence publication cannot abort"),
            );
        }
        if self.reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::Incomplete(CompletionReasons::canonical(
                self.reasons.into_iter().collect::<Vec<_>>(),
            ))
        }
    }
}

impl ResolutionCompletion {
    pub const fn kind(&self) -> ResolutionCompletionKind {
        match self {
            Self::Complete => ResolutionCompletionKind::Complete,
            Self::Incomplete(_) => ResolutionCompletionKind::Incomplete,
        }
    }

    pub fn incomplete(reasons: impl IntoIterator<Item = ResolutionIncompleteReason>) -> Self {
        let mut reasons = reasons.into_iter().collect::<Vec<_>>();
        reasons.sort_unstable();
        reasons.dedup();
        assert!(
            !reasons.is_empty(),
            "incomplete resolution requires a reason"
        );
        Self::Incomplete(CompletionReasons::canonical(reasons))
    }

    pub fn combine(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Complete, Self::Complete) => Self::Complete,
            (Self::Incomplete(reasons), Self::Complete)
            | (Self::Complete, Self::Incomplete(reasons)) => Self::Incomplete(reasons.clone()),
            (Self::Incomplete(left), Self::Incomplete(right)) => {
                Self::Incomplete(left.union(right))
            }
        }
    }

    pub(crate) fn contains_reason(&self, reason: ResolutionIncompleteReason) -> bool {
        matches!(self, Self::Incomplete(reasons) if reasons.contains(&reason))
    }

    /// Rebuild already-canonical reasons without sorting them again.
    ///
    /// Query-local fixed-point checkpoints copy potentially large completion
    /// values under cooperative cancellation. Re-running `sort_unstable`
    /// after that bounded copy would create an uninterruptible interval, so
    /// this crate-private seam validates strict canonical order while polling
    /// and then preserves it verbatim.
    pub(super) fn from_canonical_reasons(
        reasons: Box<[ResolutionIncompleteReason]>,
        mut cancelled: impl FnMut() -> bool,
    ) -> Option<Self> {
        assert!(
            !reasons.is_empty(),
            "incomplete resolution requires a reason"
        );
        for pair in reasons.windows(2) {
            if cancelled() {
                return None;
            }
            assert!(
                pair[0] < pair[1],
                "canonical incomplete reasons must be strictly sorted and deduplicated"
            );
        }
        Some(Self::Incomplete(
            CompletionReasons::from_validated_canonical_box(reasons),
        ))
    }
}

impl PartialEq for ResolutionCompletion {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Complete, Self::Complete) => true,
            (Self::Incomplete(left), Self::Incomplete(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for ResolutionCompletion {}

impl PartialOrd for ResolutionCompletion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResolutionCompletion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Complete, Self::Complete) => std::cmp::Ordering::Equal,
            (Self::Complete, Self::Incomplete(_)) => std::cmp::Ordering::Less,
            (Self::Incomplete(_), Self::Complete) => std::cmp::Ordering::Greater,
            (Self::Incomplete(left), Self::Incomplete(right)) => left.cmp(right),
        }
    }
}

impl std::hash::Hash for ResolutionCompletion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Complete => 0_u8.hash(state),
            Self::Incomplete(reasons) => {
                1_u8.hash(state);
                reasons.hash(state);
            }
        }
    }
}

/// A language-neutral type identity plus its pointer/reference indirection.
///
/// Indirection is explicit rather than folded into `identity`: Go method-set
/// and addressability rules need to distinguish `T`, `*T`, and `**T`, while
/// Java and other reference-only languages can use zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionTypeRef {
    identity: SemanticId,
    indirection: u32,
    reference_indirection: u32,
}

impl ResolutionTypeRef {
    pub const fn new(identity: SemanticId, indirection: u32) -> Self {
        Self::new_with_reference_indirection(identity, indirection, 0)
    }

    pub const fn new_with_reference_indirection(
        identity: SemanticId,
        indirection: u32,
        reference_indirection: u32,
    ) -> Self {
        assert!(
            reference_indirection <= indirection,
            "reference indirection must not exceed total indirection"
        );
        Self {
            identity,
            indirection,
            reference_indirection,
        }
    }

    pub const fn identity(self) -> SemanticId {
        self.identity
    }

    pub const fn indirection(self) -> u32 {
        self.indirection
    }

    pub const fn reference_indirection(self) -> u32 {
        self.reference_indirection
    }

    pub const fn has_only_reference_indirection(self) -> bool {
        self.indirection > 0 && self.reference_indirection == self.indirection
    }
}

/// One value alternative at the binding/type-flow frontier.
///
/// Type objects participate in static-member and constructor lookup. Runtime
/// values participate in instance-member lookup and retain addressability for
/// languages whose method sets or implicit addressing depend on it. Keeping
/// these categories separate prevents a declaration identity from silently
/// changing meaning while it flows between slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionSlotValue {
    TypeObject(ResolutionTypeRef),
    Runtime {
        ty: ResolutionTypeRef,
        addressable: bool,
    },
}

impl ResolutionSlotValue {
    pub const fn type_object(ty: ResolutionTypeRef) -> Self {
        Self::TypeObject(ty)
    }

    pub const fn runtime(ty: ResolutionTypeRef, addressable: bool) -> Self {
        Self::Runtime { ty, addressable }
    }

    pub const fn ty(self) -> ResolutionTypeRef {
        match self {
            Self::TypeObject(ty) | Self::Runtime { ty, .. } => ty,
        }
    }

    pub const fn addressable(self) -> Option<bool> {
        match self {
            Self::TypeObject(_) => None,
            Self::Runtime { addressable, .. } => Some(addressable),
        }
    }
}

/// Explicit category transform applied while a value crosses a typed slot.
///
/// Category changes are facts, not engine guesses derived from a transfer's
/// prose role. For example, declared type syntax yields a type object, while
/// the declaration's value slot holds runtime values of that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeTransferValueTransform {
    Preserve,
    ToRuntime { addressable: bool },
    ToNoValue,
    TypeObjectOnly,
    AddressableRuntimeOnly,
    AddressableOperandOnly,
    RuntimeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeTransferApplication {
    Value(ResolutionSlotValue),
    NoValue,
    IndirectionOutOfRange,
}

/// One immutable file-local rule that copies values between typed slots.
///
/// A rule deliberately stores no output values. Its output is a pure function
/// of the values supplied by the operation: category/addressability changes
/// are explicit in `value_transform`, while pointer/reference indirection is
/// adjusted with checked arithmetic. `semantic` is both the stable identity of
/// the rule and the evidence attached to an unrepresentable adjustment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeTransferRule {
    semantic: SemanticId,
    target_slot: SemanticId,
    indirection_delta: i64,
    reference_indirection_delta: i64,
    value_transform: TypeTransferValueTransform,
    completion: ResolutionCompletion,
}

impl TypeTransferRule {
    pub const MIN_INDIRECTION_DELTA: i64 = -(u32::MAX as i64);
    pub const MAX_INDIRECTION_DELTA: i64 = u32::MAX as i64;

    pub fn new(
        semantic: SemanticId,
        target_slot: SemanticId,
        indirection_delta: i64,
        value_transform: TypeTransferValueTransform,
        completion: ResolutionCompletion,
    ) -> Self {
        Self::new_with_reference_indirection(
            semantic,
            target_slot,
            indirection_delta,
            0,
            value_transform,
            completion,
        )
    }

    pub fn new_with_reference_indirection(
        semantic: SemanticId,
        target_slot: SemanticId,
        indirection_delta: i64,
        reference_indirection_delta: i64,
        value_transform: TypeTransferValueTransform,
        completion: ResolutionCompletion,
    ) -> Self {
        for (name, delta) in [
            ("indirection", indirection_delta),
            ("reference indirection", reference_indirection_delta),
        ] {
            assert!(
                (Self::MIN_INDIRECTION_DELTA..=Self::MAX_INDIRECTION_DELTA).contains(&delta),
                "type-transfer {name} delta {delta} is outside the representable u32 range"
            );
        }
        assert!(
            value_transform != TypeTransferValueTransform::ToNoValue
                || (indirection_delta == 0 && reference_indirection_delta == 0),
            "a no-value transfer must not carry a meaningless indirection delta"
        );
        Self {
            semantic,
            target_slot,
            indirection_delta,
            reference_indirection_delta,
            value_transform,
            completion,
        }
    }

    pub const fn semantic(&self) -> SemanticId {
        self.semantic
    }

    pub const fn target_slot(&self) -> SemanticId {
        self.target_slot
    }

    pub const fn indirection_delta(&self) -> i64 {
        self.indirection_delta
    }

    pub const fn reference_indirection_delta(&self) -> i64 {
        self.reference_indirection_delta
    }

    pub const fn value_transform(&self) -> TypeTransferValueTransform {
        self.value_transform
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn apply(&self, value: ResolutionSlotValue) -> TypeTransferApplication {
        if matches!(
            (self.value_transform, value),
            (TypeTransferValueTransform::ToNoValue, _)
                | (
                    TypeTransferValueTransform::TypeObjectOnly,
                    ResolutionSlotValue::Runtime { .. }
                )
                | (
                    TypeTransferValueTransform::AddressableRuntimeOnly
                        | TypeTransferValueTransform::AddressableOperandOnly
                        | TypeTransferValueTransform::RuntimeOnly,
                    ResolutionSlotValue::TypeObject(_)
                )
        ) || matches!(
            (self.value_transform, value),
            (
                TypeTransferValueTransform::AddressableOperandOnly,
                ResolutionSlotValue::Runtime {
                    addressable: false,
                    ..
                }
            )
        ) {
            return TypeTransferApplication::NoValue;
        }
        let ty = value.ty();
        let Some(indirection) = i64::from(ty.indirection()).checked_add(self.indirection_delta)
        else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        let Ok(indirection) = u32::try_from(indirection) else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        let Some(reference_indirection) =
            i64::from(ty.reference_indirection()).checked_add(self.reference_indirection_delta)
        else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        let Ok(reference_indirection) = u32::try_from(reference_indirection) else {
            return TypeTransferApplication::IndirectionOutOfRange;
        };
        if reference_indirection > indirection {
            return TypeTransferApplication::IndirectionOutOfRange;
        }
        let adjusted = ResolutionTypeRef::new_with_reference_indirection(
            ty.identity(),
            indirection,
            reference_indirection,
        );
        TypeTransferApplication::Value(match self.value_transform {
            TypeTransferValueTransform::Preserve => match value {
                ResolutionSlotValue::TypeObject(_) => ResolutionSlotValue::type_object(adjusted),
                ResolutionSlotValue::Runtime { addressable, .. } => {
                    ResolutionSlotValue::runtime(adjusted, addressable)
                }
            },
            TypeTransferValueTransform::ToRuntime { addressable } => {
                ResolutionSlotValue::runtime(adjusted, addressable)
            }
            TypeTransferValueTransform::TypeObjectOnly => {
                ResolutionSlotValue::type_object(adjusted)
            }
            TypeTransferValueTransform::AddressableRuntimeOnly => {
                ResolutionSlotValue::runtime(adjusted, true)
            }
            TypeTransferValueTransform::AddressableOperandOnly
            | TypeTransferValueTransform::RuntimeOnly => {
                ResolutionSlotValue::runtime(adjusted, false)
            }
            TypeTransferValueTransform::ToNoValue => {
                unreachable!("no-value transfers return before type adjustment")
            }
        })
    }
}

/// The value alternatives at one point where binding hands work to type flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedFrontierState {
    slot: SemanticId,
    possible_values: Box<[ResolutionSlotValue]>,
    completion: ResolutionCompletion,
}

impl TypedFrontierState {
    pub fn new(
        slot: SemanticId,
        possible_values: impl Into<Box<[ResolutionSlotValue]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        let mut possible_values = possible_values.into().into_vec();
        possible_values.sort_unstable();
        possible_values.dedup();
        Self {
            slot,
            possible_values: possible_values.into_boxed_slice(),
            completion,
        }
    }

    pub const fn slot(&self) -> SemanticId {
        self.slot
    }

    pub fn possible_values(&self) -> &[ResolutionSlotValue] {
        &self.possible_values
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn into_parts(
        self,
    ) -> (SemanticId, Box<[ResolutionSlotValue]>, ResolutionCompletion) {
        (self.slot, self.possible_values, self.completion)
    }

    pub(super) fn with_completion(mut self, completion: ResolutionCompletion) -> Self {
        self.completion = completion;
        self
    }

    /// Rebuild an already-canonical frontier without sorting its values again.
    pub(super) fn from_canonical_parts(
        slot: SemanticId,
        possible_values: Box<[ResolutionSlotValue]>,
        completion: ResolutionCompletion,
        mut cancelled: impl FnMut() -> bool,
    ) -> Option<Self> {
        for pair in possible_values.windows(2) {
            if cancelled() {
                return None;
            }
            assert!(
                pair[0] < pair[1],
                "canonical frontier values must be strictly sorted and deduplicated"
            );
        }
        Some(Self {
            slot,
            possible_values,
            completion,
        })
    }
}

/// Stable evidence for one selected or rejected semantic candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionWitness {
    reference: SemanticId,
    target: SemanticId,
    steps: Box<[WitnessStep]>,
    completion: ResolutionCompletion,
}

impl ResolutionWitness {
    pub fn new(
        reference: SemanticId,
        target: SemanticId,
        steps: impl Into<Box<[WitnessStep]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            reference,
            target,
            steps: steps.into(),
            completion,
        }
    }

    pub const fn reference(&self) -> SemanticId {
        self.reference
    }

    pub const fn target(&self) -> SemanticId {
        self.target
    }

    pub fn steps(&self) -> &[WitnessStep] {
        &self.steps
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        SemanticId,
        SemanticId,
        Box<[WitnessStep]>,
        ResolutionCompletion,
    ) {
        (self.reference, self.target, self.steps, self.completion)
    }
}

/// One alternative in a fully ordered lexical lookup. This records graph
/// structure, not language access equivalence or a complete type identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum LookupAlternative {
    Target(SemanticId),
    Unresolved {
        endpoint: EndpointSignature,
        completion: ResolutionCompletion,
    },
}

impl LookupAlternative {
    fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        Some(match self {
            Self::Target(target) => Self::Target(*target),
            Self::Unresolved {
                endpoint,
                completion,
            } => Self::Unresolved {
                endpoint: endpoint.clone_with_poll(cancelled)?,
                completion: clone_completion_with_poll(completion, cancelled)?,
            },
        })
    }
}

/// One point-resolution result. Ambiguity is a complete multi-target answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolutionAnswer {
    targets: Box<[SemanticId]>,
    witnesses: Box<[ResolutionWitness]>,
    completion: ResolutionCompletion,
    // Query-owned ordered alternatives, strongest first. Transformations that
    // rebuild an answer must re-prove this structure; `new` deliberately omits it.
    lookup_decision: Option<Box<[LookupAlternative]>>,
}

impl ResolutionAnswer {
    /// Structural payload bytes, excluding shared completion reasons and
    /// allocator overhead. Shared answers are charged once per caller entry.
    pub(super) fn structural_bytes(&self) -> usize {
        let Self {
            targets,
            witnesses,
            completion: _,
            lookup_decision,
        } = self;
        let mut bytes =
            size_of_val(self) + size_of_val(targets.as_ref()) + size_of_val(witnesses.as_ref());
        for witness in witnesses {
            bytes += size_of_val(witness.steps());
        }
        if let Some(decision) = lookup_decision {
            bytes += size_of_val(decision.as_ref());
            for alternative in decision {
                if let LookupAlternative::Unresolved { endpoint, .. } = alternative {
                    bytes += size_of_val(endpoint.symbols.fixed());
                    bytes += size_of_val(endpoint.scopes.fixed());
                    for symbol in endpoint.symbols.fixed() {
                        if let Some(scopes) = symbol.scopes() {
                            bytes += size_of_val(scopes.fixed());
                        }
                    }
                }
            }
        }
        bytes
    }

    pub fn new(
        targets: impl Into<Box<[SemanticId]>>,
        witnesses: impl Into<Box<[ResolutionWitness]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            targets: targets.into(),
            witnesses: witnesses.into(),
            completion,
            lookup_decision: None,
        }
    }

    pub(super) fn with_lookup_decision(mut self, decision: Box<[LookupAlternative]>) -> Self {
        self.lookup_decision = Some(decision);
        self
    }

    pub(super) fn lookup_decision(&self) -> Option<&[LookupAlternative]> {
        self.lookup_decision.as_deref()
    }

    pub(super) fn lookup_decisions_equal_with_poll(
        &self,
        other: &Self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Option<bool> {
        let (left, right) = match (&self.lookup_decision, &other.lookup_decision) {
            (None, None) => return Some(true),
            (Some(left), Some(right)) if left.len() == right.len() => (left, right),
            _ => return Some(false),
        };
        for (left, right) in left.iter().zip(right.iter()) {
            if cancelled() {
                return None;
            }
            let equal = match (left, right) {
                (LookupAlternative::Target(left), LookupAlternative::Target(right)) => {
                    left == right
                }
                (
                    LookupAlternative::Unresolved {
                        endpoint: left,
                        completion: left_completion,
                    },
                    LookupAlternative::Unresolved {
                        endpoint: right,
                        completion: right_completion,
                    },
                ) => {
                    left.equals_with_poll(right, cancelled)?
                        && completion_values_equal_with_poll(
                            left_completion,
                            right_completion,
                            cancelled,
                        )?
                }
                _ => false,
            };
            if !equal {
                return Some(false);
            }
        }
        Some(true)
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let targets = clone_copy_slice_with_poll(&self.targets, cancelled)?;
        let mut witnesses = Vec::with_capacity(self.witnesses.len());
        for witness in &self.witnesses {
            if cancelled() {
                return None;
            }
            witnesses.push(ResolutionWitness::new(
                witness.reference(),
                witness.target(),
                clone_copy_slice_with_poll(witness.steps(), cancelled)?,
                clone_completion_with_poll(witness.completion(), cancelled)?,
            ));
        }
        let lookup_decision = match &self.lookup_decision {
            Some(decision) => {
                let mut cloned = Vec::with_capacity(decision.len());
                for alternative in decision {
                    cloned.push(alternative.clone_with_poll(cancelled)?);
                }
                Some(cloned.into_boxed_slice())
            }
            None => None,
        };
        Some(Self {
            targets: targets.into_boxed_slice(),
            witnesses: witnesses.into_boxed_slice(),
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
            lookup_decision,
        })
    }

    pub fn targets(&self) -> &[SemanticId] {
        &self.targets
    }

    pub fn witnesses(&self) -> &[ResolutionWitness] {
        &self.witnesses
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        Box<[SemanticId]>,
        Box<[ResolutionWitness]>,
        ResolutionCompletion,
    ) {
        (self.targets, self.witnesses, self.completion)
    }
}

/// Exact, hashable alpha-normal form of a path's endpoint stack behavior.
/// Variable ordinals preserve aliasing across both endpoints. Symbol-tail and
/// scope-tail variables occupy separate namespaces because they are unified
/// by separate substitutions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StackEffectAlphaKey {
    start: AlphaEndpointKey,
    end: AlphaEndpointKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaEndpointKey {
    node: BindingNodeId,
    symbols: AlphaSymbolStackKey,
    scopes: AlphaStackKey<BindingNodeId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaSymbolStackKey {
    fixed: Box<[AlphaScopedSymbolKey]>,
    tail: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaScopedSymbolKey {
    symbol: SemanticId,
    scopes: Option<AlphaStackKey<BindingNodeId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AlphaStackKey<T> {
    fixed: Box<[T]>,
    tail: Option<u32>,
}

impl StackEffectAlphaKey {
    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        Some(Self {
            start: clone_alpha_endpoint_with_poll(&self.start, cancelled)?,
            end: clone_alpha_endpoint_with_poll(&self.end, cancelled)?,
        })
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        Some(
            alpha_endpoints_equal_with_poll(&self.start, &other.start, cancelled)?
                && alpha_endpoints_equal_with_poll(&self.end, &other.end, cancelled)?,
        )
    }

    pub(crate) fn canonical_digest_with_poll<P>(&self, cancelled: &mut P) -> Option<[u8; 32]>
    where
        P: FnMut() -> bool,
    {
        let mut hasher = CanonicalHasher::new(b"bifrost-resolution-stack-effect-alpha-key:v1");
        hash_alpha_endpoint_with_poll(&mut hasher, b"start", &self.start, cancelled)?;
        hash_alpha_endpoint_with_poll(&mut hasher, b"end", &self.end, cancelled)?;
        Some(hasher.finish())
    }
}

fn clone_alpha_endpoint_with_poll<P>(
    endpoint: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<AlphaEndpointKey>
where
    P: FnMut() -> bool,
{
    let mut symbols = Vec::with_capacity(endpoint.symbols.fixed.len());
    for symbol in endpoint.symbols.fixed.iter() {
        if cancelled() {
            return None;
        }
        symbols.push(AlphaScopedSymbolKey {
            symbol: symbol.symbol,
            scopes: match symbol.scopes.as_ref() {
                Some(scopes) => Some(clone_alpha_scope_stack_with_poll(scopes, cancelled)?),
                None => None,
            },
        });
    }
    Some(AlphaEndpointKey {
        node: endpoint.node,
        symbols: AlphaSymbolStackKey {
            fixed: symbols.into_boxed_slice(),
            tail: endpoint.symbols.tail,
        },
        scopes: clone_alpha_scope_stack_with_poll(&endpoint.scopes, cancelled)?,
    })
}

fn clone_alpha_scope_stack_with_poll<P>(
    stack: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<AlphaStackKey<BindingNodeId>>
where
    P: FnMut() -> bool,
{
    Some(AlphaStackKey {
        fixed: clone_copy_slice_with_poll(&stack.fixed, cancelled)?.into_boxed_slice(),
        tail: stack.tail,
    })
}

fn alpha_endpoints_equal_with_poll<P>(
    left: &AlphaEndpointKey,
    right: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.node != right.node
        || left.symbols.tail != right.symbols.tail
        || left.symbols.fixed.len() != right.symbols.fixed.len()
    {
        return Some(false);
    }
    for (left, right) in left.symbols.fixed.iter().zip(right.symbols.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left.symbol != right.symbol {
            return Some(false);
        }
        match (left.scopes.as_ref(), right.scopes.as_ref()) {
            (None, None) => {}
            (Some(left), Some(right)) => {
                if !alpha_scope_stacks_equal_with_poll(left, right, cancelled)? {
                    return Some(false);
                }
            }
            (None, Some(_)) | (Some(_), None) => return Some(false),
        }
    }
    alpha_scope_stacks_equal_with_poll(&left.scopes, &right.scopes, cancelled)
}

fn alpha_scope_stacks_equal_with_poll<P>(
    left: &AlphaStackKey<BindingNodeId>,
    right: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    if left.tail != right.tail || left.fixed.len() != right.fixed.len() {
        return Some(false);
    }
    for (left, right) in left.fixed.iter().zip(right.fixed.iter()) {
        if cancelled() {
            return None;
        }
        if left != right {
            return Some(false);
        }
    }
    Some(true)
}

fn hash_alpha_endpoint_with_poll<P>(
    hasher: &mut CanonicalHasher,
    label: &[u8],
    endpoint: &AlphaEndpointKey,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    hasher.value(label);
    hasher.value(&endpoint.node.as_bytes());
    hasher.value(&(endpoint.symbols.fixed.len() as u64).to_le_bytes());
    hash_optional_ordinal(hasher, endpoint.symbols.tail);
    for symbol in endpoint.symbols.fixed.iter() {
        if cancelled() {
            return None;
        }
        hasher.value(&symbol.symbol.as_bytes());
        match symbol.scopes.as_ref() {
            Some(scopes) => {
                hasher.value(b"scoped");
                hash_alpha_scope_stack_with_poll(hasher, scopes, cancelled)?;
            }
            None => hasher.value(b"unscoped"),
        }
    }
    hash_alpha_scope_stack_with_poll(hasher, &endpoint.scopes, cancelled)
}

fn hash_alpha_scope_stack_with_poll<P>(
    hasher: &mut CanonicalHasher,
    stack: &AlphaStackKey<BindingNodeId>,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    hasher.value(&(stack.fixed.len() as u64).to_le_bytes());
    hash_optional_ordinal(hasher, stack.tail);
    for node in stack.fixed.iter() {
        if cancelled() {
            return None;
        }
        hasher.value(&node.as_bytes());
    }
    Some(())
}

fn hash_optional_ordinal(hasher: &mut CanonicalHasher, ordinal: Option<u32>) {
    match ordinal {
        Some(ordinal) => {
            hasher.value(b"some");
            hasher.value(&ordinal.to_le_bytes());
        }
        None => hasher.value(b"none"),
    }
}

#[derive(Default)]
struct AlphaNormalizer {
    symbol_variables: HashMap<StackVariableId, u32>,
    scope_variables: HashMap<StackVariableId, u32>,
}

impl AlphaNormalizer {
    fn symbol_variable(&mut self, variable: StackVariableId) -> u32 {
        let next = self.symbol_variables.len() as u32;
        *self.symbol_variables.entry(variable).or_insert(next)
    }

    fn scope_variable(&mut self, variable: StackVariableId) -> u32 {
        let next = self.scope_variables.len() as u32;
        *self.scope_variables.entry(variable).or_insert(next)
    }

    fn scope_stack_with_poll<P>(
        &mut self,
        pattern: &ScopeStackPattern,
        cancelled: &mut P,
    ) -> Option<AlphaStackKey<BindingNodeId>>
    where
        P: FnMut() -> bool,
    {
        Some(AlphaStackKey {
            fixed: clone_copy_slice_with_poll(&pattern.fixed, cancelled)?.into_boxed_slice(),
            tail: pattern.tail.map(|variable| self.scope_variable(variable)),
        })
    }

    fn symbol_stack_with_poll<P>(
        &mut self,
        pattern: &SymbolStackPattern,
        cancelled: &mut P,
    ) -> Option<AlphaSymbolStackKey>
    where
        P: FnMut() -> bool,
    {
        let mut fixed = Vec::with_capacity(pattern.fixed.len());
        for cell in pattern.fixed.iter() {
            if cancelled() {
                return None;
            }
            fixed.push(AlphaScopedSymbolKey {
                symbol: cell.symbol,
                scopes: match cell.scopes.as_ref() {
                    Some(scopes) => Some(self.scope_stack_with_poll(scopes, cancelled)?),
                    None => None,
                },
            });
        }
        Some(AlphaSymbolStackKey {
            fixed: fixed.into_boxed_slice(),
            tail: pattern.tail.map(|variable| self.symbol_variable(variable)),
        })
    }

    fn endpoint_with_poll<P>(
        &mut self,
        endpoint: &EndpointSignature,
        cancelled: &mut P,
    ) -> Option<AlphaEndpointKey>
    where
        P: FnMut() -> bool,
    {
        Some(AlphaEndpointKey {
            node: endpoint.node,
            symbols: self.symbol_stack_with_poll(&endpoint.symbols, cancelled)?,
            scopes: self.scope_stack_with_poll(&endpoint.scopes, cancelled)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PartialPath {
    start: EndpointSignature,
    end: EndpointSignature,
    precedence: Box<[PrecedenceStep]>,
    witness: Box<[WitnessStep]>,
    completion: ResolutionCompletion,
    /// A number past every operation-local variable the two endpoints hold,
    /// which is where a renaming composing against this path starts.
    ///
    /// It is an upper bound and not the exact ceiling. `assembled` and
    /// `clone_with_poll` do compute it from the endpoints, but
    /// `alpha_renamed_with_poll` takes the number its renaming stopped at,
    /// which can be past anything either endpoint kept, and `concatenate`
    /// takes the higher of its two inputs, which the result's endpoints need
    /// not reach. Its one reader is `AlphaRenaming::after`, which wants
    /// freshness, and an upper bound is exactly as good for that.
    ///
    /// Because it is a bound rather than a value, it is not observable, which
    /// is why `PartialEq` and `Hash` are written out to exclude it: two paths
    /// that differ only in this field are the same path.
    ///
    /// It is carried rather than computed because a composition asks for it
    /// once per candidate and a saturation chain composes against the same
    /// growing path many times; walking that path each time made one chain of
    /// n compositions O(n^2).
    variable_ceiling: u64,
}

impl PartialEq for PartialPath {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            start,
            end,
            precedence,
            witness,
            completion,
            variable_ceiling: _,
        } = self;
        *start == other.start
            && *end == other.end
            && *precedence == other.precedence
            && *witness == other.witness
            && *completion == other.completion
    }
}

impl Eq for PartialPath {}

impl std::hash::Hash for PartialPath {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let Self {
            start,
            end,
            precedence,
            witness,
            completion,
            variable_ceiling: _,
        } = self;
        start.hash(state);
        end.hash(state);
        precedence.hash(state);
        witness.hash(state);
        completion.hash(state);
    }
}

fn clone_copy_slice_with_poll<T: Copy, P>(values: &[T], cancelled: &mut P) -> Option<Vec<T>>
where
    P: FnMut() -> bool,
{
    if cancelled() {
        return None;
    }
    let mut cloned = Vec::with_capacity(values.len());
    for &value in values {
        if cancelled() {
            return None;
        }
        cloned.push(value);
    }
    Some(cloned)
}

pub(crate) fn clone_completion_with_poll<P>(
    completion: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<ResolutionCompletion>
where
    P: FnMut() -> bool,
{
    match completion {
        ResolutionCompletion::Complete => Some(ResolutionCompletion::Complete),
        ResolutionCompletion::Incomplete(reasons) => Some(ResolutionCompletion::Incomplete(
            reasons.clone_with_poll(cancelled)?,
        )),
    }
}

pub(crate) fn combine_completion_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<ResolutionCompletion>
where
    P: FnMut() -> bool,
{
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => {
            Some(ResolutionCompletion::Complete)
        }
        (ResolutionCompletion::Incomplete(_), ResolutionCompletion::Complete) => {
            clone_completion_with_poll(left, cancelled)
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(_)) => {
            clone_completion_with_poll(right, cancelled)
        }
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => Some(
            ResolutionCompletion::Incomplete(left.union_with_poll(right, cancelled)?),
        ),
    }
}

fn assert_semantic_completion_with_poll<P>(
    completion: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<()>
where
    P: FnMut() -> bool,
{
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        if reasons.is_shared() {
            assert!(
                !reasons.contains_with_poll(&ResolutionIncompleteReason::Cancelled, cancelled)?,
                "partial-path completion cannot contain operation-local cancellation"
            );
        } else {
            for &reason in reasons.iter() {
                if cancelled() {
                    return None;
                }
                assert_ne!(
                    reason,
                    ResolutionIncompleteReason::Cancelled,
                    "partial-path completion cannot contain operation-local cancellation"
                );
            }
        }
    }
    Some(())
}

impl PartialPath {
    pub fn new(
        start: EndpointSignature,
        end: EndpointSignature,
        precedence: impl Into<Box<[PrecedenceStep]>>,
        witness: impl Into<Box<[WitnessStep]>>,
        completion: ResolutionCompletion,
    ) -> Self {
        let Some(path) = Self::new_with_poll(
            start,
            end,
            precedence.into(),
            witness.into(),
            completion,
            &mut never_cancelled,
        ) else {
            unreachable!("the never-cancelled partial-path poll returned cancellation")
        };
        path
    }

    pub(crate) fn new_with_poll<P>(
        start: EndpointSignature,
        end: EndpointSignature,
        precedence: Box<[PrecedenceStep]>,
        witness: Box<[WitnessStep]>,
        completion: ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        assert_semantic_completion_with_poll(&completion, cancelled)?;
        if cancelled() {
            return None;
        }
        Some(Self::assembled(start, end, precedence, witness, completion))
    }

    /// One path from parts, with its variable ceiling taken from the two
    /// endpoints it is built from. Every construction of a `PartialPath` goes
    /// through here, so the ceiling cannot be left stale.
    fn assembled(
        start: EndpointSignature,
        end: EndpointSignature,
        precedence: Box<[PrecedenceStep]>,
        witness: Box<[WitnessStep]>,
        completion: ResolutionCompletion,
    ) -> Self {
        let variable_ceiling = start
            .operation_local_variable_ceiling()
            .max(end.operation_local_variable_ceiling());
        Self {
            start,
            end,
            precedence,
            witness,
            completion,
            variable_ceiling,
        }
    }

    pub fn start(&self) -> &EndpointSignature {
        &self.start
    }

    pub fn end(&self) -> &EndpointSignature {
        &self.end
    }

    pub fn precedence(&self) -> &[PrecedenceStep] {
        &self.precedence
    }

    pub fn witness(&self) -> &[WitnessStep] {
        &self.witness
    }

    pub fn completion(&self) -> &ResolutionCompletion {
        &self.completion
    }

    /// The path without the reasons the selected stage proved closed
    /// (`temp.selected_resolution_stage_closed_reasons`). A persisted path
    /// carries every gap reason on its way, and a closed reason must leave the
    /// path the way it leaves a candidate completion.
    pub(crate) fn without_closed_reasons(mut self, closed: &[ResolutionIncompleteReason]) -> Self {
        if let ResolutionCompletion::Incomplete(reasons) = &self.completion {
            self.completion = reasons
                .without_reasons_with_poll(closed.iter().copied(), &mut || false)
                .expect("a never-cancelled poll finishes")
                .map_or(
                    ResolutionCompletion::Complete,
                    ResolutionCompletion::Incomplete,
                );
        }
        self
    }

    pub(crate) fn with_additional_completion(mut self, completion: &ResolutionCompletion) -> Self {
        assert!(
            !completion.contains_reason(ResolutionIncompleteReason::Cancelled),
            "partial-path completion cannot contain operation-local cancellation"
        );
        self.completion = self.completion.combine(completion);
        self
    }

    pub(crate) fn with_additional_completion_with_poll<P>(
        mut self,
        completion: &ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        assert_semantic_completion_with_poll(completion, cancelled)?;
        self.completion = combine_completion_with_poll(&self.completion, completion, cancelled)?;
        Some(self)
    }

    pub(crate) fn with_seed_completion_with_poll<P>(
        mut self,
        seed_completion: &ResolutionCompletion,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let completion =
            combine_completion_with_poll(seed_completion, &self.completion, cancelled)?;
        assert_semantic_completion_with_poll(&completion, cancelled)?;
        self.completion = completion;
        Some(self)
    }

    pub(crate) fn equals_with_poll<P>(&self, other: &Self, cancelled: &mut P) -> Option<bool>
    where
        P: FnMut() -> bool,
    {
        if !self.start.equals_with_poll(&other.start, cancelled)?
            || !self.end.equals_with_poll(&other.end, cancelled)?
            || self.precedence.len() != other.precedence.len()
            || self.witness.len() != other.witness.len()
        {
            return Some(false);
        }
        for (left, right) in self.precedence.iter().zip(other.precedence.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        for (left, right) in self.witness.iter().zip(other.witness.iter()) {
            if cancelled() {
                return None;
            }
            if left != right {
                return Some(false);
            }
        }
        completion_values_equal_with_poll(&self.completion, &other.completion, cancelled)
    }

    pub(crate) fn stack_effect_alpha_key_with_poll<P>(
        &self,
        cancelled: &mut P,
    ) -> Option<StackEffectAlphaKey>
    where
        P: FnMut() -> bool,
    {
        let mut normalizer = AlphaNormalizer::default();
        Some(StackEffectAlphaKey {
            start: normalizer.endpoint_with_poll(&self.start, cancelled)?,
            end: normalizer.endpoint_with_poll(&self.end, cancelled)?,
        })
    }

    /// Collapse repeated semantic evidence to the same finite representative
    /// used by cycle saturation. This makes the retained replay witness
    /// independent of which equivalent route reaches the quotient first.
    pub(crate) fn canonicalized_observations(self) -> Self {
        let Some(path) = self.canonicalized_observations_with_poll(&mut never_cancelled) else {
            unreachable!("the never-cancelled observation poll returned cancellation")
        };
        path
    }

    pub(crate) fn canonicalized_observations_with_poll<P>(
        mut self,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        self.precedence = first_occurrences_with_poll(&self.precedence, cancelled)?;
        self.witness = first_occurrences_with_poll(&self.witness, cancelled)?;
        Some(self)
    }

    pub(crate) fn clone_with_poll<P>(&self, cancelled: &mut P) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        // A clone keeps the ceiling it was given rather than recomputing it:
        // the endpoints are the same endpoints.
        Some(Self {
            start: self.start.clone_with_poll(cancelled)?,
            end: self.end.clone_with_poll(cancelled)?,
            precedence: clone_copy_slice_with_poll(&self.precedence, cancelled)?.into_boxed_slice(),
            witness: clone_copy_slice_with_poll(&self.witness, cancelled)?.into_boxed_slice(),
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
            variable_ceiling: self.variable_ceiling,
        })
    }

    /// This path with its variables renamed from `base`, which is what one
    /// composition against a path whose highest operation-local variable is
    /// `base - 1` would produce.
    #[cfg(test)]
    pub(super) fn alpha_renamed_from_for_test(&self, base: u64) -> Self {
        let mut renaming = AlphaRenaming {
            next: base,
            assigned: Vec::new(),
        };
        self.alpha_renamed_with_poll(&mut renaming, &mut never_cancelled)
            .expect("the never-cancelled renaming poll returned cancellation")
    }

    /// Whether this path holds any stack variable at all.
    ///
    /// A closed path has nothing to rename, which is the common case and lets
    /// a composition skip both the walk that finds the other side's ceiling
    /// and the rename itself.
    fn holds_a_variable(&self) -> bool {
        self.start.holds_a_variable() || self.end.holds_a_variable()
    }

    fn alpha_renamed_with_poll<P>(
        &self,
        renaming: &mut AlphaRenaming,
        cancelled: &mut P,
    ) -> Option<Self>
    where
        P: FnMut() -> bool,
    {
        let start = self.start.alpha_renamed_with_poll(renaming, cancelled)?;
        let end = self.end.alpha_renamed_with_poll(renaming, cancelled)?;
        Some(Self {
            start,
            end,
            precedence: clone_copy_slice_with_poll(&self.precedence, cancelled)?.into_boxed_slice(),
            witness: clone_copy_slice_with_poll(&self.witness, cancelled)?.into_boxed_slice(),
            completion: clone_completion_with_poll(&self.completion, cancelled)?,
            // Every variable the rename touched came from this one renaming,
            // so its next number is the ceiling of what it produced.
            variable_ceiling: renaming.next,
        })
    }

    pub fn concatenate(&self, next: &Self) -> Result<Self, PathCompositionError> {
        let Some(result) = self.concatenate_with_poll(next, &mut never_cancelled) else {
            unreachable!("the never-cancelled composition poll returned cancellation")
        };
        result
    }

    pub(crate) fn concatenate_with_poll<P>(
        &self,
        next: &Self,
        cancelled: &mut P,
    ) -> Option<Result<Self, PathCompositionError>>
    where
        P: FnMut() -> bool,
    {
        if cancelled() {
            return None;
        }
        let next = if next.holds_a_variable() {
            let mut renaming = AlphaRenaming::after(self);
            next.alpha_renamed_with_poll(&mut renaming, cancelled)?
        } else {
            next.clone_with_poll(cancelled)?
        };
        let (symbols, scopes) =
            match unify_middle_endpoints_with_poll(&self.end, &next.start, cancelled)? {
                Ok(substitutions) => substitutions,
                Err(error) => return Some(Err(error)),
            };

        let start = match self
            .start
            .substituted_with_poll(&symbols, &scopes, cancelled)?
        {
            Ok(start) => start,
            Err(error) => return Some(Err(PathCompositionError::Substitution(error))),
        };
        let end = match next
            .end
            .substituted_with_poll(&symbols, &scopes, cancelled)?
        {
            Ok(end) => end,
            Err(error) => return Some(Err(PathCompositionError::Substitution(error))),
        };

        let mut precedence = Vec::with_capacity(self.precedence.len() + next.precedence.len());
        precedence.extend(clone_copy_slice_with_poll(&self.precedence, cancelled)?);
        precedence.extend(clone_copy_slice_with_poll(&next.precedence, cancelled)?);
        let mut witness = Vec::with_capacity(self.witness.len() + next.witness.len());
        witness.extend(clone_copy_slice_with_poll(&self.witness, cancelled)?);
        witness.extend(clone_copy_slice_with_poll(&next.witness, cancelled)?);
        let completion =
            combine_completion_with_poll(&self.completion, &next.completion, cancelled)?;

        Some(Ok(Self {
            start,
            end,
            precedence: precedence.into_boxed_slice(),
            witness: witness.into_boxed_slice(),
            completion,
            // Substitution replaces variables with stacks the two sides
            // already held and mints no operation-local number of its own, so
            // the higher of the two inputs' ceilings bounds the result. Taking
            // it rather than walking the result is what keeps a saturation
            // chain linear.
            variable_ceiling: self.variable_ceiling.max(next.variable_ceiling),
        }))
    }
}

type MiddleEndpointUnification = Result<
    (
        StackSubstitution<PartialScopedSymbol>,
        StackSubstitution<BindingNodeId>,
    ),
    PathCompositionError,
>;

fn unify_middle_endpoints_with_poll<P>(
    left: &EndpointSignature,
    right: &EndpointSignature,
    cancelled: &mut P,
) -> Option<MiddleEndpointUnification>
where
    P: FnMut() -> bool,
{
    if left.node != right.node {
        return Some(Err(PathCompositionError::EndpointMismatch {
            left: left.node,
            right: right.node,
        }));
    }
    let mut symbols = StackSubstitution::default();
    let mut scopes = StackSubstitution::default();
    match unify_symbol_stacks_with_poll(
        &mut symbols,
        &mut scopes,
        &left.symbols,
        &right.symbols,
        cancelled,
    )? {
        Ok(()) => {}
        Err(error) => return Some(Err(PathCompositionError::SymbolStack(error))),
    }
    let mut clone_node = |node: &BindingNodeId, cancelled: &mut P| (!cancelled()).then_some(*node);
    match scopes.unify_patterns_with_poll(
        &left.scopes,
        &right.scopes,
        &mut clone_node,
        cancelled,
    )? {
        Ok(()) => Some(Ok((symbols, scopes))),
        Err(error) => Some(Err(PathCompositionError::ScopeStack(error))),
    }
}

pub(crate) fn completion_values_equal_with_poll<P>(
    left: &ResolutionCompletion,
    right: &ResolutionCompletion,
    cancelled: &mut P,
) -> Option<bool>
where
    P: FnMut() -> bool,
{
    match (left, right) {
        (ResolutionCompletion::Complete, ResolutionCompletion::Complete) => Some(true),
        (ResolutionCompletion::Incomplete(left), ResolutionCompletion::Incomplete(right)) => {
            left.equals_with_poll(right, cancelled)
        }
        (ResolutionCompletion::Complete, ResolutionCompletion::Incomplete(_))
        | (ResolutionCompletion::Incomplete(_), ResolutionCompletion::Complete) => Some(false),
    }
}

fn first_occurrences_with_poll<T: Copy + Eq + std::hash::Hash, P>(
    values: &[T],
    cancelled: &mut P,
) -> Option<Box<[T]>>
where
    P: FnMut() -> bool,
{
    let mut seen = HashSet::default();
    let mut first = Vec::with_capacity(values.len());
    for &value in values {
        if cancelled() {
            return None;
        }
        if seen.insert(value) {
            first.push(value);
        }
    }
    Some(first.into_boxed_slice())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCompositionError {
    EndpointMismatch {
        left: BindingNodeId,
        right: BindingNodeId,
    },
    SymbolStack(StackUnificationError),
    ScopeStack(StackUnificationError),
    Substitution(StackUnificationError),
}

impl fmt::Display for PathCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointMismatch { left, right } => {
                write!(formatter, "path endpoints differ: {left} != {right}")
            }
            Self::SymbolStack(error) => write!(formatter, "symbol stack: {error}"),
            Self::ScopeStack(error) => write!(formatter, "scope stack: {error}"),
            Self::Substitution(error) => write!(formatter, "path substitution: {error}"),
        }
    }
}

impl std::error::Error for PathCompositionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn semantic(value: &str) -> SemanticId {
        SemanticId::for_test(value.as_bytes())
    }

    fn variable(value: &str) -> StackVariableId {
        StackVariableId::for_test(value.as_bytes())
    }

    fn node(value: &str) -> BindingNodeId {
        BindingNodeId::for_test(value.as_bytes())
    }

    fn unify_patterns(
        left: &StackPattern<SemanticId>,
        right: &StackPattern<SemanticId>,
    ) -> Result<StackSubstitution<SemanticId>, StackUnificationError> {
        let mut substitution = StackSubstitution::default();
        let mut clone_cell = |cell: &SemanticId, _: &mut _| Some(*cell);
        substitution
            .unify_patterns_with_poll(left, right, &mut clone_cell, &mut || false)
            .expect("live test unification completes")?;
        Ok(substitution)
    }

    fn apply_substitution(
        substitution: &StackSubstitution<SemanticId>,
        pattern: &StackPattern<SemanticId>,
    ) -> Result<StackPattern<SemanticId>, StackUnificationError> {
        let mut clone_cell = |cell: &SemanticId, _: &mut _| Some(*cell);
        substitution
            .apply_with_poll(pattern, &mut clone_cell, &mut || false)
            .expect("live test substitution completes")
    }

    /// A path whose variables are renamed away from `path`'s own, through the
    /// one door a rename has: composing against a path.
    fn alpha_renamed(path: &PartialPath) -> PartialPath {
        let mut renaming = AlphaRenaming::after(path);
        path.alpha_renamed_with_poll(&mut renaming, &mut || false)
            .expect("live test alpha renaming completes")
    }

    fn stack_effect_alpha_key(path: &PartialPath) -> StackEffectAlphaKey {
        path.stack_effect_alpha_key_with_poll(&mut || false)
            .expect("live test alpha-key construction completes")
    }

    fn endpoint(
        node: BindingNodeId,
        symbols: Vec<SemanticId>,
        scopes: Vec<BindingNodeId>,
    ) -> EndpointSignature {
        EndpointSignature::new(
            node,
            StackPattern::closed(symbols),
            StackPattern::closed(scopes),
        )
    }

    #[test]
    fn canonical_source_accumulator_preserves_shared_bases_and_normalizes_raw_evidence() {
        let first = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"first"));
        let second =
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(b"second"));
        let raw = ResolutionCompletion::Incomplete(vec![second, first, second].into());
        let mut raw_accumulator = ResolutionCompletionAccumulator::default();
        raw_accumulator.include(&ResolutionCompletion::Incomplete(Vec::new().into()));
        assert_eq!(raw_accumulator.finish(), ResolutionCompletion::Complete);
        let mut raw_accumulator = ResolutionCompletionAccumulator::default();
        raw_accumulator.include(&raw);
        assert_eq!(
            raw_accumulator.finish(),
            ResolutionCompletion::incomplete([first, second])
        );

        for count in [8_usize, 4_096] {
            let reasons = (0..count)
                .map(|index| {
                    ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                        index.to_le_bytes(),
                    ))
                })
                .collect::<Vec<_>>();
            let shared = ResolutionCompletion::Incomplete(
                CompletionReasons::from(reasons.clone())
                    .to_shared_with_poll(&mut || false)
                    .unwrap(),
            );
            for operands in [[&shared, &raw], [&raw, &shared]] {
                let mut accumulator = ResolutionCompletionAccumulator::default();
                for operand in operands {
                    accumulator.include(operand);
                }
                for _ in 0..64 {
                    accumulator.include(&shared);
                }
                let completion = accumulator.finish();
                assert_eq!(
                    completion,
                    ResolutionCompletion::incomplete(
                        reasons.iter().copied().chain([first, second])
                    )
                );
                let ResolutionCompletion::Incomplete(retained) = completion else {
                    panic!("source evidence cannot become complete")
                };
                assert!(retained.is_shared());
                assert_eq!(retained.clone_work_len(), 3);
            }
        }
    }

    #[test]
    fn canonical_source_accumulator_retains_growing_additions_across_shared_operands() {
        let common = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
            b"source-accumulation-common",
        ));
        let shared = ResolutionCompletion::Incomplete(
            CompletionReasons::from(vec![common])
                .to_shared_with_poll(&mut never_cancelled)
                .unwrap(),
        );
        let additions = (0..1_024_usize)
            .map(|index| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    index.to_le_bytes(),
                ))
            })
            .collect::<Vec<_>>();
        let mut accumulator = ResolutionCompletionAccumulator::default();
        accumulator.include(&shared);
        for &reason in &additions {
            accumulator.include(&ResolutionCompletion::incomplete([reason]));
            accumulator.include(&shared);
        }
        let completion = accumulator.finish();
        assert_eq!(
            completion,
            ResolutionCompletion::incomplete(additions.into_iter().chain([common]))
        );
        assert!(
            matches!(completion, ResolutionCompletion::Incomplete(reasons) if reasons.is_shared())
        );
    }

    #[test]
    fn fragment_local_keys_have_globally_distinct_mounted_identities() {
        // One catalog position at two mounts is two identities, because a
        // local id is the ordinal and the position. This used to be a
        // property of the digest the two were hashed into; it is arithmetic
        // now, and it is the property the whole layout rests on.
        let first = 1_u32;
        let second = 2_u32;
        assert_ne!(
            BindingNodeId::local(first, 17),
            BindingNodeId::local(second, 17)
        );
        assert_ne!(
            PartialPathId::local(first, 17),
            PartialPathId::local(second, 17)
        );
        assert_ne!(SemanticId::local(first, 17), SemanticId::local(second, 17));
        assert_ne!(
            StackVariableId::local(first, 17),
            StackVariableId::local(second, 17)
        );
        assert_eq!(
            PartialPathId::local(first, 17),
            PartialPathId::local(first, 17)
        );
    }

    #[test]
    #[should_panic(
        expected = "partial-path completion cannot contain operation-local cancellation"
    )]
    fn partial_paths_reject_operation_local_cancellation_evidence() {
        let endpoint = EndpointSignature::new(
            node("cancelled-path-endpoint"),
            StackPattern::closed(Vec::new()),
            StackPattern::closed(Vec::new()),
        );

        PartialPath::new(
            endpoint.clone(),
            endpoint,
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
        );
    }

    #[test]
    fn unification_binds_the_shorter_open_prefix() {
        let remainder = variable("remainder");
        let left = StackPattern::open(vec![semantic("a")], remainder);
        let right = StackPattern::closed(vec![semantic("a"), semantic("b")]);

        let substitution = unify_patterns(&left, &right).expect("patterns unify");

        assert_eq!(
            substitution.binding(remainder),
            Some(&StackPattern::closed(vec![semantic("b")]))
        );
        assert_eq!(apply_substitution(&substitution, &left).unwrap(), right);
    }

    #[test]
    fn unification_rejects_mismatched_and_recursive_patterns() {
        let remainder = variable("remainder");
        assert_eq!(
            unify_patterns(
                &StackPattern::closed(vec![semantic("a")]),
                &StackPattern::closed(vec![semantic("b")]),
            ),
            Err(StackUnificationError::FixedCellMismatch { index: 0 })
        );
        assert_eq!(
            unify_patterns(
                &StackPattern::open(Vec::<SemanticId>::new(), remainder),
                &StackPattern::open(vec![semantic("a")], remainder),
            ),
            Err(StackUnificationError::RecursiveVariableBinding(remainder))
        );
    }

    #[test]
    fn alpha_renaming_is_consistent_and_separates_uses() {
        let pattern = StackPattern::open(vec![semantic("a")], variable("tail"));
        // Two renamings, the second starting where a path holding the first's
        // variables would put it.
        let mut first = AlphaRenaming {
            next: 0,
            assigned: Vec::new(),
        };
        let mut second = AlphaRenaming {
            next: 1,
            assigned: Vec::new(),
        };

        let first_use = pattern.alpha_renamed(&mut first);

        assert_eq!(first_use, pattern.alpha_renamed(&mut first));
        assert_ne!(first_use.tail(), pattern.tail());
        assert_ne!(first_use, pattern.alpha_renamed(&mut second));
        assert_eq!(first_use.fixed(), pattern.fixed());
    }

    #[test]
    fn polled_path_clone_preserves_every_nested_structure() {
        let symbol_tail = variable("polled-clone-symbol-tail");
        let attached_tail = variable("polled-clone-attached-tail");
        let scope_tail = variable("polled-clone-scope-tail");
        let path = PartialPath::new(
            EndpointSignature::new_scoped(
                node("polled-clone-start"),
                StackPattern::open(
                    vec![PartialScopedSymbol::scoped(
                        semantic("polled-clone-symbol"),
                        StackPattern::open(
                            vec![node("polled-clone-captured-scope")],
                            attached_tail,
                        ),
                    )],
                    symbol_tail,
                ),
                StackPattern::open(vec![node("polled-clone-scope")], scope_tail),
            ),
            EndpointSignature::new(
                node("polled-clone-end"),
                StackPattern::open(vec![semantic("polled-clone-end-symbol")], symbol_tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            [PrecedenceStep {
                tier: PrecedenceTier::OwnMember,
                ordinal: 7,
                semantic: semantic("polled-clone-precedence"),
            }],
            [
                WitnessStep::Node(node("polled-clone-witness")),
                WitnessStep::Candidate {
                    semantic: semantic("polled-clone-target"),
                    outcome: CandidateOutcome::Selected,
                },
            ],
            ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-clone-gap-a")),
                ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-clone-gap-b")),
            ]),
        );
        let mut polls = 0_usize;

        let cloned = path
            .clone_with_poll(&mut || {
                polls += 1;
                false
            })
            .expect("an uncancelled structural clone completes");

        assert_eq!(cloned, path);
        assert!(polls > path.precedence().len() + path.witness().len());
    }

    #[test]
    fn concatenation_unifies_middle_stacks_and_preserves_evidence() {
        let tail = variable("tail");
        let scope_tail = variable("scope-tail");
        let seam = node("seam");
        let left = PartialPath::new(
            EndpointSignature::new(
                node("left-start"),
                StackPattern::open(Vec::new(), tail),
                StackPattern::open(Vec::new(), scope_tail),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::open(vec![semantic("name")], tail),
                StackPattern::open(vec![node("scope")], scope_tail),
            ),
            vec![PrecedenceStep {
                semantic: semantic("left"),
                tier: PrecedenceTier::LexicalBinding,
                ordinal: 0,
            }],
            vec![WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let right = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(vec![semantic("name")]),
                StackPattern::closed(vec![node("scope")]),
            ),
            EndpointSignature::new(
                node("right-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            vec![PrecedenceStep {
                semantic: semantic("right"),
                tier: PrecedenceTier::OwnMember,
                ordinal: 0,
            }],
            vec![WitnessStep::Candidate {
                semantic: semantic("target"),
                outcome: CandidateOutcome::Selected,
            }],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::OpenBoundary {
                semantic: semantic("dependency"),
                status: BoundaryStatus::ExternalDeclaredUnindexed,
            }]),
        );

        let joined = left.concatenate(&right).expect("middle signatures compose");
        let mut polls = 0_usize;
        let polled = left
            .concatenate_with_poll(&right, &mut || {
                polls += 1;
                false
            })
            .expect("an uncancelled composition is not cancelled")
            .expect("middle signatures compose through the polled seam");

        assert_eq!(polled, joined);
        assert!(polls > 0);
        assert_eq!(joined.start().symbols(), &StackPattern::closed(Vec::new()));
        assert_eq!(joined.start().scopes(), &StackPattern::closed(Vec::new()));
        assert_eq!(joined.end(), right.end());
        assert_eq!(joined.precedence().len(), 2);
        assert_eq!(joined.witness().len(), 2);
        assert!(matches!(
            joined.completion(),
            ResolutionCompletion::Incomplete(reasons) if reasons.len() == 1
        ));
    }

    #[test]
    fn polled_concatenation_preserves_public_noncanonical_completion_semantics() {
        let seam = node("noncanonical-completion-seam");
        let first = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "noncanonical-completion-first",
        ));
        let second = ResolutionIncompleteReason::UnsupportedSemantic(semantic(
            "noncanonical-completion-second",
        ));
        let left_completion =
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![second, first, second]));
        let right_completion =
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![first, second, first]));
        let left = PartialPath::new(
            EndpointSignature::new(
                node("noncanonical-completion-start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            left_completion.clone(),
        );
        let right = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                node("noncanonical-completion-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            right_completion.clone(),
        );
        let expected = left_completion.combine(&right_completion);

        let public = left
            .concatenate(&right)
            .expect("compatible paths concatenate");
        let polled = left
            .concatenate_with_poll(&right, &mut || false)
            .expect("uncancelled structural work completes")
            .expect("compatible paths concatenate");

        assert_eq!(public.completion(), &expected);
        assert_eq!(polled, public);
        assert_eq!(
            expected,
            ResolutionCompletion::Incomplete(CompletionReasons::from(vec![first, second]))
        );
    }

    #[test]
    fn concatenation_preserves_the_public_two_empty_incomplete_panic() {
        let seam = node("empty-incomplete-seam");
        let empty = ResolutionCompletion::Incomplete(CompletionReasons::from(Vec::new()));
        let left = PartialPath::new(
            endpoint(node("empty-incomplete-left"), Vec::new(), Vec::new()),
            endpoint(seam, Vec::new(), Vec::new()),
            Vec::new(),
            Vec::new(),
            empty.clone(),
        );
        let right = PartialPath::new(
            endpoint(seam, Vec::new(), Vec::new()),
            endpoint(node("empty-incomplete-right"), Vec::new(), Vec::new()),
            Vec::new(),
            Vec::new(),
            empty,
        );

        assert!(
            std::panic::catch_unwind(|| {
                let _ = left.concatenate(&right);
            })
            .is_err()
        );
    }

    #[test]
    fn concatenation_rejects_different_endpoint_nodes() {
        let endpoint = |name| {
            EndpointSignature::new(
                node(name),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            )
        };
        let path = |start, end| {
            PartialPath::new(
                endpoint(start),
                endpoint(end),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let left = path("left-start", "left-end");
        let right = path("right-start", "right-end");

        assert_eq!(
            left.concatenate(&right),
            Err(PathCompositionError::EndpointMismatch {
                left: node("left-end"),
                right: node("right-start"),
            })
        );
        assert_eq!(
            left.concatenate_with_poll(&right, &mut || false,),
            Some(Err(PathCompositionError::EndpointMismatch {
                left: node("left-end"),
                right: node("right-start"),
            }))
        );
        assert_eq!(
            left.end()
                .can_concatenate_with_poll(right.start(), &mut || false,),
            Some(Err(PathCompositionError::EndpointMismatch {
                left: node("left-end"),
                right: node("right-start"),
            }))
        );
    }

    #[test]
    fn endpoint_compatibility_matches_full_composition_and_cancels_without_evidence_copy() {
        use super::super::engine::CANCELLATION_QUANTUM;

        let seam = node("endpoint-compatibility-seam");
        let lookup = semantic("endpoint-compatibility-lookup");
        let left = PartialPath::new(
            endpoint(node("endpoint-compatibility-left"), Vec::new(), Vec::new()),
            endpoint(seam, vec![lookup], Vec::new()),
            Vec::new(),
            vec![WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let right = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::open(vec![lookup], variable("endpoint-compatibility-tail")),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(node("endpoint-compatibility-right"), Vec::new(), Vec::new()),
            Vec::new(),
            vec![WitnessStep::Node(seam)],
            ResolutionCompletion::Complete,
        );
        let full = left.concatenate(&right).map(|_| ());
        let compatibility = left
            .end()
            .can_concatenate_with_poll(right.start(), &mut || false)
            .expect("uncancelled endpoint compatibility completes");
        assert_eq!(compatibility, full);

        let mismatched = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed([semantic("endpoint-compatibility-other")]),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(
                node("endpoint-compatibility-mismatch-end"),
                Vec::new(),
                Vec::new(),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let full_mismatch = left.concatenate(&mismatched).map(|_| ());
        let endpoint_mismatch = left
            .end()
            .can_concatenate_with_poll(mismatched.start(), &mut || false)
            .expect("uncancelled endpoint mismatch completes");
        assert_eq!(endpoint_mismatch, full_mismatch);
        assert!(matches!(
            endpoint_mismatch,
            Err(PathCompositionError::SymbolStack(
                StackUnificationError::FixedCellMismatch { .. }
            ))
        ));

        let large = EndpointSignature::new(
            seam,
            StackPattern::open(
                std::iter::repeat_n(lookup, CANCELLATION_QUANTUM + 1).collect::<Vec<_>>(),
                variable("endpoint-compatibility-large-tail"),
            ),
            StackPattern::closed(Vec::new()),
        );
        let mut polls = 0_usize;
        assert!(
            left.end()
                .can_concatenate_with_poll(&large, &mut || {
                    polls += 1;
                    polls > CANCELLATION_QUANTUM
                })
                .is_none()
        );
        assert_eq!(polls, CANCELLATION_QUANTUM + 1);
    }

    #[test]
    fn shared_completion_path_construction_and_seed_updates_do_not_scan_the_base() {
        let mut work_by_size = Vec::new();
        for count in [8_usize, 4_096] {
            let expected = ResolutionCompletion::incomplete((0..count).map(|index| {
                ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
                    index.to_le_bytes(),
                ))
            }));
            let ResolutionCompletion::Incomplete(reasons) = &expected else {
                unreachable!()
            };
            let shared = ResolutionCompletion::Incomplete(
                reasons.to_shared_with_poll(&mut || false).unwrap(),
            );
            let at = endpoint(node("shared-completion-path"), Vec::new(), Vec::new());
            let mut work = 0;
            let mut paths = Vec::new();
            for _ in 0..64 {
                let mut poll = || {
                    work += 1;
                    false
                };
                let path = PartialPath::new_with_poll(
                    at.clone(),
                    at.clone(),
                    Box::new([]),
                    Box::new([]),
                    shared.clone(),
                    &mut poll,
                )
                .unwrap();
                let path = path
                    .with_seed_completion_with_poll(&shared, &mut poll)
                    .unwrap();
                let path = path
                    .with_additional_completion_with_poll(&shared, &mut poll)
                    .unwrap();
                let path = path.clone_with_poll(&mut poll).unwrap();
                assert_eq!(path.completion(), &expected);
                assert!(
                    matches!(path.completion(), ResolutionCompletion::Incomplete(reasons) if reasons.clone_work_len() == 1)
                );
                paths.push(path);
            }
            assert_eq!(paths.len(), 64);
            work_by_size.push(work);
        }
        assert!(
            work_by_size[1] <= work_by_size[0] * 4,
            "512-fold base growth permits logarithmic membership work, not full scans per path: {work_by_size:?}"
        );
    }

    #[test]
    fn polled_path_construction_matches_public_semantics_and_cancels_inside_completion() {
        use super::super::engine::CANCELLATION_QUANTUM;

        let start = endpoint(node("polled-construction-start"), Vec::new(), Vec::new());
        let end = endpoint(node("polled-construction-end"), Vec::new(), Vec::new());
        let reason =
            ResolutionIncompleteReason::UnsupportedSemantic(semantic("polled-construction-gap"));
        let completion = ResolutionCompletion::Incomplete(CompletionReasons::from(
            std::iter::repeat_n(reason, CANCELLATION_QUANTUM + 1).collect::<Vec<_>>(),
        ));
        let expected = PartialPath::new(
            start.clone(),
            end.clone(),
            Vec::new(),
            Vec::new(),
            completion.clone(),
        );
        let actual = PartialPath::new_with_poll(
            start.clone(),
            end.clone(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            completion.clone(),
            &mut || false,
        )
        .expect("uncancelled path construction completes");
        assert_eq!(actual, expected);

        let mut polls = 0_usize;
        assert!(
            PartialPath::new_with_poll(
                start,
                end,
                Vec::new().into_boxed_slice(),
                Vec::new().into_boxed_slice(),
                completion,
                &mut || {
                    polls += 1;
                    polls > CANCELLATION_QUANTUM
                },
            )
            .is_none()
        );
        assert_eq!(polls, CANCELLATION_QUANTUM + 1);
    }

    #[test]
    fn polled_path_clone_and_composition_cancel_inside_one_large_path() {
        use super::super::engine::CANCELLATION_QUANTUM;

        let seam = node("polled-large-path-seam");
        let large = PartialPath::new(
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                node("polled-large-path-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            std::iter::repeat_n(
                WitnessStep::Node(node("polled-large-path-witness")),
                CANCELLATION_QUANTUM + 1,
            )
            .collect::<Vec<_>>(),
            ResolutionCompletion::Complete,
        );
        let left = PartialPath::new(
            EndpointSignature::new(
                node("polled-large-path-start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            EndpointSignature::new(
                seam,
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let cancelled_after_quantum = |polls: &mut usize| {
            *polls += 1;
            *polls > CANCELLATION_QUANTUM
        };
        let mut clone_polls = 0_usize;
        let mut composition_polls = 0_usize;
        let mut canonicalization_polls = 0_usize;

        let expected_canonical = large.clone().canonicalized_observations();
        let actual_canonical = large
            .clone()
            .canonicalized_observations_with_poll(&mut || false)
            .expect("uncancelled canonicalization completes");
        assert_eq!(actual_canonical, expected_canonical);

        assert!(
            large
                .clone_with_poll(&mut || cancelled_after_quantum(&mut clone_polls))
                .is_none(),
            "a cancelled clone must not expose a structural prefix"
        );
        assert!(
            left.concatenate_with_poll(&large, &mut || cancelled_after_quantum(
                &mut composition_polls
            ),)
                .is_none(),
            "cancellation is distinct from a stack-unification failure"
        );
        assert!(
            large
                .canonicalized_observations_with_poll(&mut || {
                    cancelled_after_quantum(&mut canonicalization_polls)
                })
                .is_none(),
            "cancelled observation canonicalization must not expose a path prefix"
        );
        assert_eq!(clone_polls, CANCELLATION_QUANTUM + 1);
        assert_eq!(composition_polls, CANCELLATION_QUANTUM + 1);
        assert_eq!(canonicalization_polls, CANCELLATION_QUANTUM + 1);
    }

    #[test]
    fn attached_scope_unification_propagates_through_the_whole_path() {
        let captured_tail = variable("captured-tail");
        let seam = node("scoped-seam");
        let captured_scope = node("captured-scope");
        let lexical_scope = node("lexical-scope");
        let left = PartialPath::new(
            EndpointSignature::new_scoped(
                node("left-start"),
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("closure"),
                    StackPattern::open(Vec::new(), captured_tail),
                )]),
                StackPattern::open(Vec::new(), captured_tail),
            ),
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("member"),
                    StackPattern::open(vec![lexical_scope], captured_tail),
                )]),
                StackPattern::open(Vec::new(), captured_tail),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );
        let right = PartialPath::new(
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![PartialScopedSymbol::scoped(
                    semantic("member"),
                    StackPattern::closed(vec![lexical_scope, captured_scope]),
                )]),
                StackPattern::closed(vec![captured_scope]),
            ),
            EndpointSignature::new(
                node("right-end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            Vec::new(),
            Vec::new(),
            ResolutionCompletion::Complete,
        );

        let joined = left
            .concatenate(&right)
            .expect("attached and top-level scopes share one substitution");

        assert_eq!(
            joined.start().symbols().fixed()[0].scopes(),
            Some(&StackPattern::closed(vec![captured_scope]))
        );
        assert_eq!(
            joined.start().scopes(),
            &StackPattern::closed(vec![captured_scope])
        );
    }

    #[test]
    fn scoped_and_unscoped_symbol_cells_do_not_unify() {
        let seam = node("seam");
        let endpoint = |scoped| {
            let symbol = if scoped {
                PartialScopedSymbol::scoped(
                    semantic("name"),
                    StackPattern::closed(vec![node("scope")]),
                )
            } else {
                PartialScopedSymbol::unscoped(semantic("name"))
            };
            EndpointSignature::new_scoped(
                seam,
                StackPattern::closed(vec![symbol]),
                StackPattern::closed(Vec::new()),
            )
        };
        let path = |start, end| {
            PartialPath::new(
                start,
                end,
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let left = path(
            EndpointSignature::new(
                node("start"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
            endpoint(true),
        );
        let right = path(
            endpoint(false),
            EndpointSignature::new(
                node("end"),
                StackPattern::closed(Vec::new()),
                StackPattern::closed(Vec::new()),
            ),
        );

        assert_eq!(
            left.concatenate(&right),
            Err(PathCompositionError::SymbolStack(
                StackUnificationError::FixedCellMismatch { index: 0 }
            ))
        );
    }

    #[test]
    fn stack_effect_key_preserves_nested_scope_variable_aliasing() {
        let make_path = |attached_tail, top_tail| {
            PartialPath::new(
                EndpointSignature::new_scoped(
                    node("start"),
                    StackPattern::closed(vec![PartialScopedSymbol::scoped(
                        semantic("name"),
                        StackPattern::open(vec![node("scope")], attached_tail),
                    )]),
                    StackPattern::open(Vec::new(), top_tail),
                ),
                EndpointSignature::new_scoped(
                    node("end"),
                    StackPattern::open(Vec::new(), variable("symbol-tail")),
                    StackPattern::open(Vec::new(), top_tail),
                ),
                Vec::new(),
                Vec::new(),
                ResolutionCompletion::Complete,
            )
        };
        let aliased = make_path(variable("scope-a"), variable("scope-a"));
        let alpha_equivalent = make_path(variable("scope-b"), variable("scope-b"));
        let split = make_path(variable("scope-c"), variable("scope-d"));

        assert_eq!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&alpha_equivalent)
        );
        assert_ne!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&split)
        );
        assert_eq!(
            stack_effect_alpha_key(&aliased),
            stack_effect_alpha_key(&alpha_renamed(&aliased))
        );
    }

    #[test]
    fn typed_frontier_canonicalizes_semantically_distinct_value_alternatives() {
        let first = semantic("first-type");
        let second = semantic("second-type");
        let runtime_first = ResolutionSlotValue::runtime(ResolutionTypeRef::new(first, 0), false);
        let addressable_first =
            ResolutionSlotValue::runtime(ResolutionTypeRef::new(first, 0), true);
        let pointer_second = ResolutionSlotValue::runtime(ResolutionTypeRef::new(second, 2), false);
        let type_object_second =
            ResolutionSlotValue::type_object(ResolutionTypeRef::new(second, 0));
        let state = TypedFrontierState::new(
            semantic("slot"),
            [
                pointer_second,
                addressable_first,
                runtime_first,
                type_object_second,
                runtime_first,
            ],
            ResolutionCompletion::Complete,
        );

        let mut expected = vec![
            runtime_first,
            addressable_first,
            pointer_second,
            type_object_second,
        ];
        expected.sort_unstable();
        assert_eq!(state.possible_values(), expected);
        assert_eq!(type_object_second.addressable(), None);
        assert_eq!(addressable_first.addressable(), Some(true));
        assert_eq!(pointer_second.ty().indirection(), 2);
        assert_eq!(pointer_second.ty().identity(), second);
    }

    #[test]
    fn address_of_filters_operands_and_produces_non_addressable_pointers() {
        let ty = semantic("address-operand");
        for transform in [
            TypeTransferValueTransform::AddressableOperandOnly,
            TypeTransferValueTransform::RuntimeOnly,
        ] {
            let rule = TypeTransferRule::new(
                semantic("address-rule"),
                semantic("address-output"),
                1,
                transform,
                ResolutionCompletion::Complete,
            );
            assert_eq!(
                rule.apply(ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new(ty, 0),
                    true
                )),
                TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new(ty, 1),
                    false
                ))
            );
            assert_eq!(
                rule.apply(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                    ty,
                    u32::MAX
                ))),
                TypeTransferApplication::NoValue
            );
            assert_eq!(
                rule.apply(ResolutionSlotValue::runtime(
                    ResolutionTypeRef::new(ty, u32::MAX),
                    true
                )),
                TypeTransferApplication::IndirectionOutOfRange
            );
        }
        let address = TypeTransferRule::new(
            semantic("address-rule"),
            semantic("address-output"),
            1,
            TypeTransferValueTransform::AddressableOperandOnly,
            ResolutionCompletion::Complete,
        );
        assert_eq!(
            address.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, u32::MAX),
                false
            )),
            TypeTransferApplication::NoValue
        );
        let literal = TypeTransferRule::new(
            semantic("literal-address-rule"),
            semantic("address-output"),
            1,
            TypeTransferValueTransform::RuntimeOnly,
            ResolutionCompletion::Complete,
        );
        assert_eq!(
            literal.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 0),
                false
            )),
            TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 1),
                false
            ))
        );
    }

    #[test]
    fn pointer_operand_filters_category_before_checked_adjustment() {
        let ty = semantic("pointer-operand-type");
        let pointer = TypeTransferRule::new(
            semantic("pointer-type-rule"),
            semantic("pointer-output"),
            1,
            TypeTransferValueTransform::TypeObjectOnly,
            ResolutionCompletion::Complete,
        );
        let dereference = TypeTransferRule::new(
            semantic("dereference-rule"),
            semantic("pointer-output"),
            -1,
            TypeTransferValueTransform::AddressableRuntimeOnly,
            ResolutionCompletion::Complete,
        );
        assert_eq!(
            pointer.apply(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                ty, 0
            ))),
            TypeTransferApplication::Value(ResolutionSlotValue::type_object(
                ResolutionTypeRef::new(ty, 1)
            ))
        );
        assert_eq!(
            dereference.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 1),
                false
            )),
            TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 0),
                true
            ))
        );
        // Inapplicable branches must not report underflow/overflow or fabricate values.
        assert_eq!(
            pointer.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, u32::MAX),
                true
            )),
            TypeTransferApplication::NoValue
        );
        assert_eq!(
            dereference.apply(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                ty, 0
            ))),
            TypeTransferApplication::NoValue
        );
        assert_eq!(
            pointer.apply(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                ty,
                u32::MAX
            ))),
            TypeTransferApplication::IndirectionOutOfRange
        );
        assert_eq!(
            dereference.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 0),
                true
            )),
            TypeTransferApplication::IndirectionOutOfRange
        );
    }

    #[test]
    fn type_transfer_rule_applies_explicit_category_transform_after_checked_delta() {
        let ty = semantic("declared-type");
        let rule = TypeTransferRule::new(
            semantic("declared-type-rule"),
            semantic("declared-value-slot"),
            2,
            TypeTransferValueTransform::ToRuntime { addressable: false },
            ResolutionCompletion::Complete,
        );

        assert_eq!(
            rule.apply(ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                ty, 1
            ))),
            TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, 3),
                false
            ))
        );
        assert_eq!(
            rule.apply(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new(ty, u32::MAX),
                true
            )),
            TypeTransferApplication::IndirectionOutOfRange
        );
    }

    #[test]
    fn type_transfer_rule_preserves_and_checks_reference_provenance() {
        let ty = semantic("borrowed-type");
        let borrowed = ResolutionTypeRef::new_with_reference_indirection(ty, 2, 2);
        assert!(borrowed.has_only_reference_indirection());
        assert!(!ResolutionTypeRef::new(ty, 2).has_only_reference_indirection());

        let add_reference = TypeTransferRule::new_with_reference_indirection(
            semantic("add-reference-rule"),
            semantic("add-reference-target"),
            1,
            1,
            TypeTransferValueTransform::Preserve,
            ResolutionCompletion::Complete,
        );
        assert_eq!(add_reference.reference_indirection_delta(), 1);
        assert_eq!(
            add_reference.apply(ResolutionSlotValue::runtime(borrowed, false)),
            TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new_with_reference_indirection(ty, 3, 3),
                false,
            ))
        );

        let discard_nonreference_layer = TypeTransferRule::new_with_reference_indirection(
            semantic("discard-nonreference-rule"),
            semantic("discard-nonreference-target"),
            -1,
            0,
            TypeTransferValueTransform::Preserve,
            ResolutionCompletion::Complete,
        );
        assert_eq!(
            discard_nonreference_layer.apply(ResolutionSlotValue::runtime(borrowed, false)),
            TypeTransferApplication::IndirectionOutOfRange,
        );

        let remove_reference = TypeTransferRule::new_with_reference_indirection(
            semantic("remove-reference-rule"),
            semantic("remove-reference-target"),
            -1,
            -1,
            TypeTransferValueTransform::Preserve,
            ResolutionCompletion::Complete,
        );
        assert_eq!(
            remove_reference.apply(ResolutionSlotValue::runtime(borrowed, false)),
            TypeTransferApplication::Value(ResolutionSlotValue::runtime(
                ResolutionTypeRef::new_with_reference_indirection(ty, 1, 1),
                false,
            ))
        );
    }
}
