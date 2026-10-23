//! Collection and implicit edges share one per-language identity. Split them
//! only when a second consumer needs their lifetimes to vary independently.
use super::*;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HierarchyPolicyId(pub(crate) u64);
impl HierarchyPolicyId {
    fn hash_extension(self, state: &mut impl Hasher) {
        if self.0 != 0 {
            b"hierarchy-policy".hash(state);
            self.0.hash(state);
        }
    }
}

/// Collection and implicit edges are governed by one immutable per-language identity.
pub(crate) trait HierarchyPolicy: std::fmt::Debug + Sync + std::any::Any {
    fn identity(&self) -> HierarchyPolicyId {
        HierarchyPolicyId(0)
    }
    fn compare_distance(&self, shape: HierarchyLookupShape, new: u32, old: u32) -> Ordering {
        if shape.searches_callable_overload_set() {
            Ordering::Equal
        } else {
            new.cmp(&old)
        }
    }
    fn retain_owner(&self, has_matching_declaration: bool) -> bool {
        has_matching_declaration
    }
    fn direct_hit_stops(&self, shape: HierarchyLookupShape) -> bool {
        !shape.searches_callable_overload_set()
    }
    fn evidence_cutoff(&self, shape: HierarchyLookupShape, nearest: Option<u32>) -> Option<u32> {
        if shape.searches_callable_overload_set() {
            None
        } else {
            nearest
        }
    }
    /// The default cannot prove that an owner has no implicit root, so it keeps
    /// the hierarchy open. A policy whose producer emits implicit roots as
    /// ordinary edges selects `ExplicitHierarchyEdges` instead.
    fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
        &CONSERVATIVE_HIERARCHY_EDGES
    }
}
#[derive(Debug)]
pub(crate) struct DefaultHierarchyPolicy {
    // A nonzero-sized singleton has a distinct data address for registry admission.
    _identity: u8,
}
/// The engine's baseline policy (identity 0), used by every owner without a
/// registered policy, including the JVM, Go and Rust. It assumes the producer
/// emits every implicit root as an ordinary edge, as the Java producer does
/// for the implicit `Object` supertype. A language whose implicit root is not
/// emitted must register its own policy and edge provider, as Python does.
/// The baseline stays identity 0 because nonzero identities enter hashed keys.
impl HierarchyPolicy for DefaultHierarchyPolicy {
    fn edge_provider(&self) -> &'static dyn HierarchyEdgeProvider {
        &EXPLICIT_HIERARCHY_EDGES
    }
}
pub(crate) static DEFAULT_HIERARCHY_POLICY: DefaultHierarchyPolicy =
    DefaultHierarchyPolicy { _identity: 0 };

pub(crate) trait HierarchyEdgeProvider: std::fmt::Debug + Sync {
    fn implicit_base(
        &self,
        _owner: SemanticId,
        _source: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseRead>> {
        Ok(Some(ImplicitBaseRead {
            base: None,
            observations: Box::new([]),
            completion: ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(_owner),
            ]),
        }))
    }
}
/// Use when the producer emits implicit roots as ordinary hierarchy edges.
#[derive(Debug)]
pub(crate) struct ExplicitHierarchyEdges;
impl HierarchyEdgeProvider for ExplicitHierarchyEdges {
    fn implicit_base(
        &self,
        _owner: SemanticId,
        _source: &dyn SelectedTypedFactSource,
        _cancellation: &CancellationToken,
    ) -> StoreResult<Option<ImplicitBaseRead>> {
        Ok(Some(ImplicitBaseRead {
            base: None,
            observations: Box::new([]),
            completion: ResolutionCompletion::Complete,
        }))
    }
}
pub(crate) static EXPLICIT_HIERARCHY_EDGES: ExplicitHierarchyEdges = ExplicitHierarchyEdges;
/// Uses the trait's conservative `implicit_base`.
#[derive(Debug)]
struct ConservativeHierarchyEdges;
impl HierarchyEdgeProvider for ConservativeHierarchyEdges {}
static CONSERVATIVE_HIERARCHY_EDGES: ConservativeHierarchyEdges = ConservativeHierarchyEdges;
pub(crate) struct ImplicitBaseRead {
    pub(crate) base: Option<ImplicitBaseFact>,
    pub(crate) observations: Box<[HierarchyProviderObservation]>,
    pub(crate) completion: ResolutionCompletion,
}
pub(crate) struct ImplicitBaseFact {
    pub(crate) target: SemanticId,
    pub(crate) ordinal: u32,
    pub(crate) provider: HierarchyProviderKey,
    pub(crate) occurrence: SemanticId,
}

impl Hash for HierarchyLookupShape {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Keep the exact pre-policy field sequence; zero contributes NO bytes.
        self.lookup.hash(state);
        self.namespace.hash(state);
        self.category.hash(state);
        self.receiver_indirection.hash(state);
        self.candidate_policy.hash(state);
        self.namespace_aliases.hash(state);
        self.policy.hash_extension(state);
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct HierarchyOwnerKey {
    pub(super) owner: SemanticId,
    pub(super) policy: HierarchyPolicyId,
}
impl Hash for HierarchyOwnerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.policy.hash_extension(state);
    }
}
impl From<SemanticId> for HierarchyOwnerKey {
    fn from(owner: SemanticId) -> Self {
        Self {
            owner,
            policy: HierarchyPolicyId(0),
        }
    }
}

impl HierarchyOperationArena {
    pub(super) fn register_policy(
        &mut self,
        policy: &'static dyn HierarchyPolicy,
    ) -> HierarchyPolicyId {
        let id = policy.identity();
        if id == HierarchyPolicyId(0) {
            assert!(
                std::ptr::addr_eq(policy, &DEFAULT_HIERARCHY_POLICY as &dyn HierarchyPolicy),
                "zero identifies only the default policy"
            );
        } else if let Some(previous) = self.policies.insert(id, policy) {
            // Vtables can be duplicated across codegen units. Compare the data
            // address and concrete type for admission only; neither enters a key.
            assert!(
                std::ptr::addr_eq(previous, policy) && previous.type_id() == policy.type_id(),
                "one static policy per identity"
            );
        }
        id
    }
    pub(super) fn policy(&self, id: HierarchyPolicyId) -> &'static dyn HierarchyPolicy {
        if id == HierarchyPolicyId(0) {
            &DEFAULT_HIERARCHY_POLICY
        } else {
            self.policies[&id]
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum HierarchyBaseOrigin {
    Typed(SelectedTypedRowIdentity),
    Implicit(HierarchyProviderKey),
}
impl HierarchyBaseOrigin {
    pub(super) fn provider(
        &self,
        key: HierarchyNodeKey,
        operand: HierarchyProviderOperand,
    ) -> HierarchyProviderKey {
        match self {
            Self::Typed(row) => HierarchyProviderKey::new(
                key,
                HierarchyProviderAuthority::Typed(row.clone()),
                operand,
            ),
            Self::Implicit(provider) => provider.with_operand(operand),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Bytes(Vec<u8>);
    impl Hasher for Bytes {
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
        fn finish(&self) -> u64 {
            unreachable!("capture exact input bytes, not a digest")
        }
    }
    // This is the pre-#5658 shape, deliberately retaining its derived Hash.
    #[derive(Hash)]
    struct OldShape {
        lookup: SemanticId,
        namespace: ResolutionNamespace,
        category: QualifierCategory,
        receiver_indirection: i64,
        candidate_policy: HierarchyCandidatePolicy,
        namespace_aliases: &'static [ResolutionMemberKind],
    }
    #[derive(Hash)]
    struct OldSummaryKey {
        shape: OldShape,
        owner: SemanticId,
    }
    fn bytes(value: &impl Hash) -> Vec<u8> {
        let mut hash = Bytes::default();
        value.hash(&mut hash);
        hash.0
    }
    fn old(shape: HierarchyLookupShape) -> OldShape {
        OldShape {
            lookup: shape.lookup,
            namespace: shape.namespace,
            category: shape.category,
            receiver_indirection: shape.receiver_indirection,
            candidate_policy: shape.candidate_policy,
            namespace_aliases: shape.namespace_aliases,
        }
    }
    #[test]
    fn hierarchy_policy_default_lookup_summary_and_edge_bytes_are_unchanged() {
        for language in [
            Language::Rust,
            Language::Go,
            Language::Java,
            Language::Kotlin,
            Language::Scala,
        ] {
            for namespace in [
                ResolutionNamespace::Value,
                ResolutionNamespace::Type,
                ResolutionNamespace::Callable,
            ] {
                for category in [QualifierCategory::Type, QualifierCategory::Runtime] {
                    let mut shape = HierarchyLookupShape::new(
                        SemanticId::for_test("key-lookup"),
                        namespace,
                        category,
                        0,
                    );
                    shape.namespace_aliases =
                        super::super::super::fact_source::language_value_member_aliases(language);
                    let owner = SemanticId::for_test("key-owner");
                    for shape in [shape, shape.with_callable_overload_set()] {
                        assert_eq!(
                            bytes(&shape),
                            bytes(&old(shape)),
                            "{language:?} {namespace:?}"
                        );
                        let summary = HierarchyNodeKey { shape, owner };
                        assert_eq!(
                            bytes(&summary),
                            bytes(&OldSummaryKey {
                                shape: old(shape),
                                owner
                            }),
                            "{language:?} summary"
                        );
                        assert_eq!(
                            bytes(&HierarchyOwnerKey::from(owner)),
                            bytes(&owner),
                            "{language:?} edges"
                        );
                        let custom = HierarchyLookupShape {
                            policy: HierarchyPolicyId(7),
                            ..shape
                        };
                        assert_ne!(bytes(&custom), bytes(&shape));
                        assert_ne!(
                            bytes(&HierarchyOwnerKey {
                                owner,
                                policy: custom.policy
                            }),
                            bytes(&owner)
                        );
                    }
                }
            }
        }
    }
    #[derive(Debug)]
    struct Exhaustive;
    impl HierarchyPolicy for Exhaustive {
        fn identity(&self) -> HierarchyPolicyId {
            HierarchyPolicyId(7)
        }
        fn compare_distance(&self, _: HierarchyLookupShape, _: u32, _: u32) -> Ordering {
            Ordering::Equal
        }
        fn retain_owner(&self, _: bool) -> bool {
            true
        }
        fn direct_hit_stops(&self, _: HierarchyLookupShape) -> bool {
            false
        }
        fn evidence_cutoff(&self, _: HierarchyLookupShape, _: Option<u32>) -> Option<u32> {
            None
        }
    }
    static EXHAUSTIVE: Exhaustive = Exhaustive;
    #[test]
    fn hierarchy_policy_registry_preserves_default_and_exhaustive_identity() {
        let mut arena = HierarchyOperationArena::default();
        assert_eq!(
            arena.register_policy(&DEFAULT_HIERARCHY_POLICY),
            HierarchyPolicyId(0)
        );
        assert!(arena.policies.is_empty());
        assert_eq!(arena.register_policy(&EXHAUSTIVE), HierarchyPolicyId(7));
        assert_eq!(arena.register_policy(&EXHAUSTIVE), HierarchyPolicyId(7));
        assert!(arena.policy(HierarchyPolicyId(7)).retain_owner(false));
        assert!(!arena.policy(HierarchyPolicyId(0)).retain_owner(false));
    }
    #[test]
    #[should_panic(expected = "one static policy per identity")]
    fn hierarchy_policy_registry_rejects_conflicting_static_policy() {
        #[derive(Debug)]
        struct Different;
        impl HierarchyPolicy for Different {
            fn identity(&self) -> HierarchyPolicyId {
                HierarchyPolicyId(7)
            }
        }
        static DIFFERENT: Different = Different;
        let mut arena = HierarchyOperationArena::default();
        arena.register_policy(&EXHAUSTIVE);
        arena.register_policy(&DIFFERENT);
    }
}
