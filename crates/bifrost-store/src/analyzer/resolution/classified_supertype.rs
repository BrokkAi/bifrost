//! Query-local parent roles. Stored kinds remain part of raw row identity;
//! only resolved, alias-expanded target evidence may classify a nominal parent.

use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind;

/// Semantic roles accepted by hierarchy ordering and member selection. There
/// is deliberately no authored-but-unclassified variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassifiedSupertypeKind {
    Superclass,
    Interface,
    GoInterfaceElement,
    ImplicitSuperclass,
    SelfType,
    LookupOnlyRoot,
}

impl ClassifiedSupertypeKind {
    /// Declared nominal order used by the existing JVM cursor.
    pub const fn nominal_order_tier(self) -> u8 {
        match self {
            Self::Superclass | Self::ImplicitSuperclass => 0,
            Self::Interface | Self::GoInterfaceElement | Self::SelfType | Self::LookupOnlyRoot => 1,
        }
    }
}

/// Roles permitted at the nominal parent API boundary. Lookup-only roots
/// have no representation here and cannot seed ancestry, subtype or base proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NominalSupertypeKind {
    Superclass,
    Interface,
    GoInterfaceElement,
    ImplicitSuperclass,
    SelfType,
}

impl NominalSupertypeKind {
    pub const fn nominal_order_tier(self) -> u8 {
        match self {
            Self::Superclass | Self::ImplicitSuperclass => 0,
            Self::Interface | Self::GoInterfaceElement | Self::SelfType => 1,
        }
    }

    pub(super) const fn from_classified(kind: ClassifiedSupertypeKind) -> Option<Self> {
        match kind {
            ClassifiedSupertypeKind::Superclass => Some(Self::Superclass),
            ClassifiedSupertypeKind::Interface => Some(Self::Interface),
            ClassifiedSupertypeKind::GoInterfaceElement => Some(Self::GoInterfaceElement),
            ClassifiedSupertypeKind::ImplicitSuperclass => Some(Self::ImplicitSuperclass),
            ClassifiedSupertypeKind::SelfType => Some(Self::SelfType),
            ClassifiedSupertypeKind::LookupOnlyRoot => None,
        }
    }
}

/// Evidence from the selected declaration after alias/forward expansion. A
/// non-base declaration includes structs, enums, delegates and type parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NominalParentTargetKind {
    Class,
    Interface,
    Struct,
    Enum,
    NonBase,
    Missing,
    Ambiguous,
    Incomplete,
}

/// Existing language roles are already classified by their producer. Languages
/// with deferred authored parents must supply selected evidence, including for
/// an authored interface expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupertypeKindEvidence {
    ProducerClassified,
    Selected(NominalParentTargetKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupertypeKindOpenReason {
    MissingTargetKind,
    AmbiguousTarget,
    IncompleteTarget,
    NonBaseTarget,
    ExpectedInterface,
    InvalidParentList,
}

impl SupertypeKindOpenReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingTargetKind => "nominal-parent-kind-missing",
            Self::AmbiguousTarget => "nominal-parent-kind-ambiguous",
            Self::IncompleteTarget => "nominal-parent-kind-incomplete",
            Self::NonBaseTarget => "nominal-parent-kind-nonbase",
            Self::ExpectedInterface => "nominal-parent-kind-expected-interface",
            Self::InvalidParentList => "nominal-parent-list-invalid",
        }
    }

    pub fn semantic(self, identities: &super::SelectedContextIdentities) -> super::SemanticId {
        let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-nominal-parent-kind-open:v1",
        );
        hash.field("reason", self.code().as_bytes());
        identities.named_semantic(
            hash.finish(),
            self.code(),
            crate::analyzer::resolution::ReasonDeterminism::Unaudited,
            self.code(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupertypeClassification {
    Classified(Option<ClassifiedSupertypeKind>),
    Open(SupertypeKindOpenReason),
}

/// One pure classification boundary, called after scheduled reference and alias
/// resolution, never by raw row decoding or a selected page visitor. It makes
/// no reads: callers must retain/replay the evidence that supplied `evidence`.
pub const fn classify_supertype_kind(
    stored: Option<ResolutionSupertypeKind>,
    evidence: SupertypeKindEvidence,
) -> SupertypeClassification {
    use ClassifiedSupertypeKind as C;
    use NominalParentTargetKind as T;
    use ResolutionSupertypeKind as S;
    use SupertypeClassification::{Classified, Open};
    use SupertypeKindEvidence::{ProducerClassified, Selected};
    use SupertypeKindOpenReason as R;

    match stored {
        None => Classified(None),
        Some(S::Superclass) => Classified(Some(C::Superclass)),
        Some(S::GoInterfaceElement) => Classified(Some(C::GoInterfaceElement)),
        Some(S::ImplicitSuperclass) => Classified(Some(C::ImplicitSuperclass)),
        Some(S::SelfType) => Classified(Some(C::SelfType)),
        Some(S::ImplicitInterfaceMembers) => Classified(Some(C::LookupOnlyRoot)),
        Some(S::Interface) => match evidence {
            ProducerClassified | Selected(T::Interface) => Classified(Some(C::Interface)),
            Selected(T::Class) => Open(R::ExpectedInterface),
            Selected(T::Struct | T::Enum | T::NonBase) => Open(R::NonBaseTarget),
            Selected(T::Missing) => Open(R::MissingTargetKind),
            Selected(T::Ambiguous) => Open(R::AmbiguousTarget),
            Selected(T::Incomplete) => Open(R::IncompleteTarget),
        },
        Some(S::AuthoredNominalParent) => match evidence {
            Selected(T::Class) => Classified(Some(C::Superclass)),
            Selected(T::Interface) => Classified(Some(C::Interface)),
            Selected(T::Struct | T::Enum | T::NonBase) => Open(R::NonBaseTarget),
            ProducerClassified | Selected(T::Missing) => Open(R::MissingTargetKind),
            Selected(T::Ambiguous) => Open(R::AmbiguousTarget),
            Selected(T::Incomplete) => Open(R::IncompleteTarget),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_roles_preserve_declared_parent_order() {
        use ResolutionSupertypeKind as S;
        let stored = [
            S::Superclass,
            S::Interface,
            S::GoInterfaceElement,
            S::ImplicitSuperclass,
            S::SelfType,
            S::ImplicitInterfaceMembers,
        ];
        // Reverse source ordinal and vary ties so this compares entire orders,
        // including the four roles that occupy the interface tier.
        for rotation in 0..stored.len() {
            let mut before = stored
                .iter()
                .copied()
                .enumerate()
                .map(|(index, kind)| (kind, (index + rotation) % stored.len(), index))
                .collect::<Vec<_>>();
            let mut after = before.clone();
            before.sort_by_key(|(kind, ordinal, reference)| {
                let tier = match kind {
                    S::Superclass | S::ImplicitSuperclass => 0,
                    S::Interface
                    | S::GoInterfaceElement
                    | S::SelfType
                    | S::ImplicitInterfaceMembers => 1,
                    S::AuthoredNominalParent => unreachable!("only existing roles"),
                };
                (tier, *ordinal, *reference)
            });
            after.sort_by_key(|(kind, ordinal, reference)| {
                let SupertypeClassification::Classified(Some(kind)) =
                    classify_supertype_kind(Some(*kind), SupertypeKindEvidence::ProducerClassified)
                else {
                    panic!("an existing producer role must remain classified")
                };
                (kind.nominal_order_tier(), *ordinal, *reference)
            });
            assert_eq!(before, after);
        }
    }
}
