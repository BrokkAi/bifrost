//! The lexical-resolution vocabulary: how a name resolves, and why a candidate
//! won or lost (issue #1474).
//!
//! Today a resolver encodes precedence as statement order and discards every
//! losing candidate. These enums are the typed values that ordering and that
//! discard become: a [`PrecedenceTier`] for the strength of a candidate, a
//! [`CandidateOutcome`] carrying a typed [`RejectionReason`] for the losers, a
//! [`BoundaryStatus`] for how far the lookup could see, and a
//! [`HoistingClass`] for the interval a binding is in effect over.
//!
//! Support is declared, never assumed: [`LexicalEnvironmentSupport`] is a total
//! table sized by [`EnvironmentAxis::COUNT`], so an adapter that says nothing
//! says `Unsupported` for every axis, and a query that depends on an axis the
//! adapter cannot model becomes incomplete rather than silently empty. This
//! mirrors [`super::occurrences::OccurrenceRoleSupport`] exactly.

use super::occurrences::labelled_enum;
use crate::analyzer::Range;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// When a binding starts being in effect, relative to where it is written.
    ///
    /// This is the one input the general reaching-binding algorithm needs from a
    /// language: everything else (name equality, scope ancestry, nearest scope
    /// wins) is language-neutral.
    ///
    /// - `SourceOrder`: in effect from the end of its declarator to the end of
    ///   its scope (a Rust `let`, a Java local).
    /// - `ScopeWide`: in effect for the whole scope whatever the position (a
    ///   JavaScript `var` or function declaration, a Python function local, a
    ///   Rust item).
    /// - `DeclaredHead`: in effect exactly within a sub-interval the adapter
    ///   states (a match arm, a comprehension clause, a for-header).
    HoistingClass, ALL_HOISTING_CLASSES {
        SourceOrder => "source_order",
        ScopeWide => "scope_wide",
        DeclaredHead => "declared_head",
    }
}

labelled_enum! {
    /// What kind of binder introduced a name into a scope.
    BindingKind, ALL_BINDING_KINDS {
        Local => "local",
        Parameter => "parameter",
        PatternBinder => "pattern_binder",
        LoopVariable => "loop_variable",
        CatchOrResource => "catch_or_resource",
        ImportBinder => "import_binder",
        TypeParameter => "type_parameter",
    }
}

labelled_enum! {
    /// How strong a resolution candidate is. Declaration order is precedence
    /// order, strongest first, and `Ord` is derived from it, so a policy that
    /// asks for "at least this tier" is a comparison rather than a table.
    ///
    /// `NameOnlyFallback` is last on purpose: it is the tier a resolver selects
    /// at when it scans a bare-name index after a structured route was
    /// available, which is exactly the selection the anti-fallback contract
    /// forbids.
    PrecedenceTier, ALL_PRECEDENCE_TIERS {
        LexicalBinding => "lexical_binding",
        OwnMember => "own_member",
        InheritedMember => "inherited_member",
        ExplicitImport => "explicit_import",
        PackageOrModule => "package_or_module",
        WildcardImport => "wildcard_import",
        ExternalRoot => "external_root",
        NameOnlyFallback => "name_only_fallback",
    }
}

labelled_enum! {
    /// Why the resolver discarded a candidate. Each variant names a check a
    /// resolver already performs today and throws away.
    RejectionReason, ALL_REJECTION_REASONS {
        ShadowedByNearer => "shadowed_by_nearer",
        NotInScopeAtPosition => "not_in_scope_at_position",
        WrongNamespace => "wrong_namespace",
        NotVisible => "not_visible",
        WrongDeclarationSpace => "wrong_declaration_space",
        AmbiguousPeer => "ambiguous_peer",
        BoundaryBlocked => "boundary_blocked",
        HiddenByCloserMember => "hidden_by_closer_member",
        CallableApplicabilityDeferred => "callable_applicability_deferred",
    }
}

labelled_enum! {
    /// The language-neutral ordering bucket a member candidate was found in
    /// (#1477). Each language adapter maps its own precedence rules into these
    /// buckets; the bucket never replaces the language's real precedence, it
    /// only makes buckets comparable across languages in one policy.
    ///
    /// Declaration order is precedence order, strongest first, and `Ord` is
    /// derived from it, exactly as for [`PrecedenceTier`].
    MemberDispatchTier, ALL_MEMBER_DISPATCH_TIERS {
        InherentOrDirect => "inherent_or_direct",
        InheritedOrPromoted => "inherited_or_promoted",
        TraitOrInterface => "trait_or_interface",
        Extension => "extension",
        StaticOrCompanion => "static_or_companion",
        DynamicOrOpen => "dynamic_or_open",
    }
}

labelled_enum! {
    /// The kind of one exact hierarchy edge on one candidate's route (#1477).
    ///
    /// `Supertype` is the undifferentiated edge: the hierarchy provider that
    /// recorded it does not distinguish extension from implementation, and the
    /// row must not claim a distinction the provider never made.
    HierarchyRelation, ALL_HIERARCHY_RELATIONS {
        Extends => "extends",
        Implements => "implements",
        Supertype => "supertype",
        Embedded => "embedded",
        TraitImpl => "trait_impl",
    }
}

labelled_enum! {
    /// One typed edge of a canonical method family (#1477 M4).
    ///
    /// `Overrides` and `Implements` are the only edges an analyzer proves
    /// directly: a member redefines a superclass member, or supplies the body
    /// for an interface member. `OverriddenBy` and `ImplementedBy` are their
    /// inverses and are only ever derived by bounded inversion over indexed
    /// forward edges -- never resolved on their own -- so the two directions
    /// cannot disagree.
    MethodFamilyRelation, ALL_METHOD_FAMILY_RELATIONS {
        Overrides => "overrides",
        Implements => "implements",
        OverriddenBy => "overridden_by",
        ImplementedBy => "implemented_by",
    }
}

impl MethodFamilyRelation {
    /// Whether this relation is one an analyzer proves directly from the
    /// member's own declaration and its owner's hierarchy.
    pub const fn is_forward(self) -> bool {
        matches!(self, Self::Overrides | Self::Implements)
    }

    /// The relation that names the same edge from the other end.
    pub const fn inverse(self) -> Self {
        match self {
            Self::Overrides => Self::OverriddenBy,
            Self::Implements => Self::ImplementedBy,
            Self::OverriddenBy => Self::Overrides,
            Self::ImplementedBy => Self::Implements,
        }
    }
}

labelled_enum! {
    /// The per-member result of asking for a method family (#1477 M4).
    ///
    /// `Proven` and `NoFamily` are both complete answers: the first means the
    /// analyzer enumerated the member's family roots, the second means the
    /// member is structurally outside any family (a constructor, a static
    /// method, a private method, or a declaration that is not a method at
    /// all). `Incomplete` and `Unsupported` are the honest failures, and
    /// neither ever carries a family id.
    MemberFamilyOutcome, ALL_MEMBER_FAMILY_OUTCOMES {
        Proven => "proven",
        NoFamily => "no_family",
        Incomplete => "incomplete",
        Unsupported => "unsupported",
    }
}

labelled_enum! {
    /// Why a method-family answer is not `proven` (#1477 M4).
    ///
    /// The first group are proven exclusions that accompany `no_family`: the
    /// language itself says the member participates in no override family, so
    /// zero edges is the complete answer. The second group accompanies
    /// `incomplete` or `unsupported`: the analyzer looked for a fact and did
    /// not find it. No variant is ever reported beside an edge row -- a
    /// not-proven family emits no edges rather than a guessed one.
    MemberFamilyReason, ALL_MEMBER_FAMILY_REASONS {
        NotAMethod => "not_a_method",
        ConstructorExcluded => "constructor_excluded",
        StaticMemberExcluded => "static_member_excluded",
        PrivateMemberExcluded => "private_member_excluded",
        UnsupportedLanguage => "unsupported_language",
        OwnerUnknown => "owner_unknown",
        ModifiersUnrecorded => "modifiers_unrecorded",
        OwnerKindUnrecorded => "owner_kind_unrecorded",
        OverloadIdentityUnproven => "overload_identity_unproven",
        HierarchyTruncated => "hierarchy_truncated",
        FamilyRootNotCanonical => "family_root_not_canonical",
    }
}

impl MemberFamilyReason {
    /// Whether this reason states a proven exclusion rather than missing
    /// evidence. A proven exclusion is a complete answer with zero edges; the
    /// rest are honest failures.
    pub const fn is_proven_exclusion(self) -> bool {
        matches!(
            self,
            Self::NotAMethod
                | Self::ConstructorExcluded
                | Self::StaticMemberExcluded
                | Self::PrivateMemberExcluded
        )
    }
}

labelled_enum! {
    /// How strong an analyzer's member-identity evidence is when it matches a
    /// member against an ancestor's members (#1477 M4).
    ///
    /// This is a measured property of a language adapter, not an aspiration.
    /// `Unsupported` is the default for every language that states nothing,
    /// which is what keeps the family rollout per-language honest.
    MemberFamilyCapability, ALL_MEMBER_FAMILY_CAPABILITIES {
        Unsupported => "unsupported",
        NameAndArity => "name_and_arity",
        ParameterTypeSpellings => "parameter_type_spellings",
        ErasedParameterTypes => "erased_parameter_types",
    }
}

labelled_enum! {
    /// How far the lookup could see when it produced a candidate.
    ///
    /// `ExternalDeclaredUnindexed` is the case a single "unresolvable import"
    /// bucket cannot express today: the build declares the dependency, so the
    /// name is not unknown, but nothing indexed it, so no answer is possible.
    BoundaryStatus, ALL_BOUNDARY_STATUSES {
        WorkspaceLocal => "workspace_local",
        ExternalIndexed => "external_indexed",
        ExternalDeclaredUnindexed => "external_declared_unindexed",
        ExternalUnknown => "external_unknown",
    }
}

labelled_enum! {
    /// The visibility a declaration states, as far as an adapter can read it
    /// from source. `Unknown` is never equal to `Public`: an adapter that
    /// cannot read a modifier says so.
    DeclaredVisibility, ALL_DECLARED_VISIBILITIES {
        Public => "public",
        Protected => "protected",
        Internal => "internal",
        PackagePrivate => "package_private",
        Private => "private",
        CrateOrModule => "crate_or_module",
        Unknown => "unknown",
    }
}

/// Everything an adapter states about one binder token: what kind of binding
/// it introduces, when that binding starts being in effect, and the exact byte
/// interval over which it is in effect.
///
/// This is the whole per-language input to the reaching-binding algorithm. The
/// algorithm itself (name equality, scope ancestry, nearest scope wins,
/// rebinding order) is language-neutral and lives in the derivation layer, so
/// an adapter that can answer this one question gets correct reaching bindings
/// without contributing any resolution logic.
///
/// The kind travels with the interval rather than being classified by the
/// shared layer because deciding "this identifier is a catch parameter, not a
/// local" is grammar knowledge; classifying it centrally would put a
/// per-language node-kind match in the language-neutral producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingActivation {
    pub kind: BindingKind,
    pub hoisting: HoistingClass,
    /// The byte interval in which the binding is in effect. Always contained
    /// in the declaring scope's range.
    pub activation: Range,
}

/// What happened to one candidate the resolver considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOutcome {
    Selected,
    Rejected(RejectionReason),
}

impl CandidateOutcome {
    /// The coarse label. The rejection reason is a separate field on every
    /// surface that renders an outcome, so the label stays a two-value
    /// vocabulary a filter can be written against.
    pub const fn label(self) -> &'static str {
        match self {
            CandidateOutcome::Selected => "selected",
            CandidateOutcome::Rejected(_) => "rejected",
        }
    }

    pub const fn is_selected(self) -> bool {
        matches!(self, CandidateOutcome::Selected)
    }

    pub const fn rejection(self) -> Option<RejectionReason> {
        match self {
            CandidateOutcome::Selected => None,
            CandidateOutcome::Rejected(reason) => Some(reason),
        }
    }
}

impl fmt::Display for CandidateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

macro_rules! environment_axes {
    ($($variant:ident => $label:literal: $description:literal,)+) => {
        /// One independently answerable part of a file's lexical environment.
        /// Support is declared per axis so an adapter that knows its scopes but
        /// not its binding intervals reports exactly that.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum EnvironmentAxis {
            $($variant,)+
        }

        /// Every axis, in declaration order, for iteration in validation, docs
        /// and tests. Also sizes [`LexicalEnvironmentSupport`].
        pub const ALL_ENVIRONMENT_AXES: &[EnvironmentAxis] = &[
            $(EnvironmentAxis::$variant,)+
        ];

        impl EnvironmentAxis {
            pub const COUNT: usize = ALL_ENVIRONMENT_AXES.len();

            /// Stable slot in the total support table. Matches declaration order.
            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(EnvironmentAxis::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<EnvironmentAxis> {
                ALL_ENVIRONMENT_AXES
                    .iter()
                    .copied()
                    .find(|axis| axis.label() == label)
            }

            pub const fn signature(self) -> &'static str {
                self.label()
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(EnvironmentAxis::$variant => $description,)+
                }
            }
        }
    };
}

environment_axes! {
    Scopes => "scopes":
        "Which nodes form lexical scopes in a file and how those scopes nest.",
    BindingIntervals => "binding_intervals":
        "The byte interval each binding is in effect over, with its hoisting class.",
    ImportBinders => "import_binders":
        "The local names an import introduces, with their target segments and activation interval.",
    PackageClause => "package_clause":
        "The package or module a file belongs to.",
    CandidateSelection => "candidate_selection":
        "Which candidate the resolver selected for a reference, and at which precedence tier.",
    CandidateRejection => "candidate_rejection":
        "Which candidates the resolver rejected for a reference, and for which typed reason.",
}

impl fmt::Display for EnvironmentAxis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Whether an adapter answers a given environment axis precisely enough for
/// queries and assertions to depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvironmentSupport {
    Supported,
    #[default]
    Unsupported,
}

impl EnvironmentSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total environment-axis support table. Every axis an adapter does not name
/// explicitly is explicitly unsupported, so a new axis cannot silently inherit
/// "supported" from an adapter that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalEnvironmentSupport {
    support: [EnvironmentSupport; EnvironmentAxis::COUNT],
}

impl Default for LexicalEnvironmentSupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl LexicalEnvironmentSupport {
    /// The all-unsupported table. Adapters build their own by chaining
    /// [`LexicalEnvironmentSupport::supported`] off this in a `static`
    /// initializer; the chain is `const` precisely so no adapter needs lazy
    /// storage to declare a table the spec trait hands out by reference.
    pub const NONE: Self = Self {
        support: [EnvironmentSupport::Unsupported; EnvironmentAxis::COUNT],
    };

    pub const fn supported(mut self, axis: EnvironmentAxis) -> Self {
        self.support[axis.index()] = EnvironmentSupport::Supported;
        self
    }

    pub const fn unsupported(mut self, axis: EnvironmentAxis) -> Self {
        self.support[axis.index()] = EnvironmentSupport::Unsupported;
        self
    }

    pub const fn support(&self, axis: EnvironmentAxis) -> EnvironmentSupport {
        self.support[axis.index()]
    }

    pub const fn is_supported(&self, axis: EnvironmentAxis) -> bool {
        self.support(axis).is_supported()
    }

    pub fn is_empty(&self) -> bool {
        self.support.iter().all(|support| !support.is_supported())
    }

    /// Iterate in the stable order declared by [`ALL_ENVIRONMENT_AXES`].
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (EnvironmentAxis, EnvironmentSupport)> + '_ {
        ALL_ENVIRONMENT_AXES
            .iter()
            .map(|&axis| (axis, self.support(axis)))
    }
}

/// The table every adapter that has not yet learned lexical environments
/// returns.
pub static NO_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport =
    LexicalEnvironmentSupport::NONE;

/// The table a deep adapter without per-tier resolver tracing returns (Python
/// and JS/TS): it carries the occurrence-role classification the environment
/// layer derives bindings from, and its resolver reaches the shared outcome
/// constructors that report a selected candidate, but no tier of its resolver
/// reports the candidates it discarded.
pub static DEEP_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport = DEEP_SELECTION_ONLY;

const DEEP_SELECTION_ONLY: LexicalEnvironmentSupport = LexicalEnvironmentSupport::NONE
    .supported(EnvironmentAxis::Scopes)
    .supported(EnvironmentAxis::BindingIntervals)
    .supported(EnvironmentAxis::ImportBinders)
    .supported(EnvironmentAxis::PackageClause)
    .supported(EnvironmentAxis::CandidateSelection);

/// The table a deep adapter whose resolver reports rejected candidates returns
/// (Java and Rust). It is the table above plus `CandidateRejection`.
///
/// The two tables are separate statics rather than one widened table because
/// the difference between them is the whole point: an adapter that claims
/// `CandidateRejection` has had its resolver tiers instrumented, so an absent
/// rejection row for it means "the resolver did not reject anything there",
/// while for an adapter that does not claim it an absent row means nothing.
pub static DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS: LexicalEnvironmentSupport =
    DEEP_SELECTION_ONLY.supported(EnvironmentAxis::CandidateRejection);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every labelled vocabulary in this registry must have unique labels that
    /// round-trip through both `from_label` and serde, so a JSON surface and a
    /// rendered surface never disagree about a name.
    #[test]
    fn resolution_vocabularies_are_unique_and_round_trip() {
        macro_rules! check {
            ($all:expr, $type:ty) => {{
                let mut labels = HashSet::new();
                for &value in $all {
                    assert!(labels.insert(value.label()), "duplicate label {value:?}");
                    assert_eq!(<$type>::from_label(value.label()), Some(value));
                    let json = serde_json::to_value(value).expect("serialize");
                    assert_eq!(
                        json,
                        serde_json::Value::String(value.label().to_owned()),
                        "serde label diverges from label() for {value:?}"
                    );
                    let back: $type = serde_json::from_value(json).expect("deserialize");
                    assert_eq!(back, value);
                }
                assert_eq!(labels.len(), $all.len());
            }};
        }

        check!(ALL_HOISTING_CLASSES, HoistingClass);
        check!(ALL_BINDING_KINDS, BindingKind);
        check!(ALL_PRECEDENCE_TIERS, PrecedenceTier);
        check!(ALL_REJECTION_REASONS, RejectionReason);
        check!(ALL_MEMBER_DISPATCH_TIERS, MemberDispatchTier);
        check!(ALL_HIERARCHY_RELATIONS, HierarchyRelation);
        check!(ALL_BOUNDARY_STATUSES, BoundaryStatus);
        check!(ALL_DECLARED_VISIBILITIES, DeclaredVisibility);
        check!(ALL_ENVIRONMENT_AXES, EnvironmentAxis);
        check!(ALL_METHOD_FAMILY_RELATIONS, MethodFamilyRelation);
        check!(ALL_MEMBER_FAMILY_OUTCOMES, MemberFamilyOutcome);
        check!(ALL_MEMBER_FAMILY_REASONS, MemberFamilyReason);
        check!(ALL_MEMBER_FAMILY_CAPABILITIES, MemberFamilyCapability);

        assert!(PrecedenceTier::from_label("not_a_tier").is_none());
        assert!(EnvironmentAxis::from_label("not_an_axis").is_none());
    }

    /// A family edge names the same pair from either end, so inversion must be
    /// an involution over forward and inverse relations alike.
    #[test]
    fn family_relations_invert_as_an_involution() {
        for &relation in ALL_METHOD_FAMILY_RELATIONS {
            assert_eq!(relation.inverse().inverse(), relation);
            assert_ne!(relation.inverse(), relation);
            assert_eq!(relation.is_forward(), !relation.inverse().is_forward());
        }
        assert!(MethodFamilyRelation::Overrides.is_forward());
        assert!(MethodFamilyRelation::Implements.is_forward());
        assert_eq!(
            MethodFamilyRelation::Overrides.inverse(),
            MethodFamilyRelation::OverriddenBy
        );
        assert_eq!(
            MethodFamilyRelation::Implements.inverse(),
            MethodFamilyRelation::ImplementedBy
        );
    }

    /// Precedence is a comparison, not a table: the derived `Ord` must follow
    /// declaration order, strongest tier first.
    #[test]
    fn precedence_tiers_are_ordered_strongest_first() {
        let mut sorted = ALL_PRECEDENCE_TIERS.to_vec();
        sorted.sort();
        assert_eq!(sorted, ALL_PRECEDENCE_TIERS);

        assert!(PrecedenceTier::LexicalBinding < PrecedenceTier::OwnMember);
        assert!(PrecedenceTier::OwnMember < PrecedenceTier::InheritedMember);
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::ExternalRoot < PrecedenceTier::NameOnlyFallback);
        assert_eq!(
            ALL_PRECEDENCE_TIERS.last(),
            Some(&PrecedenceTier::NameOnlyFallback)
        );

        let mut dispatch = ALL_MEMBER_DISPATCH_TIERS.to_vec();
        dispatch.sort();
        assert_eq!(dispatch, ALL_MEMBER_DISPATCH_TIERS);
        assert!(MemberDispatchTier::InherentOrDirect < MemberDispatchTier::InheritedOrPromoted);
        assert!(MemberDispatchTier::Extension < MemberDispatchTier::StaticOrCompanion);
        assert_eq!(
            ALL_MEMBER_DISPATCH_TIERS.last(),
            Some(&MemberDispatchTier::DynamicOrOpen)
        );
    }

    #[test]
    fn candidate_outcome_carries_its_reason_and_round_trips() {
        assert!(CandidateOutcome::Selected.is_selected());
        assert_eq!(CandidateOutcome::Selected.rejection(), None);
        assert_eq!(CandidateOutcome::Selected.label(), "selected");

        for &reason in ALL_REJECTION_REASONS {
            let outcome = CandidateOutcome::Rejected(reason);
            assert!(!outcome.is_selected());
            assert_eq!(outcome.rejection(), Some(reason));
            assert_eq!(outcome.label(), "rejected");

            let json = serde_json::to_value(outcome).expect("serialize outcome");
            let back: CandidateOutcome = serde_json::from_value(json).expect("deserialize outcome");
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn axis_indices_are_dense_and_size_the_support_table() {
        assert_eq!(ALL_ENVIRONMENT_AXES.len(), EnvironmentAxis::COUNT);
        for (slot, &axis) in ALL_ENVIRONMENT_AXES.iter().enumerate() {
            assert_eq!(axis.index(), slot);
        }
        assert_eq!(
            LexicalEnvironmentSupport::NONE.iter().count(),
            EnvironmentAxis::COUNT
        );
    }

    #[test]
    fn support_table_is_total_and_defaults_to_unsupported() {
        let table = LexicalEnvironmentSupport::default();
        assert!(table.is_empty());
        for &axis in ALL_ENVIRONMENT_AXES {
            assert_eq!(table.support(axis), EnvironmentSupport::Unsupported);
            assert!(!table.is_supported(axis));
        }

        let declared = LexicalEnvironmentSupport::NONE
            .supported(EnvironmentAxis::Scopes)
            .supported(EnvironmentAxis::CandidateRejection)
            .unsupported(EnvironmentAxis::CandidateRejection);
        assert!(declared.is_supported(EnvironmentAxis::Scopes));
        assert!(!declared.is_supported(EnvironmentAxis::CandidateRejection));
        assert!(!declared.is_supported(EnvironmentAxis::PackageClause));
        assert!(!declared.is_empty());
        assert!(NO_LEXICAL_ENVIRONMENT_SUPPORT.is_empty());
    }

    /// The two shared deep-adapter tables are the one place the deep adapters
    /// state what they answer, so their contents are asserted once here rather
    /// than eleven times across the adapters. The only axis they disagree on is
    /// the one that separates them.
    #[test]
    fn deep_adapter_tables_differ_only_in_rejections() {
        for &axis in ALL_ENVIRONMENT_AXES {
            let expected = axis != EnvironmentAxis::CandidateRejection;
            assert_eq!(
                DEEP_LEXICAL_ENVIRONMENT_SUPPORT.is_supported(axis),
                expected,
                "unexpected selection-only deep-adapter support for {axis}"
            );
            assert!(
                DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS.is_supported(axis),
                "a traced deep adapter must answer {axis}"
            );
        }
    }

    #[test]
    fn every_axis_and_tier_describes_itself() {
        for &axis in ALL_ENVIRONMENT_AXES {
            assert!(!axis.description().is_empty());
            assert_eq!(axis.signature(), axis.label());
        }
    }
}
