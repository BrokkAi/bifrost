//! The identity-route vocabulary: how a declaration's canonical identity flows
//! through qualified paths and indirection (issue #1475).
//!
//! Today every indirection hop — an alias, a re-export, a partial part, a
//! header/body peer — is a private step inside one consumer, and a qualified
//! path is queryable only as its resolved endpoint. These types are what those
//! hops and segments become as data: a [`RouteHopKind`] for the kind of
//! indirection, a [`SegmentResolutionStatus`] for what a path-segment prefix
//! resolved to, a [`RouteTermination`] for why a traversal stopped, and a
//! [`CanonicalIdentity`] that compares declarations structurally so no
//! consumer ever compares rendered display strings.
//!
//! Support is declared, never assumed, on two independent tables inside
//! [`IdentityRouteSupport`]: per [`IdentityAxis`] (what the adapter can state
//! about paths and identities) and per [`RouteHopKind`] (which indirection
//! relations the adapter supplies edges for). An adapter that says nothing
//! says `Unsupported` for everything, exactly like
//! [`super::occurrences::OccurrenceRoleSupport`] and
//! [`super::resolution::LexicalEnvironmentSupport`].

use super::occurrences::{Namespace, labelled_enum};
use crate::analyzer::Language;
use crate::analyzer::fq_name::{FqName, SegmentInterner, SegmentKind};
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! described_vocab {
    ($(#[$meta:meta])* $name:ident, $all:ident, $count:ident {
        $($variant:ident => $label:literal: $description:literal,)+
    }) => {
        $(#[$meta])*
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant,)+
        }

        /// Every value, in declaration order, for iteration in validation,
        /// docs and tests. Also sizes the support table.
        pub const $all: &[$name] = &[
            $($name::$variant,)+
        ];

        impl $name {
            pub const $count: usize = $all.len();

            /// Stable slot in the total support table. Matches declaration order.
            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<$name> {
                $all.iter().copied().find(|value| value.label() == label)
            }

            pub const fn signature(self) -> &'static str {
                self.label()
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $($name::$variant => $description,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.label())
            }
        }
    };
}

described_vocab! {
    /// One kind of indirection an identity route can pass through. Each
    /// variant names a relation the analyzer already computes somewhere
    /// private; a hop of that kind is the typed, provenance-carrying record of
    /// one such step.
    RouteHopKind, ALL_ROUTE_HOP_KINDS, COUNT {
        Alias => "alias":
            "A local respelling of a declaration: an import alias or a type alias.",
        Import => "import":
            "An import binding that brings a declaration's name into a file or scope.",
        Export => "export":
            "An export site that makes a local declaration reachable from outside its file or module.",
        ReExport => "re_export":
            "An export whose subject is itself imported or exported from elsewhere, forwarding identity onward.",
        PartialPart => "partial_part":
            "One physical part of a declaration that source spells in several pieces, such as a C# partial type.",
        DeclarationDefinitionPeer => "declaration_definition_peer":
            "The peer link between a declaration head and its definition body, such as a C++ prototype and its function body.",
        NestedOwner => "nested_owner":
            "The projection from a nested declaration to the owner declaration its qualified name nests under.",
        Implementation => "implementation":
            "The link from an abstract member to a concrete member that implements it, such as a Rust trait member and its impl item.",
        GeneratedPeer => "generated_peer":
            "The link between a synthetic declaration and the source declaration it was generated from.",
    }
}

described_vocab! {
    /// One independently answerable part of the identity/route surface.
    /// Support is declared per axis so an adapter that can decode its
    /// qualified paths but cannot resolve segment prefixes reports exactly
    /// that. Route relations are deliberately not an axis: they are claimed
    /// per [`RouteHopKind`] on the sibling table, because "supplies re-export
    /// edges but not partial parts" is the honest shape of every adapter.
    IdentityAxis, ALL_IDENTITY_AXES, COUNT {
        PathSegments => "path_segments":
            "Grouping a file's qualified-path expressions into ordered, decoded path-segment rows.",
        SegmentResolution => "segment_resolution":
            "Resolving each path segment's prefix independently and assigning the segment's namespace from the result.",
        CanonicalIdentity => "canonical_identity":
            "Projecting declarations onto structured canonical identities that compare without display strings.",
        PhysicalGrouping => "physical_grouping":
            "Enumerating the physical source occurrences that share one canonical declaration identity.",
    }
}

labelled_enum! {
    /// What resolving one path segment's prefix produced. `Incomplete` is a
    /// statement about the resolver's reach (the prefix crossed ground the
    /// resolver cannot see), not about the source; `Unresolved` means the
    /// resolver looked and found nothing.
    SegmentResolutionStatus, ALL_SEGMENT_RESOLUTION_STATUSES {
        Resolved => "resolved",
        Ambiguous => "ambiguous",
        Unresolved => "unresolved",
        Incomplete => "incomplete",
    }
}

labelled_enum! {
    /// Why a route traversal stopped where it did. Everything except
    /// `Terminal` is an explicit non-answer: a consumer that reads a route
    /// with any other termination must not treat its last hop as the target.
    RouteTermination, ALL_ROUTE_TERMINATIONS {
        Terminal => "terminal",
        Cycle => "cycle",
        FanOutTruncated => "fan_out_truncated",
        DepthTruncated => "depth_truncated",
        Incomplete => "incomplete",
    }
}

/// Whether an adapter answers a given identity axis or supplies a given route
/// relation precisely enough for queries and assertions to depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentitySupport {
    Supported,
    #[default]
    Unsupported,
}

impl IdentitySupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total identity/route support table: one slot per [`IdentityAxis`] and one
/// per [`RouteHopKind`]. Every slot an adapter does not name explicitly is
/// explicitly unsupported, so a new axis or relation cannot silently inherit
/// "supported" from an adapter that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRouteSupport {
    axes: [IdentitySupport; IdentityAxis::COUNT],
    relations: [IdentitySupport; RouteHopKind::COUNT],
}

impl Default for IdentityRouteSupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl IdentityRouteSupport {
    /// The all-unsupported table. Adapters build their own by chaining
    /// [`IdentityRouteSupport::supported_axis`] and
    /// [`IdentityRouteSupport::supported_relation`] off this in a `static`
    /// initializer; the chain is `const` so no adapter needs lazy storage.
    pub const NONE: Self = Self {
        axes: [IdentitySupport::Unsupported; IdentityAxis::COUNT],
        relations: [IdentitySupport::Unsupported; RouteHopKind::COUNT],
    };

    pub const fn supported_axis(mut self, axis: IdentityAxis) -> Self {
        self.axes[axis.index()] = IdentitySupport::Supported;
        self
    }

    pub const fn supported_relation(mut self, relation: RouteHopKind) -> Self {
        self.relations[relation.index()] = IdentitySupport::Supported;
        self
    }

    pub const fn axis(&self, axis: IdentityAxis) -> IdentitySupport {
        self.axes[axis.index()]
    }

    pub const fn relation(&self, relation: RouteHopKind) -> IdentitySupport {
        self.relations[relation.index()]
    }

    pub const fn supports_axis(&self, axis: IdentityAxis) -> bool {
        self.axis(axis).is_supported()
    }

    pub const fn supports_relation(&self, relation: RouteHopKind) -> bool {
        self.relation(relation).is_supported()
    }

    pub fn is_empty(&self) -> bool {
        self.axes.iter().all(|support| !support.is_supported())
            && self.relations.iter().all(|support| !support.is_supported())
    }

    /// Iterate the axis table in the stable order declared by
    /// [`ALL_IDENTITY_AXES`].
    pub fn iter_axes(&self) -> impl ExactSizeIterator<Item = (IdentityAxis, IdentitySupport)> + '_ {
        ALL_IDENTITY_AXES
            .iter()
            .map(|&axis| (axis, self.axis(axis)))
    }

    /// Iterate the relation table in the stable order declared by
    /// [`ALL_ROUTE_HOP_KINDS`].
    pub fn iter_relations(
        &self,
    ) -> impl ExactSizeIterator<Item = (RouteHopKind, IdentitySupport)> + '_ {
        ALL_ROUTE_HOP_KINDS
            .iter()
            .map(|&relation| (relation, self.relation(relation)))
    }
}

/// The table every adapter that has not yet learned identity routes returns.
pub static NO_IDENTITY_ROUTE_SUPPORT: IdentityRouteSupport = IdentityRouteSupport::NONE;

/// The axis base every deep occurrence adapter (Java, Rust, Python, JS/TS)
/// shares: it can group and decode its qualified paths, its resolver can
/// resolve segment prefixes, and its declarations project onto canonical
/// identities with their own physical ranges. Each deep adapter chains its own
/// claimed relations onto this base, because the relations they supply differ
/// (Rust has `pub use` re-exports; Java has neither exports nor re-exports).
pub const DEEP_IDENTITY_AXES: IdentityRouteSupport = IdentityRouteSupport::NONE
    .supported_axis(IdentityAxis::PathSegments)
    .supported_axis(IdentityAxis::SegmentResolution)
    .supported_axis(IdentityAxis::CanonicalIdentity)
    .supported_axis(IdentityAxis::PhysicalGrouping);

/// One decoded qualified-name segment of a [`CanonicalIdentity`]: the segment
/// kind the extractor recorded and the punctuation-safe text it denotes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalSegment {
    pub kind: CanonicalSegmentKind,
    pub text: String,
}

labelled_enum! {
    /// The public, serializable projection of the interner's
    /// [`SegmentKind`]. A separate vocabulary because `SegmentKind` is a
    /// persistence contract (its tags are on disk) while this one is a wire
    /// vocabulary; conflating them would couple the cache format to the query
    /// surface.
    CanonicalSegmentKind, ALL_CANONICAL_SEGMENT_KINDS {
        Path => "path",
        Package => "package",
        Type => "type",
        Companion => "companion",
        Nested => "nested",
        Member => "member",
        Unknown => "unknown",
    }
}

impl From<SegmentKind> for CanonicalSegmentKind {
    fn from(kind: SegmentKind) -> Self {
        match kind {
            SegmentKind::Path => CanonicalSegmentKind::Path,
            SegmentKind::Package => CanonicalSegmentKind::Package,
            SegmentKind::Type => CanonicalSegmentKind::Type,
            SegmentKind::Companion => CanonicalSegmentKind::Companion,
            SegmentKind::Nested => CanonicalSegmentKind::Nested,
            SegmentKind::Member => CanonicalSegmentKind::Member,
            SegmentKind::Unknown => CanonicalSegmentKind::Unknown,
        }
    }
}

/// The structured semantic identity of a declaration: language, namespace,
/// ordered kind-tagged segments, and generic arity where the declaration
/// records one. Equality and hashing are over this structure and nothing
/// else — no constructor takes a rendered string, and no comparison reads a
/// rendering. Two declarations whose displays coincide but whose segment
/// kinds differ (a module `util` and a type `util`) are different identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalIdentity {
    pub language: Language,
    pub namespace: Namespace,
    pub segments: Vec<CanonicalSegment>,
    /// The number of generic (type) parameters the declaration itself
    /// declares, when the language records one on its signature. `None` means
    /// "not recorded", which is never equal to `Some(0)` ("recorded, and there
    /// are none"): a generic and a nongeneric sibling sharing a spelling must
    /// compare unequal only when the language actually states the arity.
    pub generic_arity: Option<u32>,
}

impl CanonicalIdentity {
    /// Build an identity from an [`FqName`], decoding each interned segment to
    /// its `(kind, text)` pair. Panics on an empty name: a declaration always
    /// has at least one segment, so an empty identity is a construction bug at
    /// the caller, not a state to represent.
    pub fn from_fq(
        language: Language,
        namespace: Namespace,
        fq: &FqName,
        interner: &SegmentInterner,
        generic_arity: Option<u32>,
    ) -> Self {
        assert!(
            !fq.is_empty(),
            "a canonical identity requires at least one segment (language={language:?}, namespace={namespace})"
        );
        let segments = fq
            .segments()
            .iter()
            .map(|&id| {
                let (text, kind) = interner.resolve(id);
                CanonicalSegment {
                    kind: kind.into(),
                    text: text.to_owned(),
                }
            })
            .collect();
        Self {
            language,
            namespace,
            segments,
            generic_arity,
        }
    }

    /// A human-readable rendering for diagnostics and logs only. This is not
    /// identity: it joins segment text with `.` regardless of kind, so decoy
    /// pairs that differ only in segment kinds render identically. Never
    /// compare, hash, or persist this value.
    pub fn diagnostic_rendering(&self) -> String {
        let mut out = String::new();
        for (position, segment) in self.segments.iter().enumerate() {
            if position > 0 {
                out.push('.');
            }
            out.push_str(&segment.text);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::fq_name::segment_interner;
    use std::collections::HashSet;

    /// Every labelled vocabulary in this registry must have unique labels that
    /// round-trip through both `from_label` and serde, so a JSON surface and a
    /// rendered surface never disagree about a name.
    #[test]
    fn route_vocabularies_are_unique_and_round_trip() {
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

        check!(ALL_ROUTE_HOP_KINDS, RouteHopKind);
        check!(ALL_IDENTITY_AXES, IdentityAxis);
        check!(ALL_SEGMENT_RESOLUTION_STATUSES, SegmentResolutionStatus);
        check!(ALL_ROUTE_TERMINATIONS, RouteTermination);
        check!(ALL_CANONICAL_SEGMENT_KINDS, CanonicalSegmentKind);

        assert!(RouteHopKind::from_label("not_a_hop").is_none());
        assert!(IdentityAxis::from_label("not_an_axis").is_none());
    }

    #[test]
    fn indices_are_dense_and_size_the_support_tables() {
        assert_eq!(ALL_IDENTITY_AXES.len(), IdentityAxis::COUNT);
        for (slot, &axis) in ALL_IDENTITY_AXES.iter().enumerate() {
            assert_eq!(axis.index(), slot);
        }
        assert_eq!(ALL_ROUTE_HOP_KINDS.len(), RouteHopKind::COUNT);
        for (slot, &relation) in ALL_ROUTE_HOP_KINDS.iter().enumerate() {
            assert_eq!(relation.index(), slot);
        }
        assert_eq!(
            IdentityRouteSupport::NONE.iter_axes().count(),
            IdentityAxis::COUNT
        );
        assert_eq!(
            IdentityRouteSupport::NONE.iter_relations().count(),
            RouteHopKind::COUNT
        );
    }

    #[test]
    fn support_table_is_total_and_defaults_to_unsupported() {
        let table = IdentityRouteSupport::default();
        assert!(table.is_empty());
        for &axis in ALL_IDENTITY_AXES {
            assert!(!table.supports_axis(axis));
        }
        for &relation in ALL_ROUTE_HOP_KINDS {
            assert!(!table.supports_relation(relation));
        }

        let declared = IdentityRouteSupport::NONE
            .supported_axis(IdentityAxis::PathSegments)
            .supported_relation(RouteHopKind::ReExport);
        assert!(declared.supports_axis(IdentityAxis::PathSegments));
        assert!(!declared.supports_axis(IdentityAxis::SegmentResolution));
        assert!(declared.supports_relation(RouteHopKind::ReExport));
        assert!(!declared.supports_relation(RouteHopKind::Alias));
        assert!(!declared.is_empty());
        assert!(NO_IDENTITY_ROUTE_SUPPORT.is_empty());
    }

    /// The shared deep-adapter base claims every axis and no relation, so each
    /// deep adapter's relation claims stay visible at its own declaration.
    #[test]
    fn deep_axis_base_claims_all_axes_and_no_relations() {
        for &axis in ALL_IDENTITY_AXES {
            assert!(
                DEEP_IDENTITY_AXES.supports_axis(axis),
                "deep base must claim {axis}"
            );
        }
        for &relation in ALL_ROUTE_HOP_KINDS {
            assert!(
                !DEEP_IDENTITY_AXES.supports_relation(relation),
                "the base must not claim {relation}; relations are per-adapter"
            );
        }
    }

    #[test]
    fn every_vocabulary_value_describes_itself() {
        for &axis in ALL_IDENTITY_AXES {
            assert!(!axis.description().is_empty());
            assert_eq!(axis.signature(), axis.label());
        }
        for &relation in ALL_ROUTE_HOP_KINDS {
            assert!(!relation.description().is_empty());
            assert_eq!(relation.signature(), relation.label());
        }
    }

    /// The load-bearing identity property: two identities that render the same
    /// but differ structurally are unequal, and equality never consults the
    /// rendering.
    #[test]
    fn canonical_identity_compares_structure_not_display() {
        let module_util = CanonicalIdentity {
            language: Language::Java,
            namespace: Namespace::Type,
            segments: vec![
                CanonicalSegment {
                    kind: CanonicalSegmentKind::Package,
                    text: "util".to_owned(),
                },
                CanonicalSegment {
                    kind: CanonicalSegmentKind::Type,
                    text: "Map".to_owned(),
                },
            ],
            generic_arity: None,
        };
        let type_util = CanonicalIdentity {
            segments: vec![
                CanonicalSegment {
                    kind: CanonicalSegmentKind::Type,
                    text: "util".to_owned(),
                },
                CanonicalSegment {
                    kind: CanonicalSegmentKind::Type,
                    text: "Map".to_owned(),
                },
            ],
            ..module_util.clone()
        };
        assert_eq!(
            module_util.diagnostic_rendering(),
            type_util.diagnostic_rendering()
        );
        assert_ne!(module_util, type_util);

        let generic = CanonicalIdentity {
            generic_arity: Some(2),
            ..module_util.clone()
        };
        let recorded_nongeneric = CanonicalIdentity {
            generic_arity: Some(0),
            ..module_util.clone()
        };
        assert_ne!(module_util, generic);
        assert_ne!(generic, recorded_nongeneric);
        assert_ne!(module_util, recorded_nongeneric);
    }

    /// A quoted or punctuation-bearing identifier is one semantic segment: its
    /// literal text survives the projection and the identity has exactly as
    /// many segments as the `FqName`, never a re-split of the rendering.
    #[test]
    fn quoted_identifier_segments_stay_atomic_through_the_projection() {
        let interner = segment_interner();
        let mut fq = FqName::new();
        fq.push(interner.intern(".github", SegmentKind::Package));
        fq.push(interner.intern("workflows", SegmentKind::Package));
        fq.push(interner.intern("release.v2", SegmentKind::Type));

        let identity =
            CanonicalIdentity::from_fq(Language::Rust, Namespace::Type, &fq, interner, None);
        assert_eq!(identity.segments.len(), 3);
        assert_eq!(identity.segments[0].text, ".github");
        assert_eq!(identity.segments[0].kind, CanonicalSegmentKind::Package);
        assert_eq!(identity.segments[2].text, "release.v2");
        assert_eq!(identity.segments[2].kind, CanonicalSegmentKind::Type);
        assert_eq!(
            identity.diagnostic_rendering(),
            ".github.workflows.release.v2"
        );
    }

    #[test]
    #[should_panic(expected = "at least one segment")]
    fn empty_identity_fails_at_the_construction_point() {
        let interner = segment_interner();
        let _ = CanonicalIdentity::from_fq(
            Language::Rust,
            Namespace::Value,
            &FqName::new(),
            interner,
            None,
        );
    }
}
