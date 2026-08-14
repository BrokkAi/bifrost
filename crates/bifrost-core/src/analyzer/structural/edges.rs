//! The reference-edge vocabulary: one edge from a use site to a target
//! declaration, stated the same way whichever direction derived it (issue
//! #1479).
//!
//! Today the forward direction (an occurrence resolving to a target) and the
//! inverse direction (a declaration enumerating its usage sites) are two
//! independent derivations with no shared row, so nothing can state -- let
//! alone assert -- that they agree. These enums are the typed values that
//! comparison needs: an [`EdgeProvenance`] naming which producer derived a
//! row, an [`OwnerRelation`] classifying the site's owner against the
//! target's, and a [`SiteClass`] separating use sites from declaration sites
//! so a surface that intentionally omits declaration sites is compared
//! per-surface rather than accused of missing edges.
//!
//! Support is declared, never assumed: [`ReferenceEdgeSupport`] is a total
//! table sized by [`EdgeAxis::COUNT`], so an adapter that says nothing says
//! `Unsupported` for every axis, and a query that depends on an axis the
//! adapter cannot model becomes incomplete rather than silently empty. This
//! mirrors [`super::resolution::LexicalEnvironmentSupport`] exactly.

use super::occurrences::labelled_enum;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// Which producer derived an edge row.
    ///
    /// `Forward` rows come from the resolver: a classified reference
    /// occurrence resolving to its target. `Inverse` rows come from the usage
    /// index: a declaration enumerating the sites that point at it. The two
    /// state the same fact from opposite ends, and a parity assertion is a
    /// comparison across this field -- so it is data on every row, never
    /// implied by which query step produced the set.
    EdgeProvenance, ALL_EDGE_PROVENANCES {
        Forward => "forward",
        Inverse => "inverse",
    }
}

labelled_enum! {
    /// How the declaration enclosing a use site relates to the edge's target.
    ///
    /// - `SameOwner`: the site's enclosing declaration and the target share
    ///   the same owner (a method calling a sibling method of its own type).
    /// - `InheritedOwner`: the site's owner reaches the target's owner through
    ///   the type hierarchy (a subclass method calling an inherited member).
    /// - `SelfReference`: the site's enclosing declaration *is* the target
    ///   (recursion, or a reference inside the target's own definition).
    /// - `External`: the owners are unrelated.
    /// - `Unknown`: the classifier could not relate the owners. Never silently
    ///   equal to `External`: an assertion over unknown relations is
    ///   inconclusive, not clean.
    OwnerRelation, ALL_OWNER_RELATIONS {
        SameOwner => "same_owner",
        InheritedOwner => "inherited_owner",
        SelfReference => "self_reference",
        External => "external",
        Unknown => "unknown",
    }
}

labelled_enum! {
    /// Whether the site end of an edge is an ordinary use or a declaration
    /// site (a definition body for a separate declaration, an override
    /// declaration). Declaration sites are editor-visible for navigation but
    /// are not runtime usages, and the whole-workspace edge build drops them
    /// by design -- so parity comparison must hold this classification as a
    /// field rather than treating the drop as a missing edge.
    SiteClass, ALL_SITE_CLASSES {
        UseSite => "use_site",
        DeclarationSite => "declaration_site",
    }
}

macro_rules! edge_axes {
    ($($variant:ident => $label:literal: $description:literal,)+) => {
        /// One independently answerable part of the reference-edge domain.
        /// Support is declared per axis so an adapter whose usage index
        /// enumerates sites but whose resolver has no occurrence surface
        /// reports exactly that.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum EdgeAxis {
            $($variant,)+
        }

        /// Every axis, in declaration order, for iteration in validation, docs
        /// and tests. Also sizes [`ReferenceEdgeSupport`].
        pub const ALL_EDGE_AXES: &[EdgeAxis] = &[
            $(EdgeAxis::$variant,)+
        ];

        impl EdgeAxis {
            pub const COUNT: usize = ALL_EDGE_AXES.len();

            /// Stable slot in the total support table. Matches declaration order.
            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(EdgeAxis::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<EdgeAxis> {
                ALL_EDGE_AXES
                    .iter()
                    .copied()
                    .find(|axis| axis.label() == label)
            }

            pub const fn signature(self) -> &'static str {
                self.label()
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(EdgeAxis::$variant => $description,)+
                }
            }
        }
    };
}

edge_axes! {
    ForwardProjection => "forward_projection":
        "Site-to-target edges derived from classified occurrences and the resolver.",
    InverseProjection => "inverse_projection":
        "Target-to-site edges derived from the usage index for a seed declaration.",
    KindClassification => "kind_classification":
        "Typed source-level reference kinds (call, field read, type reference, ...) on edges.",
    ProofAttribution => "proof_attribution":
        "Proven versus unproven attribution on every edge, preserved by both projections.",
    OwnerClassification => "owner_classification":
        "Same-owner, inherited-owner, self, or external classification of a site against its target.",
}

impl fmt::Display for EdgeAxis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Whether an adapter answers a given edge axis precisely enough for queries
/// and assertions to depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeSupport {
    Supported,
    #[default]
    Unsupported,
}

impl EdgeSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total edge-axis support table. Every axis an adapter does not name
/// explicitly is explicitly unsupported, so a new axis cannot silently inherit
/// "supported" from an adapter that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEdgeSupport {
    support: [EdgeSupport; EdgeAxis::COUNT],
}

impl Default for ReferenceEdgeSupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl ReferenceEdgeSupport {
    /// The all-unsupported table. Adapters build their own by chaining
    /// [`ReferenceEdgeSupport::supported`] off this in a `static` initializer;
    /// the chain is `const` precisely so no adapter needs lazy storage to
    /// declare a table the spec trait hands out by reference.
    pub const NONE: Self = Self {
        support: [EdgeSupport::Unsupported; EdgeAxis::COUNT],
    };

    pub const fn supported(mut self, axis: EdgeAxis) -> Self {
        self.support[axis.index()] = EdgeSupport::Supported;
        self
    }

    pub const fn unsupported(mut self, axis: EdgeAxis) -> Self {
        self.support[axis.index()] = EdgeSupport::Unsupported;
        self
    }

    pub const fn support(&self, axis: EdgeAxis) -> EdgeSupport {
        self.support[axis.index()]
    }

    pub const fn is_supported(&self, axis: EdgeAxis) -> bool {
        self.support(axis).is_supported()
    }

    pub fn is_empty(&self) -> bool {
        self.support.iter().all(|support| !support.is_supported())
    }

    /// Iterate in the stable order declared by [`ALL_EDGE_AXES`].
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (EdgeAxis, EdgeSupport)> + '_ {
        ALL_EDGE_AXES.iter().map(|&axis| (axis, self.support(axis)))
    }
}

/// The table an adapter that has not yet learned reference edges returns.
pub static NO_REFERENCE_EDGE_SUPPORT: ReferenceEdgeSupport = ReferenceEdgeSupport::NONE;

/// The table an adapter whose usage index answers inverse edges returns, when
/// it has no forward occurrence surface to project from. Kind and owner
/// classification stay unsupported until the derivation layer measures what
/// the language's usage strategies actually attribute: an edge query filtered
/// by an unclaimed axis reports incomplete rather than silently empty.
pub static INVERSE_REFERENCE_EDGE_SUPPORT: ReferenceEdgeSupport = INVERSE_ONLY;

const INVERSE_ONLY: ReferenceEdgeSupport = ReferenceEdgeSupport::NONE
    .supported(EdgeAxis::InverseProjection)
    .supported(EdgeAxis::ProofAttribution);

/// The table a deep adapter (Java, Rust, Python, JS/TS) returns: both
/// projections, because these four carry the occurrence-role classification
/// and resolver trace the forward producer projects from, plus the
/// classification axes the shared derivation layer computes once for both
/// directions.
pub static DEEP_REFERENCE_EDGE_SUPPORT: ReferenceEdgeSupport = INVERSE_ONLY
    .supported(EdgeAxis::ForwardProjection)
    .supported(EdgeAxis::KindClassification)
    .supported(EdgeAxis::OwnerClassification);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every labelled vocabulary in this registry must have unique labels that
    /// round-trip through both `from_label` and serde, so a JSON surface and a
    /// rendered surface never disagree about a name.
    #[test]
    fn edge_vocabularies_are_unique_and_round_trip() {
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

        check!(ALL_EDGE_PROVENANCES, EdgeProvenance);
        check!(ALL_OWNER_RELATIONS, OwnerRelation);
        check!(ALL_SITE_CLASSES, SiteClass);
        check!(ALL_EDGE_AXES, EdgeAxis);

        assert!(EdgeAxis::from_label("not_an_axis").is_none());
        assert!(OwnerRelation::from_label("owner").is_none());
    }

    #[test]
    fn axis_indices_are_dense_and_size_the_support_table() {
        assert_eq!(ALL_EDGE_AXES.len(), EdgeAxis::COUNT);
        for (slot, &axis) in ALL_EDGE_AXES.iter().enumerate() {
            assert_eq!(axis.index(), slot);
        }
        assert_eq!(ReferenceEdgeSupport::NONE.iter().count(), EdgeAxis::COUNT);
    }

    #[test]
    fn support_table_is_total_and_defaults_to_unsupported() {
        let table = ReferenceEdgeSupport::default();
        assert!(table.is_empty());
        for &axis in ALL_EDGE_AXES {
            assert_eq!(table.support(axis), EdgeSupport::Unsupported);
            assert!(!table.is_supported(axis));
        }

        let declared = ReferenceEdgeSupport::NONE
            .supported(EdgeAxis::InverseProjection)
            .supported(EdgeAxis::OwnerClassification)
            .unsupported(EdgeAxis::OwnerClassification);
        assert!(declared.is_supported(EdgeAxis::InverseProjection));
        assert!(!declared.is_supported(EdgeAxis::OwnerClassification));
        assert!(!declared.is_supported(EdgeAxis::ForwardProjection));
        assert!(!declared.is_empty());
        assert!(NO_REFERENCE_EDGE_SUPPORT.is_empty());
    }

    /// The two shared adapter tables are the one place adapters state what
    /// they answer, so their contents are asserted once here rather than
    /// eleven times across the adapters: inverse-only adapters answer exactly
    /// the two axes every usage index carries, and deep adapters answer
    /// everything.
    #[test]
    fn shared_adapter_tables_state_the_claimed_axes() {
        for &axis in ALL_EDGE_AXES {
            let expected = matches!(
                axis,
                EdgeAxis::InverseProjection | EdgeAxis::ProofAttribution
            );
            assert_eq!(
                INVERSE_REFERENCE_EDGE_SUPPORT.is_supported(axis),
                expected,
                "unexpected inverse-only support for {axis}"
            );
            assert!(
                DEEP_REFERENCE_EDGE_SUPPORT.is_supported(axis),
                "a deep adapter must answer {axis}"
            );
        }
    }

    #[test]
    fn every_axis_describes_itself() {
        for &axis in ALL_EDGE_AXES {
            assert!(!axis.description().is_empty());
            assert_eq!(axis.signature(), axis.label());
        }
    }
}
