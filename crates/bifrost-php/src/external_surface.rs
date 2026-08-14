//! The external-boundary facts PHP's semantic diagnostics read.
//!
//! The semantic-model overlay and retained dependency-discovery evidence live
//! in `brokk-bifrost-analysis`, which this crate must not depend on. This trait
//! is the narrow window through which the collector reads them, and
//! `analyzer/php/diagnostics.rs` on the analysis side implements it.
//!
//! Every method must answer from state a host already published. A diagnostic
//! request must never start dependency discovery, scan a vendor tree, or read
//! any package file.

use brokk_bifrost_core::analyzer::SemanticDiagnosticIncompleteReason;

/// What the indexed external surface says about one PHP name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpExternalSymbol {
    /// Exactly one indexed declaration.
    Indexed {
        /// The overlay identity, so a later member lookup can name its owner.
        id: String,
    },
    /// More than one indexed declaration, or one an indexed pack flagged
    /// ambiguous. Two Composer packages can install the same class name.
    Ambiguous,
    /// Nothing indexed the name.
    Absent,
}

/// What the indexed external surface proves about one member of an owner that
/// already resolved.
///
/// A member question has an answer a name question does not: the owner is
/// published, the member is not on what the packs published, and the packs
/// still do not add up to the owner's whole inherited surface. Reporting that
/// as `Absent` would turn an unindexed base class into a fabricated error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhpExternalMember {
    /// The member is on the owner's surface or on an ancestor's.
    Indexed,
    /// Every declaration that answers the name is one an indexed pack flagged
    /// ambiguous.
    Ambiguous,
    /// The owner's whole inherited surface is published and complete, and the
    /// member is not on it.
    Absent,
    /// The published surface is not provably all of it. `detail` names the
    /// first gap: the base class no pack published, the partial pack, or the
    /// type two packs both declare.
    Unproven { detail: String },
}

/// The read-only external boundary a PHP diagnostic request may consult.
pub trait PhpExternalSurface {
    /// The indexed declaration for a fully qualified PHP name, in Bifrost's
    /// dotted form.
    fn lookup_type(&self, fqn: &str) -> PhpExternalSymbol;

    /// The indexed member of an already-resolved external owner, including
    /// members the owner inherits.
    ///
    /// `owner_id` must be an identity a prior [`Self::lookup_type`] returned.
    /// The implementation is responsible for the owner's whole ancestry: only
    /// it can tell an owner with no base apart from an owner whose base no
    /// pack published.
    fn lookup_member(&self, owner_id: &str, member: &str) -> PhpExternalMember;

    /// Whether an indexed pack covers `namespace_fq` and claims that coverage
    /// complete, so a name missing from it is provably absent.
    ///
    /// This is deliberately namespace-scoped rather than "an overlay exists":
    /// indexing one Composer package says nothing about an unrelated vendor
    /// namespace, and must not license an error there.
    fn namespace_surface_is_complete(&self, namespace_fq: &str) -> bool;

    /// Whether the build declares a package that could own `fqn`.
    ///
    /// Callers must consult [`Self::namespace_surface_is_complete`] first: a
    /// declared package is often also an indexed one, and only a declared name
    /// that nothing indexed is `ExternalDeclaredUnindexed`.
    fn declares_unindexed(&self, fqn: &str) -> bool;

    /// Typed reasons that retained discovery evidence is missing or partial.
    /// An empty result means discovery evidence is present and complete.
    fn discovery_incomplete_reasons(&self) -> Vec<SemanticDiagnosticIncompleteReason>;
}

/// The surface a collector sees when no host ever activated dependency packs.
///
/// Every lookup is absent and no namespace is complete, so the ladder reports
/// `ExternalUnknown` and publishes nothing. This is the honest answer for an
/// analyzer that has not indexed its dependencies.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnindexedPhpExternalSurface;

impl PhpExternalSurface for UnindexedPhpExternalSurface {
    fn lookup_type(&self, _fqn: &str) -> PhpExternalSymbol {
        PhpExternalSymbol::Absent
    }

    fn lookup_member(&self, _owner_id: &str, _member: &str) -> PhpExternalMember {
        PhpExternalMember::Unproven {
            detail: "no active semantic pack publishes a PHP surface".to_owned(),
        }
    }

    fn namespace_surface_is_complete(&self, _namespace_fq: &str) -> bool {
        false
    }

    fn declares_unindexed(&self, _fqn: &str) -> bool {
        false
    }

    fn discovery_incomplete_reasons(&self) -> Vec<SemanticDiagnosticIncompleteReason> {
        vec![
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary:
                    brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus::ExternalUnknown,
            },
        ]
    }
}
