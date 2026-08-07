//! The proof vocabulary Rust's semantic diagnostics answer (#1625).
//!
//! A Rust reference is a path. Resolving one walks the same surfaces in the
//! same order every time: the enclosing lexical scopes, the file's `use`
//! bindings, the workspace crate graph, and finally the activated dependency
//! packs built from rustdoc JSON. [`RustNameProof`] is what one such walk
//! proved, and [`record_rust_name_proof`] is the single place a proof becomes a
//! report entry. Only [`RustNameProof::Absent`] can produce an error.
//!
//! # Why a diagnostic reads and never builds
//!
//! Producing a Rust dependency pack runs `cargo` and `rustdoc` and reads
//! `target/doc`. Issue #1615 forbids that work inside a diagnostic request, and
//! #1625 keeps the prohibition: the ladder below reads what an earlier
//! resolution or `IAnalyzer::warm_query_indexes` already retained, and an
//! unbuilt surface is an unknown boundary rather than a reason to go build one.
//!
//! That makes the diagnostic path's evidence a strict subset of the resolver's.
//! The subset is the point: with less evidence a lookup can only fall further
//! down this ladder toward [`RustNameProof::Incomplete`], never up toward
//! [`RustNameProof::Absent`], so a diagnostic can never contradict a
//! `get_definition` that resolved the same reference.
//!
//! # Why so much of Rust is deliberately incomplete
//!
//! Rust decides what a path means with information a pack does not carry.
//! A macro synthesizes names that no surface declares; a `cfg` attribute
//! selects between item sets by a configuration the pack was not necessarily
//! built under; a glob import re-exports an unknown set of names into scope; a
//! trait bound or a `Deref` chain puts methods on a type whose own `impl`
//! blocks never mention them. Each of those is a typed
//! [`RustProofGap`] here rather than a silent suppression, because "we cannot
//! tell" and "we checked and it is not there" are different answers and only
//! the second may become an error.

use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

/// What every retained Rust surface proved about one written path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustNameProof {
    /// Exactly one workspace declaration, `use` binding or lexical binding
    /// spells the path.
    Workspace,
    /// An activated dependency pack spells the path.
    ExternalIndexed,
    /// Several in-scope routes spell the path. The name exists; which
    /// declaration it denotes is not decided here. That is ambiguity, not
    /// absence, and must never become an unrecognized-symbol error.
    Ambiguous { boundaries: Vec<BoundaryStatus> },
    /// Every surface this lookup needed was read to completion and none spells
    /// the path. `boundary` is the widest surface that was complete.
    Absent { boundary: BoundaryStatus },
    /// A surface this lookup needed could not answer.
    Incomplete(RustProofGap),
}

/// Why a Rust path lookup could not reach a complete answer.
///
/// Every variant names the specific construct or surface that stopped the
/// proof. A gap never carries a bare "unknown": the reason a reader sees must
/// identify what to go and fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustProofGap {
    /// Nothing past the workspace is retained for the crate this path enters,
    /// or what is retained does not claim to cover it. `boundary` names how far
    /// the lookup saw.
    ExternalBoundary { boundary: BoundaryStatus },
    /// A construct whose meaning the resolver does not model, named exactly:
    /// a `cfg`-selected item set, a glob import, a trait-bound or `Deref`
    /// method surface.
    Unsupported { detail: String },
    /// A name that a macro or a proc-macro derive may synthesize. No surface
    /// declares such a name, so its absence from every surface proves nothing.
    Generated { detail: String },
    /// A surface exists but was recorded as partially read, so a miss may lie
    /// in the part that was never read.
    Truncated,
}

impl RustProofGap {
    pub fn into_reason(self) -> SemanticDiagnosticIncompleteReason {
        match self {
            Self::ExternalBoundary { boundary } => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }
            }
            Self::Unsupported { detail } => {
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
            }
            Self::Generated { detail } => {
                SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { detail }
            }
            Self::Truncated => SemanticDiagnosticIncompleteReason::Truncated,
        }
    }
}

/// Record what `proof` established about the reference at `range`, and return
/// whether it earned an error.
///
/// `absence` is called only on the one arm that can produce a diagnostic, so a
/// resolved reference -- the overwhelming majority in any real file -- never
/// pays for a message it will not emit.
pub fn record_rust_name_proof(
    report: &mut SemanticDiagnosticReport,
    range: Range,
    proof: RustNameProof,
    absence: impl FnOnce() -> (SemanticDiagnosticDomain, SemanticDiagnostic),
) -> bool {
    match proof {
        RustNameProof::Workspace => {
            report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
            false
        }
        RustNameProof::ExternalIndexed => {
            report.push_resolved(range, BoundaryStatus::ExternalIndexed);
            false
        }
        RustNameProof::Ambiguous { boundaries } => {
            report.push_ambiguous(range, boundaries);
            false
        }
        RustNameProof::Absent { boundary } => {
            let (domain, diagnostic) = absence();
            debug_assert_eq!(
                diagnostic.range, range,
                "a Rust absence must be reported at the reference it proved absent"
            );
            report.push_absent(
                SemanticAbsenceProof {
                    range,
                    domain,
                    boundary,
                },
                diagnostic,
            );
            true
        }
        RustNameProof::Incomplete(gap) => {
            report.push_incomplete(Some(range), vec![gap.into_reason()]);
            false
        }
    }
}
