//! The one proof vocabulary Java, Kotlin and Scala diagnostics share (#1619).
//!
//! Java, Kotlin and Scala sources in one workspace compile to one classpath, so
//! they answer "does this name exist" from the same surfaces in the same order:
//! the workspace source realm first, then the jar-backed external declaration
//! index, then the active dependency model. [`JvmNameProof`] is what one such
//! lookup proved, and [`record_jvm_name_proof`] is the single place a proof
//! becomes a report entry. Only [`JvmNameProof::Absent`] can produce an error.
//!
//! # Why a diagnostic reads and never builds
//!
//! `JvmExternalDeclarationIndex::build_for_project` reads jars -- up to 128
//! artifacts and 512 MiB of them -- and, under
//! `JvmDependencyDiscoveryMode::OfflineBuildTools`, shells out to `mvn` or
//! `gradle`. Issue #1615 forbids that work inside a diagnostic request. So the
//! diagnostic path peeks at what an earlier resolution or
//! `IAnalyzer::warm_query_indexes` already built, and an unbuilt index is an
//! unknown boundary rather than a reason to go build one.
//!
//! That makes the diagnostic path's evidence a strict subset of the resolver's.
//! The subset is the point: with less evidence a lookup can only fall further
//! down this ladder toward [`JvmNameProof::Incomplete`], never up toward
//! [`JvmNameProof::Absent`], so a diagnostic can never contradict a
//! `get_definition` that resolved the same reference.
//!
//! # Member surfaces
//!
//! [`brokk_bifrost_core::analyzer::model::SemanticDiagnosticDomain::MemberSurface`]
//! has no JVM producer. The jar-backed index stores a type's name, package,
//! kind, visibility and origin artifact and nothing else -- it discards the
//! member tables it parses out of `.class` entries -- so no JVM surface can
//! prove a *member* absent from a complete owner. All three collectors below
//! therefore diagnose written type and term names only, and none constructs a
//! `MemberSurface` domain. See this crate's `#1619` decision log entry.

use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::model::{
    SemanticAbsenceProof, SemanticDiagnostic, SemanticDiagnosticDomain,
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticReport,
};
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

/// The active dependency model a JVM diagnostic may consult, narrowed to what
/// `brokk-bifrost-jvm` can see.
///
/// The model itself is `brokk-bifrost-analysis`'s `SemanticModelOverlay`, and
/// this crate depends on no Bifrost crate but core, so the analysis side passes
/// this view across the boundary the same way it already passes
/// [`crate::java::graph_support::JavaSource::external_boundary_evidence`]'s
/// answer.
pub trait JvmActiveSemanticModel {
    /// Whether a model set is published for the analyzer generation serving
    /// this request.
    ///
    /// Publication is what makes a miss provable. A jar index built from
    /// whatever artifacts happen to be on disk claims nothing about the whole
    /// classpath; a published model set is an activated, complete API surface,
    /// so missing it is evidence rather than silence.
    fn is_published(&self) -> bool;

    /// What the published set says about the fully-qualified name `fqn`.
    fn qualified_name_disposition(&self, fqn: &str) -> JvmModelDisposition;
}

/// What a published dependency model says about one fully-qualified name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmModelDisposition {
    /// No published model declares it.
    Absent,
    /// Exactly one published declaration owns the name.
    Unique,
    /// Several published declarations own it. The name exists; which
    /// declaration it denotes is not decided. That is ambiguity, not absence,
    /// and must never become an unrecognized-symbol error.
    Conflicting { declarations: usize },
}

/// What the analyzer has *retained* about the JVM dependency surface, read
/// without building anything. See this module's note on why a diagnostic peeks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JvmRetainedExternalIndex {
    /// No index is retained for this analyzer generation.
    Unbuilt,
    /// An index is retained and the build declared artifacts it could not
    /// finish reading, so a name may be in the part it never read.
    Partial,
    /// An index is retained and holds everything the build declared.
    Complete,
}

impl JvmRetainedExternalIndex {
    /// How far past the workspace a lookup that missed this index could see.
    ///
    /// A complete jar index still answers [`BoundaryStatus::ExternalUnknown`]:
    /// it is complete for the artifacts that were resolvable on disk, which is
    /// not a claim about the classpath the build would actually use. Only a
    /// published dependency model makes an external miss provable.
    pub fn miss_boundary(self) -> BoundaryStatus {
        match self {
            Self::Partial => BoundaryStatus::ExternalDeclaredUnindexed,
            Self::Unbuilt | Self::Complete => BoundaryStatus::ExternalUnknown,
        }
    }

    /// Whether a name lookup against this index means anything at all.
    pub fn is_readable(self) -> bool {
        !matches!(self, Self::Unbuilt)
    }
}

/// What every retained JVM surface proved about one written name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmNameProof {
    /// Exactly one workspace declaration spells the name.
    Workspace,
    /// A retained external surface -- the jar-backed index or the active
    /// dependency model -- spells the name.
    ExternalIndexed,
    /// Several in-scope routes spell the name. The language itself rejects such
    /// a reference, so this is a real answer, not a failure to look hard
    /// enough, and it must never become an unrecognized-symbol error.
    Ambiguous { boundaries: Vec<BoundaryStatus> },
    /// Every retained surface was read to completion and none spells the name.
    /// `boundary` is the widest surface that was complete.
    Absent { boundary: BoundaryStatus },
    /// A surface this lookup needed could not answer.
    Incomplete(JvmProofGap),
}

/// Why a JVM name lookup could not reach a complete answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JvmProofGap {
    /// Nothing past the workspace is retained, or what is retained does not
    /// claim to cover the name. `boundary` names how far the lookup saw.
    ExternalBoundary { boundary: BoundaryStatus },
    /// A construct the resolver does not model, named exactly.
    Unsupported { detail: String },
}

impl JvmProofGap {
    fn into_reason(self) -> SemanticDiagnosticIncompleteReason {
        match self {
            Self::ExternalBoundary { boundary } => {
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { boundary }
            }
            Self::Unsupported { detail } => {
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
            }
        }
    }
}

/// Record what `proof` established about the reference at `range`, and return
/// whether it earned an error.
///
/// `absence` is called only on the one arm that can produce a diagnostic, so a
/// resolved reference -- the overwhelming majority in any real file -- never
/// pays for a message it will not emit.
pub fn record_jvm_name_proof(
    report: &mut SemanticDiagnosticReport,
    range: Range,
    proof: JvmNameProof,
    absence: impl FnOnce() -> (SemanticDiagnosticDomain, SemanticDiagnostic),
) -> bool {
    match proof {
        JvmNameProof::Workspace => {
            report.push_resolved(range, BoundaryStatus::WorkspaceLocal);
            false
        }
        JvmNameProof::ExternalIndexed => {
            report.push_resolved(range, BoundaryStatus::ExternalIndexed);
            false
        }
        JvmNameProof::Ambiguous { boundaries } => {
            report.push_ambiguous(range, boundaries);
            false
        }
        JvmNameProof::Absent { boundary } => {
            let (domain, diagnostic) = absence();
            debug_assert_eq!(
                diagnostic.range, range,
                "a JVM absence must be reported at the reference it proved absent"
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
        JvmNameProof::Incomplete(gap) => {
            report.push_incomplete(Some(range), vec![gap.into_reason()]);
            false
        }
    }
}

/// The last rung, for a name no retained surface spells: the active dependency
/// model, or the typed gap that stops an error.
///
/// A language calls this once its own workspace realm and its own read of the
/// retained jar index have both missed. The tier walks stay in the language
/// modules, where the spelling rules are; what stays here is the single
/// decision about when a miss has become a proof.
///
/// `model_disposition` walks that language's import tiers against the active
/// model and answers for the strongest tier that matched.
pub fn prove_against_active_model(
    retained: JvmRetainedExternalIndex,
    model: &dyn JvmActiveSemanticModel,
    model_disposition: impl FnOnce() -> JvmModelDisposition,
) -> JvmNameProof {
    // A partially-read index may hold the name in the part it never read, so
    // nothing can be proved past it. That stays true however complete the model
    // is: the artifacts the index failed to read are exactly the ones no
    // activation evidence covers.
    if retained == JvmRetainedExternalIndex::Partial {
        return JvmNameProof::Incomplete(JvmProofGap::ExternalBoundary {
            boundary: BoundaryStatus::ExternalDeclaredUnindexed,
        });
    }
    if !model.is_published() {
        return JvmNameProof::Incomplete(JvmProofGap::ExternalBoundary {
            boundary: retained.miss_boundary(),
        });
    }
    match model_disposition() {
        JvmModelDisposition::Unique => JvmNameProof::ExternalIndexed,
        JvmModelDisposition::Conflicting { declarations } => JvmNameProof::Ambiguous {
            boundaries: vec![BoundaryStatus::ExternalIndexed; declarations],
        },
        JvmModelDisposition::Absent => JvmNameProof::Absent {
            boundary: BoundaryStatus::ExternalIndexed,
        },
    }
}

/// The strongest tier that the published model answers for, given a language's
/// candidate spellings in tier order.
///
/// Stops at the first spelling the model knows: a weaker tier cannot overturn a
/// stronger one, and a name that is `Conflicting` at its strongest tier is
/// ambiguous however many later tiers would have resolved it.
pub fn model_disposition_over_tiers<'a>(
    model: &dyn JvmActiveSemanticModel,
    spellings: impl IntoIterator<Item = &'a str>,
) -> JvmModelDisposition {
    for spelling in spellings {
        let disposition = model.qualified_name_disposition(spelling);
        if disposition != JvmModelDisposition::Absent {
            return disposition;
        }
    }
    JvmModelDisposition::Absent
}
