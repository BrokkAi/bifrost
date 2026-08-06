//! The analyzer-resident products Scala's language logic resolves through.
//!
//! `ScalaAnalyzer` owns four moka caches, six `Arc<OnceLock<..>>` cells and two
//! `PoolSafeMemo`s; every one of them stays in `brokk-bifrost-analysis` because
//! `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale through
//! `Self::from_inner`. What crosses the crate line is this trait, which is how
//! a free function reaches back for a memoized product without naming the
//! analyzer type -- the same idiom `RubySource` and `CppAnalysisSource` landed.
//!
//! The two members below are load-bearing beyond their signature. Both answer
//! "does the workspace know this bare Scala name", and both consult
//! `JvmExternalDeclarationIndex` -- the classpath-artifact index built out of
//! `analyzer/jvm/`, which is parked in `brokk-bifrost-analysis` with the rest
//! of the `semantic_model` band. That index is why they are trait members
//! rather than moved bodies: the decision they make is Scala's, but one of the
//! facts it reads is not reachable from this crate.

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, ProjectFile};

/// What the workspace can prove about a bare Scala type name at a site.
///
/// `Uncertain` is the answer that keeps the semantic-diagnostic pass honest: an
/// unresolved wildcard or aliased import means the name *may* be declared
/// somewhere this analyzer does not index, so reporting it would be a false
/// positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalaTypeKnownness {
    Known,
    Absent,
    Uncertain,
}

pub trait ScalaSource: CodeUnitIndex + ImportAnalysisProvider {
    /// What the workspace can prove about the bare type name `name` as written
    /// in `file`. See this module's note on why this is not a moved body.
    fn simple_type_knownness(&self, file: &ProjectFile, name: &str) -> ScalaTypeKnownness;

    /// Whether `name` names a value the workspace declares in `file`'s own
    /// package, source-side or on the classpath.
    fn is_known_simple_term(&self, file: &ProjectFile, name: &str) -> bool;
}
