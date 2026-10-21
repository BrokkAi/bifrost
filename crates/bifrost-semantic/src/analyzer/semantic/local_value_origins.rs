//! Bounded exact local-copy origins over the production procedure CFG.
//!
//! Only the qualified Java adapter participates. Its callable, allocation and
//! invocation results have non-copy value kinds or AST shapes and never enter
//! the allowed set. Parentheses and conditional arms are followed through
//! exact Local edges, so a supported wrapper cannot hide an unsupported child.
//! Heap carriers must have a local-variable declaration mapping, excluding
//! Java's implicit-field carriers even when their uses look like identifiers.

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ValueId;

#[derive(Clone, Copy, Debug)]
pub struct LocalConstantOriginLimits {
    pub max_depth: usize,
    pub max_work: usize,
    pub max_roots: usize,
    pub max_source_bytes: usize,
}

impl Default for LocalConstantOriginLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_work: 4096,
            max_roots: 16,
            max_source_bytes: 1_048_576,
        }
    }
}

/// No partial roots escape this boundary. All failures preserve the caller's
/// whole-store join, while budget exhaustion remains separately observable.
#[derive(Debug)]
pub struct LocalConstantOrigins {
    pub roots: Option<Vec<ValueId>>,
    pub work: usize,
    pub source_bytes: usize,
    pub budget_exhausted: bool,
    pub cancelled: bool,
}

#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct Definition {
    #[doc(hidden)]
    pub target: ValueId,
    #[doc(hidden)]
    pub source: Option<ValueId>,
    #[doc(hidden)]
    pub point: ProgramPointId,
    #[doc(hidden)]
    pub event: usize,
}
