//! Shared direct parent binding evidence.
use super::*;
use crate::analyzer::resolution::ClassifiedSupertypeKind;

/// One authored or implicit parent, with all binding alternatives preserved.
#[derive(Debug)]
pub struct DirectSupertype {
    pub kind: Option<ClassifiedSupertypeKind>,
    pub parent_ordinal: u32,
    pub reference: SemanticId,
    pub applied_arguments: Option<crate::analyzer::resolution::LoweredSupertypeArguments>,
    pub targets: Vec<SemanticId>,
    pub completion: ResolutionCompletion,
}

/// Request-local parent bindings. Empty or incomplete bindings remain open.
#[derive(Debug)]
pub struct DirectSupertypeAnswer {
    pub parents: Vec<DirectSupertype>,
    pub completion: ResolutionCompletion,
}

impl DirectSupertypeAnswer {
    /// Definite parents, preserving language parent order.
    pub fn edges(&self) -> impl Iterator<Item = &DirectSupertype> {
        self.parents.iter().filter(|parent| {
            parent.targets.len() == 1 && parent.completion == ResolutionCompletion::Complete
        })
    }

    /// Alternatives for one parent reference; never definite edges.
    pub fn ambiguous(&self) -> impl Iterator<Item = &DirectSupertype> {
        self.parents
            .iter()
            .filter(|parent| parent.targets.len() > 1)
    }

    /// Unresolved or incomplete parents with their original binding evidence.
    /// An empty complete binding still leaves the declared parent open.
    pub fn open(&self) -> impl Iterator<Item = &DirectSupertype> {
        self.parents.iter().filter(|parent| {
            parent.targets.is_empty() || parent.completion != ResolutionCompletion::Complete
        })
    }
}
