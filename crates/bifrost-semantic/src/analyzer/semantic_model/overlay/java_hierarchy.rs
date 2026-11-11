//! Bounded Java subtype evidence over activated declaration facts.

use crate::analyzer::semantic_model::overlay::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaHierarchyIncomplete {
    MissingHierarchy,
    Ambiguous,
    GenericSubstitution,
    BudgetExhausted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHierarchyWitness {
    /// Exact declaration provenance, in source-to-supertype order.
    pub declarations: Vec<SemanticModelProvenance>,
    /// Ordered parameters for each declaration, when its edges came from inventory.
    pub type_parameters: Vec<Option<Vec<String>>>,
    pub edges: Vec<HierarchyFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHierarchyAnswer {
    pub witness: Option<JavaHierarchyWitness>,
    /// Enumeration completeness is independent of a positive path witness.
    pub incomplete: Vec<JavaHierarchyIncomplete>,
}
