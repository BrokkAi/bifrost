//! Mounted read-side input for Scala declaration consumers.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::scala_facts::ScalaSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceFactRows};
use brokk_bifrost_core::hash::HashMap;

#[derive(Debug, Clone)]
pub struct ScalaFileSourceFacts {
    pub source: SourceFactRows,
    pub facts: ScalaSourceFacts,
    /// Exact primary projection links, including repeated inline members.
    pub declaration_units: HashMap<SourceDeclarationId, Vec<CodeUnit>>,
}

impl ScalaFileSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        brokk_bifrost_core::analyzer::source_facts::source_projection_retained_bytes(
            &self.source,
            self.facts.estimated_retained_bytes(),
            &self.declaration_units,
        )
    }
}

impl ScalaFileSourceFacts {
    pub fn for_unit<'a>(
        &'a self,
        unit: &'a CodeUnit,
    ) -> impl Iterator<Item = &'a brokk_bifrost_core::analyzer::scala_facts::ScalaDeclarationSourceFact>
    {
        brokk_bifrost_core::analyzer::source_facts::declarations_for_unit(
            &self.facts.declarations,
            &self.declaration_units,
            unit,
            |fact| fact.declaration,
        )
    }
}
