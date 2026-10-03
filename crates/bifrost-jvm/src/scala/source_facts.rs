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
        self.source
            .estimated_bytes()
            .saturating_add(self.facts.estimated_retained_bytes())
            .saturating_add(
                self.declaration_units
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(SourceDeclarationId, Vec<CodeUnit>)>()),
            )
            .saturating_add(
                self.declaration_units
                    .values()
                    .map(|units| {
                        units
                            .capacity()
                            .saturating_mul(std::mem::size_of::<CodeUnit>())
                            .saturating_add(
                                units
                                    .iter()
                                    .map(|unit| {
                                        unit.fq_name()
                                            .len()
                                            .saturating_add(unit.signature().map_or(0, str::len))
                                            .saturating_add(
                                                unit.source().rel_path().to_string_lossy().len(),
                                            )
                                    })
                                    .sum::<usize>(),
                            )
                    })
                    .sum::<usize>(),
            )
    }
}

impl ScalaFileSourceFacts {
    pub fn for_unit<'a>(
        &'a self,
        unit: &'a CodeUnit,
    ) -> impl Iterator<Item = &'a brokk_bifrost_core::analyzer::scala_facts::ScalaDeclarationSourceFact>
    {
        self.facts.declarations.iter().filter(move |fact| {
            self.declaration_units
                .get(&fact.declaration)
                .is_some_and(|units| units.contains(unit))
        })
    }
}
