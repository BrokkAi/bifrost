//! Mounted canonical Java declaration input for foreign-file readers.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::java_facts::JavaSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceFactRows};
use brokk_bifrost_core::hash::HashMap;

#[derive(Debug, Clone)]
pub struct JavaFileSourceFacts {
    pub source: SourceFactRows,
    pub facts: JavaSourceFacts,
    pub declaration_units: HashMap<SourceDeclarationId, Vec<CodeUnit>>,
}

impl JavaFileSourceFacts {
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
