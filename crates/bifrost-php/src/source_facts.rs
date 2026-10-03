//! Mounted canonical PHP source facts for declaration readers.

use brokk_bifrost_core::analyzer::php_facts::{PhpDeclarationSourceFact, PhpSourceFacts};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceFactRows};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PhpFileSourceFacts {
    pub source: SourceFactRows,
    pub imports: Vec<brokk_bifrost_core::analyzer::parsed_file::SourceImportFact>,
    pub facts: PhpSourceFacts,
    pub declaration_units: HashMap<SourceDeclarationId, Vec<CodeUnit>>,
}

impl PhpFileSourceFacts {
    pub fn declarations_for<'a>(
        &'a self,
        unit: &'a CodeUnit,
    ) -> impl Iterator<Item = &'a PhpDeclarationSourceFact> + 'a {
        self.facts.declarations.iter().filter(|fact| {
            self.declaration_units
                .get(&fact.declaration)
                .is_some_and(|units| units.contains(unit))
        })
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.imports.capacity()
            * std::mem::size_of::<brokk_bifrost_core::analyzer::parsed_file::SourceImportFact>()
            + self
                .imports
                .iter()
                .map(|import| import.estimated_retained_bytes())
                .sum::<usize>()
            + self.source.estimated_bytes()
            + self.facts.estimated_retained_bytes()
            + self.declaration_units.capacity()
                * std::mem::size_of::<(SourceDeclarationId, Vec<CodeUnit>)>()
            + self
                .declaration_units
                .values()
                .map(|units| {
                    units.capacity() * std::mem::size_of::<CodeUnit>()
                        + units
                            .iter()
                            .map(|unit| {
                                unit.fq_name().len()
                                    + unit.source().rel_path().to_string_lossy().len()
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
}

pub trait PhpSourceFactProvider: Send + Sync {
    /// None is unavailable. A canonical empty file is Some with empty rows.
    fn php_source_facts(&self, file: &ProjectFile) -> Option<Arc<PhpFileSourceFacts>> {
        self.php_source_facts_while(file, &|| true)
    }

    fn php_source_facts_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<PhpFileSourceFacts>>;
}
