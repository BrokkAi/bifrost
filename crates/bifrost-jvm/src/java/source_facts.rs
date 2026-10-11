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
        brokk_bifrost_core::analyzer::source_facts::source_projection_retained_bytes(
            &self.source,
            self.facts.estimated_retained_bytes(),
            &self.declaration_units,
        )
    }
}
