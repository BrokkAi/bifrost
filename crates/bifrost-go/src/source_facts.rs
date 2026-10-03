//! Mounted read-side input for Go declaration consumers.

use brokk_bifrost_core::analyzer::go_facts::GoSourceFacts;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceFactRows};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct GoFileSourceFacts {
    pub source: SourceFactRows,
    pub facts: GoSourceFacts,
    /// Exact primary projection links, including repeated inline members.
    pub declaration_units: HashMap<SourceDeclarationId, Vec<CodeUnit>>,
}

impl GoFileSourceFacts {
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

pub trait GoSourceFactProvider: Send + Sync {
    /// Missing publication is unavailable; a published empty file returns Some.
    fn go_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<GoFileSourceFacts>>;
}
