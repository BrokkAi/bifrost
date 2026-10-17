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
        brokk_bifrost_core::analyzer::source_facts::source_projection_retained_bytes(
            &self.source,
            self.facts.estimated_retained_bytes(),
            &self.declaration_units,
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
