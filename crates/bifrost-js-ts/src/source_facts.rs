//! Mounted read-side input for JavaScript and TypeScript declaration facts.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::js_ts_facts::JsTsSourceFacts;
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceFactRows};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct JsTsFileSourceFacts {
    pub source: SourceFactRows,
    pub imports: Vec<SourceImportFact>,
    pub facts: JsTsSourceFacts,
    /// Exact source-declaration to mounted-code-unit links. A declaration can
    /// intentionally have more than one unit (for example an inline member).
    pub declaration_units: HashMap<SourceDeclarationId, Vec<CodeUnit>>,
}

impl JsTsFileSourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        brokk_bifrost_core::analyzer::source_facts::source_projection_retained_bytes(
            &self.source,
            self.facts.estimated_retained_bytes(),
            &self.declaration_units,
        )
        .saturating_add(
            self.imports
                .capacity()
                .saturating_mul(std::mem::size_of::<SourceImportFact>()),
        )
        .saturating_add(
            self.imports
                .iter()
                .map(SourceImportFact::estimated_retained_bytes)
                .fold(0usize, usize::saturating_add),
        )
    }
}

pub trait JsTsSourceFactProvider: Send + Sync {
    /// Missing publication is unavailable; a published empty file returns
    /// `Some` with empty vectors.
    fn js_ts_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<JsTsFileSourceFacts>>;
}
