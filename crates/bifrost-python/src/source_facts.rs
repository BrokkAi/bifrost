//! Mounted read-side input for Python declaration consumers.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::python_facts::PythonSourceFacts;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::source_facts::SourceFactRows;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PythonFileSourceFacts {
    pub occurrences: SourceFactRows,
    pub facts: PythonSourceFacts,
}

impl PythonFileSourceFacts {
    /// Select the canonical callable for one exact current-syntax focus.
    pub fn callable_return_for_range(
        &self,
        start: usize,
        end: usize,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<&brokk_bifrost_core::analyzer::python_facts::PythonCallableReturnFact> {
        for fact in &self.facts.callable_returns {
            if !keep_going() {
                return None;
            }
            let declaration = self.occurrences.declaration(fact.declaration);
            let range = self.occurrences.occurrence(declaration.occurrence).range;
            if range.start_byte == start && range.end_byte == end {
                return Some(fact);
            }
        }
        None
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.occurrences
            .estimated_bytes()
            .saturating_add(self.facts.estimated_retained_bytes())
    }
}

pub trait PythonSourceFactProvider: Send + Sync {
    /// Missing publication is unavailable; a published empty file returns Some.
    /// `keep_going` is the caller's admission and traversal continuation check.
    fn python_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<PythonFileSourceFacts>>;
}
