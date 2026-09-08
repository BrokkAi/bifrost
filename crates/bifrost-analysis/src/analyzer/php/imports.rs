//! PHP's `ImportAnalysisProvider` impl and the memo cells behind it.
//!
//! What one PHP file imports is decided in `brokk-bifrost-php` while the
//! parser tree is present and persisted as that file's `type_identifiers`:
//! the FQ name every `use` declaration binds, plus the FQ name every type
//! reference resolves to through PHP's namespace rule. What stays here is the
//! lookup from those names to the declarations other workspace files publish,
//! the cache over it, and the reverse index built from it.

use std::sync::Arc;

use super::PhpAnalyzer;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, ImportAnalysisProvider, ImportInfo, ProjectFile,
    QueryScope,
};
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

impl ImportAnalysisProvider for PhpAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let names: Vec<String> = self
            .inner
            .type_identifiers_of(file)
            .unwrap_or_default()
            .into_iter()
            .collect();
        // One batched read for the whole file rather than one store round trip
        // per imported name (#1748's shape).
        let scope = AnalyzerQueryScope::new(self);
        let _token = scope.token();
        self.inner.prefetch_definitions(&names);

        let mut imported: HashSet<CodeUnit> = HashSet::default();
        for name in &names {
            // A file's own declarations are not imports: PHP reaches them
            // because they are declared here, not because a name was bound.
            imported.extend(self.definitions(name).filter(|unit| unit.source() != file));
        }

        let imported = Arc::new(imported);
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&imported));
        imported
    }

    /// The `use` declarations the parser recorded for this file, one row per
    /// bound local name (#2962). This is what the lexical-environment layer
    /// derives PHP's import binders from; `imported_code_units_of` above stays
    /// on `type_identifiers`, which additionally covers the names PHP's
    /// namespace rule binds with no `use` declaration at all (#1713).
    fn import_info_of(&self, token: QueryToken<'_>, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(token, file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        )
        .get(file)
        .map(|files| (**files).clone())
        .unwrap_or_default()
    }
}
