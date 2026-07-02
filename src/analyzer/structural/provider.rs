//! The capability surface a language analyzer exposes to structural search.
//!
//! Follows the `import_analysis_provider()` idiom: `IAnalyzer` has a default
//! `structural_search_providers()` returning nothing; each language analyzer
//! whose adapter supplies a [`StructuralSpec`] exposes its inner
//! `TreeSitterAnalyzer` as a provider, and `MultiAnalyzer` concatenates its
//! delegates'. Each provider covers exactly one language.

use super::extract::extract_file_facts;
use super::facts::FileFacts;
use super::spec::StructuralSpec;
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
use crate::analyzer::{Language, ProjectFile};
use std::sync::Arc;

pub trait StructuralSearchProvider: Send + Sync {
    fn structural_language(&self) -> Language;

    /// Every analyzed file of this provider's language, unsorted; callers
    /// order for determinism.
    fn structural_files(&self) -> Vec<ProjectFile>;

    /// Normalized facts for one file, extracted from the in-memory source.
    /// `None` when the file is not held by this analyzer, is empty, or the
    /// adapter has no structural spec. Milestone 3 adds a moka facts cache
    /// behind this same signature.
    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>>;
}

impl<A: LanguageAdapter> StructuralSearchProvider for TreeSitterAnalyzer<A> {
    fn structural_language(&self) -> Language {
        self.adapter().language()
    }

    fn structural_files(&self) -> Vec<ProjectFile> {
        self.all_files().cloned().collect()
    }

    fn structural_facts(&self, file: &ProjectFile) -> Option<Arc<FileFacts>> {
        let spec: &'static dyn StructuralSpec = self.adapter().structural_spec()?;
        let source = self.file_source(file)?;
        let grammar = self.adapter().parser_language();
        extract_file_facts(spec, &grammar, source).map(Arc::new)
    }
}
