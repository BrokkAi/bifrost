use crate::analyzer::IAnalyzer;
use crate::analyzer::store::Result;
use crate::analyzer::store::StoreError;
use crate::analyzer::store::resolution_operation::reverse::*;

use crate::analyzer::{CodeUnit, ProjectFile};
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
/// Choose source admission and site projection using the caller file's rules.
/// Kept here so reverse consumers share the same caller-language dispatch.
pub fn selected_reverse_reference_file<'a>(
    analyzer: &'a dyn IAnalyzer,
    target_analyzer: &'a dyn IAnalyzer,
    file: &ProjectFile,
) -> Result<crate::analyzer::structural::reference_edges::SelectedReferenceFileProjection<'a>> {
    crate::analyzer::languages::language_support_for_hook(
        crate::analyzer::common::language_for_file(file),
        "selected_reverse_reference_file",
    )
    .expect("a selected reverse caller has language support")
    .selected_reverse_reference_file(analyzer, target_analyzer, file)
}
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
/// Source admission has already selected the caller-language analyzer through
/// LanguageSupport. A missing facade or package-object bridge is an error,
/// whereas a reference explicitly outside a declaration has no enclosing unit.
pub fn selected_reverse_reference_owner(
    file: &crate::analyzer::structural::reference_edges::SelectedReferenceFileProjection<'_>,
    owner: ReverseEnclosingUnit,
) -> Result<Option<CodeUnit>> {
    if matches!(owner, ReverseEnclosingUnit::MissingSource) {
        return Err(StoreError::corrupt(format!(
            "selected reverse caller owner is absent from selected source: {}",
            file.file
        )));
    }
    owner.into_unit()
}
