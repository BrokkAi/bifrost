use super::*;
#[doc(hidden)]
pub fn navigation(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    definition: DefinitionLookupOutcome,
    operation: NavigationOperation,
) -> NavigationLookupOutcome {
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    navigation_lookup_outcome(
        analyzer,
        scope.token(),
        &mut context,
        file,
        definition.into(),
        language_for_file(file),
        operation,
    )
}
