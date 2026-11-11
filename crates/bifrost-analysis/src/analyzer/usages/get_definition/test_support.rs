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

thread_local! {
    static PREPARATION_WORK: std::cell::Cell<(usize, usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0, 0)) };
}

/// Parser invocations, line-start bytes, and prepared files on this query thread.
pub fn preparation_work() -> (usize, usize, usize, usize) {
    PREPARATION_WORK.with(std::cell::Cell::get)
}

pub(super) fn count_preparation_work(parses: usize, bytes: usize, preparations: usize) {
    PREPARATION_WORK.with(|work| {
        let old = work.get();
        work.set((old.0 + parses, old.1 + bytes, old.2 + preparations, old.3));
    });
}

pub(super) fn count_source_validation_bytes(bytes: usize) {
    PREPARATION_WORK.with(|work| {
        let old = work.get();
        work.set((old.0, old.1, old.2, old.3 + bytes));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_preparation_is_rejected() {
        // `/tmp` is not absolute on Windows, and `ProjectFile` requires an
        // absolute root.
        let file = ProjectFile::new(std::env::temp_dir(), "Sample.java");
        let source: Arc<str> = Arc::from("final class Sample {}");
        let tree = parse_tree_for_language(&file, Language::Java, &source).unwrap();
        let prepared = PreparedDefinitionSource::new(Arc::clone(&source), tree);
        let stale: Arc<str> = Arc::from("final class Other {}");
        assert!(
            std::panic::catch_unwind(|| assert_prepared_source_matches(&prepared, &stale)).is_err()
        );
    }
}
