#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::index::SnapshotStructuralIndexCache;

    use brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexAcquisition;

    use brokk_bifrost_test_macros::hardwon;

    /// #1459: an empty file (a real workspace shape -- empty `__init__.py`)
    /// must not abort the provider index. Before the fix,
    /// `extract_file_facts_limited` returned `Unavailable` for empty sources,
    /// this acquire came back `Unavailable { "structural index facts
    /// unavailable" }`, and the whole Python slice fell back to scan mode for
    /// the session.
    #[test]
    #[hardwon("#1459: an empty file prevented the structural provider index from completing")]
    fn empty_file_does_not_abort_the_provider_index() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let empty = ProjectFile::new(root.clone(), "pkg/__init__.py");
        empty.write("").expect("write empty file");
        let module = ProjectFile::new(root.clone(), "pkg/module.py");
        module
            .write("def real_function():\n    return 1\n")
            .expect("write module");
        let analyzer = brokk_bifrost_python_analysis::analyzer::PythonAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(
                root,
                brokk_bifrost_core::analyzer::model::Language::Python,
            ),
        );
        let providers =
            brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer::structural_fact_providers(
                &analyzer,
            );
        let provider = *providers.first().expect("python structural provider");

        let cache = SnapshotStructuralIndexCache::new(64 * 1024 * 1024);
        let StructuralIndexAcquisition::Ready { index, .. } =
            cache.acquire(provider, &CancellationToken::default())
        else {
            panic!("empty file must not reject the index")
        };
        assert!(index.file(&empty).is_some());
        assert!(index.file(&module).is_some());
    }
}
