#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::index::SnapshotStructuralIndexCache;

    use brokk_bifrost_analysis::analyzer::structural::index::StructuralIndexAcquisition;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#2445: master's import-binding cell gave a later capture its answer without the fill's reads"
    )]
    fn reference_edges_import_binding_memo_replays_reads_across_captures() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::read_ledger::{
            FactSubject, LookupKind, LookupQuestion, ReadKey, WorkspaceFactFamily,
        };
        use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceSiteClassifier;
        use brokk_bifrost_analysis::test_support::token_range;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_python_analysis::analyzer::PythonAnalyzer;

        // Match the Python shape of the aliased-import-kinds golden fixture.
        let source = "import a as b\nfrom a import x as y\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("a.py", "def x():\n    pass\n")
            .file("caller.py", source)
            .build();
        let analyzer = PythonAnalyzer::from_project(project.project().clone());
        let file = project.file("caller.py");
        let classifier =
            ReferenceSiteClassifier::new(&analyzer, &file).expect("Python must provide facts");
        let (start, end) = token_range(source, "from a import x as y", "y");

        let (first, first_reads) = capture_query_reads(&analyzer, || {
            classifier.is_import_binding_reference(&file, start, end)
        });
        let (second, second_reads) = capture_query_reads(&analyzer, || {
            classifier.is_import_binding_reference(&file, start, end)
        });

        assert!(first, "the alias must fill the import-binding memo");
        assert!(second, "the same classifier must retain its import answer");
        let first_keys = first_reads.keys();
        assert_eq!(second_reads.keys(), first_keys);
        assert_eq!(first_keys.len(), 2, "fill read keys: {first_keys:?}");
        assert_eq!(
            first_keys[0],
            ReadKey::file(
                Language::Python,
                "caller.py",
                git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                    .expect("fixture blob identity"),
            )
        );
        let ReadKey::Lookup { kind, question, .. } = &first_keys[1] else {
            panic!("fill must record overlay membership: {first_keys:?}");
        };
        assert_eq!(*kind, LookupKind::WorkspaceFact);
        assert_eq!(
            *question,
            LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::WorkspaceOverlayMembership,
                language: Language::None,
                subject: FactSubject::File {
                    rel_path: "caller.py".into(),
                },
            }
        );
        assert_eq!(first_reads.unattributed_reads(), 0);
        assert_eq!(second_reads.unattributed_reads(), 0);
    }

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
