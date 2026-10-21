#[cfg(test)]
mod ruby_extraction_tests {
    use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

    use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::fq_name::FqName;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuery;

    use brokk_bifrost_core::analyzer::RelationalName;

    use brokk_bifrost_core::analyzer::definition_lookup::sort_units;

    use brokk_bifrost_ruby_analysis::RubyAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_test_macros::hardwon;
    use std::path::PathBuf;
    #[test]
    #[hardwon("#3078: an incomplete C++ lookup was cached as an authoritative empty result")]
    fn cancelled_relational_lookup_does_not_memoize_an_empty_answer() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("widget.rb", "class Widget\nend\n")
            .build();
        let analyzer = RubyAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Ruby);
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        cancellation.cancel();
        {
            let _scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_cancellation(
                    &analyzer,
                    &cancellation,
                );
            assert!(lookup.fqn("Widget").is_empty());
            assert!(
                lookup
                    .file_identifier(&fixture.file("widget.rb"), "Widget")
                    .is_empty()
            );
        }

        let recovered = lookup.fqn("Widget");
        assert!(
            recovered.iter().any(|unit| unit.fq_name() == "Widget"),
            "{recovered:?}"
        );
        assert_eq!(
            lookup.file_identifier(&fixture.file("widget.rb"), "Widget"),
            recovered,
            "a cancelled file-identifier read must be retried too"
        );
        assert!(lookup.memo.fqn_cache.lock().unwrap().is_empty());
    }
    #[test]
    #[hardwon("#3078: a failed C++ definition batch could poison later lookup answers")]
    fn failed_relational_lookup_does_not_publish_later_memo_entries() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("widget.rb", "class Widget\nend\n")
            .build();
        let analyzer = RubyAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Ruby);
        // The store rejects an exact-name question with no name. This takes
        // the real Failed batch path without relying on an I/O race.
        assert!(
            lookup
                .query_values(
                    Language::Ruby,
                    vec![(
                        RelationalName::stable(FqName::new()),
                        RelationalDefinitionQuery::ExactName
                    )]
                )
                .is_empty()
        );
        let recovered = lookup.fqn("Widget");
        assert!(
            recovered.iter().any(|unit| unit.fq_name() == "Widget"),
            "{recovered:?}"
        );
        assert!(
            lookup.memo.fqn_cache.lock().unwrap().is_empty(),
            "a lookup that observed a failed batch must not publish memo entries"
        );
    }
    /// Four Ruby files declaring one bare top-level method: two inside the
    /// file set a test passes, one outside it, and one file that declares an
    /// unrelated name only.
    struct BareIdentifierProject {
        _temp: tempfile::TempDir,
        root: PathBuf,
        analyzer: RubyAnalyzer,
    }
    impl BareIdentifierProject {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("create temp dir");
            let root = temp.path().canonicalize().expect("canonicalize temp dir");
            for (rel, contents) in [
                ("lib/alpha.rb", "def shared_helper\n  1\nend\n"),
                ("lib/beta.rb", "def shared_helper\n  2\nend\n"),
                ("lib/gamma.rb", "def other_helper\n  3\nend\n"),
                ("lib/delta.rb", "def shared_helper\n  4\nend\n"),
            ] {
                ProjectFile::new(root.clone(), rel)
                    .write(contents)
                    .unwrap_or_else(|err| panic!("write {rel}: {err}"));
            }
            let analyzer =
                RubyAnalyzer::from_project(TestProject::new(root.clone(), Language::Ruby));
            Self {
                _temp: temp,
                root,
                analyzer,
            }
        }

        fn file(&self, rel: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel)
        }

        fn lookup(&self) -> AnalyzerDefinitionLookup<'_> {
            AnalyzerDefinitionLookup::new(&self.analyzer, Language::None)
        }

        /// What the `BoundedDefinitionLookup::file_identifier_in_files` trait
        /// default computes: one file-scoped store read per file, published in
        /// the canonical order.
        fn per_file_union(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
            let lookup = self.lookup();
            let mut units = files
                .iter()
                .flat_map(|file| lookup.file_identifier(file, ident))
                .collect::<Vec<_>>();
            sort_units(&mut units);
            units.dedup();
            units
        }

        fn sources(units: &[CodeUnit]) -> Vec<String> {
            units
                .iter()
                .map(|unit| brokk_bifrost_core::path_utils::rel_path_string(unit.source()))
                .collect()
        }
    }
    #[test]
    #[hardwon("#2883: optimized bare-name lookup must preserve file-set membership and ordering")]
    fn file_set_identifier_lookup_matches_the_per_file_union() {
        let project = BareIdentifierProject::new();
        let all_three = [
            project.file("lib/alpha.rb"),
            project.file("lib/beta.rb"),
            project.file("lib/gamma.rb"),
        ];

        let overridden = project
            .lookup()
            .file_identifier_in_files(&all_three, "shared_helper");
        assert_eq!(
            overridden,
            project.per_file_union(&all_three, "shared_helper"),
            "the workspace-wide filter must publish exactly the trait default's set and order"
        );
        assert_eq!(
            BareIdentifierProject::sources(&overridden),
            vec!["lib/alpha.rb".to_string(), "lib/beta.rb".to_string()],
            "lib/delta.rb declares the same identifier but is outside the file set"
        );

        let subset = [project.file("lib/alpha.rb"), project.file("lib/gamma.rb")];
        let overridden_subset = project
            .lookup()
            .file_identifier_in_files(&subset, "shared_helper");
        assert_eq!(
            overridden_subset,
            project.per_file_union(&subset, "shared_helper"),
            "a subset must agree with the trait default over that same subset"
        );
        assert_eq!(
            BareIdentifierProject::sources(&overridden_subset),
            vec!["lib/alpha.rb".to_string()],
            "dropping lib/beta.rb from the set must drop its declaration"
        );
    }
    /// Cost pin for #2883: every lookup built under one request scope answers
    /// from one memo, so the second lookup to ask for a name it already holds
    /// costs no store read. Candidate discovery builds one lookup per candidate
    /// file, which is why this is what the scan actually pays.
    #[test]
    #[hardwon(
        "#2883: each candidate lookup repeated the same relational answer within one request"
    )]
    fn lookups_under_one_query_scope_share_one_definition_memo() {
        let project = BareIdentifierProject::new();
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };
        let _scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
            &project.analyzer,
        );

        let before = checkouts();
        let first = project.lookup().identifier("shared_helper");
        let first_cost = checkouts() - before;
        let second = project.lookup().identifier("shared_helper");
        let second_cost = checkouts() - before - first_cost;

        assert!(
            first_cost > 0,
            "the first lookup must actually ask the store"
        );
        assert_eq!(
            second_cost, 0,
            "a second lookup under the same scope must answer from the shared memo"
        );
        assert_eq!(
            first, second,
            "the shared memo must publish the answer the store read produced"
        );
    }
    /// The counterpart: with no request scope open there is no shared memo, so
    /// each lookup owns its own and pays its own store read. Ownership of the
    /// memo is what changes, not what a lookup answers.
    #[test]
    #[hardwon("#2883: shared request memoization must not outlive the request scope")]
    fn lookups_outside_a_query_scope_keep_their_own_definition_memo() {
        let project = BareIdentifierProject::new();
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };

        let before = checkouts();
        let first = project.lookup().identifier("shared_helper");
        let first_cost = checkouts() - before;
        let second = project.lookup().identifier("shared_helper");
        let second_cost = checkouts() - before - first_cost;

        assert_eq!(
            (first_cost, second_cost),
            (1, 1),
            "without a scope each lookup asks the store for itself"
        );
        assert_eq!(first, second);
    }
    /// Parity and cost pin for the batched name prefetch: after
    /// `prefetch_fqns`, a point `fqn` ask costs no store read and answers
    /// exactly what the unprefetched point path computed -- including the
    /// name that resolves to nothing.
    #[test]
    #[hardwon("#2743: prefetched Ruby name answers still incurred one store read per visible file")]
    fn prefetched_fqns_answer_from_the_shared_memo_without_store_reads() {
        let project = BareIdentifierProject::new();
        let names = vec!["shared_helper".to_string(), "no_such_name".to_string()];
        let unprefetched: Vec<_> = {
            let _scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
                &project.analyzer,
            );
            names
                .iter()
                .map(|name| project.lookup().fqn(name))
                .collect()
        };

        let _scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
            &project.analyzer,
        );
        let checkouts = || {
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
        };
        project.lookup().prefetch_fqns(&names);
        let before = checkouts();
        let prefetched: Vec<_> = names
            .iter()
            .map(|name| project.lookup().fqn(name))
            .collect();
        assert_eq!(
            checkouts() - before,
            0,
            "a prefetched name must answer from the shared memo"
        );
        assert_eq!(
            prefetched, unprefetched,
            "a memoized answer must equal the point path's"
        );
    }
    /// Cost pin for #2743: what one bare identifier costs in store reads must
    /// not grow with the size of the file set.
    ///
    /// The counter is the relational batch reader checkout, one per store
    /// round trip. `EXPLAIN QUERY PLAN` is this repository's preferred pin for
    /// the shape of one query; it cannot express how many queries a caller
    /// issues, which is the whole defect here.
    #[test]
    #[hardwon("#2743: a bare Ruby method lookup paid one relational read for every visible file")]
    fn file_set_identifier_lookup_cost_is_independent_of_the_file_count() {
        let project = BareIdentifierProject::new();
        let all_four = [
            project.file("lib/alpha.rb"),
            project.file("lib/beta.rb"),
            project.file("lib/gamma.rb"),
            project.file("lib/delta.rb"),
        ];

        let measure = |files: &[ProjectFile]| {
            let before = project
                .analyzer
                .relational_batch_reader_checkouts_for_test();
            project
                .lookup()
                .file_identifier_in_files(files, "shared_helper");
            project
                .analyzer
                .relational_batch_reader_checkouts_for_test()
                - before
        };

        let two_files = measure(&all_four[..2]);
        let four_files = measure(&all_four);
        assert_eq!(
            (two_files, four_files),
            (1, 1),
            "the override asks the store once for this single-language file set, whatever its size"
        );

        let before = project
            .analyzer
            .relational_batch_reader_checkouts_for_test();
        project.per_file_union(&all_four, "shared_helper");
        let trait_default = project
            .analyzer
            .relational_batch_reader_checkouts_for_test()
            - before;
        assert_eq!(
            trait_default,
            four_files * all_four.len(),
            "the trait default pays one store read per file, which is what the override removes"
        );
    }
}
