#[cfg(test)]
mod definition_lookup_tests {

    use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;
    use brokk_bifrost_core::analyzer::BoundedDefinitionLookup;

    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_test_macros::hardwon;

    /// One lookup's interner calls on this thread, with the answer it produced.
    ///
    /// The process-global segment interner is grow-only, so every distinct
    /// spelling a lookup mints is permanent vocabulary. The Cartesian suffix x
    /// object-encoding expansion minted ~500 of them per missed scala name
    /// (2^K - 1 per suffix, K <= 8), which accumulated ~2.5 GB of transient
    /// spellings per large scala repository and OOM-killed the #3268 corpus
    /// lane.
    fn measured_lookup(lookup: &AnalyzerDefinitionLookup<'_>, name: &str) -> (Vec<String>, u64) {
        brokk_bifrost_core::analyzer::fq_name::counters::reset();
        let units = lookup.by_normalized_fqn(name);
        let (_resolves, interns) = brokk_bifrost_core::analyzer::fq_name::counters::counts();
        (
            units.into_iter().map(|unit| unit.fq_name()).collect(),
            interns,
        )
    }

    /// A deep qualified name that addresses no declaration must cost the
    /// interner one spelling per separator suffix plus the query's own
    /// identity work, not the suffix x encoding product.
    #[test]
    #[hardwon(
        "#3299: a missed Scala name expanded the process-global identifier interner combinatorially"
    )]
    fn missed_scala_lookup_mints_only_terminal_spellings() {
        use brokk_bifrost_jvm_analysis::analyzer::ScalaAnalyzer;

        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file(
                "app/Facade.scala",
                "package app\n\nobject Facade {\n  object Nested {\n    class Member\n  }\n}\n\nclass Consumer\n",
            )
            .build();
        let analyzer = ScalaAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Scala);
        let name = "com.example.very.deeply.nested.missing.Absent";
        let (found, minted) = measured_lookup(&lookup, name);
        assert!(found.is_empty(), "{found:?}");
        let segments = name.split('.').count() as u64;
        assert!(
            minted <= 4 * segments,
            "a missed lookup must mint at most one spelling per separator suffix plus its own \
             query identity, got {minted} spellings for {segments} segments"
        );
    }

    /// A name the normalized view answers does not consult the terminal-keyed
    /// identifier view at all: that view is the compatibility net for the rows
    /// the structural seek cannot reach, not a second round for every answer.
    #[test]
    #[hardwon("#3299: a successful Scala lookup still generated the expensive fallback vocabulary")]
    fn resolved_scala_lookup_does_not_expand_identifier_candidates() {
        use brokk_bifrost_jvm_analysis::analyzer::ScalaAnalyzer;

        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file(
                "app/Facade.scala",
                "package app\n\nobject Facade {\n  object Nested {\n    class Member\n  }\n}\n\nclass Consumer\n",
            )
            .build();
        let analyzer = ScalaAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Scala);
        let name = "app.Facade.Nested.Member";
        let (found, minted) = measured_lookup(&lookup, name);
        assert!(
            found
                .iter()
                .any(|fq_name| fq_name == "app.Facade$.Nested$.Member"),
            "{found:?}"
        );
        let segments = name.split('.').count() as u64;
        assert!(
            minted <= 4 * segments,
            "a resolved lookup must not mint the identifier fallback vocabulary, got {minted} \
             spellings for {segments} segments"
        );
    }

    /// The bounded vocabulary still answers the declaration the encoded
    /// spelling persists: a dot-joined scala query resolves a nested object
    /// chain that is stored with `$` markers, and the object terminal is
    /// reached through its own `$` decoration.
    #[test]
    #[hardwon(
        "#3299: a bounded fallback must keep resolving Scala names stored with object markers"
    )]
    fn terminal_spelling_vocabulary_still_resolves_encoded_scala_names() {
        use brokk_bifrost_jvm_analysis::analyzer::ScalaAnalyzer;

        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file(
                "app/Facade.scala",
                "package app\n\nobject Facade {\n  object Nested {\n    class Member\n  }\n}\n\nclass Consumer\n",
            )
            .build();
        let analyzer = ScalaAnalyzer::from_project(fixture.project().clone());
        let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Scala);
        for (query, expected) in [
            ("app.Facade", "app.Facade$"),
            ("app.Facade.Nested", "app.Facade$.Nested$"),
            ("app.Facade.Nested.Member", "app.Facade$.Nested$.Member"),
        ] {
            let found = lookup.by_normalized_fqn(query);
            assert!(
                found.iter().any(|unit| unit.fq_name() == expected),
                "{query} must resolve {expected}: {found:?}"
            );
        }
        // The nested member is also reachable from its bare terminal, which is
        // the spelling the identifier index is keyed by.
        assert!(
            lookup
                .identifier("Member")
                .iter()
                .any(|unit| unit.fq_name() == "app.Facade$.Nested$.Member")
        );
    }
}
