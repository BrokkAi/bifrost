#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

    use brokk_bifrost_core::analyzer::Language;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredCandidateDirection;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringCoverageFrontier;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_core::analyzer::structural::resolution::PrecedenceTier;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter;

    use brokk_bifrost_analysis::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test;

    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use brokk_bifrost_core::analyzer::model::ProjectFile;
    use std::collections::BTreeSet;

    fn parsed_scala(
        label: &str,
        source: &str,
    ) -> (
        FileResolutionFacts,
        LoweredResolutionFactsWithIdentityCatalog,
    ) {
        let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.scala"));
        let adapter = ScalaAdapter;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
        let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Scala, &facts);
        (facts, artifact)
    }

    fn parsed_kotlin(
        label: &str,
        source: &str,
    ) -> (
        FileResolutionFacts,
        LoweredResolutionFactsWithIdentityCatalog,
    ) {
        let file = ProjectFile::new(std::env::temp_dir(), format!("{label}.kt"));
        let adapter = KotlinAdapter;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let facts = adapter.parse_file(&file, source, &tree).resolution_facts;
        let artifact = lower_for_test(BindingFragmentId::for_test(label), Language::Kotlin, &facts);
        (facts, artifact)
    }

    #[test]
    fn kotlin_source_package_lookups_cover_placement_when_every_root_name_is_requested() {
        let (facts, lowered) = parsed_kotlin(
            "kotlin-package-placement-covered",
            "package sample\nfun use() { missing() }\n",
        );
        let placement = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .expect("Kotlin source records its package placement endpoint")
            .site;
        assert!(facts.package_references.iter().any(|reference| {
            facts.identifiers.iter().any(|identifier| {
                identifier.site == reference.reference
                    && facts.names[identifier.name.index()].spelling == "missing"
            })
        }));
        assert!(!lowered.lexical.gaps().iter().any(|gap| {
            gap.site() == placement
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
    }

    #[test]
    fn kotlin_placement_closes_without_any_package_lookup() {
        let (facts, lowered) = parsed_kotlin(
            "kotlin-package-placement-closed",
            "package sample\nclass Box\n",
        );
        let placement = facts
            .gaps
            .iter()
            .find(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
            .expect("Kotlin source records its package placement endpoint")
            .site;
        assert!(facts.package_references.is_empty());
        // An empty set of package lookups is complete when every root
        // reference is covered, so no placement frontier remains open.
        assert!(!lowered.lexical.gaps().iter().any(|gap| {
            gap.site() == placement
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
        }));
    }

    #[test]
    fn scala_package_reference_uses_other_compilation_unit_precedence() {
        let (facts, lowered) = parsed_scala(
            "scala-package-precedence",
            "package sample\nobject Consumer { val value: Remote = null }\n",
        );
        let reference = lowered
            .common
            .package_references
            .iter()
            .find(|reference| reference.namespace == ResolutionNamespace::Type)
            .expect("unresolved Scala type reference publishes package membership lookup");
        assert!(
            facts
                .identifiers
                .iter()
                .any(|identifier| identifier.site == reference.source_site)
        );

        let path = lowered
            .lexical
            .paths()
            .iter()
            .map(|(_, path)| path)
            .find(|path| {
                path.start().node() == reference.root_scope
                    && path.end().node() == BindingNodeId::universal_root()
                    && path
                        .precedence()
                        .iter()
                        .any(|step| step.tier == PrecedenceTier::OtherCompilationUnitPackage)
            })
            .expect("Scala package lookup path is lowered");
        assert_eq!(
            path.precedence()
                .iter()
                .find(|step| step.tier == PrecedenceTier::OtherCompilationUnitPackage)
                .expect("Scala package lookup keeps its existing package tier")
                .ordinal,
            0
        );
        assert_eq!(
            path.precedence()
                .iter()
                .find(|step| step.tier == PrecedenceTier::CandidateOriginRank)
                .expect("Scala package lookup records its candidate origin")
                .ordinal,
            3
        );
        assert!(PrecedenceTier::LexicalBinding < PrecedenceTier::ExplicitImport);
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::WildcardImport < path.precedence()[0].tier);
    }

    #[test]
    fn scala_named_import_precedes_wildcard_and_other_unit_package_lookup() {
        let (_, lowered) = parsed_scala(
            "scala-import-precedence",
            "package sample\n\
             import named.Remote\n\
             import wildcard.*\n\
             object Consumer { val named: Remote = null; val wildcard: Wild = null }\n",
        );
        let tiers = lowered
            .lexical
            .paths()
            .iter()
            .flat_map(|(_, path)| path.precedence().iter().map(|step| step.tier))
            .collect::<BTreeSet<_>>();
        assert!(tiers.contains(&PrecedenceTier::ExplicitImport), "{tiers:?}");
        assert!(tiers.contains(&PrecedenceTier::WildcardImport), "{tiers:?}");
        assert!(
            tiers.contains(&PrecedenceTier::OtherCompilationUnitPackage),
            "{tiers:?}"
        );
        assert!(PrecedenceTier::ExplicitImport < PrecedenceTier::WildcardImport);
        assert!(PrecedenceTier::WildcardImport < PrecedenceTier::OtherCompilationUnitPackage);
    }
}
