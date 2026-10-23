#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeSite;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::tests::JAVA_REFERENCE_KIND_SITES;

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;

    use brokk_bifrost_core::analyzer::usages::model::ReferenceKind;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceSiteClassifier;

    use brokk_bifrost_core::analyzer::structural::edges::SiteClass;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitSurface;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::ast_id;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_reference_kind;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_reference_kind_scan_oracle;

    use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::token_range;

    /// The reusable index is a semantics-preserving acceleration of the former
    /// arena scan. Exercise every source classification branch against that
    /// scan oracle, the public delegating function, and the exact AST-id join.
    #[test]
    fn indexed_reference_sites_match_the_scan_oracle_for_every_kind() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/ReferenceKinds.java", JAVA_REFERENCE_KIND_SITES)
            .build();
        let file = project.file("src/ReferenceKinds.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declaration = |fq_suffix: &str| {
            analyzer
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        };
        let classifier =
            ReferenceSiteClassifier::new(&analyzer, &file).expect("Java must provide facts");
        let base = declaration("Base");
        let cases = [
            (
                "method call",
                "        method();",
                "method",
                declaration("Child.method"),
                ReferenceKind::MethodCall,
            ),
            (
                "static call",
                "        Base.staticPing();",
                "staticPing",
                declaration("Base.staticPing"),
                ReferenceKind::StaticReference,
            ),
            (
                "super call",
                "        super.ping();",
                "ping",
                declaration("Base.ping"),
                ReferenceKind::SuperCall,
            ),
            (
                "field read",
                "        int read = this.field;",
                "field",
                declaration("Child.field"),
                ReferenceKind::FieldRead,
            ),
            (
                "field write",
                "        this.field = read;",
                "field",
                declaration("Child.field"),
                ReferenceKind::FieldWrite,
            ),
            (
                "type reference",
                "        Base local = other;",
                "Base",
                base.clone(),
                ReferenceKind::TypeReference,
            ),
            (
                "inheritance",
                "class Child extends Base",
                "Base",
                base,
                ReferenceKind::Inheritance,
            ),
        ];

        for (label, marker, token, target, expected) in cases {
            let (start_byte, end_byte) = token_range(JAVA_REFERENCE_KIND_SITES, marker, token);
            let indexed = classifier.classify_reference_kind(start_byte, end_byte, &target);
            let scanned = classify_reference_kind_scan_oracle(
                &analyzer,
                &classifier.facts,
                start_byte,
                end_byte,
                &target,
            );
            assert_eq!(indexed, scanned, "indexed/scanned disagreement at {label}");
            assert_eq!(indexed, Some(expected), "wrong kind at {label}");
            assert_eq!(
                classify_reference_kind(&analyzer, &file, start_byte, end_byte, &target),
                indexed,
                "public delegator disagrees at {label}"
            );
            let identifier = classifier
                .facts
                .nodes()
                .iter()
                .enumerate()
                .find(|(_, node)| {
                    node.kind == NormalizedKind::Identifier
                        && node.range.start_byte == start_byte
                        && node.range.end_byte == end_byte
                })
                .map(|(id, _)| u32::try_from(id).expect("structural fact id must fit u32"))
                .unwrap_or_else(|| panic!("exact identifier fact missing at {label}"));
            assert_eq!(
                classifier.ast_id(start_byte, end_byte),
                Some(ast_id(classifier.facts.source_identity(), identifier)),
                "wrong exact identifier AST id at {label}"
            );
        }
    }
    #[test]
    fn external_usage_graph_excludes_only_target_definition_overlap() {
        const SOURCE: &str = r#"package fixture;

class External {}

class Target {
    Target child() { return this; }
    External external() { return null; }
}
"#;
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Target.java", SOURCE)
            .build();
        let file = project.file("src/Target.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declaration = |fq_suffix: &str| {
            analyzer
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        };
        let target = declaration("Target");
        let external = declaration("External");
        let child = declaration("Target.child");
        let external_method = declaration("Target.external");
        let (self_start, self_end) = token_range(SOURCE, "    Target child()", "Target");
        let (external_start, external_end) =
            token_range(SOURCE, "    External external()", "External");
        let row = |start_byte, end_byte, enclosing, target| ReferenceEdgeRow {
            site: EdgeSite {
                file: file.clone(),
                range: Range {
                    start_byte,
                    end_byte,
                    start_line: 1,
                    end_line: 1,
                },
                ast_id: None,
                enclosing: Some(enclosing),
            },
            target,
            reference_kind: Some(ReferenceKind::TypeReference),
            proof: UsageProof::Proven,
            ambiguous_candidate: false,
            usage_kind: UsageHitKind::Reference,
            site_class: SiteClass::UseSite,
            owner_relation: OwnerRelation::SameOwner,
            provenance: EdgeProvenance::Forward,
            generation: analyzer.project().analysis_generation(),
        };
        let self_type = row(self_start, self_end, child, target.clone());
        let external_type = row(
            external_start,
            external_end,
            external_method,
            external.clone(),
        );

        assert!(self_type.included_in(UsageHitSurface::ExternalUsages));
        assert!(external_type.included_in(UsageHitSurface::ExternalUsages));
        let target_spans = analyzer
            .ranges(&target)
            .into_iter()
            .map(|range| (target.source().clone(), range))
            .collect::<Vec<_>>();
        let external_spans = analyzer
            .ranges(&external)
            .into_iter()
            .map(|range| (external.source().clone(), range))
            .collect::<Vec<_>>();
        assert!(!self_type.included_in_external_usage_graph(&target_spans));
        assert!(external_type.included_in_external_usage_graph(&external_spans));

        let mut self_receiver = self_type.clone();
        self_receiver.usage_kind = UsageHitKind::SelfReceiver;
        assert!(
            !self_receiver.included_in(UsageHitSurface::ExternalUsages),
            "querying definition overlap must not reclassify a self-receiver as external"
        );
        assert!(
            self_receiver.overlaps_target_definition_spans(&target_spans),
            "definition overlap remains available independently of usage surface"
        );
    }
}
