#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

    use brokk_bifrost_analysis::analyzer::resolution::reference_vocabulary::EdgeCompleteness;

    use brokk_bifrost_analysis::analyzer::resolution::reference_vocabulary::EdgeIncompleteReason;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::test_support::Fixture;

    use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::tests::JAVA_BASE;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::tests::JAVA_CALLER;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::tests::JAVA_DERIVED;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::tests::JAVA_TARGET;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceFileResult;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceRow;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceTarget;

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_analysis::analyzer::usages::finder::ReferenceEngine;

    use brokk_bifrost_core::analyzer::usages::model::UsageHit;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_owner_relation;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::forward_edges_for_file;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::forward_edges_from_occurrences;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::inverse_edges_for_declaration;

    use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::occurrences_for_file;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::reference_hits_from_fuzzy_result;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    #[cfg(test)]
    use std::collections::BTreeSet;
    #[cfg(test)]
    #[test]
    #[hardwon(
        "#4428: retained incomplete and ambiguous resolution candidates must not become proven forward edges"
    )]
    fn forward_resolution_status_preserves_proof_and_run_completeness() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/fixture/Registry.java", JAVA_TARGET),
                ("src/fixture/Startup.java", JAVA_CALLER),
            ],
        );
        let analyzer = fixture.analyzer();
        let caller = &fixture.files[1];
        let target = fixture.declaration("Registry.register");
        let occurrences = occurrences_for_file(analyzer, caller, &CancellationToken::new())
            .expect("uncancelled occurrence derivation");
        let template = occurrences
            .rows
            .iter()
            .find(|row| {
                matches!(
                    &row.target,
                    OccurrenceTarget::Resolved(units)
                        if units.len() == 1 && units[0] == target
                )
            })
            .cloned()
            .expect("fixture must contain a resolved singleton reference");
        assert_eq!(
            template.resolution_status,
            Some(DefinitionLookupStatus::Resolved)
        );

        let derive_rows = |rows: Vec<OccurrenceRow>| {
            forward_edges_from_occurrences(
                analyzer,
                caller,
                OccurrenceFileResult {
                    rows,
                    completeness: OccurrenceCompleteness::Complete,
                },
                analyzer.project().analysis_generation(),
            )
            .expect("forward edge conversion does not perform cancellable work")
        };
        let derive = |target: OccurrenceTarget, status: DefinitionLookupStatus| {
            let mut row = template.clone();
            row.target = target;
            row.resolution_status = Some(status);
            derive_rows(vec![row])
        };

        let alternatives = fixture.declaration("Startup.boot");
        let cases = [
            (
                DefinitionLookupStatus::Resolved,
                1,
                Some(UsageProof::Proven),
                None,
            ),
            (DefinitionLookupStatus::NoDefinition, 0, None, None),
            (
                DefinitionLookupStatus::Incomplete,
                1,
                Some(UsageProof::Unproven),
                Some(EdgeIncompleteReason::ForwardResolutionIncomplete),
            ),
            (
                DefinitionLookupStatus::Ambiguous,
                2,
                Some(UsageProof::Unproven),
                Some(EdgeIncompleteReason::ForwardResolutionIncomplete),
            ),
            (
                DefinitionLookupStatus::ExceededBudget(ReceiverBudgetLimit::ScopeNodes),
                0,
                None,
                Some(EdgeIncompleteReason::ForwardResolutionIncomplete),
            ),
            (
                DefinitionLookupStatus::Cancelled,
                0,
                None,
                Some(EdgeIncompleteReason::Cancelled),
            ),
        ];
        for (status, edge_count, proof, reason) in cases {
            let target = match status {
                DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Incomplete => {
                    OccurrenceTarget::Resolved(vec![target.clone()])
                }
                DefinitionLookupStatus::Ambiguous => {
                    OccurrenceTarget::Resolved(vec![target.clone(), alternatives.clone()])
                }
                _ => OccurrenceTarget::Unresolved(status),
            };
            let result = derive(target, status);
            assert_eq!(result.edges.len(), edge_count, "status {status:?}");
            if let Some(proof) = proof {
                assert!(
                    result.edges.iter().all(|edge| edge.proof == proof),
                    "status {status:?} produced the wrong proof: {:?}",
                    result.edges
                );
            }
            match (reason, result.completeness) {
                (None, EdgeCompleteness::Complete) => {}
                (Some(reason), EdgeCompleteness::Incomplete { reasons }) => {
                    assert!(reasons.contains(&reason), "status {status:?}: {reasons:?}");
                    if status == DefinitionLookupStatus::Cancelled {
                        assert!(
                            !reasons.contains(&EdgeIncompleteReason::ForwardResolutionIncomplete)
                        );
                    }
                }
                (reason, completeness) => {
                    panic!("status {status:?} expected reason {reason:?}, got {completeness:?}")
                }
            }
        }

        let mut incomplete = template.clone();
        incomplete.resolution_status = Some(DefinitionLookupStatus::Incomplete);
        let mixed = derive_rows(vec![template.clone(), incomplete]);
        assert_eq!(mixed.edges.len(), 2);
        assert_eq!(
            mixed
                .edges
                .iter()
                .filter(|edge| edge.proof == UsageProof::Proven)
                .count(),
            1
        );
        assert_eq!(
            mixed
                .edges
                .iter()
                .filter(|edge| edge.proof == UsageProof::Unproven)
                .count(),
            1
        );
        assert!(matches!(
            mixed.completeness,
            EdgeCompleteness::Incomplete { ref reasons }
                if reasons.contains(&EdgeIncompleteReason::ForwardResolutionIncomplete)
        ));
    }
    #[cfg(test)]
    #[test]
    fn reference_engine_file_scan_never_expands_its_hard_scope() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
                (
                    "src/Other.java",
                    "package fixture; class Other { void unrelated() {} }",
                ),
            ],
        );
        let run = ReferenceEngine::new().scan_file_edges(fixture.analyzer(), &fixture.files[1..2]);
        assert_eq!(run.work.candidate_files, 1);
        assert_eq!(run.work.scanned_files, 1);
        assert!(
            run.edges
                .iter()
                .all(|edge| edge.site.file == fixture.files[1])
        );
    }
    #[cfg(test)]
    #[test]
    fn fuzzy_overload_buckets_keep_their_exact_edge_targets() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Overloads.java",
                "package fixture; class Overloads { void call(int value) {} void call(String value) {} void caller() {} }",
            )],
        );
        let analyzer = fixture.analyzer();
        let mut overloads = analyzer
            .all_declarations()
            .filter(|unit| unit.fq_name().ends_with("Overloads.call"))
            .collect::<Vec<_>>();
        overloads.sort_by(|left, right| left.signature().cmp(&right.signature()));
        assert_eq!(overloads.len(), 2);
        let enclosing = fixture.declaration("Overloads.caller");
        let hits_by_overload = overloads
            .iter()
            .enumerate()
            .map(|(index, target)| {
                (
                    target.clone(),
                    BTreeSet::from([UsageHit::new(
                        fixture.files[0].clone(),
                        1,
                        index,
                        index + 1,
                        enclosing.clone(),
                        1.0,
                        "call",
                    )]),
                )
            })
            .collect();
        let (hits, truncated) = reference_hits_from_fuzzy_result(
            analyzer,
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload: HashMap::default(),
                unproven_total_by_overload: HashMap::default(),
            },
            &overloads,
        );
        assert!(!truncated);
        assert_eq!(hits.len(), 2);
        assert_eq!(
            hits.into_iter()
                .map(|hit| hit.resolved)
                .collect::<BTreeSet<_>>(),
            overloads.into_iter().collect::<BTreeSet<_>>()
        );
    }
    #[cfg(test)]
    #[test]
    fn the_owner_classifier_states_each_relation() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Base.java", JAVA_BASE),
                ("src/Derived.java", JAVA_DERIVED),
            ],
        );
        let analyzer = fixture.analyzer();
        let base_ping = fixture.declaration("Base.ping");
        let derived_run = fixture.declaration("Derived.run");
        let derived_helper = fixture.declaration("Derived.helper");

        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_helper),
            OwnerRelation::SameOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_run),
            OwnerRelation::SelfReference
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &base_ping),
            OwnerRelation::InheritedOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, None, &base_ping),
            OwnerRelation::Unknown
        );
    }
    #[cfg(test)]
    #[test]
    fn forward_and_inverse_classify_import_binding() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                (
                    "src/client/Startup.java",
                    "package client;\n\nimport fixture.Registry;\n\nclass Startup {\n    Registry registry;\n}\n",
                ),
            ],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[1], &CancellationToken::new())
                .expect("not cancelled");
        let import_edge = forward
            .edges
            .iter()
            .find(|edge| {
                edge.target == target
                    && edge.site.range.start_byte
                        == fixture.files[1]
                            .read_to_string()
                            .expect("fixture source")
                            .find("Registry;")
                            .expect("import target")
            })
            .expect("the import target must appear as a forward edge");
        assert_eq!(import_edge.usage_kind, UsageHitKind::Import);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_import = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[1] && edge.site.range == import_edge.site.range
            })
            .expect("the import target must appear as an inverse edge");
        assert_eq!(inverse_import.usage_kind, UsageHitKind::Import);
    }
    #[cfg(test)]
    #[test]
    fn forward_and_inverse_classify_recursive_self_reference() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Registry.java",
                "package fixture;\n\nclass Registry {\n    void register() {\n        register();\n    }\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.register");
        let call_start = fixture.files[0]
            .read_to_string()
            .expect("fixture source")
            .rfind("register();")
            .expect("recursive call");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[0], &CancellationToken::new())
                .expect("not cancelled");
        let forward_self = forward
            .edges
            .iter()
            .find(|edge| edge.target == target && edge.site.range.start_byte == call_start)
            .expect("recursive call must appear as a forward edge");
        assert_eq!(forward_self.usage_kind, UsageHitKind::SelfReceiver);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_self = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[0] && edge.site.range == forward_self.site.range
            })
            .expect("recursive call must appear as an inverse edge");
        assert_eq!(inverse_self.usage_kind, UsageHitKind::SelfReceiver);
    }
    #[cfg(test)]
    #[test]
    fn forward_keeps_same_owner_different_receiver_as_reference() {
        let fixture = Fixture::new(
            Language::Java,
            &[(
                "src/Registry.java",
                "package fixture;\n\nclass Registry {\n    void helper() {}\n    void invoke(Registry other) {\n        other.helper();\n    }\n}\n",
            )],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.helper");
        let call_start = fixture.files[0]
            .read_to_string()
            .expect("fixture source")
            .rfind("helper();")
            .expect("member call");
        let forward =
            forward_edges_for_file(analyzer, &fixture.files[0], &CancellationToken::new())
                .expect("not cancelled");
        let forward_call = forward
            .edges
            .iter()
            .find(|edge| edge.target == target && edge.site.range.start_byte == call_start)
            .expect("the member call must appear as a forward edge");
        assert_eq!(forward_call.owner_relation, OwnerRelation::SameOwner);
        assert_eq!(forward_call.usage_kind, UsageHitKind::Reference);

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        let inverse_call = inverse
            .edges
            .iter()
            .find(|edge| {
                edge.site.file == fixture.files[0] && edge.site.range == forward_call.site.range
            })
            .expect("the member call must appear as an inverse edge");
        assert_eq!(inverse_call.usage_kind, UsageHitKind::Reference);
    }
    #[cfg(test)]
    #[test]
    fn kotlin_forward_support_reports_only_its_uncovered_occurrence_role() {
        let fixture = Fixture::new(
            Language::Kotlin,
            &[(
                "src/Main.kt",
                "class Registry {\n    fun register() {\n    }\n}\n",
            )],
        );
        let result = forward_edges_for_file(
            fixture.analyzer(),
            &fixture.files[0],
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        assert!(result.edges.is_empty());
        assert_eq!(
            result.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::OccurrenceRowsIncomplete {
                    uncovered_roles: vec![OccurrenceRole::PatternPosition]
                }]
            }
        );
        assert!(!result.covers(EdgeAxis::ForwardProjection));
        assert!(!result.covers(EdgeAxis::InverseProjection));
        assert!(result.covers_forward_role(OccurrenceRole::MemberPosition));
        assert!(!result.covers_forward_role(OccurrenceRole::PatternPosition));
    }
}
