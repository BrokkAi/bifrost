#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeBatch;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeCatalog;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclaration;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclarationCandidate;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclarationDomain;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeGap;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeGapDomain;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeGapDomainResolution;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeLookupImpact;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedDefinition;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSummary;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactReferenceReceiverGap;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH;

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::OwnerRelationMemo;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionAnswer;

    use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::SelectedReferenceInverseIndexAccumulator;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::SelectedReferenceInverseIndexBuildOutcome;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::assert_lookup_resolution_status;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::assert_same_inverse_index;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::binding_gap_domain_without_metadata;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::build_selected_reference_inverse_index;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::declaration_domain;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::exact_site_row;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::finish_fact_reference_edge_batch;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::graph_targets;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::inverse_index_for_binding_gap;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lookup_semantic;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::project_fact_reference_edge_batch;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::reference_gap_domain;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::select_graph_declaration;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::selected_inverse_index;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::tests::semantic;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::sort_inverse_rows_with_cancellation;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::stage_selected_reference_edge_batches;

    use crate::engine_tests::jvm_fact_reference_support::go_extraction_support_1::*;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::reference_semantic;

    use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedFactResolutionEngine;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate;

    use brokk_bifrost_jvm_analysis::analyzer::KotlinAnalyzer;

    use crate::inline_project::InlineTestProject;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionIdentifierRole,
    };

    use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};
    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeMap;

    #[test]
    fn receiver_dependencies_suppress_only_type_or_value_value_qualifiers() {
        const SOURCE: &str = "package demo;\n\
class Leaf { int terminal; }\n\
class Owner {\n\
    int bareField;\n\
    Leaf valueQualifier;\n\
    static Leaf memberQualifier;\n\
    int bare() { return bareField; }\n\
    int viaValue() { return valueQualifier.terminal; }\n\
    int viaLocal(Leaf localQualifier) { return localQualifier.terminal; }\n\
    int viaType() { return Owner.memberQualifier.terminal; }\n\
}\n";

        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"native-edge-receiver-dependency-law",
            b"native-edge-receiver-dependency-law:demo",
        );
        let hostile_typed =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                fixture.fragment,
                Language::Java,
                &FileResolutionFacts::default(),
            )
            .typed()
            .clone();
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                SOURCE,
                &fixture.facts,
                &fixture.lexical,
                &hostile_typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("same-fragment typed receiver drift must fail atomically"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("typed receiver dependencies are misaligned"),
            "unexpected typed receiver drift error: {error}"
        );

        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("receiver-dependency law source must project");

        let bare_start =
            SOURCE.find("return bareField").expect("bare field read") + "return ".len();
        let value_start = SOURCE
            .find("return valueQualifier")
            .expect("field-valued qualifier")
            + "return ".len();
        let local_start = SOURCE
            .find("return localQualifier")
            .expect("local-valued qualifier")
            + "return ".len();
        let type_start = SOURCE
            .find("return Owner.memberQualifier")
            .expect("type qualifier")
            + "return ".len();
        let intermediate_member_start = type_start + "Owner.".len();
        let value_terminal_start = value_start + "valueQualifier.".len();
        let local_terminal_start = local_start + "localQualifier.".len();
        let type_terminal_start = intermediate_member_start + "memberQualifier.".len();

        let bare = exact_site_row(&projected, bare_start, bare_start + "bareField".len());
        assert!(bare.target.is_field());
        assert_eq!(bare.target.terminal_name(), "bareField");
        let intermediate_member = exact_site_row(
            &projected,
            intermediate_member_start,
            intermediate_member_start + "memberQualifier".len(),
        );
        assert!(intermediate_member.target.is_field());
        assert_eq!(
            intermediate_member.target.terminal_name(),
            "memberQualifier"
        );
        for terminal_start in [
            value_terminal_start,
            local_terminal_start,
            type_terminal_start,
        ] {
            let terminal = exact_site_row(
                &projected,
                terminal_start,
                terminal_start + "terminal".len(),
            );
            assert!(terminal.target.is_field());
            assert_eq!(terminal.target.terminal_name(), "terminal");
        }
        for (start, name) in [
            (value_start, "valueQualifier"),
            (local_start, "localQualifier"),
            (type_start, "Owner"),
        ] {
            assert!(
                projected.edges().iter().all(|row| {
                    row.site.range.start_byte != start
                        || row.site.range.end_byte != start + name.len()
                }),
                "a source-proven ValueReference receiver dependency must not publish a canonical row: start={start}, name={name:?}, edges={:?}",
                projected.edges()
            );
        }

        let file = catalog.file(fixture.fragment).expect("selected file");
        let (bare_reference, bare_namespace, bare_kind) =
            reference_semantic_at(&fixture, bare_start, bare_start + "bareField".len());
        assert_eq!(
            reference_gap_domain(file, bare_reference, bare_namespace, bare_kind),
            Some(FactReferenceEdgeGapDomain::Field),
            "a selected bare Java value expression is field-domain, not a qualifier"
        );
        for (start, name) in [
            (value_start, "valueQualifier"),
            (local_start, "localQualifier"),
            (type_start, "Owner"),
        ] {
            let (reference, namespace, kind) =
                reference_semantic_at(&fixture, start, start + name.len());
            assert_eq!(
                reference_gap_domain(file, reference, namespace, kind),
                None,
                "the exact projection-to-receiver join must suppress {name:?}"
            );
        }
        let (member_reference, member_namespace, member_kind) = reference_semantic_at(
            &fixture,
            intermediate_member_start,
            intermediate_member_start + "memberQualifier".len(),
        );
        assert_eq!(
            reference_gap_domain(file, member_reference, member_namespace, member_kind),
            Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
            "an intermediate MemberReference remains canonical even when its value feeds a receiver"
        );

        let mut manual = FactReferenceEdgeCatalog::new(&fixture.analyzer);
        manual
            .insert_file(fixture.fragment, fixture.file.clone())
            .expect("manual catalog file");
        let manual_file = manual.file(fixture.fragment).expect("manual file");
        let (type_reference, type_namespace, type_kind) =
            reference_semantic_at(&fixture, type_start, type_start + "Owner".len());
        assert_eq!(
            reference_gap_domain(manual_file, type_reference, type_namespace, type_kind),
            Some(FactReferenceEdgeGapDomain::AnyGraphDeclaration),
            "a manual catalog without the structured join must fail conservative"
        );
    }
    #[test]
    fn selected_inverse_index_localizes_open_bindings_by_exact_lookup_impact() {
        const SOURCE: &str = "package demo;\nclass Owner {\n    class open {}\n    int open;\n    int closed;\n    void open() {}\n    void open(int value) {}\n    void closedCall() {}\n    void use(Owner receiver) {\n        int bare = open;\n        open();\n        Object member = receiver.open;\n        missing();\n    }\n}\n";
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"selected-inverse-lookup-impact-law",
            b"selected-inverse-lookup-impact-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let targets = graph_targets(&catalog);
        let named_targets = |spelling: &str| {
            targets
                .iter()
                .filter(|target| target.terminal_name() == spelling)
                .cloned()
                .collect::<Vec<_>>()
        };
        let open_targets = named_targets("open");
        let open_field = open_targets
            .iter()
            .find(|target| target.is_field())
            .expect("the law source must retain the open field");
        let closed_field = named_targets("closed")
            .into_iter()
            .find(CodeUnit::is_field)
            .expect("the law source must retain the closed field");
        let open_type = open_targets
            .iter()
            .find(|target| target.is_class())
            .expect("the law source must retain the nested open type");
        let open_callables = open_targets
            .iter()
            .filter(|target| target.is_callable())
            .collect::<Vec<_>>();
        assert_eq!(open_callables.len(), 2, "both overloads must be indexed");

        let bare_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::Value,
            ResolutionSiteKind::ValueReference,
        );
        assert_eq!(
            catalog
                .reference_lookup_impacts(bare_open)
                .expect("the bare reference must own lookup impacts"),
            &[FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Java,
                    ResolutionNamespace::Value,
                    "open"
                ),
                domain: FactReferenceEdgeDeclarationDomain::Field,
            }],
            "a Java value occurrence is admitted only as a field"
        );
        let bare_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            bare_open,
            FactReferenceEdgeGapDomain::Field,
        );
        assert!(!bare_index.run_completeness().is_complete());
        assert_lookup_resolution_status(&bare_index, open_field, true);
        assert_lookup_resolution_status(&bare_index, &closed_field, false);
        assert_lookup_resolution_status(&bare_index, open_type, false);
        for callable in &open_callables {
            assert_lookup_resolution_status(&bare_index, callable, false);
        }

        let callable_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let callable_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            callable_open,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        for callable in &open_callables {
            assert_lookup_resolution_status(&callable_index, callable, true);
        }
        assert_lookup_resolution_status(&callable_index, open_field, false);
        assert_lookup_resolution_status(&callable_index, open_type, false);

        let member_open = reference_semantic_named(
            &fixture,
            "open",
            ResolutionNamespace::TypeOrValue,
            ResolutionSiteKind::MemberReference,
        );
        let mut expected_member_impacts = vec![
            FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Java,
                    ResolutionNamespace::Value,
                    "open",
                ),
                domain: FactReferenceEdgeDeclarationDomain::Field,
            },
            FactReferenceEdgeLookupImpact {
                lookup: lookup_semantic(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Java,
                    ResolutionNamespace::Type,
                    "open",
                ),
                domain: FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            },
        ];
        expected_member_impacts.sort_unstable();
        assert_eq!(
            catalog
                .reference_lookup_impacts(member_open)
                .expect("the member reference must own both exact routes"),
            expected_member_impacts,
        );
        let member_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            member_open,
            FactReferenceEdgeGapDomain::AnyGraphDeclaration,
        );
        assert_lookup_resolution_status(&member_index, open_field, true);
        assert_lookup_resolution_status(&member_index, open_type, true);
        for callable in &open_callables {
            assert_lookup_resolution_status(&member_index, callable, false);
        }
        assert_lookup_resolution_status(&member_index, &closed_field, false);

        let missing = reference_semantic_named(
            &fixture,
            "missing",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let missing_index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            missing,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        assert!(!missing_index.run_completeness().is_complete());
        for target in targets {
            assert_lookup_resolution_status(&missing_index, &target, false);
        }
    }
    #[test]
    fn selected_inverse_index_keeps_covered_empty_target_complete_across_field_only_gaps() {
        const SOURCE: &str =
            "package demo;\nclass Owner {\n    int value;\n    void write() { value = 1; }\n}\n";
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"selected-inverse-empty-domain-law",
            b"selected-inverse-empty-domain-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let index = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the field-local selected inverse index must build"),
        );
        assert!(
            !index.run_completeness().covers(EdgeAxis::InverseProjection),
            "the aggregate run must retain the field gap"
        );
        let targets = graph_targets(&catalog);
        let empty_type_or_callable = targets
            .iter()
            .filter(|target| !target.is_field())
            .map(|target| (target, index.inverse_for(target)))
            .find(|(_, result)| result.edges.is_empty())
            .expect("the law source must contain one covered empty type/callable target");
        assert_eq!(
            empty_type_or_callable.1.completeness,
            EdgeCompleteness::Complete,
            "field-only gaps must not overtaint a covered empty type/callable"
        );
        assert!(
            targets
                .iter()
                .filter(|target| target.is_field())
                .any(|target| {
                    !index
                        .inverse_for(target)
                        .completeness
                        .covers(EdgeAxis::KindClassification)
                })
        );

        let uncovered = CodeUnit::new(
            fixture.file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            "demo",
            "NotSelected",
        );
        let uncovered = index.inverse_for(&uncovered);
        assert!(uncovered.edges.is_empty());
        assert_eq!(
            uncovered.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexTargetUncovered]
            }
        );
        assert!(!uncovered.covers(EdgeAxis::InverseProjection));
    }
    #[test]
    fn selected_inverse_index_localizes_receiver_gap_to_one_exact_sibling_target() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let mut siblings = catalog
            .declarations
            .iter()
            .filter_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if !target.is_field() => {
                    Some((semantic, target.clone()))
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .collect::<Vec<_>>();
        siblings.sort_unstable_by(|left, right| left.1.cmp(&right.1));
        siblings.dedup_by(|left, right| left.1 == right.1);
        let [(open_semantic, open_target), (_, unaffected_target), ..] = siblings.as_slice() else {
            panic!("the law source must contain two type/callable sibling targets: {siblings:?}");
        };
        let mut target_domains = HashMap::default();
        assert!(
            target_domains
                .insert(
                    open_target.clone(),
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                )
                .is_none()
        );
        assert!(
            target_domains
                .insert(
                    unaffected_target.clone(),
                    FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                )
                .is_none()
        );
        let open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardAdmissionIncomplete],
        };
        let batch = FactReferenceEdgeBatch {
            fragment: fixture.fragment,
            generation: catalog.generation(),
            reference_count: 1,
            edges: Box::new([]),
            gaps: vec![FactReferenceEdgeGap::ReceiverAdmission {
                reference: semantic(b"selected-inverse-local-receiver-gap"),
                target: *open_semantic,
                gap: FactReferenceReceiverGap::MissingOrigin,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            }]
            .into_boxed_slice(),
            unresolved_names: None,
            withheld_references: Box::new([]),
            completeness: open.clone(),
            type_or_callable_completeness: open.clone(),
            field_completeness: EdgeCompleteness::Complete,
        };
        let mut accumulator =
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains);
        assert!(
            accumulator
                .stage(&catalog, &batch, &CancellationToken::new())
                .expect("the exact target-local gap must stage")
        );
        let index = selected_inverse_index(accumulator.finish(
            FactReferenceEdgeSummary {
                generation: catalog.generation(),
                completeness: open.clone(),
                type_or_callable_completeness: open,
                field_completeness: EdgeCompleteness::Complete,
                reference_count: 1,
                edge_count: 0,
                batch_count: 1,
                root_binding_metrics: ResolutionBatchMetrics::default(),
            },
            &CancellationToken::new(),
        ));
        assert_eq!(
            index.inverse_for(open_target).completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::InverseIndexAdmissionIncomplete]
            }
        );
        assert_eq!(
            index.inverse_for(unaffected_target).completeness,
            EdgeCompleteness::Complete,
            "a target-local receiver gap must not overtaint a same-domain sibling"
        );
    }
    #[test]
    #[hardwon("3bf50ffa2952: a proven call was dropped when its owner was outside the graph")]
    fn native_edge_projection_retains_calls_with_out_of_graph_owners() {
        let fixture = native_edge_projection_fixture_for(
            "Projector.java",
            "class Target { static void hit() {} }\nclass Caller { static void run() { Target.hit(); } }\n",
            b"out-of-graph-owner",
            b"out-of-graph-owner-package",
        );
        let mut catalog = native_edge_catalog(&fixture);
        let cancellation = CancellationToken::new();
        let original = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .unwrap();
        let call = original
            .edges()
            .iter()
            .find(|edge| edge.target.identifier() == "hit")
            .expect("the source call has a canonical target");
        let owner = catalog
            .declarations
            .iter()
            .find_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(unit)
                    if Some(unit) == call.site.enclosing.as_ref() =>
                {
                    Some(semantic)
                }
                _ => None,
            })
            .expect("the original call has a graph owner");
        // Model an explicitly lexical-only source owner. The real Rust
        // block-local construct is exercised by the native graph regression.
        catalog
            .declarations
            .insert(owner, FactReferenceEdgeDeclaration::OutOfGraphDomain);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .unwrap();
        let retained = projected
            .edges()
            .iter()
            .find(|edge| edge.target == call.target && edge.site.range == call.site.range)
            .expect("an unavailable owner must not erase the canonical reference");
        assert_eq!(retained.proof, call.proof);
        assert_eq!(retained.site.file, call.site.file);
        assert_eq!(retained.site.enclosing, None);
        assert!(projected.gaps().iter().any(|gap| {
            let FactReferenceEdgeGap::OutOfGraphReferenceOwner {
                reference,
                owner: gap_owner,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            } = gap
            else {
                return false;
            };
            *gap_owner == owner
                && fixture.batch.answers().iter().any(|answer| {
                    answer.reference() == *reference
                        && answer.site_metadata().is_some_and(|metadata| {
                            metadata.start_byte() == call.site.range.start_byte
                                && metadata.end_byte() == call.site.range.end_byte
                        })
                })
        }));
        assert!(
            !projected
                .completeness()
                .covers(EdgeAxis::OwnerClassification)
        );
        assert!(
            projected
                .field_completeness
                .covers(EdgeAxis::OwnerClassification)
        );

        catalog.declarations.remove(&owner);
        let error = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .expect_err("a missing declaration remains corruption, not lexical incompleteness");
        assert!(error.to_string().contains("Projector.java"), "{error}");
    }
    #[test]
    fn native_edge_catalog_rejects_foreign_and_unindexed_declarations() {
        use brokk_bifrost_core::analyzer::model::CodeUnitType;

        let fixture = native_edge_projection_fixture();
        let mut catalog = FactReferenceEdgeCatalog::new(&fixture.analyzer);
        let unindexed_file =
            ProjectFile::new(fixture.file.root().to_path_buf(), "unindexed/Missing.java");
        let error = catalog
            .insert_file(
                BindingFragmentId::for_test(b"unindexed-native-edge-file"),
                unindexed_file,
            )
            .expect_err("an unindexed source file must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected unindexed-file error: {error}"
        );

        let missing = CodeUnit::new(fixture.file.clone(), CodeUnitType::Class, "demo", "Missing");
        let error = catalog
            .insert_graph_declaration(semantic(b"missing-current-declaration"), missing)
            .expect_err("a fabricated declaration must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected fabricated-declaration error: {error}"
        );

        let foreign_file = ProjectFile::new(
            fixture.file.root().join("foreign-workspace"),
            "Foreign.java",
        );
        let foreign = CodeUnit::new(foreign_file, CodeUnitType::Class, "foreign", "Foreign");
        let error = catalog
            .insert_graph_declaration(semantic(b"foreign-declaration"), foreign)
            .expect_err("a foreign declaration must not enter the current catalog");
        assert!(
            error.to_string().contains("belongs to foreign workspace"),
            "unexpected foreign-declaration error: {error}"
        );
    }
    #[test]
    fn native_edge_catalog_accepts_java_module_descriptor_file_scope() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("module-info.java", "module demo {}\n")
            .build();
        let file = project.file("module-info.java");
        let root = file.root().to_path_buf();
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let mut catalog = FactReferenceEdgeCatalog::new(&analyzer);
        catalog
            .insert_graph_declaration(
                semantic(b"java-module-descriptor-file-scope"),
                CodeUnit::file_scope(file),
            )
            .expect("the canonical graph admits Java module descriptor file scope");

        let unindexed = ProjectFile::new(root, "unindexed/module-info.java");
        let error = catalog
            .insert_graph_declaration(
                semantic(b"unindexed-java-module-descriptor-file-scope"),
                CodeUnit::file_scope(unindexed),
            )
            .expect_err("an unindexed module descriptor must not enter the current catalog");
        assert!(
            error
                .to_string()
                .contains("is absent from the current analyzer index"),
            "unexpected unindexed module-descriptor error: {error}"
        );
    }
    #[test]
    fn selected_fragment_catalog_maps_fields_and_nested_overloads_but_excludes_locals() {
        const SOURCE: &str = "package demo;\nclass Outer {\n    int field;\n    class Nested {\n        Nested() {}\n        void run() {}\n        void run(int parameter) {}\n    }\n}\n";

        let project = InlineTestProject::with_language(Language::Java)
            .file("Outer.java", SOURCE)
            .build();
        let file = project.file("Outer.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            brokk_bifrost_analysis::native_resolution_test_support::parse_java_resolution_facts(
                &file, SOURCE,
            );
        let fragment = BindingFragmentId::for_test(b"selected-edge-catalog-overloads");
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .typed()
        .clone();
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &facts,
                &lexical,
                &typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("structured selected declarations must map exactly")
        .expect("uncancelled catalog construction must publish");

        let names = facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let sites = facts
            .sites
            .iter()
            .map(|site| (site.id, site))
            .collect::<HashMap<_, _>>();
        let identifiers = facts
            .identifiers
            .iter()
            .map(|identifier| (identifier.site, identifier))
            .collect::<HashMap<_, _>>();
        let mut run_declarations = HashSet::default();
        let mut saw_nested = false;
        let mut saw_field = false;
        let mut saw_out_of_graph_local = false;
        for semantic in lexical
            .semantics()
            .iter()
            .filter(|semantic| semantic.role() == LoweredSemanticRole::Definition)
        {
            let site = sites[&semantic.site()];
            let identifier = identifiers[&semantic.site()];
            assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
            let name = names[&identifier.name];
            let declaration = catalog
                .graph_declaration(semantic.semantic())
                .expect("every selected definition must be classified");
            let is_member_field = site.kind == ResolutionSiteKind::ValueDeclaration
                && facts
                    .member_owners
                    .iter()
                    .any(|owner| owner.member == site.id);
            let is_graph_definition = matches!(
                site.kind,
                ResolutionSiteKind::TypeDeclaration
                    | ResolutionSiteKind::CallableDeclaration
                    | ResolutionSiteKind::ConstructorDeclaration
            ) || is_member_field;
            if is_graph_definition {
                let declaration = declaration
                    .unwrap_or_else(|| panic!("graph definition was excluded: {semantic:?}"));
                assert_eq!(declaration.source(), &file);
                assert_eq!(declaration.terminal_name(), name);
                assert!(analyzer.ranges(declaration).iter().any(|range| {
                    range.start_byte <= site.start_byte && site.end_byte <= range.end_byte
                }));
                if name == "Nested" && site.kind == ResolutionSiteKind::TypeDeclaration {
                    saw_nested = true;
                }
                if name == "run" {
                    assert!(run_declarations.insert(declaration.declaration_id()));
                }
                if is_member_field {
                    assert!(declaration.is_field());
                    saw_field = true;
                }
            } else {
                assert!(declaration.is_none());
                if site.kind == ResolutionSiteKind::ValueDeclaration {
                    saw_out_of_graph_local = true;
                }
            }
        }
        assert!(
            saw_nested,
            "the law must exercise structured nested ownership"
        );
        assert!(
            saw_field,
            "the law must exercise an analyzer-owned canonical field"
        );
        assert!(
            saw_out_of_graph_local,
            "the law must exercise an explicit out-of-graph local or parameter"
        );
        assert_eq!(
            run_declarations.len(),
            2,
            "same-name overloads must retain distinct exact declaration identities"
        );
    }
    #[test]
    fn selected_fragment_catalog_indexes_graph_targets_with_withheld_binders() {
        let fixture = native_edge_projection_fixture();
        let names = fixture
            .facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let field_site = fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.namespace == ResolutionNamespace::Value
                    && names[&identifier.name] == "value"
            })
            .expect("the law source must retain its value field")
            .site;
        let reference_site = fixture
            .facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && names[&identifier.name] == "value"
            })
            .expect("the law source must retain its value reference")
            .site;
        let mut facts = fixture.facts.clone();
        facts
            .binders
            .retain(|binder| binder.declaration != field_site);
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fixture.fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        assert!(lexical.gaps().iter().any(|gap| {
            gap.site() == field_site && gap.origin() == LoweringGapOrigin::MissingBinder
        }));
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fixture.fragment,
            Language::Java,
            &facts,
        )
        .typed()
        .clone();
        let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                fixture.source,
                &facts,
                &lexical,
                &typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the withheld-binder catalog must remain structurally valid")
        .expect("uncancelled withheld-binder catalog construction must publish");
        let target = catalog
            .graph_targets_for_lookup(lookup_semantic(
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Java,
                ResolutionNamespace::Value,
                "value",
            ))
            .expect("the withheld field lookup bucket must be readable");
        let [target] = target else {
            panic!("one withheld field target must remain indexed: {target:?}");
        };
        assert!(target.is_field());

        let index = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            reference_semantic(fixture.fragment, reference_site),
            FactReferenceEdgeGapDomain::Field,
        );
        assert_lookup_resolution_status(&index, target, true);
    }
    #[test]
    fn selected_fragment_catalog_rejects_misaligned_member_kinds_and_receiver_origins() {
        const SOURCE: &str = "package demo;\nclass Owner {\n    void target() {}\n    void caller() { target(); }\n}\n";

        let project = InlineTestProject::with_language(Language::Java)
            .file("Owner.java", SOURCE)
            .build();
        let file = project.file("Owner.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            brokk_bifrost_analysis::native_resolution_test_support::parse_java_resolution_facts(
                &file, SOURCE,
            );
        let fragment = BindingFragmentId::for_test(b"selected-edge-catalog-corruption");
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .typed()
        .clone();

        let mut wrong_member_kind = facts.clone();
        let method = wrong_member_kind
            .member_owners
            .iter_mut()
            .find(|owner| owner.kind == ResolutionMemberKind::Method)
            .expect("the law source must publish a method member-owner row");
        method.kind = ResolutionMemberKind::Field;
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &wrong_member_kind,
                &lexical,
                &typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("a member kind that contradicts its positioned definition must fail"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("member ownership is misaligned"),
            "unexpected member-kind mismatch error: {error}"
        );

        let mut hostile_receiver_origin = facts.clone();
        let declaration_site = hostile_receiver_origin
            .identifiers
            .iter()
            .find(|identifier| identifier.role == ResolutionIdentifierRole::Declaration)
            .expect("the law source must publish a positioned declaration")
            .site;
        hostile_receiver_origin
            .callable_receiver_origins
            .first_mut()
            .expect("the law source must publish an implicit callable receiver origin")
            .reference = declaration_site;
        let mismatch = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file,
                SOURCE,
                &hostile_receiver_origin,
                &lexical,
                &typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        );
        let error = match mismatch {
            Ok(_) => panic!("a receiver-origin row that names a definition must fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("callable receiver origin is misaligned"),
            "unexpected receiver-origin mismatch error: {error}"
        );
    }
    #[test]
    fn exact_graph_declaration_selection_rejects_equal_innermost_candidates() {
        use brokk_bifrost_core::analyzer::model::CodeUnitType;

        let fixture = native_edge_projection_fixture();
        let semantic =
            fixture
                .lexical
                .semantics()
                .iter()
                .find(|semantic| {
                    semantic.role() == LoweredSemanticRole::Definition
                        && fixture.facts.identifiers.iter().any(|identifier| {
                            identifier.site == semantic.site()
                                && fixture.facts.names.iter().any(|name| {
                                    name.id == identifier.name && name.spelling == "write"
                                })
                        })
                })
                .expect("the fixture must retain its write declaration");
        let site = fixture
            .facts
            .sites
            .iter()
            .find(|site| site.id == semantic.site())
            .expect("the write definition must retain its exact site");
        let declaration = fixture
            .analyzer
            .get_declarations(&fixture.file)
            .into_iter()
            .find(|declaration| {
                declaration.kind() == CodeUnitType::Function
                    && declaration.terminal_name() == "write"
            })
            .expect("the analyzer must retain the write declaration");
        let competing = CodeUnit::with_signature_and_fq(
            fixture.file.clone(),
            declaration.kind(),
            declaration.package_name().to_owned(),
            declaration.short_name().to_owned(),
            Some("(competing)".to_owned()),
            false,
            declaration.fq().clone(),
        );
        let range = Range {
            start_byte: site.start_byte,
            end_byte: site.end_byte,
            start_line: 1,
            end_line: 1,
        };
        let candidates = vec![
            FactReferenceEdgeDeclarationCandidate {
                declaration,
                ranges: vec![range],
            },
            FactReferenceEdgeDeclarationCandidate {
                declaration: competing,
                ranges: vec![range],
            },
        ];
        let selected = select_graph_declaration(
            &fixture.analyzer,
            &fixture.file,
            FactReferenceEdgeSelectedDefinition {
                semantic: semantic.semantic(),
                lookup: lookup_semantic(
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Java,
                    ResolutionNamespace::Callable,
                    "write",
                ),
                lookup_domain: FactReferenceEdgeDeclarationDomain::TypeOrCallable,
                site,
                name: "write",
                owner: None,
            },
            None,
            &candidates,
            &CancellationToken::new(),
        );
        let error = selected.expect_err("equal innermost candidates must be ambiguous");
        assert!(
            error
                .to_string()
                .contains("one current analyzer graph declaration"),
            "unexpected graph ambiguity error: {error}"
        );
    }
    #[test]
    fn field_only_uncertainty_preserves_type_or_callable_domain_completeness() {
        const SOURCE: &str =
            "package demo;\nclass Owner {\n    int value;\n    void write() { value = 1; }\n}\n";

        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            SOURCE,
            b"native-edge-field-domain-law",
            b"native-edge-field-domain-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("field-only native edges must project");
        assert!(
            projected.edges().iter().any(|row| row.target.is_field()),
            "fields must remain canonical edge declarations: {:?}",
            projected.edges()
        );
        assert!(
            !projected.completeness().is_complete(),
            "the broad canonical domain must retain field uncertainty: {:?}",
            projected.gaps()
        );
        let type_or_callable =
            projected.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        assert_eq!(
            type_or_callable.domain(),
            FactReferenceEdgeDeclarationDomain::TypeOrCallable
        );
        assert_eq!(type_or_callable.generation(), catalog.generation());
        assert_eq!(type_or_callable.completeness(), &EdgeCompleteness::Complete);
        assert!(
            !projected
                .domain_status(FactReferenceEdgeDeclarationDomain::Field)
                .completeness()
                .is_complete(),
            "field-only gaps must still make the field domain incomplete"
        );
        assert!(
            projected.gaps().iter().all(|gap| {
                gap.domain()
                    .affects(FactReferenceEdgeDeclarationDomain::Field)
                    && !gap
                        .domain()
                        .affects(FactReferenceEdgeDeclarationDomain::TypeOrCallable)
            }),
            "the law source must retain only field-domain gaps: {:?}",
            projected.gaps()
        );

        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the field-domain selected snapshot must assemble");
        let summary = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect("field-domain canonical staging must finish");
        let type_or_callable =
            summary.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        assert_eq!(
            type_or_callable.domain(),
            FactReferenceEdgeDeclarationDomain::TypeOrCallable
        );
        assert_eq!(type_or_callable.generation(), catalog.generation());
        assert_eq!(type_or_callable.completeness(), &EdgeCompleteness::Complete);
        assert!(
            !summary.completeness().is_complete(),
            "summary canonical completeness must retain field-only gaps"
        );
    }
    #[test]
    fn edge_summary_retains_root_batch_metrics_and_cancellation_resets_them() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected edge-metrics snapshot must assemble");

        let expected_metrics = snapshot
            .stage_all_reference_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |_| Ok(()),
            )
            .expect("the underlying selected batches must finish")
            .root_binding_metrics();
        assert_ne!(
            expected_metrics,
            ResolutionBatchMetrics::default(),
            "the law source must exercise shared lexical root batches"
        );
        let summary = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &CancellationToken::new(),
            &mut |_| Ok(()),
        )
        .expect("canonical edge staging must finish");
        assert_eq!(summary.root_binding_metrics(), expected_metrics);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = stage_selected_reference_edge_batches(
            &snapshot,
            &catalog,
            MAX_REFERENCE_SEEDS_PER_BATCH,
            &cancellation,
            &mut |_| panic!("a pre-cancelled edge operation must not stage a batch"),
        )
        .expect("cancellation is a semantic edge summary");
        assert_eq!(
            cancelled.root_binding_metrics(),
            ResolutionBatchMetrics::default()
        );
    }
    #[test]
    fn missing_metadata_domain_fails_closed() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let field = catalog
            .declarations
            .iter()
            .find_map(|(&semantic, declaration)| match declaration {
                FactReferenceEdgeDeclaration::Graph(declaration) if declaration.is_field() => {
                    Some(semantic)
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .expect("the fixture must map its field declaration");
        let complete_field = ResolutionAnswer::new([field], [], ResolutionCompletion::Complete);
        assert!(matches!(
            binding_gap_domain_without_metadata(
                &catalog,
                &complete_field,
                &CancellationToken::new(),
            )
            .expect("complete retained targets must classify"),
            FactReferenceEdgeGapDomainResolution::Graph(FactReferenceEdgeGapDomain::Field)
        ));

        let incomplete_field = ResolutionAnswer::new(
            [field],
            [],
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                semantic(b"missing-metadata-open-binding"),
            )]),
        );
        assert!(matches!(
            binding_gap_domain_without_metadata(
                &catalog,
                &incomplete_field,
                &CancellationToken::new(),
            )
            .expect("an open binding without metadata must classify"),
            FactReferenceEdgeGapDomainResolution::Graph(
                FactReferenceEdgeGapDomain::AnyGraphDeclaration
            )
        ));
    }
    #[test]
    fn native_edge_projector_splits_non_callable_same_owner_and_external_targets() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the inline native edge batch must project");
        assert_eq!(
            projected.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![
                    EdgeIncompleteReason::ForwardResolutionIncomplete,
                    EdgeIncompleteReason::AxisUnsupported(EdgeAxis::KindClassification),
                ],
            }
        );
        assert!(
            projected.completeness().covers(EdgeAxis::InverseProjection),
            "semantic completeness alone does not encode producer provenance"
        );
        assert!(
            !projected.covers(EdgeAxis::InverseProjection),
            "a forward-native batch must never vouch for inverse projection"
        );
        assert_eq!(projected.generation(), catalog.generation());
        assert_eq!(projected.reference_count(), fixture.batch.answers().len());

        let same_owner_start = PROJECTOR_SOURCE
            .find("value = 1")
            .expect("the fixture must retain its same-owner value location reference");
        let same_owner = exact_site_row(
            &projected,
            same_owner_start,
            same_owner_start + "value".len(),
        );
        assert_eq!(same_owner.target.terminal_name(), "value");
        assert_eq!(same_owner.owner_relation, OwnerRelation::SameOwner);
        assert_eq!(same_owner.usage_kind, UsageHitKind::SelfReceiver);
        assert_eq!(same_owner.proof, UsageProof::Proven);
        assert_eq!(
            same_owner.site.range,
            Range {
                start_byte: same_owner_start,
                end_byte: same_owner_start + "value".len(),
                start_line: 8,
                end_line: 8,
            }
        );
        assert!(same_owner.site.ast_id.is_some());
        assert_eq!(same_owner.provenance, EdgeProvenance::Forward);
        assert_eq!(same_owner.generation, catalog.generation());

        let external_start = PROJECTOR_SOURCE
            .find("External external")
            .expect("the fixture must retain its external type reference");
        let external = exact_site_row(
            &projected,
            external_start,
            external_start + "External".len(),
        );
        assert_eq!(external.target.terminal_name(), "External");
        assert_eq!(external.owner_relation, OwnerRelation::External);
        assert_eq!(external.usage_kind, UsageHitKind::Reference);
        assert_eq!(external.proof, UsageProof::Proven);
        assert_eq!(
            external.site.range,
            Range {
                start_byte: external_start,
                end_byte: external_start + "External".len(),
                start_line: 7,
                end_line: 7,
            }
        );
        assert!(external.site.ast_id.is_some());
        assert_eq!(external.provenance, EdgeProvenance::Forward);
        assert_eq!(external.generation, catalog.generation());
    }
    #[test]
    fn native_edge_projector_cancellation_discards_the_batch_and_retry_is_exact() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let baseline = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the baseline native edge batch must project");

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &cancellation,
        )
        .expect("cancellation is a semantic result");
        assert_eq!(cancelled.fragment(), fixture.fragment);
        assert_eq!(cancelled.generation(), catalog.generation());
        assert_eq!(cancelled.reference_count(), 0);
        assert!(cancelled.edges().is_empty());
        assert!(cancelled.gaps().is_empty());
        assert_eq!(
            cancelled.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::Cancelled],
            }
        );
        assert!(!cancelled.covers(EdgeAxis::ForwardProjection));
        assert!(!cancelled.covers(EdgeAxis::InverseProjection));

        let retry = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("a fresh retry must project");
        assert_eq!(retry, baseline);
    }
    #[test]
    fn native_edge_publication_gates_domain_scan_cancellation_and_stale_generation() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let gaps = (0..128)
            .map(|ordinal| FactReferenceEdgeGap::MissingReferenceKind {
                reference: SemanticId::for_test(
                    format!("late-domain-reference-{ordinal}").as_bytes(),
                ),
                target: SemanticId::for_test(format!("late-domain-target-{ordinal}").as_bytes()),
                domain: FactReferenceEdgeGapDomain::Field,
            })
            .collect::<Vec<_>>();
        let cancellation = CancellationToken::cancel_after_checks_for_test(16);
        let cancelled = finish_fact_reference_edge_batch(
            &catalog,
            fixture.fragment,
            128,
            Vec::new(),
            gaps,
            vec![EdgeIncompleteReason::AxisUnsupported(
                EdgeAxis::KindClassification,
            )],
            None,
            Vec::new(),
            &cancellation,
        )
        .expect("late domain-scan cancellation is semantic");
        assert_eq!(cancelled.reference_count(), 0);
        assert!(cancelled.edges().is_empty());
        assert!(cancelled.gaps().is_empty());
        assert_eq!(
            cancelled.completeness(),
            &EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::Cancelled],
            },
            "cancellation during the source-sized domain scan must discard the materialized batch"
        );

        let mut stale_catalog = native_edge_catalog(&fixture);
        stale_catalog.generation = stale_catalog
            .generation
            .checked_add(1)
            .expect("test generation must advance");
        let error = finish_fact_reference_edge_batch(
            &stale_catalog,
            fixture.fragment,
            0,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            Vec::new(),
            &CancellationToken::new(),
        )
        .expect_err("a generation change before the final publication gate must reject the batch");
        assert!(
            error
                .to_string()
                .contains("is stale against current generation"),
            "unexpected stale-generation publication error: {error}"
        );
    }
    #[test]
    fn selected_inverse_index_preserves_multi_target_rows_and_batch_independent_order() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let one_at_a_time = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("one-row selected inverse-index staging must succeed"),
        );
        let broad = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
            )
            .expect("broad selected inverse-index staging must succeed"),
        );
        assert_eq!(broad.batch_count(), 1);
        assert_eq!(one_at_a_time.batch_count(), one_at_a_time.reference_count());
        assert!(one_at_a_time.batch_count() > broad.batch_count());
        let targets = graph_targets(&catalog);
        assert_same_inverse_index(&one_at_a_time, &broad, &targets);
        assert_eq!(broad.target_count(), targets.len());
        assert!(
            broad.nonempty_target_count() > 1,
            "the law source must exercise multiple incoming target buckets"
        );

        let projected = project_fact_reference_edge_batch(
            &catalog,
            &fixture.batch,
            &mut OwnerRelationMemo::default(),
            &CancellationToken::new(),
        )
        .expect("the comparison forward batch must project");
        for target in targets {
            let mut expected = projected
                .edges()
                .iter()
                .filter(|row| row.target == target)
                .cloned()
                .collect::<Vec<_>>();
            assert!(sort_inverse_rows_with_cancellation(
                &mut expected,
                &CancellationToken::new()
            ));
            for row in &mut expected {
                row.provenance = EdgeProvenance::Inverse;
            }
            let indexed = broad.inverse_for(&target);
            assert_eq!(indexed.edges, expected);
            assert_eq!(indexed.provenance, EdgeProvenance::Inverse);
            assert!(
                indexed
                    .edges
                    .iter()
                    .all(|row| row.provenance == EdgeProvenance::Inverse)
            );
        }
    }
    #[test]
    fn selected_inverse_lookup_join_discards_late_cancellation_and_retries_cleanly() {
        let mut source = String::from("package demo;\nclass Owner {\n");
        for arity in 0..32 {
            source.push_str("  void fanout(");
            for parameter in 0..arity {
                if parameter > 0 {
                    source.push_str(", ");
                }
                source.push_str(&format!("int p{parameter}"));
            }
            source.push_str(") {}\n");
        }
        source.push_str("  void unrelated() {}\n  void use() { fanout(); }\n}\n");
        let source = Box::leak(source.into_boxed_str());
        let fixture = native_edge_projection_fixture_for(
            "Owner.java",
            source,
            b"selected-inverse-late-lookup-cancellation-law",
            b"selected-inverse-late-lookup-cancellation-law:demo",
        );
        let catalog = native_edge_catalog(&fixture);
        let reference = reference_semantic_named(
            &fixture,
            "fanout",
            ResolutionNamespace::Callable,
            ResolutionSiteKind::CallableReference,
        );
        let fanout_targets = catalog
            .graph_targets_for_lookup(lookup_semantic(
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Java,
                ResolutionNamespace::Callable,
                "fanout",
            ))
            .expect("the fanout target bucket must be readable");
        assert_eq!(fanout_targets.len(), 32);
        let target_domains = graph_targets(&catalog)
            .into_iter()
            .map(|target| {
                let domain = declaration_domain(&target);
                (target, domain)
            })
            .collect::<HashMap<_, _>>();
        let open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
        };
        let batch = FactReferenceEdgeBatch {
            fragment: fixture.fragment,
            generation: catalog.generation(),
            reference_count: 1,
            edges: Box::new([]),
            gaps: vec![FactReferenceEdgeGap::IncompleteBinding {
                reference,
                domain: FactReferenceEdgeGapDomain::TypeOrCallable,
            }]
            .into_boxed_slice(),
            unresolved_names: None,
            withheld_references: Box::new([]),
            completeness: open.clone(),
            type_or_callable_completeness: open,
            field_completeness: EdgeCompleteness::Complete,
        };
        let mut provisional =
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains);
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        assert!(
            !provisional
                .stage(&catalog, &batch, &cancellation)
                .expect("late lookup cancellation is a typed staging outcome")
        );
        assert!(cancellation.is_cancelled());
        assert!(
            !provisional.target_reasons.is_empty()
                && provisional.target_reasons.len() < fanout_targets.len(),
            "the token must cancel after a real target prefix but before the lookup bucket closes: staged={:?}",
            provisional.target_reasons
        );
        drop(provisional);

        let retry = inverse_index_for_binding_gap(
            &catalog,
            fixture.fragment,
            reference,
            FactReferenceEdgeGapDomain::TypeOrCallable,
        );
        for target in fanout_targets {
            assert_lookup_resolution_status(&retry, target, true);
        }
        let unrelated = graph_targets(&catalog)
            .into_iter()
            .find(|target| target.is_callable() && target.terminal_name() == "unrelated")
            .expect("the law source must retain an unrelated callable target");
        assert_lookup_resolution_status(&retry, &unrelated, false);
    }
    #[test]
    fn selected_inverse_index_localizes_remaining_global_gap_axes() {
        struct GlobalGapCase {
            gap: FactReferenceEdgeGap,
            forward_reason: EdgeIncompleteReason,
            inverse_reason: EdgeIncompleteReason,
            covers_inverse: bool,
            covers_kind: bool,
            covers_owner: bool,
        }

        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let mut type_targets = catalog
            .declarations
            .values()
            .filter_map(|declaration| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if !target.is_field() => {
                    Some(target.clone())
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .collect::<Vec<_>>();
        type_targets.sort_unstable();
        type_targets.dedup();
        let [first_type, second_type, ..] = type_targets.as_slice() else {
            panic!("the global-gap law requires two type/callable targets: {type_targets:?}");
        };
        let field = catalog
            .declarations
            .values()
            .find_map(|declaration| match declaration {
                FactReferenceEdgeDeclaration::Graph(target) if target.is_field() => {
                    Some(target.clone())
                }
                FactReferenceEdgeDeclaration::Graph(_)
                | FactReferenceEdgeDeclaration::OutOfGraphDomain => None,
            })
            .expect("the global-gap law requires one field target");
        let target_domains = [
            (
                first_type.clone(),
                FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            ),
            (
                second_type.clone(),
                FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            ),
            (field.clone(), FactReferenceEdgeDeclarationDomain::Field),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        let cases = [
            GlobalGapCase {
                gap: FactReferenceEdgeGap::MissingSiteMetadata {
                    reference: semantic(b"selected-inverse-global-metadata-gap"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::ForwardMetadataIncomplete,
                inverse_reason: EdgeIncompleteReason::InverseIndexMetadataIncomplete,
                covers_inverse: false,
                covers_kind: false,
                covers_owner: false,
            },
            GlobalGapCase {
                gap: FactReferenceEdgeGap::UnknownReferenceOwner {
                    reference: semantic(b"selected-inverse-global-owner-gap"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                inverse_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                covers_inverse: true,
                covers_kind: true,
                covers_owner: false,
            },
            GlobalGapCase {
                gap: FactReferenceEdgeGap::OutOfGraphReferenceOwner {
                    reference: semantic(b"selected-inverse-lexical-owner-reference"),
                    owner: semantic(b"selected-inverse-lexical-owner"),
                    domain: FactReferenceEdgeGapDomain::TypeOrCallable,
                },
                forward_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                inverse_reason: EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::OwnerClassification,
                ),
                covers_inverse: true,
                covers_kind: true,
                covers_owner: false,
            },
        ];
        for case in cases {
            let open = EdgeCompleteness::Incomplete {
                reasons: vec![case.forward_reason],
            };
            let batch = FactReferenceEdgeBatch {
                fragment: fixture.fragment,
                generation: catalog.generation(),
                reference_count: 1,
                edges: Box::new([]),
                gaps: vec![case.gap].into_boxed_slice(),
                unresolved_names: None,
                withheld_references: Box::new([]),
                completeness: open.clone(),
                type_or_callable_completeness: open.clone(),
                field_completeness: EdgeCompleteness::Complete,
            };
            let mut accumulator = SelectedReferenceInverseIndexAccumulator::new(
                catalog.generation(),
                target_domains.clone(),
            );
            assert!(
                accumulator
                    .stage(&catalog, &batch, &CancellationToken::new())
                    .expect("the domain-global gap must stage")
            );
            let index = selected_inverse_index(accumulator.finish(
                FactReferenceEdgeSummary {
                    generation: catalog.generation(),
                    completeness: open.clone(),
                    type_or_callable_completeness: open,
                    field_completeness: EdgeCompleteness::Complete,
                    reference_count: 1,
                    edge_count: 0,
                    batch_count: 1,
                    root_binding_metrics: ResolutionBatchMetrics::default(),
                },
                &CancellationToken::new(),
            ));
            for target in [first_type, second_type] {
                let result = index.inverse_for(target);
                assert_eq!(
                    result.completeness,
                    EdgeCompleteness::Incomplete {
                        reasons: vec![case.inverse_reason.clone()]
                    }
                );
                assert_eq!(
                    result.covers(EdgeAxis::InverseProjection),
                    case.covers_inverse
                );
                assert_eq!(
                    result.covers(EdgeAxis::KindClassification),
                    case.covers_kind
                );
                assert_eq!(
                    result.covers(EdgeAxis::OwnerClassification),
                    case.covers_owner
                );
                assert!(result.covers(EdgeAxis::ProofAttribution));
            }
            let unaffected = index.inverse_for(&field);
            assert_eq!(unaffected.completeness, EdgeCompleteness::Complete);
            for axis in [
                EdgeAxis::InverseProjection,
                EdgeAxis::KindClassification,
                EdgeAxis::ProofAttribution,
                EdgeAxis::OwnerClassification,
            ] {
                assert!(unaffected.covers(axis));
            }
        }

        let enumeration_open = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ReferenceEnumerationIncomplete],
        };
        let index = selected_inverse_index(
            SelectedReferenceInverseIndexAccumulator::new(catalog.generation(), target_domains)
                .finish(
                    FactReferenceEdgeSummary {
                        generation: catalog.generation(),
                        completeness: enumeration_open.clone(),
                        type_or_callable_completeness: enumeration_open.clone(),
                        field_completeness: enumeration_open,
                        reference_count: 0,
                        edge_count: 0,
                        batch_count: 0,
                        root_binding_metrics: ResolutionBatchMetrics::default(),
                    },
                    &CancellationToken::new(),
                ),
        );
        for target in [first_type, second_type, &field] {
            let result = index.inverse_for(target);
            assert_eq!(
                result.completeness,
                EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete]
                }
            );
            assert!(!result.covers(EdgeAxis::InverseProjection));
            assert!(result.covers(EdgeAxis::KindClassification));
            assert!(result.covers(EdgeAxis::ProofAttribution));
            assert!(result.covers(EdgeAxis::OwnerClassification));
        }
    }
    #[test]
    fn selected_inverse_index_discards_cancelled_and_stale_builds_and_retries_exactly() {
        let fixture = native_edge_projection_fixture();
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the selected inverse-index snapshot must assemble");
        let baseline = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the baseline selected inverse index must build"),
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(8);
        assert!(matches!(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &cancellation,
            )
            .expect("cancellation is a typed selected inverse-index outcome"),
            SelectedReferenceInverseIndexBuildOutcome::Cancelled
        ));

        let retry = selected_inverse_index(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("the selected inverse-index retry must build"),
        );
        let targets = graph_targets(&catalog);
        assert_same_inverse_index(&baseline, &retry, &targets);

        let mut stale_catalog = native_edge_catalog(&fixture);
        stale_catalog.generation = stale_catalog
            .generation
            .checked_add(1)
            .expect("the test generation must advance");
        assert!(matches!(
            build_selected_reference_inverse_index(
                &fixture.analyzer,
                &snapshot,
                &stale_catalog,
                1,
                &CancellationToken::new(),
            )
            .expect("generation mismatch is a typed selected inverse-index outcome"),
            SelectedReferenceInverseIndexBuildOutcome::Stale
        ));
    }
    #[test]
    fn selected_inverse_index_rejects_unselected_mixed_language_reference_sites_without_a_prefix() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("Projector.java", PROJECTOR_SOURCE)
            .file(
                "demo/Foreign.kt",
                "package demo\nclass Foreign { fun use(target: External) = target }\n",
            )
            .build();
        let fixture = native_edge_projection_fixture_from_project(
            project,
            "Projector.java",
            PROJECTOR_SOURCE,
            b"selected-inverse-mixed-language-law",
            b"selected-inverse-mixed-language-law:demo",
        );
        let analyzer = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::new(JavaAnalyzer::new(fixture._project.project_dyn())),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::new(KotlinAnalyzer::new(fixture._project.project_dyn())),
            ),
        ]));
        let catalog = native_edge_catalog(&fixture);
        let base_service = native_edge_selected_java_base_service(&fixture);
        let engine = SelectedFactResolutionEngine::new(&base_service);
        let snapshot = engine
            .snapshot(&CancellationToken::new())
            .expect("the Java selection itself must remain valid");
        let error = build_selected_reference_inverse_index(
            &analyzer,
            &snapshot,
            &catalog,
            1,
            &CancellationToken::new(),
        )
        .expect_err("a Java-only stream cannot certify Kotlin incoming sites");
        assert!(
            error
                .to_string()
                .contains("does not cover the complete analyzed workspace"),
            "unexpected mixed-language coverage error: {error}"
        );
    }
    fn native_edge_selected_java_base_service(
        fixture: &NativeEdgeProjectionFixture,
    ) -> PreloadedFactResolutionService {
        PreloadedFactResolutionService::from_lowered_fragments(
            [fixture.lexical.clone()],
            [fixture.typed.clone()],
        )
    }
    fn reference_semantic_at(
        fixture: &NativeEdgeProjectionFixture,
        start_byte: usize,
        end_byte: usize,
    ) -> (SemanticId, ResolutionNamespace, ResolutionSiteKind) {
        let sites = fixture
            .facts
            .sites
            .iter()
            .filter(|site| site.start_byte == start_byte && site.end_byte == end_byte)
            .collect::<Vec<_>>();
        assert_eq!(
            sites.len(),
            1,
            "one exact fact site must own {start_byte}..{end_byte}: {:?}",
            fixture.facts.sites
        );
        let site = sites[0];
        let identifiers = fixture
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.site == site.id && identifier.role == ResolutionIdentifierRole::Reference
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identifiers.len(),
            1,
            "one exact reference identifier must own {site:?}: {:?}",
            fixture.facts.identifiers
        );
        (
            reference_semantic(fixture.fragment, site.id),
            identifiers[0].namespace,
            site.kind,
        )
    }
    fn reference_semantic_named(
        fixture: &NativeEdgeProjectionFixture,
        spelling: &str,
        namespace: ResolutionNamespace,
        kind: ResolutionSiteKind,
    ) -> SemanticId {
        let names = fixture
            .facts
            .names
            .iter()
            .map(|name| (name.id, name.spelling.as_str()))
            .collect::<HashMap<_, _>>();
        let sites = fixture
            .facts
            .sites
            .iter()
            .map(|site| (site.id, site))
            .collect::<HashMap<_, _>>();
        let matches = fixture
            .facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Reference
                    && identifier.namespace == namespace
                    && names[&identifier.name] == spelling
                    && sites[&identifier.site].kind == kind
            })
            .map(|identifier| reference_semantic(fixture.fragment, identifier.site))
            .collect::<Vec<_>>();
        let [reference] = matches.as_slice() else {
            panic!(
                "one exact reference must match spelling={spelling:?}, namespace={namespace:?}, kind={kind:?}: {matches:?}"
            );
        };
        *reference
    }
}
