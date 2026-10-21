#[cfg(test)]
mod tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::BackingStoreOffset;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapDischarge;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueFlowKind;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueTransfer;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::AccessPathTail;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowEndpoint;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowRelationKind;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::AccessPathResolution;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::AccessSelectorDraft;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::LoadOrigin;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::ValueOriginFacts;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::abort_paths_run_user_code;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::exact_unsigned_integer_origin;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::implicit_abort_gap_is_discharged;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::procedure_value_facts;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::resolve_access_path;
    use brokk_bifrost_core::cancellation::CancellationToken;

    use std::collections::HashMap;
    use std::collections::HashSet;

    use brokk_bifrost_analysis::analyzer::semantic::ValueFlowOracle as _;
    #[test]
    fn integer_offset_is_a_non_identity_value_flow_relation() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "countdown.go",
                r#"package countdown

func next(depth int) int {
    return depth - 1
}
"#,
            )
            .build();
        let file = project.file("countdown.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("next")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("next procedure");
        let oracle = analyzer.semantic_oracle_provider();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("value-flow relation query runs");
        let relations = outcome
            .available_value()
            .expect("value-flow relation query retains its snapshot")
            .relations();

        assert!(relations.iter().any(|relation| {
            let point = relation
                .point()
                .procedure()
                .semantics()
                .point(relation.point().id())
                .expect("relation point is retained");
            let SemanticEffect::ValueFlow { kind, .. } =
                &point.events[relation.event_index() as usize].effect
            else {
                return false;
            };
            matches!(kind, ValueFlowKind::IntegerOffset { .. })
                && relation.kind == ValueFlowRelationKind::LanguageDefined
                && !kind.preserves_runtime_class()
        }));
    }
    #[test]
    fn active_cleanup_exceptional_completion_keeps_value_flow_open() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type item struct { value int }

func cleanup() {}

func active(input *item) int {
    defer cleanup()
    return input.value
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("active")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("active procedure");
        let exceptional_gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.detail.as_ref() == "selection may panic on a nil operand"
            })
            .expect("field selection exceptional-flow gap");
        assert_eq!(
            exceptional_gap.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion
        );
        assert!(
            exceptional_gap
                .impacts
                .contains(SemanticGapImpact::ValueFlow)
        );
        let abort_user_code = abort_paths_run_user_code(procedure.semantics());
        assert!(abort_user_code, "the active defer runs user code on unwind");
        assert!(
            !implicit_abort_gap_is_discharged(exceptional_gap, abort_user_code),
            "exit-only procedure completion is not a value-flow discharge"
        );

        let oracle = analyzer.semantic_oracle_provider();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go value-flow relation query runs");
        assert!(!outcome.is_complete(), "{outcome:#?}");
        let snapshot = outcome
            .available_value()
            .expect("an open value-flow snapshot remains available");
        assert_eq!(snapshot.coverage(), CandidateCoverage::Open);
        assert!(
            !snapshot.gap_is_discharged(exceptional_gap.id),
            "the new completion marker remains an explicit value-flow boundary: {outcome:#?}"
        );
    }
    #[test]
    fn go_canonical_literal_indices_require_closed_base_identity() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

func literal() int {
    values := [2]int{}
    values[0] = 1
    return values[0]
}

func directLiteral() int {
    return [2]int{1}[0]
}

func source() int { return 1 }

func directCallStore() int {
    values := [2]int{}
    values[0] = source()
    values[1] = 0
    return values[0]
}

func siblingLiteral() int {
    values := [2]int{}
    values[0] = 1
    values[1] = 0
    return values[0]
}

func siblingLiteralNegative() int {
    values := [2]int{}
    values[0] = 1
    values[1] = 0
    return values[1]
}

func dynamic(index int) int {
    values := [2]int{}
    values[index] = 1
    return values[index]
}

func rebound() int {
    values := [2]int{}
    index := 0
    values[index] = 1
    return values[index]
}

func parameterAlias(first, second []int) int {
    first[0] = 1
    return second[0]
}

func addressEscape(consume func(*[2]int)) int {
    values := [2]int{}
    consume(&values)
    values[0] = 1
    return values[0]
}

func arrayCopy() int {
    first := [2]int{}
    first[0] = 1
    second := first
    first[0] = 0
    return second[0]
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let oracle = analyzer.semantic_oracle_provider();
        let query = |name: &str| {
            let semantics = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .unwrap_or_else(|| panic!("missing Go procedure {name}"));
            let gaps = semantics
                .gaps()
                .iter()
                .map(|gap| {
                    (
                        gap.id,
                        gap.capability,
                        gap.discharge,
                        gap.point,
                        gap.subject,
                        gap.detail.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let index_gaps = gaps
                .iter()
                .filter(|(_, capability, _, _, _, _)| {
                    *capability == SemanticCapability::IndexMemory
                })
                .map(|(id, _, _, _, _, _)| *id)
                .collect::<Vec<_>>();
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("Go procedure handle");
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let outcome = oracle
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go value-flow relation query runs");
            (index_gaps, gaps, outcome)
        };

        for (name, expected_gaps) in [
            ("literal", 2),
            ("directLiteral", 2),
            ("siblingLiteral", 3),
            ("siblingLiteralNegative", 3),
        ] {
            let (literal_gaps, gaps, literal) = query(name);
            let SemanticOutcome::Complete {
                value: literal_snapshot,
                ..
            } = literal
            else {
                panic!("{name} canonical literal index flow must be complete; gaps: {gaps:#?}");
            };
            assert_eq!(literal_gaps.len(), expected_gaps, "{name}");
            assert_eq!(
                literal_snapshot.coverage(),
                CandidateCoverage::Exhaustive,
                "{name}"
            );
            assert!(
                literal_gaps
                    .iter()
                    .all(|gap| literal_snapshot.gap_is_discharged(*gap)),
                "{name}"
            );
        }

        let (direct_call_index_gaps, direct_call_gaps, direct_call) = query("directCallStore");
        assert_eq!(direct_call_index_gaps.len(), 3);
        assert!(direct_call_gaps.iter().all(|(_, _, discharge, _, _, _)| {
            *discharge != SemanticGapDischarge::RetainedEvaluationOrder
        }));
        let direct_call_snapshot = direct_call
            .available_value()
            .unwrap_or_else(|| panic!("directCallStore must retain relations: {direct_call:#?}"));
        assert!(
            direct_call_index_gaps
                .iter()
                .all(|gap| direct_call_snapshot.gap_is_discharged(*gap)),
            "directCallStore: {direct_call:#?}"
        );
        for (gap, capability, discharge, point, subject, detail) in direct_call_gaps {
            let must_be_discharged = matches!(
                discharge,
                SemanticGapDischarge::CanonicalIndexIdentity
                    | SemanticGapDischarge::NonRejoiningExceptionalExit
            );
            assert_eq!(
                direct_call_snapshot.gap_is_discharged(gap),
                must_be_discharged,
                "directCallStore {capability:?} gap {gap:?} at {point:?} subject={subject:?} detail={detail}"
            );
        }

        for (name, expected_gaps) in [("dynamic", 2), ("rebound", 2), ("parameterAlias", 2)] {
            let (index_gaps, _, outcome) = query(name);
            assert_eq!(index_gaps.len(), expected_gaps, "{name}");
            assert!(!outcome.is_complete(), "{name}: {outcome:#?}");
            let snapshot = outcome
                .available_value()
                .unwrap_or_else(|| panic!("{name} must retain partial relations: {outcome:#?}"));
            assert_eq!(snapshot.coverage(), CandidateCoverage::Open, "{name}");
            assert!(
                index_gaps
                    .iter()
                    .all(|gap| !snapshot.gap_is_discharged(*gap)),
                "{name}: {outcome:#?}"
            );
        }

        let (address_escape_gaps, _, address_escape) = query("addressEscape");
        assert_eq!(address_escape_gaps.len(), 2);
        assert!(
            !address_escape.is_complete(),
            "an array passed by address to an unresolved call must remain open"
        );

        let (array_copy_gaps, _, array_copy) = query("arrayCopy");
        let [first_store, first_overwrite, copied_load] = array_copy_gaps.as_slice() else {
            panic!("arrayCopy must retain its three index gaps: {array_copy_gaps:#?}");
        };
        assert!(!array_copy.is_complete(), "arrayCopy: {array_copy:#?}");
        let snapshot = array_copy
            .available_value()
            .unwrap_or_else(|| panic!("arrayCopy must retain partial relations: {array_copy:#?}"));
        assert_eq!(snapshot.coverage(), CandidateCoverage::Open);
        assert!(
            snapshot.relations().iter().any(|relation| {
                matches!(
                    relation.transfer,
                    Some(ValueTransfer {
                        kind: crate::analyzer::semantic::TransferKind::AggregateCopy,
                        operation: crate::analyzer::semantic::TransferOperation::None,
                    })
                ) && relation.kind == ValueFlowRelationKind::Assignment
                    && relation.is_proven_complete()
            }),
            "the proven transfer positive survives unrelated open index coverage: {array_copy:#?}"
        );
        assert!(snapshot.gap_is_discharged(*first_store));
        assert!(snapshot.gap_is_discharged(*first_overwrite));
        assert!(
            !snapshot.gap_is_discharged(*copied_load),
            "the copied array has no proven element-store identity: {array_copy:#?}"
        );
    }
    use brokk_bifrost_analysis::analyzer::semantic::AccessPathRoot;
    use brokk_bifrost_analysis::analyzer::semantic::ProcedurePortKind;
    #[test]
    fn returned_members_keep_their_field_path_at_the_return_event() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

type S struct { N string }
func next(a S) S { return a }
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("next")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("next procedure");
        let oracle = analyzer.semantic_oracle_provider();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("value-flow relation query runs");
        let relations = outcome
            .available_value()
            .expect("value-flow relation query retains its snapshot")
            .relations();

        let members = relations
            .iter()
            .filter(|relation| {
                relation.kind == ValueFlowRelationKind::NormalReturn
                    && matches!(&relation.target, ValueFlowEndpoint::Location(_))
            })
            .collect::<Vec<_>>();
        assert!(
            !members.is_empty(),
            "returned fields retain a port location: {relations:#?}"
        );
        for relation in members {
            let ValueFlowEndpoint::Location(source) = &relation.source else {
                panic!("returned member reads a location");
            };
            let ValueFlowEndpoint::Location(target) = &relation.target else {
                unreachable!();
            };
            assert!(!target.path().selectors().is_empty());
            assert!(
                source
                    .path()
                    .selectors()
                    .ends_with(target.path().selectors())
            );
            assert!(
                matches!(target.path().root(), AccessPathRoot::ProcedurePort(port)
                if port.kind() == ProcedurePortKind::NormalReturn)
            );
            let point = procedure.semantics().point(relation.point.id()).unwrap();
            assert!(matches!(
                point.events[relation.event_index as usize].effect,
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Return,
                    ..
                }
            ));
        }
    }
    #[test]
    fn a_transfer_is_separated_only_where_its_contents_are_stated() {
        fn destination_origins(
            language: Language,
            path: &str,
            source: &str,
            procedure: &str,
        ) -> Vec<LoadOrigin> {
            let project = InlineTestProject::with_language(language)
                .file(path, source)
                .build();
            let file = project.file(path);
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let artifact = analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("semantic materialization runs")
                .available_value()
                .cloned()
                .expect("the semantic artifact is available");
            let handle = artifact
                .procedures()
                .iter()
                .find(|candidate| {
                    candidate
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(procedure)
                })
                .and_then(|candidate| artifact.procedure_handle(candidate.id()))
                .unwrap_or_else(|| panic!("{procedure} is lowered"));
            let transferred = handle
                .semantics()
                .points()
                .iter()
                .flat_map(|point| &point.events)
                .filter_map(|event| match event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(_),
                        target,
                        ..
                    } => Some(target),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(
                !transferred.is_empty(),
                "{procedure} must publish a transfer: {:#?}",
                handle.semantics()
            );
            let facts = procedure_value_facts(
                &handle,
                &HashMap::new(),
                &HashSet::new(),
                &cancellation,
                |_| Ok(()),
            )
            .expect("unbudgeted local origin derivation completes");
            transferred
                .into_iter()
                .map(|target| {
                    facts
                        .load_origins
                        .get(&target)
                        .copied()
                        .unwrap_or_else(|| panic!("a transfer target has an origin"))
                })
                .collect()
        }

        let go = destination_origins(
            Language::Go,
            "main.go",
            r#"package main

type S struct { n string }

func run(a S) string {
    b := a
    return b.n
}
"#,
            "run",
        );
        assert!(
            go.iter()
                .all(|origin| matches!(origin, LoadOrigin::Separated { .. })),
            "Go states the copied members, so the copy is an exact root: {go:#?}"
        );

        // A Rust transfer separates storage identity only when the producer
        // publishes the copied members at the transfer point. A named-field
        // struct layout states them (#4913), so the copy is an exact root with
        // definitions to answer a member read.
        let rust = destination_origins(
            Language::Rust,
            "src/lib.rs",
            r#"#[derive(core::clone::Clone, core::marker::Copy)]
struct S { n: i32 }

fn run(a: S) -> i32 {
    let b = a;
    b.n
}
"#,
            "run",
        );
        assert!(
            rust.iter()
                .all(|origin| matches!(origin, LoadOrigin::Separated { .. })),
            "a named-field struct layout states its members, so the copy is an exact root: {rust:#?}"
        );

        // Where the producer states no copied members, the same transfer shape
        // must stay ambiguous instead of answering a member read against an
        // exact root that has no definition. A positional struct layout states
        // none.
        let unstated_layout = destination_origins(
            Language::Rust,
            "src/lib.rs",
            r#"#[derive(core::clone::Clone, core::marker::Copy)]
struct S(i32);

fn run(a: S) -> i32 {
    let b = a;
    b.0
}
"#,
            "run",
        );
        assert!(
            unstated_layout
                .iter()
                .all(|origin| *origin == LoadOrigin::Ambiguous),
            "an unstated layout states no contents, so the copy stays ambiguous: {unstated_layout:#?}"
        );
    }
    #[test]
    fn local_integer_slice_offsets_canonicalize_index_paths() {
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                r#"package main

func shifted(dynamic int) int {
    values := make([]int, 4)
    start := 1
    exact := values[start:dynamic]
    open := values[dynamic:]
    exact[0] = 7
    open[0] = 8
    return values[1]
}
"#,
            )
            .build();
        let file = project.file("main.go");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Go semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Go semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("shifted")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("shifted procedure");
        let facts = procedure_value_facts(
            &procedure,
            &HashMap::new(),
            &HashSet::new(),
            &cancellation,
            |_| Ok(()),
        )
        .expect("unbudgeted local origin derivation completes");
        let exact_integer = |value| {
            exact_unsigned_integer_origin(procedure.semantics(), &facts.load_origins, value)
        };
        let offset_values = facts
            .load_origins
            .values()
            .filter_map(|origin| match origin {
                LoadOrigin::BackingStore {
                    offset: BackingStoreOffset::Value(value),
                    ..
                } => Some(*value),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(offset_values.len(), 2, "{:#?}", procedure.semantics());
        let mut refined_offsets = offset_values
            .into_iter()
            .map(exact_integer)
            .collect::<Vec<_>>();
        refined_offsets.sort_unstable();
        assert_eq!(refined_offsets, [None, Some(1)]);

        let mut translated = Vec::new();
        let mut open = Vec::new();
        for location in procedure.semantics().memory_locations() {
            let resolution = resolve_access_path(
                location.id,
                ValueOriginFacts {
                    load_origins: &facts.load_origins,
                    copied_reference_members: &facts.copied_reference_members,
                    binding_origins: None,
                },
                8,
                &cancellation,
                |id| {
                    procedure
                        .semantics()
                        .memory_location(id)
                        .map(|row| &row.kind)
                },
                exact_integer,
                |_| Ok(()),
            )
            .expect("access-path resolution runs");
            let AccessPathResolution::Resolved(draft) = resolution else {
                panic!("unbudgeted access-path resolution completes")
            };
            let [
                AccessSelectorDraft::Index {
                    constant: Some(index),
                    ..
                },
            ] = draft.selectors.as_slice()
            else {
                continue;
            };
            if draft.tail == AccessPathTail::Exact {
                translated.push(*index);
            } else {
                open.push(*index);
            }
        }
        translated.sort_unstable();
        assert_eq!(translated, [1, 1], "{:#?}", procedure.semantics());
        assert_eq!(
            open,
            [0],
            "an unknown start preserves the backing root but leaves index overlap open: {:#?}",
            procedure.semantics()
        );
    }
}
