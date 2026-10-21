//! Shared emission mechanics for language-owned semantic lowerers.
//!
//! This module deliberately knows nothing about tree-sitter node kinds or
//! language syntax. Adapters choose source anchors, evaluation order, control
//! topology, and uncertainty; the session owns dense IDs, exact provenance,
//! common call rows, and batch-level budget/cancellation semantics.

use crate::analyzer::semantic::DependencyFingerprint;
pub use brokk_bifrost_semantic::analyzer::semantic::lowering::*;
#[doc(hidden)]
pub fn semantic_model_dependency_fingerprint(
    snapshot: Option<&crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>,
    domain: &[u8],
) -> DependencyFingerprint {
    let Some(snapshot) = snapshot else {
        return DependencyFingerprint::hash_bytes(b"no-intrafile-dependencies");
    };
    let mut identity = domain.to_vec();
    identity.extend_from_slice(snapshot.active_models().active_model_set_hash().as_bytes());
    DependencyFingerprint::hash_bytes(&identity)
}

/// Collect children associated with one structured tree-sitter field.
pub(crate) use brokk_bifrost_core::analyzer::tree_walk::children_by_field_name;

#[cfg(test)]
pub(crate) mod tests {

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallContinuationKind;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::CallSiteScaffold;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::CleanupRegionId;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::CleanupRoutePlanner;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::CleanupRouteStep;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlEdgeKind;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::ControlTarget;

    use brokk_bifrost_analysis::analyzer::semantic::ids::EvidenceId;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::LoweringCancelled;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::ProcedureLoweringError;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::ProcedureLoweringSession;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::ProcedureLoweringStart;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureSemanticsParts;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ProgramPointId;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::ReceiverCaptureSpec;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::ScopeBinding;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::ScopeCleanupAction;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::ScopeFrameId;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticLocator;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SemanticRole;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValueKind;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

    use brokk_bifrost_analysis::analyzer::semantic::ids::SourceMappingId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SourceMappingKind;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::drive_and_finish_procedure;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::lower_procedure_batch;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::relay_receiver_capture_demand;

    use brokk_bifrost_analysis::analyzer::semantic::lowering::schedule_loop_flow;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::CompletionKind;

    use brokk_bifrost_analysis::analyzer::semantic::cfg::CompletionRequest;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationLocator;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegmentKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::DropBehavior;

    use brokk_bifrost_analysis::analyzer::semantic::ids::MemoryLocationId;

    use brokk_bifrost_analysis::analyzer::semantic::ids::ProcedureId;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetDimension;

    use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticPlace;

    use brokk_bifrost_analysis::analyzer::semantic::ids::WorkspaceMountId;

    use brokk_bifrost_analysis::analyzer::semantic::ids::WorkspaceRelativePath;
    use std::cell::Cell;

    use brokk_bifrost_analysis::test_support::source_anchor;

    fn parts() -> ProcedureSemanticsParts {
        let declaration_anchor = source_anchor(0, 7, 0);
        let declaration = DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Function,
                "fixture",
                declaration_anchor,
                0,
            )
            .expect("declaration segment"),
        ])
        .expect("declaration locator");
        let locator = SemanticLocator::new(
            WorkspaceMountId::hash_bytes(b"lowering-session-test"),
            WorkspaceRelativePath::new("fixture.ts").expect("path"),
            SemanticLanguage::Standard(brokk_bifrost_core::analyzer::model::Language::TypeScript),
            declaration,
            SemanticRole::Procedure,
            declaration_anchor,
        );
        ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
            SourceMappingId::new(0),
            EvidenceId::new(0),
        )
    }

    #[test]
    fn cleanup_planner_emits_ordered_typed_action_points() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            function_scope,
            normal_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let region = CleanupRegionId::new(0);
        let cleanup_scope =
            builder.push_scope(Some(function_scope), ScopeBinding::Cleanup { region });
        let place = SemanticPlace::MemoryLocation(MemoryLocationId::new(0));
        let action_metadata = session
            .add_mapping(
                &mut builder,
                source_anchor(10, 11, 1),
                SourceMappingKind::Exact,
            )
            .expect("action source mapping");
        builder
            .register_scope_cleanup_action(
                cleanup_scope,
                ScopeCleanupAction::Drop {
                    place: place.clone(),
                    behavior: DropBehavior::Trivial,
                    source: action_metadata.source,
                    evidence: action_metadata.evidence,
                },
            )
            .expect("drop action");
        builder
            .register_scope_cleanup_action(
                cleanup_scope,
                ScopeCleanupAction::ScopeEnd {
                    place: place.clone(),
                    source: action_metadata.source,
                    evidence: action_metadata.evidence,
                },
            )
            .expect("scope-end action");
        let route = builder.normal_cleanup_completion(region, normal_exit);
        let region_metadata = session
            .add_mapping(
                &mut builder,
                source_anchor(12, 13, 2),
                SourceMappingKind::Exact,
            )
            .expect("cleanup region mapping");
        let (region_entry, created) = builder
            .cleanup_specialization(&route, 0, region_metadata.source, region_metadata.evidence)
            .expect("cleanup region entry");
        assert!(created);
        session
            .register_point(
                region_entry,
                region_metadata,
                "test cleanup region broke dense point allocation",
            )
            .expect("cleanup region point metadata");

        let mut planner = CleanupRoutePlanner::new(&route);
        let mut action_steps = Vec::new();
        while let Some(step) = planner
            .next_step_with_lookup(
                &mut builder,
                &mut session,
                |_| Some(()),
                |()| unreachable!("the existing region specialization is reused"),
            )
            .expect("cleanup route step")
        {
            match step {
                CleanupRouteStep::Action(action) => action_steps.push(*action),
                CleanupRouteStep::Region(_) => panic!("the existing region is reused"),
            }
        }
        let target = planner.target();
        assert_eq!(action_steps.len(), 2);
        assert!(matches!(
            action_steps[0].action,
            ScopeCleanupAction::ScopeEnd { .. }
        ));
        assert!(matches!(
            action_steps[1].action,
            ScopeCleanupAction::Drop { .. }
        ));
        assert_eq!(target.point, action_steps[1].entry);
        assert_eq!(action_steps[1].next.point, action_steps[0].entry);
        assert_eq!(action_steps[0].next.point, region_entry);

        let (parts, _) = builder.finish_with_work().expect("finish procedure CFG");
        assert_eq!(parts.drops.len(), 1);
        assert_eq!(parts.drops[0].place, place);
        assert_eq!(parts.drops[0].point, action_steps[1].entry);
        assert_eq!(parts.scope_ends.len(), 1);
        assert_eq!(parts.scope_ends[0].place, place);
        assert_eq!(
            parts.scope_ends[0].at,
            brokk_bifrost_analysis::analyzer::semantic::ScopeEndAt::Point(action_steps[0].entry)
        );
    }

    #[derive(Clone, Copy)]
    struct CaptureSpec {
        parent: Option<ProcedureId>,
        relays_receiver_capture: bool,
        captures_receiver: bool,
    }

    impl ReceiverCaptureSpec for CaptureSpec {
        fn lexical_parent(&self) -> Option<ProcedureId> {
            self.parent
        }

        fn relays_receiver_capture(&self) -> bool {
            self.relays_receiver_capture
        }

        fn captures_receiver(&self) -> bool {
            self.captures_receiver
        }

        fn captures_receiver_mut(&mut self) -> &mut bool {
            &mut self.captures_receiver
        }
    }

    fn nested_capture_specs(depth: usize) -> Vec<CaptureSpec> {
        (0..depth)
            .map(|index| CaptureSpec {
                parent: (index > 0).then(|| {
                    ProcedureId::try_from_index(index - 1).expect("small test procedure ID")
                }),
                relays_receiver_capture: true,
                captures_receiver: index + 1 == depth,
            })
            .collect()
    }

    #[test]
    fn receiver_capture_demand_relays_in_one_cancellable_reverse_pass() {
        const DEPTH: usize = 128;
        let mut specs = nested_capture_specs(DEPTH);
        let cancellation = CancellationToken::cancel_after_checks_for_test(DEPTH + 2);

        relay_receiver_capture_demand(&mut specs, &cancellation)
            .expect("one cancellation check per procedure must complete");

        assert!(specs.iter().all(|spec| spec.captures_receiver));
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    fn receiver_capture_demand_stops_at_non_relaying_parent() {
        let mut specs = nested_capture_specs(4);
        specs[2].relays_receiver_capture = false;

        relay_receiver_capture_demand(&mut specs, &CancellationToken::default())
            .expect("uncancelled relay must complete");

        assert!(!specs[0].captures_receiver);
        assert!(!specs[1].captures_receiver);
        assert!(!specs[2].captures_receiver);
        assert!(specs[3].captures_receiver);
    }

    #[test]
    fn c_style_loop_schedules_execution_and_continue_targets() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            entry,
            normal_exit,
            function_scope,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mut points = Vec::new();
        for occurrence in 0..6 {
            let metadata = session
                .add_mapping(
                    &mut builder,
                    source_anchor(20 + occurrence, 21 + occurrence, occurrence),
                    SourceMappingKind::Exact,
                )
                .expect("loop mapping");
            points.push(
                session
                    .add_point(&mut builder, metadata, Vec::new())
                    .expect("loop point"),
            );
        }
        let [condition, body, update_one, update_two, init_one, init_two] = points.as_slice()
        else {
            panic!("expected six loop points");
        };
        type LoopWork = (
            &'static str,
            u8,
            ProgramPointId,
            ControlTarget,
            Option<ControlTarget>,
            ScopeFrameId,
        );
        let mut stack: Vec<LoopWork> = Vec::new();

        schedule_loop_flow(
            &mut builder,
            &session,
            entry,
            ControlTarget::normal(normal_exit),
            function_scope,
            None,
            &[(1, *init_one), (2, *init_two)],
            Some((3, *condition)),
            *condition,
            ControlTarget::normal(*condition),
            (4, *body),
            &[(5, *update_one), (6, *update_two)],
            &mut stack,
            |payload, entry, next, scope| ("init", payload, entry, next, None, scope),
            |payload, entry, next, scope| ("update", payload, entry, next, None, scope),
            |payload, entry, next, scope| ("body", payload, entry, next, None, scope),
            |payload, entry, when_true, when_false, scope| {
                (
                    "condition",
                    payload,
                    entry,
                    when_true,
                    Some(when_false),
                    scope,
                )
            },
        )
        .expect("scheduled C-style loop");

        let execution = stack.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(
            execution
                .iter()
                .map(|work| (work.0, work.1))
                .collect::<Vec<_>>(),
            vec![
                ("init", 1),
                ("init", 2),
                ("condition", 3),
                ("body", 4),
                ("update", 5),
                ("update", 6),
            ]
        );
        assert_eq!(execution[0].3, ControlTarget::normal(*init_two));
        assert_eq!(execution[1].3, ControlTarget::normal(*condition));
        assert_eq!(
            execution[2].3,
            ControlTarget {
                point: *body,
                kind: ControlEdgeKind::ConditionalTrue,
            }
        );
        assert_eq!(
            execution[2].4,
            Some(ControlTarget {
                point: normal_exit,
                kind: ControlEdgeKind::ConditionalFalse,
            })
        );
        assert_eq!(execution[3].3, ControlTarget::normal(*update_one));
        assert_eq!(execution[4].3, ControlTarget::normal(*update_two));
        assert_eq!(
            execution[5].3,
            ControlTarget {
                point: *condition,
                kind: ControlEdgeKind::LoopBack,
            }
        );

        let loop_scope = execution[0].5;
        let continue_route = builder
            .resolve_completion(
                loop_scope,
                &CompletionRequest::new(CompletionKind::Continue, None),
            )
            .expect("continue route");
        assert_eq!(continue_route.destination().target(), *update_one);
        assert_eq!(
            continue_route.destination().edge_kind(),
            ControlEdgeKind::Normal
        );
    }

    #[test]
    fn cleanup_planner_yields_before_allocating_the_next_step() {
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = 5;
        let budget = SemanticBudget::new(limits).expect("positive budget");
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            exceptional_exit,
            function_scope,
            ..
        } = ProcedureLoweringSession::start(parts(), &budget, &cancellation)
            .expect("lowering start");
        let outer_region = CleanupRegionId::new(1);
        let inner_region = CleanupRegionId::new(2);
        let outer_scope = builder.push_scope(
            Some(function_scope),
            ScopeBinding::Cleanup {
                region: outer_region,
            },
        );
        let inner_scope = builder.push_scope(
            Some(outer_scope),
            ScopeBinding::Cleanup {
                region: inner_region,
            },
        );
        let route = builder
            .resolve_completion(
                inner_scope,
                &CompletionRequest::new(CompletionKind::Throw, None),
            )
            .expect("throw route");
        assert_eq!(route.destination().target(), exceptional_exit);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser
            .parse("fn fixture() {}", None)
            .expect("parsed fixture");
        let node = tree.root_node();
        let regions = [(outer_region, node), (inner_region, node)];
        let mut planner = CleanupRoutePlanner::new(&route);

        let first = planner
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect("first cleanup step")
            .expect("new outer cleanup specialization");
        assert_eq!(first.entry.index(), 3);

        let relay_metadata = session
            .add_node_mapping(&mut builder, node)
            .expect("relay mapping");
        let relay = session
            .add_point(&mut builder, relay_metadata, Vec::new())
            .expect("relay point");
        assert_eq!(relay.index(), 4);

        let error = planner
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect_err("inner entry should follow the relay and exceed the point budget");
        let ProcedureLoweringError::Budget(exceeded, _) = error else {
            panic!("expected a budget error");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints);
        let work = builder.prospective_work();
        assert_eq!(work.program_points, 5);
        assert_eq!(work.source_mappings, 4);
        assert_eq!(work.evidence, 4);
    }

    #[test]
    fn cleanup_planner_reuse_does_not_allocate_provenance() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            normal_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let region_id = CleanupRegionId::new(1);
        let route = builder.normal_cleanup_completion(region_id, normal_exit);

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        let tree = parser
            .parse("fn fixture() {}", None)
            .expect("parsed fixture");
        let node = tree.root_node();
        let regions = [(region_id, node)];

        let mut first_plan = CleanupRoutePlanner::new(&route);
        let first = first_plan
            .next(
                &mut builder,
                &mut session,
                &regions,
                |region| region.0,
                |region| region.1,
            )
            .expect("first cleanup step")
            .expect("new cleanup specialization");
        assert!(
            first_plan
                .next(
                    &mut builder,
                    &mut session,
                    &regions,
                    |region| region.0,
                    |region| region.1,
                )
                .expect("finished first plan")
                .is_none()
        );
        let before_reuse = builder.prospective_work();

        let mut reused_plan = CleanupRoutePlanner::new(&route);
        assert!(
            reused_plan
                .next(
                    &mut builder,
                    &mut session,
                    &regions,
                    |region| region.0,
                    |region| region.1,
                )
                .expect("reused cleanup plan")
                .is_none()
        );
        assert_eq!(
            reused_plan.target(),
            ControlTarget {
                point: first.entry,
                kind: ControlEdgeKind::Cleanup,
            }
        );
        assert_eq!(builder.prospective_work(), before_reuse);
    }

    #[test]
    fn receiver_capture_demand_stops_when_cancelled() {
        let mut specs = nested_capture_specs(128);
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);

        assert_eq!(
            relay_receiver_capture_demand(&mut specs, &cancellation),
            Err(LoweringCancelled)
        );
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn await_scaffold_emits_exact_suspend_resume_core() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mut occurrence = 0;
        let scaffold = session
            .add_await_scaffold(&mut builder, |session, builder| {
                let current = occurrence;
                occurrence += 1;
                session.add_mapping(
                    builder,
                    source_anchor(8, 14, current),
                    SourceMappingKind::Exact,
                )
            })
            .expect("await scaffold");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(scaffold.suspend.index(), 3);
        assert_eq!(scaffold.normal_resume.index(), 4);
        assert_eq!(scaffold.exceptional_resume.index(), 5);
        assert_eq!(scaffold.awaited.index(), 0);
        assert_eq!(scaffold.result.index(), 1);
        let resume_edges = parts
            .control_edges
            .iter()
            .filter(|edge| edge.source_point == scaffold.suspend)
            .map(|edge| (edge.target_point, edge.kind))
            .collect::<Vec<_>>();
        assert_eq!(
            resume_edges,
            vec![
                (scaffold.normal_resume, ControlEdgeKind::AsyncNormal),
                (
                    scaffold.exceptional_resume,
                    ControlEdgeKind::AsyncExceptional
                ),
            ]
        );
    }

    #[test]
    fn await_scaffold_preserves_mapping_point_budget_order() {
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = 4;
        let budget = SemanticBudget::new(limits).expect("positive budget");
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            ..
        } = ProcedureLoweringSession::start(parts(), &budget, &cancellation)
            .expect("lowering start");
        let mut occurrence = 0;

        let error = session
            .add_await_scaffold(&mut builder, |session, builder| {
                let current = occurrence;
                occurrence += 1;
                session.add_mapping(
                    builder,
                    source_anchor(8, 14, current),
                    SourceMappingKind::Exact,
                )
            })
            .expect_err("second await point should exceed the point budget");

        let ProcedureLoweringError::Budget(exceeded, _) = error else {
            panic!("expected a budget error");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::ProgramPoints);
        let work = builder.prospective_work();
        assert_eq!(work.program_points, 4);
        assert_eq!(work.source_mappings, 3);
        assert_eq!(work.evidence, 3);
    }

    #[test]
    fn shared_driver_reports_cancellation_with_retained_work() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            builder,
            entry,
            normal_exit,
            exceptional_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        cancellation.cancel();
        let outcome = drive_and_finish_procedure(
            builder,
            [()],
            entry,
            normal_exit,
            exceptional_exit,
            &cancellation,
            |_, (), _| Ok(()),
        );
        assert!(matches!(outcome, Err(ProcedureLoweringError::Cancelled(_))));
    }

    #[test]
    fn batch_lowering_preserves_initial_and_per_procedure_work() {
        let cancellation = CancellationToken::default();
        let initial = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let per_procedure = SemanticWork {
            program_points: 3,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [(), ()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| Ok((parts(), per_procedure)),
        )
        .expect("batch outcome");

        assert!(outcome.is_complete());
        assert_eq!(
            outcome.work(),
            initial.conservative_add(per_procedure.conservative_add(per_procedure))
        );
    }

    #[test]
    fn batch_cancellation_retains_precomputed_work_without_lowering() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let called = Cell::new(false);
        let initial = SemanticWork {
            source_bytes: 17,
            ..SemanticWork::default()
        };
        let outcome = lower_procedure_batch(
            [()],
            initial,
            &SemanticBudget::default(),
            &cancellation,
            |(), _, _| {
                called.set(true);
                Ok((parts(), SemanticWork::default()))
            },
        )
        .expect("batch outcome");

        assert!(matches!(outcome, SemanticOutcome::Cancelled { .. }));
        assert_eq!(outcome.work(), initial);
        assert!(!called.get());
    }

    #[test]
    fn occurrence_allocation_is_span_local_and_deterministic() {
        let cancellation = CancellationToken::default();
        let mut start =
            ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
                .expect("lowering start");

        assert_eq!(start.session.next_source_occurrence(10, 20), 0);
        assert_eq!(start.session.next_source_occurrence(10, 20), 1);
        assert_eq!(start.session.next_source_occurrence(11, 20), 0);
    }

    #[test]
    fn separate_function_throw_boundary_remains_dense_and_adapter_visible() {
        let cancellation = CancellationToken::default();
        let (start, throw_boundary) = ProcedureLoweringSession::start_with_function_throw_boundary(
            parts(),
            &SemanticBudget::default(),
            &cancellation,
            true,
        )
        .expect("lowering start");
        let throw_boundary = throw_boundary.expect("separate throw boundary");

        assert_eq!(throw_boundary.index(), 3);
        assert_eq!(start.session.point_metadata.len(), 4);
        assert_eq!(
            start.session.metadata(throw_boundary).unwrap(),
            start.session.metadata(start.exceptional_exit).unwrap()
        );
    }

    #[test]
    fn shared_call_scaffold_publishes_matched_events_and_metadata() {
        let cancellation = CancellationToken::default();
        let ProcedureLoweringStart {
            mut builder,
            mut session,
            normal_exit,
            exceptional_exit,
            ..
        } = ProcedureLoweringSession::start(parts(), &SemanticBudget::default(), &cancellation)
            .expect("lowering start");
        let mapping = session
            .add_mapping(
                &mut builder,
                source_anchor(8, 14, 0),
                SourceMappingKind::Exact,
            )
            .expect("call mapping");
        let invoke = session
            .add_point(&mut builder, mapping, Vec::new())
            .expect("invoke point");
        let callee = session
            .add_value(&mut builder, invoke, SemanticValueKind::Callable)
            .expect("callee value");
        let call_site = session
            .add_call_site(
                &mut builder,
                CallSiteScaffold {
                    point: invoke,
                    callee,
                    receiver: None,
                    arguments: Box::new([]),
                    normal_results: Box::new([]),
                    result: None,
                    thrown: None,
                    declared_targets: CallableTargetResolution::Unknown,
                    normal_continuation: normal_exit,
                    exceptional_continuation: exceptional_exit,
                },
            )
            .expect("call scaffold");
        let (parts, _) = builder.finish_with_work().expect("finished parts");

        assert_eq!(call_site.index(), 0);
        assert_eq!(parts.call_sites.len(), 1);
        assert_eq!(parts.call_sites[0].source, mapping.source);
        assert!(
            parts.points[invoke.index()]
                .events
                .iter()
                .any(|event| event.effect == SemanticEffect::Invoke { call_site })
        );
        assert!(
            parts.points[normal_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Normal,
                        }
                })
        );
        assert!(
            parts.points[exceptional_exit.index()]
                .events
                .iter()
                .any(|event| {
                    event.effect
                        == SemanticEffect::CallContinuation {
                            call_site,
                            kind: CallContinuationKind::Exceptional,
                        }
                })
        );
    }
}
