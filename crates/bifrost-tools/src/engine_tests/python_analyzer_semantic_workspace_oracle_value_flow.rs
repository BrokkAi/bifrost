#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::ValueFlowOracle;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProcedureKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::call::CallBinding;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::call::CallBindings;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::call::ImplicitArgumentKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::ProcedurePortHandle;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

    use brokk_bifrost_semantic::analyzer::semantic::ir::CallSiteHandle;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::traits::DispatchOracle;

    use crate::analyzer::semantic::OracleLimits;

    use crate::analyzer::semantic::ProcedureSemantics;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon("#3127: decorated Python calls bound to the hidden undecorated signature")]
    fn decorated_call_bindings_are_empty_open_and_unknown() {
        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "decorators.py",
                r#"def replace(function):
    return "replacement"

@replace
def decorated(value="fallback"):
    return value

def direct(value="fallback"):
    return value

def caller():
    decorated_result = decorated()
    direct_default = direct()
    direct_argument = direct("actual")
"#,
            )
            .build();
        let file = project.file("decorators.py");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python semantic materialization runs")
            .available_value()
            .cloned()
            .expect("Python semantic artifact is available");
        fn procedure_name(procedure: &ProcedureSemantics) -> Option<&str> {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
        }
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure_name(procedure) == Some("caller"))
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let calls = caller
            .semantics()
            .call_sites()
            .iter()
            .map(|call| {
                caller
                    .call_site_handle(call.id)
                    .expect("caller call-site handle")
            })
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 3, "caller retains its three call sites");

        let oracle = analyzer.semantic_oracle_provider();
        let candidate_for = |call: &CallSiteHandle, target_name: &str| {
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let dispatch = oracle
                .resolve_call(call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("call dispatch runs");
            dispatch
                .available_value()
                .expect("call dispatch retains a result")
                .candidates()
                .iter()
                .find(|candidate| {
                    procedure_name(candidate.target().semantics()) == Some(target_name)
                })
                .cloned()
                .unwrap_or_else(|| panic!("missing dispatch candidate {target_name}"))
        };
        let decorated_candidate = candidate_for(&calls[0], "decorated");
        let direct_default_candidate = candidate_for(&calls[1], "direct");
        let direct_argument_candidate = candidate_for(&calls[2], "direct");

        let mut decorated_budget =
            crate::analyzer::semantic::SemanticBudget::uniform(1).expect("positive small budget");
        let decorated_outcome = oracle
            .call_bindings(
                &calls[0],
                &decorated_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut decorated_budget, &cancellation),
            )
            .expect("decorated call bindings run");
        assert!(
            matches!(&decorated_outcome, SemanticOutcome::Unknown { .. }),
            "decorated call boundary is unknown: {decorated_outcome:#?}"
        );
        let decorated_bindings = decorated_outcome
            .available_value()
            .expect("unknown decorated call retains empty bindings");
        assert_eq!(decorated_bindings.coverage(), CandidateCoverage::Open);
        assert!(decorated_bindings.bindings().is_empty());
        assert_eq!(decorated_budget.used().procedures, 1);
        assert_eq!(decorated_budget.used().call_sites, 1);
        assert_eq!(decorated_budget.used().nested_entries, 1);

        let mut direct_budget = crate::analyzer::semantic::SemanticBudget::default();
        let direct_default_outcome = oracle
            .call_bindings(
                &calls[1],
                &direct_default_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut direct_budget, &cancellation),
            )
            .expect("undecorated default call bindings run");
        let SemanticOutcome::Complete {
            value: direct_default_bindings,
            ..
        } = direct_default_outcome
        else {
            panic!("undecorated default call bindings close: {direct_default_outcome:#?}");
        };
        assert!(direct_default_bindings.bindings().iter().any(|binding| {
            matches!(
                binding,
                CallBinding::ImplicitArgument {
                    kind: ImplicitArgumentKind::Default,
                    ..
                }
            )
        }));
        assert!(
            direct_default_bindings
                .bindings()
                .iter()
                .any(|binding| matches!(binding, CallBinding::NormalReturn { .. }))
        );
        assert_eq!(
            direct_default_bindings.coverage(),
            CandidateCoverage::Exhaustive
        );

        let mut direct_argument_budget = crate::analyzer::semantic::SemanticBudget::default();
        let direct_argument_outcome = oracle
            .call_bindings(
                &calls[2],
                &direct_argument_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut direct_argument_budget, &cancellation),
            )
            .expect("undecorated argument call bindings run");
        let SemanticOutcome::Complete {
            value: direct_argument_bindings,
            ..
        } = direct_argument_outcome
        else {
            panic!("undecorated argument call bindings close: {direct_argument_outcome:#?}");
        };
        assert!(
            direct_argument_bindings
                .bindings()
                .iter()
                .any(|binding| matches!(binding, CallBinding::ArgumentGroup(_)))
        );
        assert!(
            direct_argument_bindings
                .bindings()
                .iter()
                .any(|binding| matches!(binding, CallBinding::NormalReturn { .. }))
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let mut cancelled_budget = crate::analyzer::semantic::SemanticBudget::default();
        let cancelled_outcome = oracle
            .call_bindings(
                &calls[0],
                &decorated_candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
            )
            .expect("cancelled decorated call bindings return an outcome");
        assert!(matches!(
            &cancelled_outcome,
            SemanticOutcome::Cancelled {
                partial: None,
                work,
            } if *work == SemanticWork::default()
        ));
        assert_eq!(cancelled_budget.used(), SemanticWork::default());
    }
    #[test]
    fn construction_keeps_receiver_effects_without_an_initializer_value_result() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "class Item:\n    def __init__(self):\n        return None\ndef caller():\n    return Item()\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python materialization runs")
            .available_value()
            .cloned()
            .expect("artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller");
        let [call] = caller.semantics().call_sites() else {
            panic!("one construction call");
        };
        let call = caller.call_site_handle(call.id).expect("live call");
        let oracle = analyzer.semantic_oracle_provider();
        let dispatch = oracle
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("dispatch");
        let candidate = dispatch
            .available_value()
            .expect("dispatch result")
            .candidates()
            .iter()
            .find(|candidate| candidate.target().semantics().kind() == ProcedureKind::Constructor)
            .expect("initializer candidate");
        let outcome = oracle
            .call_bindings(
                &call,
                candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("bindings");
        let bindings = outcome
            .available_value()
            .expect("bindings retained")
            .bindings();
        assert!(
            bindings
                .iter()
                .any(|binding| matches!(binding, CallBinding::Receiver { .. })),
            "{bindings:?}"
        );
        assert!(
            bindings
                .iter()
                .any(|binding| matches!(binding, CallBinding::ExceptionalReturn { .. })),
            "{bindings:?}"
        );
        assert!(
            !bindings
                .iter()
                .any(|binding| matches!(binding, CallBinding::NormalReturn { .. })),
            "{bindings:?}"
        );
        // Even an open result must reject the old contradictory transport.
        // Reuse one valid relation's provenance, replacing its exceptional
        // binding so the failure is specifically the allocated result role.
        let mut contradictory = bindings.to_vec();
        let exceptional = contradictory
            .iter()
            .position(|binding| matches!(binding, CallBinding::ExceptionalReturn { .. }))
            .expect("exceptional binding");
        let CallBinding::ExceptionalReturn { relation, .. } = contradictory.remove(exceptional)
        else {
            unreachable!("selected exceptional binding");
        };
        let result = caller
            .semantics()
            .call_site(call.id())
            .expect("call")
            .result
            .expect("constructed result");
        contradictory.push(CallBinding::NormalReturn {
            relation,
            formal: ProcedurePortHandle::normal_return(candidate.target().clone()),
            result: caller.value_handle(result).expect("allocated result"),
        });
        assert!(matches!(
            CallBindings::new(
                call.clone(),
                candidate,
                OracleCallContext::empty(),
                contradictory,
                CandidateCoverage::Open,
                OracleLimits::default(),
            ),
            Err(
                crate::analyzer::semantic::OracleContractError::InvalidCallBinding(
                    "a construction result cannot be bound to its initializer return"
                )
            )
        ));
    }
}
