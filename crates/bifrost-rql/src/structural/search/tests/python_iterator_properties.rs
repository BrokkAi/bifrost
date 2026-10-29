//! Removing receiver evidence cannot strengthen a protocol verdict. The oracle
//! compares actual consumer rows, independently of its eligibility predicate.
use super::*;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::{
    ClassIdentity, SourceSite, SourceSiteKind, UnknownReason,
};
use brokk_bifrost_flow::type_flow::ClassSetStatus;
use proptest::prelude::*;
use std::sync::OnceLock;

struct IteratorFixture {
    _project: inline_project::BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    class_sets: Vec<crate::structural::search::type_flow::OwnedReceiverClassSet>,
}

fn fixtures() -> &'static [IteratorFixture; 2] {
    static FIXTURES: OnceLock<[IteratorFixture; 2]> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        ["self", "[]"].map(|expression| {
            let project = InlineTestProject::with_language(Language::Python)
                .file(
                    "app.py",
                    format!("class Base:\n    def __iter__(self):\n        return {expression}\n"),
                )
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let file = project.file("app.py");
            let facts = workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == Language::Python)
                .unwrap()
                .structural_facts(&file)
                .unwrap();
            let query =
                CodeQuery::from_source("(language python (method :name \"__iter__\"))").unwrap();
            let fact_match =
                super::super::super::matcher::match_query(query.seed().unwrap(), &facts, 1)
                    .into_iter()
                    .next()
                    .unwrap();
            let seed = SeedMatch {
                language: Language::Python,
                file,
                facts,
                fact_match,
                python_import: None,
            };
            let mut semantic = SemanticQueryContext::new(
                &workspace,
                None,
                CodeQueryExecutionLimits::default().semantic,
            );
            let procedure = semantic.procedure_of_match(&seed).remove(0);
            let mut full = semantic.python_iterator_return_sets(&procedure);
            drop(semantic);
            assert_eq!(full.len(), 2);
            // These are constructed
            // class-set inputs, not a claim that its original evidence is Known.
            for set in &mut full {
                set.status = ClassSetStatus::Known;
                set.unknown.clear();
                set.flow_unknown.clear();
                set.classes = vec![(
                    ClassIdentity::Intrinsic {
                        qualified_name: "builtins.object".into(),
                    },
                    SourceSite {
                        file: set.site.file.clone(),
                        span: set.site.span,
                        kind: SourceSiteKind::Literal,
                    },
                )];
            }
            IteratorFixture {
                _project: project,
                workspace,
                class_sets: full,
            }
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn weaker_class_sets_never_strengthen_verdicts(
        side in 0usize..3,
        clear_class in any::<bool>(),
        unknown in prop_oneof![Just(UnknownReason::ExternalNotModeled), Just(UnknownReason::UncertainFlow)],
        initially_open in any::<bool>(),
        flow_unknown in any::<bool>(),
        literal_return in any::<bool>(),
    ) {
        let fixture = &fixtures()[usize::from(literal_return)];
        let workspace = &fixture.workspace;
        let mut full = fixture.class_sets.clone();
        if initially_open {
            full[0].status = ClassSetStatus::Partial;
            full[0].unknown.push(UnknownReason::UncertainFlow);
        }
        let mut weak = full.clone();
        for (index, set) in weak.iter_mut().enumerate() {
            if side == 2 || side == index {
                if clear_class {
                    set.classes.clear();
                } else {
                    set.status = ClassSetStatus::Partial;
                    set.unknown.push(unknown.clone());
                    if flow_unknown {
                        set.flow_unknown.push(unknown.clone());
                    }
                }
            }
        }
        let verdicts = |sets: &[_]| {
            python_rule_facts::iterator_return_protocol_expansions(workspace.analyzer(), Some(workspace), sets, None)
                .into_iter().map(|expansion| match expansion.value {
                    PipelineValue::PythonRuleFact(fact) => (fact.row.proof == "proven", fact.row.completeness == "complete"),
                    _ => panic!("protocol consumer returned a different row kind"),
                }).collect::<Vec<_>>()
        };
        let full = verdicts(&full);
        let weak = verdicts(&weak);
        prop_assert_eq!(full.len(), 1);
        prop_assert_eq!(weak.len(), 1);
        prop_assert!(!weak[0].0 || full[0].0);
        prop_assert!(!weak[0].1 || full[0].1);
        prop_assert_eq!(weak[0], (false, false));
        prop_assert_eq!(full[0], (!initially_open, !initially_open));
    }
}
