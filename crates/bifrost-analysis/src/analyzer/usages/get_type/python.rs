use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, PythonDefinitionProvider, ResolutionSession,
    python_type_lookup_resolution_bounded,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, resolve_analyzer};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use tree_sitter::Tree;

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_python_type_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_type(
            "python_parse_failed",
            "Python source could not be parsed",
        ));
    };
    let support = PythonDefinitionProvider::new(python, &session);
    let Some(resolution) = python_type_lookup_resolution_bounded(
        &support,
        token,
        file,
        source,
        tree.root_node(),
        site,
    ) else {
        return session.finish(no_type(
            "python_dynamic_receiver_unsupported",
            format!(
                "`{}` has no structurally proven Python type; untyped values, dynamic attributes, descriptors, decorators, and metaclasses remain open",
                site.text
            ),
        ));
    };
    let fqn = resolution.unit.fq_name();
    session.finish(candidates_outcome_with_target_kind(
        fqn,
        vec![resolution.unit],
        resolution.target_kind,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{
        TypeLookupOutcome, TypeLookupRequest, TypeLookupStatus, resolve_type_batch_with_budget,
    };
    use crate::analyzer::usages::receiver_analysis::{
        INTERACTIVE_TYPE_LOOKUP_BUDGET, ReceiverAnalysisBudget, ReceiverBudgetLimit,
    };
    use crate::analyzer::{Language, ProjectFile};
    use crate::test_support::AnalyzerFixture;

    const MEMBER_SOURCE: &str = r#"class Engine:
    def start(self):
        pass


class Car:
    def __init__(self, engine: Engine):
        self.engine = engine


def drive(car: Car):
    car.engine.start()
"#;

    const WIDGET_SOURCE: &str = "class Widget:\n    def paint(self):\n        pass\n";

    const CONSUMER_SOURCE: &str =
        "from widget import Widget\n\n\ndef render(value: Widget):\n    return value\n";

    fn resolve(
        files: &[(&str, &str)],
        path: &str,
        start_byte: usize,
        length: usize,
        budget: ReceiverAnalysisBudget,
    ) -> TypeLookupOutcome {
        let fixture = AnalyzerFixture::new_for_language(Language::Python, files);
        let file = ProjectFile::new(fixture.project_root(), path);
        let mut outcomes = resolve_type_batch_with_budget(
            fixture.analyzer.analyzer(),
            vec![TypeLookupRequest {
                file,
                source: None,
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + length),
            }],
            budget,
        );
        assert_eq!(outcomes.len(), 1);
        outcomes.pop().unwrap()
    }

    /// The caret sits on `engine` in `car.engine.start()`.
    fn member_expression(budget: ReceiverAnalysisBudget) -> TypeLookupOutcome {
        let start = MEMBER_SOURCE.find("car.engine").expect("member expression") + "car.".len();
        resolve(
            &[("app.py", MEMBER_SOURCE)],
            "app.py",
            start,
            "engine".len(),
            budget,
        )
    }

    /// The caret sits on `value`, a parameter annotated with an imported class.
    fn imported_annotation(budget: ReceiverAnalysisBudget) -> TypeLookupOutcome {
        let start = CONSUMER_SOURCE.find("return value").expect("return") + "return ".len();
        resolve(
            &[
                ("widget.py", WIDGET_SOURCE),
                ("consumer.py", CONSUMER_SOURCE),
            ],
            "consumer.py",
            start,
            "value".len(),
            budget,
        )
    }

    /// The two site shapes #1887 added both answer under the interactive
    /// budget: a member expression through its receiver's class, and a
    /// parameter annotated with a class imported from another workspace file.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn the_interactive_budget_answers_both_python_site_shapes() {
        let member = member_expression(INTERACTIVE_TYPE_LOOKUP_BUDGET);
        assert_eq!(member.status, TypeLookupStatus::Resolved, "{member:#?}");
        assert_eq!(member.types[0].fqn, "app.Engine", "{member:#?}");

        let annotation = imported_annotation(INTERACTIVE_TYPE_LOOKUP_BUDGET);
        assert_eq!(
            annotation.status,
            TypeLookupStatus::Resolved,
            "{annotation:#?}"
        );
        assert_eq!(annotation.types[0].fqn, "widget.Widget", "{annotation:#?}");
    }

    /// Exhausting a budget axis on either shape stays a typed incomplete
    /// outcome that names the axis, not a silent "no type".
    #[test]
    fn budget_exhaustion_on_either_python_shape_names_the_axis() {
        for outcome in [
            member_expression(ReceiverAnalysisBudget::tiny()),
            imported_annotation(ReceiverAnalysisBudget::tiny()),
        ] {
            assert_eq!(
                outcome.status,
                TypeLookupStatus::ExceededBudget(ReceiverBudgetLimit::ScopeNodes),
                "{outcome:#?}"
            );
            assert!(outcome.types.is_empty(), "{outcome:#?}");
            assert_eq!(
                outcome.diagnostics[0].kind, "resolution_budget_exhausted",
                "{outcome:#?}"
            );
        }
    }
}
