use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ResolutionSession, ScalaDefinitionProvider, ScalaTypeLookupResolution,
    scala_type_lookup_resolution, scala_type_lookup_resolution_in_session,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    BoundedDefinitionLookup, IAnalyzer, ProjectFile, ScalaAnalyzer, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(super) fn resolve_scala_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    resolve_scala_type_with_support(analyzer, support, file, source, tree, site)
}

pub(crate) fn resolve_scala_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        ));
    };
    let support = ScalaDefinitionProvider::new(scala, &session);
    let Some(tree) = tree else {
        return session.finish(no_type(
            "scala_parse_failed",
            "Scala source could not be parsed",
        ));
    };
    let resolution = scala_type_lookup_resolution_in_session(
        analyzer,
        &support,
        file,
        source,
        tree.root_node(),
        site,
        &session,
    );
    let outcome = scala_type_resolution_outcome(&support, site, resolution);
    session.finish(outcome)
}

fn resolve_scala_type_with_support(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(_scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_type(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_type("scala_parse_failed", "Scala source could not be parsed");
    };
    let resolution =
        scala_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site);
    scala_type_resolution_outcome(support, site, resolution)
}

fn scala_type_resolution_outcome(
    support: &dyn BoundedDefinitionLookup,
    site: &ResolvedReferenceSite,
    resolution: Option<ScalaTypeLookupResolution>,
) -> TypeLookupOutcome {
    let Some(resolution) = resolution else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Scala type",
                site.text
            ),
        );
    };
    match resolution {
        ScalaTypeLookupResolution::Type { fqn, target_kind } => {
            let candidates = support.fqn(&fqn);
            if candidates.is_empty() {
                return no_type(
                    "no_indexed_type_definition",
                    format!("`{fqn}` resolved as a Scala type but has no indexed definition"),
                );
            }
            candidates_outcome_with_target_kind(fqn, candidates, target_kind)
        }
        ScalaTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn expression_site(
        file: &ProjectFile,
        source: &str,
        expression: &str,
    ) -> ResolvedReferenceSite {
        let start_byte = source
            .find(expression)
            .unwrap_or_else(|| panic!("missing expression {expression:?}"));
        let end_byte = start_byte + expression.len();
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: expression.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn last_expression_site(
        file: &ProjectFile,
        source: &str,
        expression: &str,
    ) -> ResolvedReferenceSite {
        let start_byte = source
            .rfind(expression)
            .unwrap_or_else(|| panic!("missing expression {expression:?}"));
        let end_byte = start_byte + expression.len();
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: expression.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn factory_fixture() -> (AnalyzerFixture, ProjectFile, &'static str, Tree) {
        const SOURCE: &str = r#"
class Service
object Factory {
  def makeService(): Service = new Service()
}
object Caller {
  val service = Factory.makeService()
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Receiver.scala", SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.scala");
        let tree =
            parse_tree_for_language(&file, Language::Scala, SOURCE).expect("Scala syntax tree");
        (fixture, file, SOURCE, tree)
    }

    fn deep_wide_factory_source(width: usize, depth: usize) -> String {
        let mut source = String::from(
            r#"
class Service
object Factory {
  def makeService(): Service = new Service()
}
object Caller {
  def use(): Unit = {
"#,
        );
        for index in 0..width {
            source.push_str(&format!("    val sibling{index} = {index}\n"));
        }
        for _ in 0..depth {
            source.push_str("    {\n");
        }
        source.push_str("      Factory.makeService()\n");
        for _ in 0..depth {
            source.push_str("    }\n");
        }
        source.push_str(
            r#"  }
}
"#,
        );
        source
    }

    #[test]
    fn bounded_same_file_singleton_factory_call_has_declared_result_type() {
        let (fixture, file, source, tree) = factory_fixture();
        let outcome = resolve_scala_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &expression_site(&file, source, "Factory.makeService()"),
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("bounded Scala factory lookup must complete: {outcome:#?}");
        };
        assert!(work.scope_nodes > 0, "{work:#?}");
        assert_eq!(
            value.status,
            super::super::TypeLookupStatus::Resolved,
            "{value:#?}"
        );
        assert_eq!(
            value.target_kind,
            TypeLookupTargetKind::ValueExpression,
            "{value:#?}"
        );
        assert!(
            matches!(
                value.types.as_slice(),
                [ty] if ty.fqn == "Service"
                    && matches!(ty.definitions.as_slice(), [definition] if definition.fq_name() == "Service")
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_scala_factory_lookup_reports_scope_budget_without_partial_result() {
        let (fixture, file, source, tree) = factory_fixture();
        let budget = ReceiverAnalysisBudget::tiny();
        let outcome = resolve_scala_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &expression_site(&file, source, "Factory.makeService()"),
            budget,
            None,
        );

        assert!(
            matches!(
                outcome,
                BoundedResolution::Exceeded {
                    limit: ReceiverBudgetLimit::ScopeNodes,
                    work,
                } if work.scope_nodes == budget.max_scope_nodes
            ),
            "{outcome:#?}"
        );
    }

    #[test]
    fn bounded_scala_deep_wide_lookup_stops_at_exact_small_scope_budget() {
        let source = deep_wide_factory_source(128, 128);
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Receiver.scala", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.scala");
        let tree = parse_tree_for_language(&file, Language::Scala, &source)
            .expect("deep and wide Scala syntax tree");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 48,
            ..ReceiverAnalysisBudget::default()
        };

        let outcome = resolve_scala_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &expression_site(&file, &source, "Factory.makeService()"),
            budget,
            None,
        );

        assert!(
            matches!(
                outcome,
                BoundedResolution::Exceeded {
                    limit: ReceiverBudgetLimit::ScopeNodes,
                    work,
                } if work.scope_nodes == budget.max_scope_nodes
            ),
            "{outcome:#?}"
        );
    }

    #[test]
    fn bounded_scala_deep_alias_chain_is_iterative() {
        const ALIASES: usize = 2_048;
        let mut source = String::from(
            r#"
class Service
object Caller {
  def use(): Unit = {
    val service0: Service = new Service()
"#,
        );
        for index in 1..ALIASES {
            source.push_str(&format!("    val service{index} = service{}\n", index - 1));
        }
        source.push_str(&format!("    service{}\n  }}\n}}\n", ALIASES - 1));
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Receiver.scala", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.scala");
        let tree = parse_tree_for_language(&file, Language::Scala, &source)
            .expect("deep Scala alias-chain syntax tree");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 200_000,
            ..ReceiverAnalysisBudget::default()
        };
        let target = format!("service{}", ALIASES - 1);

        let outcome = resolve_scala_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &last_expression_site(&file, &source, &target),
            budget,
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("iterative Scala alias lookup must complete: {outcome:#?}");
        };
        assert!(work.scope_nodes < budget.max_scope_nodes, "{work:#?}");
        assert_eq!(
            value.status,
            super::super::TypeLookupStatus::Resolved,
            "{value:#?}"
        );
        assert!(
            matches!(value.types.as_slice(), [ty] if ty.fqn == "Service"),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_scala_factory_lookup_reports_cancellation_without_partial_result() {
        let (fixture, file, source, tree) = factory_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let outcome = resolve_scala_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &expression_site(&file, source, "Factory.makeService()"),
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }
}
