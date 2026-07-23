use super::{TypeLookupOutcome, candidates_outcome, no_type, type_reference_outcome};
use crate::analyzer::usages::get_definition::{
    AnalyzerRustDefinitionProvider, BoundedResolution, ResolutionSession, RustTypeLookupCache,
    rust_expression_type_definition_fqn_cached, rust_is_type_definition,
    rust_resolve_type_node_fqn,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use crate::analyzer::usages::rust_graph::RustDefinitionProvider;
use crate::analyzer::{IAnalyzer, ProjectFile, RustAnalyzer, resolve_analyzer};
use crate::cancellation::CancellationToken;
use tree_sitter::{Node, Tree};

pub(super) fn resolve_rust_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> TypeLookupOutcome {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return no_type("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let support = AnalyzerRustDefinitionProvider::new(rust, true);
    resolve_rust_type_with_provider(analyzer, file, source, tree, site, cache, &support)
}

pub(crate) fn resolve_rust_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable",
        ));
    };
    let support = AnalyzerRustDefinitionProvider::bounded(rust, &session);
    let mut cache = RustTypeLookupCache::bounded_for_query(file, source, tree);
    let outcome =
        resolve_rust_type_with_provider(analyzer, file, source, tree, site, &mut cache, &support);
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
fn resolve_rust_type_with_provider(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
    support: &dyn RustDefinitionProvider,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("rust_parse_failed", "Rust source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_type(
            "no_reference_node",
            "no Rust syntax node at reference location",
        );
    };
    if rust_is_type_reference_position(node) {
        let Some(fqn) = rust_resolve_type_node_fqn(
            analyzer,
            support,
            file,
            source,
            node,
            Some(node.start_byte()),
        ) else {
            return no_type(
                "no_explicit_type",
                format!(
                    "`{}` does not have a supported explicit Rust type",
                    site.text
                ),
            );
        };
        let candidates: Vec<_> = support
            .fqn(&fqn)
            .into_iter()
            .filter(|unit| rust_is_type_definition(analyzer, unit))
            .collect();
        if candidates.is_empty() {
            return no_type(
                "no_indexed_type_definition",
                format!("`{fqn}` resolved as a Rust type but has no indexed definition"),
            );
        }
        return type_reference_outcome(fqn, candidates);
    }

    let expression = rust_type_lookup_expression(node);
    let Some(fqn) = rust_expression_type_definition_fqn_cached(
        analyzer,
        support,
        file,
        source,
        tree.root_node(),
        expression,
        site.range.start_byte,
        cache,
    ) else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Rust type",
                site.text
            ),
        );
    };
    let candidates: Vec<_> = support
        .fqn(&fqn)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .collect();
    if candidates.is_empty() {
        return no_type(
            "no_indexed_type_definition",
            format!("`{fqn}` resolved as a Rust type but has no indexed definition"),
        );
    }
    candidates_outcome(fqn, candidates)
}

fn rust_type_lookup_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        let Some(parent) = node.parent() else {
            return node;
        };
        let node_id = node.id();
        let parent_is_semantic_expression = match parent.kind() {
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "struct_expression" => parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node_id),
            "field_expression" => parent
                .child_by_field_name("field")
                .is_some_and(|field| field.id() == node_id),
            "await_expression"
            | "parenthesized_expression"
            | "reference_expression"
            | "try_expression" => true,
            _ => false,
        };
        if !parent_is_semantic_expression {
            return node;
        }
        node = parent;
    }
}

fn rust_is_type_reference_position(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.child_by_field_name("type") == Some(node)
            || parent.child_by_field_name("trait") == Some(node)
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "generic_type"
                | "scoped_type_identifier"
                | "qualified_type"
                | "reference_type"
                | "pointer_type"
                | "array_type"
                | "bracketed_type"
                | "tuple_type"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn full_expression_site(
        file: &ProjectFile,
        source: &str,
        expression: &str,
    ) -> ResolvedReferenceSite {
        let start_byte = source
            .rfind(expression)
            .unwrap_or_else(|| panic!("missing expression {expression:?}"));
        let end_byte = start_byte + expression.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let end_line = source[..end_byte]
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
                start_line,
                end_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn type_fixture() -> (AnalyzerFixture, ProjectFile, &'static str, Tree) {
        let source = r#"
struct Service {
    marker: i32,
}

impl Service {
    fn run(&self) {}
    fn current(&self) {
        self.run();
    }
}

fn make_service() -> Service {
    Service { marker: 0 }
}

fn use_service(service: Service) {
    let allocated = Service { marker: 1 };
    let factory = make_service();
    service.run();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree =
            parse_tree_for_language(&file, Language::Rust, source).expect("parse Rust source");
        (fixture, file, source, tree)
    }

    #[test]
    fn bounded_type_lookup_resolves_parameters_allocations_and_factory_returns() {
        let (fixture, file, source, tree) = type_fixture();
        for expression in ["self", "service", "Service { marker: 1 }", "make_service()"] {
            let outcome = resolve_rust_type_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &full_expression_site(&file, source, expression),
                ReceiverAnalysisBudget::default(),
                None,
            );

            let BoundedResolution::Complete { value, work } = outcome else {
                panic!("{expression} lookup should complete");
            };
            assert!(work.scope_nodes > 0, "{expression}: {work:#?}");
            assert_eq!(
                value.status,
                TypeLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert_eq!(
                value.target_kind,
                TypeLookupTargetKind::ValueExpression,
                "{expression}: {value:#?}"
            );
            assert!(
                matches!(
                    value.types.as_slice(),
                    [ty]
                        if ty.fqn == "Service"
                            && matches!(
                                ty.definitions.as_slice(),
                                [definition] if definition.fq_name() == "Service"
                            )
                ),
                "{expression}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_type_lookup_stops_at_scope_budget() {
        let (fixture, file, source, tree) = type_fixture();
        let budget = ReceiverAnalysisBudget::tiny();
        let outcome = resolve_rust_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &full_expression_site(&file, source, "service"),
            budget,
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }
}
