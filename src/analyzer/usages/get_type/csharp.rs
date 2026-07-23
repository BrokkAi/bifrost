use super::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType, no_type, sort_units,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, CSharpTypeLookupResolution, ResolutionSession,
    csharp_type_lookup_resolution, csharp_type_lookup_resolution_in_session,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(super) fn resolve_csharp_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let session = ResolutionSession::unbounded();
    resolve_csharp_type_in_session(analyzer, file, source, tree, site, &session, false)
}

pub(crate) fn resolve_csharp_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let outcome =
        resolve_csharp_type_in_session(analyzer, file, source, tree, site, &session, true);
    session.finish(outcome)
}

fn resolve_csharp_type_in_session(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    session: &ResolutionSession,
    bounded_lookup: bool,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("csharp_parse_failed", "C# source could not be parsed");
    };
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return no_type("csharp_analyzer_unavailable", "C# analyzer is unavailable");
    };
    let resolution = if bounded_lookup {
        csharp_type_lookup_resolution_in_session(
            analyzer,
            file,
            source,
            tree.root_node(),
            site,
            session,
        )
    } else {
        csharp_type_lookup_resolution(analyzer, file, source, tree.root_node(), site)
    };
    let Some(resolution) = resolution else {
        return no_type(
            "no_explicit_type",
            format!("`{}` does not have a supported explicit C# type", site.text),
        );
    };
    match resolution {
        CSharpTypeLookupResolution::Type {
            fqn,
            candidates,
            target_kind,
            ambiguous,
        } => csharp_candidates_outcome(csharp, fqn, candidates, target_kind, ambiguous, session),
        CSharpTypeLookupResolution::Dynamic { target_kind } => TypeLookupOutcome {
            status: TypeLookupStatus::NoType,
            reference: None,
            types: Vec::new(),
            diagnostics: vec![TypeLookupDiagnostic {
                kind: "csharp_dynamic_receiver_unsupported".to_string(),
                message: "C# `dynamic` receiver resolution requires runtime binding".to_string(),
            }],
            target_kind,
        },
        CSharpTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}

fn csharp_candidates_outcome(
    csharp: &CSharpAnalyzer,
    fqn: String,
    mut candidates: Vec<CodeUnit>,
    target_kind: crate::analyzer::usages::target_kind::TypeLookupTargetKind,
    ambiguous: bool,
    session: &ResolutionSession,
) -> TypeLookupOutcome {
    candidates = csharp_expand_logical_type_parts(csharp, candidates, session);
    sort_units(&mut candidates);
    candidates.dedup();
    let logical_type_count = session
        .query(|| csharp.logical_type_count(&candidates))
        .unwrap_or_default();
    let status = if !ambiguous && logical_type_count <= 1 {
        TypeLookupStatus::Resolved
    } else {
        TypeLookupStatus::Ambiguous
    };
    let fqn = if status == TypeLookupStatus::Resolved {
        session
            .query(|| csharp.first_logical_type_fqn(&candidates))
            .flatten()
            .unwrap_or(fqn)
    } else {
        fqn
    };
    TypeLookupOutcome {
        status,
        reference: None,
        types: vec![TypeLookupType {
            fqn,
            definitions: candidates,
        }],
        diagnostics: if status == TypeLookupStatus::Ambiguous {
            vec![TypeLookupDiagnostic {
                kind: "ambiguous_type".to_string(),
                message: "reference resolved to multiple possible types".to_string(),
            }]
        } else {
            Vec::new()
        },
        target_kind,
    }
}

fn csharp_expand_logical_type_parts(
    csharp: &CSharpAnalyzer,
    candidates: Vec<CodeUnit>,
    session: &ResolutionSession,
) -> Vec<CodeUnit> {
    let mut expanded = Vec::new();
    for candidate in candidates {
        if !session.scope_step() {
            return Vec::new();
        }
        let parts = session.query_rows(|| csharp.partial_type_parts(&candidate));
        if parts.is_empty() {
            expanded.push(candidate);
        } else {
            expanded.extend(parts);
        }
    }
    expanded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
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
            .find(expression)
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

    #[test]
    fn full_structured_expression_ranges_resolve_declared_csharp_types() {
        let source = r#"
namespace Demo;

public class Product {}

public class Factory
{
    public Product Value { get; }
    public Product Create() => null;
}

public class Consumer
{
    public void Run(Factory factory)
    {
        Product construction = new Product();
        Product invocation = factory.Create();
        Product member = factory.Value;
        Product conditional = factory?.Value;
    }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("Expressions.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Expressions.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");

        for expression in [
            "new Product()",
            "factory.Create()",
            "factory.Value",
            "factory?.Value",
        ] {
            let outcome = resolve_csharp_type(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &full_expression_site(&file, source, expression),
            );

            assert_eq!(
                outcome.status,
                TypeLookupStatus::Resolved,
                "{expression}: {outcome:#?}"
            );
            assert_eq!(
                outcome.target_kind,
                TypeLookupTargetKind::ValueExpression,
                "{expression}: {outcome:#?}"
            );
            assert_eq!(outcome.types.len(), 1, "{expression}: {outcome:#?}");
            assert_eq!(
                outcome.types[0].fqn, "Demo.Product",
                "{expression}: {outcome:#?}"
            );
            assert!(
                matches!(
                    outcome.types[0].definitions.as_slice(),
                    [definition] if definition.fq_name() == "Demo.Product"
                ),
                "{expression}: {outcome:#?}"
            );
        }
    }

    #[test]
    fn full_object_creation_range_preserves_ambiguous_visible_types() {
        let source = r#"
using A;
using B;

namespace App;

public class Consumer
{
    public object Create() => new Choice();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[
                ("A/Choice.cs", "namespace A { public class Choice {} }\n"),
                ("B/Choice.cs", "namespace B { public class Choice {} }\n"),
                ("App/Consumer.cs", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "App/Consumer.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let outcome = resolve_csharp_type(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &full_expression_site(&file, source, "new Choice()"),
        );

        assert_eq!(outcome.status, TypeLookupStatus::Ambiguous, "{outcome:#?}");
        let fq_names = outcome.types[0]
            .definitions
            .iter()
            .map(CodeUnit::fq_name)
            .collect::<Vec<_>>();
        assert_eq!(fq_names, ["A.Choice", "B.Choice"], "{outcome:#?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "ambiguous_type"),
            "{outcome:#?}"
        );
    }

    #[test]
    fn bounded_type_lookup_reports_scope_budget_without_partial_result() {
        let source = r#"
namespace Demo;
public class Product {}
public class Consumer
{
    public void Run(Product product) { product.ToString(); }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Budget.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Budget.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let site = full_expression_site(&file, source, "product.ToString()");
        let budget = ReceiverAnalysisBudget::tiny();

        let outcome = resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
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

    #[test]
    fn bounded_type_lookup_reports_cancellation_without_partial_result() {
        let source = r#"
namespace Demo;
public class Product {}
public class Consumer
{
    public void Run(Product product) { product.ToString(); }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("Cancelled.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Cancelled.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let site = full_expression_site(&file, source, "product.ToString()");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let outcome = resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }

    #[test]
    fn dynamic_receiver_is_a_structured_unsupported_type_outcome() {
        let source = r#"
namespace Demo;
public class Consumer
{
    public void Run(dynamic receiver) { receiver.DoWork(); }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("Dynamic.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Dynamic.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let call_start = source.rfind("receiver.DoWork()").expect("dynamic call");
        let receiver_start = call_start;
        let receiver_end = receiver_start + "receiver".len();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "receiver".to_string(),
            range: Range {
                start_byte: receiver_start,
                end_byte: receiver_end,
                start_line: 5,
                end_line: 5,
            },
            focus_start_byte: receiver_start,
            focus_end_byte: receiver_end,
        };

        let outcome = resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("dynamic lookup should complete as unsupported");
        };
        assert!(work.scope_nodes > 0);
        assert_eq!(value.status, TypeLookupStatus::NoType);
        assert_eq!(value.target_kind, TypeLookupTargetKind::ValueExpression);
        assert!(value.types.is_empty());
        assert!(
            value
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.kind == "csharp_dynamic_receiver_unsupported" })
        );
    }

    #[test]
    fn exact_this_and_base_keyword_ranges_resolve_receiver_types() {
        let source = r#"
namespace Demo;
public class Parent
{
    public void Inherited() {}
}
public class Child : Parent
{
    public void Own() {}
    public void Run()
    {
        this.Own();
        base.Inherited();
    }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("Keywords.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "Keywords.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");

        for (keyword, expected_fqn) in [("this", "Demo.Child"), ("base", "Demo.Parent")] {
            let outcome = resolve_csharp_type_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &full_expression_site(&file, source, keyword),
                ReceiverAnalysisBudget::default(),
                None,
            );

            let BoundedResolution::Complete { value, work } = outcome else {
                panic!("{keyword} lookup should complete");
            };
            assert!(work.scope_nodes > 0, "{keyword}: {work:#?}");
            assert_eq!(
                value.status,
                TypeLookupStatus::Resolved,
                "{keyword}: {value:#?}"
            );
            assert_eq!(
                value.target_kind,
                TypeLookupTargetKind::ValueExpression,
                "{keyword}: {value:#?}"
            );
            assert_eq!(value.types.len(), 1, "{keyword}: {value:#?}");
            assert_eq!(value.types[0].fqn, expected_fqn, "{keyword}: {value:#?}");
            assert!(
                matches!(
                    value.types[0].definitions.as_slice(),
                    [definition] if definition.fq_name() == expected_fqn
                ),
                "{keyword}: {value:#?}"
            );
        }
    }
}
