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
        let parts = session.query_limited_rows(|limit| {
            csharp.partial_type_parts_limited(&candidate, limit, || session.observe_cancellation())
        });
        if !session.observe_cancellation() {
            return Vec::new();
        }
        if parts.is_empty() {
            if !session.scope_step() {
                return Vec::new();
            }
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
    use std::thread;

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

    fn bounded_expression_lookup(
        file_name: &str,
        source: &str,
        expression: &str,
        budget: ReceiverAnalysisBudget,
        cancel_after_checks: Option<usize>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[(file_name, source)]);
        let file = ProjectFile::new(fixture.project_root(), file_name);
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let cancellation = cancel_after_checks.map(CancellationToken::cancel_after_checks_for_test);
        resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &full_expression_site(&file, source, expression),
            budget,
            cancellation.as_ref(),
        )
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
    fn bounded_cross_file_return_and_member_types_use_structured_metadata() {
        let caller = r#"
using Demo.Models;

namespace Demo.App;

public class Caller
{
    public void Run(Factory factory)
    {
        Product fromCall = factory.Create();
        Product fromMember = factory.Value;
    }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[
                (
                    "Models.cs",
                    r#"
namespace Demo.Models;
public class Product {}
public class Factory
{
    public Product Value { get; }
    public Product Create() => null;
}
"#,
                ),
                ("Caller.cs", caller),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "Caller.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, caller).expect("C# tree");

        for expression in ["factory.Create()", "factory.Value"] {
            let outcome = resolve_csharp_type_bounded(
                fixture.analyzer.analyzer(),
                &file,
                caller,
                Some(&tree),
                &full_expression_site(&file, caller, expression),
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, work } = outcome else {
                panic!("{expression} should complete");
            };
            assert!(work.scope_nodes > 0, "{expression}: {work:#?}");
            assert_eq!(
                value.status,
                TypeLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert_eq!(
                value.types[0].fqn, "Demo.Models.Product",
                "{expression}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_return_type_prefers_exact_nested_lexical_scope_over_same_name_decoy() {
        let source = r#"
namespace Demo;

public class Product {}

public class Outer
{
    public class Product {}

    public class Factory
    {
        public Product Create() => null;
    }

    public void Run(Outer.Factory factory)
    {
        Outer.Product product = factory.Create();
    }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("NestedReturn.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "NestedReturn.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");
        let expression = "factory.Create()";
        let outcome = resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &full_expression_site(&file, source, expression),
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("{expression} should complete");
        };
        assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert_eq!(value.types[0].fqn, "Demo.Outer$Product", "{value:#?}");
        assert_ne!(value.types[0].fqn, "Demo.Product", "{value:#?}");
    }

    #[test]
    fn bounded_generic_type_parameters_never_resolve_to_same_named_classes() {
        let source = r#"
namespace Demo;

public class T
{
    public void WrongTarget() {}
}

public class TResult
{
    public void WrongTarget() {}
}

public class Service
{
    public void RightTarget() {}
}

public class Factory<T>
{
    public T Value;
    public T Create() => default;
}

public class MethodFactory
{
    public TResult Create<TResult>() => default;
}

public class Caller
{
    public void Run(Factory<Service> factory, MethodFactory methods)
    {
        factory.Create().RightTarget();
        factory.Value.RightTarget();
        methods.Create().RightTarget();
        methods.Create<Service>().RightTarget();
    }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::CSharp, &[("TypeParameters.cs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "TypeParameters.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, source).expect("C# tree");

        for expression in ["factory.Create()", "factory.Value", "methods.Create()"] {
            let outcome = resolve_csharp_type_bounded(
                fixture.analyzer.analyzer(),
                &file,
                source,
                Some(&tree),
                &full_expression_site(&file, source, expression),
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete conservatively");
            };
            assert_eq!(
                value.status,
                TypeLookupStatus::NoType,
                "{expression} must not resolve to the unrelated Demo.T: {value:#?}"
            );
            assert!(value.types.is_empty(), "{expression}: {value:#?}");
        }

        let expression = "methods.Create<Service>()";
        let outcome = resolve_csharp_type_bounded(
            fixture.analyzer.analyzer(),
            &file,
            source,
            Some(&tree),
            &full_expression_site(&file, source, expression),
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("{expression} should complete");
        };
        assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert_eq!(value.types[0].fqn, "Demo.Service", "{value:#?}");
    }

    #[test]
    fn deeply_parenthesized_receiver_is_stack_safe_exact_and_interruptible() {
        let expression = format!("{}factory{}.Create()", "(".repeat(3_000), ")".repeat(3_000));
        let source = format!(
            r#"
namespace Demo;
public class Product {{}}
public class Factory {{ public Product Create() => null; }}
public class Caller
{{
    public void Run(Factory factory) {{ _ = {expression}; }}
}}
"#
        );

        let thread_source = source.clone();
        let thread_expression = expression.clone();
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[("DeepParentheses.cs", &thread_source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "DeepParentheses.cs");
        let tree =
            parse_tree_for_language(&file, Language::CSharp, &thread_source).expect("deep C# tree");
        let site = full_expression_site(&file, &thread_source, &thread_expression);
        let run = move || {
            resolve_csharp_type_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &thread_source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            )
        };
        let first = thread::Builder::new()
            .name("csharp-deep-parentheses".to_string())
            .stack_size(512 * 1024)
            .spawn(run)
            .expect("spawn small-stack C# lookup")
            .join()
            .expect("deep C# lookup must not overflow");
        let second = bounded_expression_lookup(
            "DeepParentheses.cs",
            &source,
            &expression,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let (
            BoundedResolution::Complete {
                value: first_value,
                work: first_work,
            },
            BoundedResolution::Complete {
                value: second_value,
                work: second_work,
            },
        ) = (first, second)
        else {
            panic!("deep C# lookup should complete");
        };
        assert_eq!(first_value.status, TypeLookupStatus::Resolved);
        assert_eq!(first_value.types[0].fqn, "Demo.Product");
        assert_eq!(second_value.status, TypeLookupStatus::Resolved);
        assert_eq!(first_work, second_work, "work accounting must be exact");

        assert!(matches!(
            bounded_expression_lookup(
                "DeepParentheses.cs",
                &source,
                &expression,
                ReceiverAnalysisBudget::tiny(),
                None,
            ),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == ReceiverAnalysisBudget::tiny().max_scope_nodes
        ));
        assert!(matches!(
            bounded_expression_lookup(
                "DeepParentheses.cs",
                &source,
                &expression,
                ReceiverAnalysisBudget::default(),
                Some(64),
            ),
            BoundedResolution::Cancelled { work } if work.scope_nodes > 0
        ));
    }

    #[test]
    fn alternating_call_member_chain_is_stack_safe_and_budgeted() {
        let mut expression = "link".to_string();
        for index in 0..256 {
            if index % 2 == 0 {
                expression.push_str(".Next()");
            } else {
                expression.push_str(".Value");
            }
        }
        let source = format!(
            r#"
namespace Demo;
public class Link
{{
    public Link Value => this;
    public Link Next() => this;
}}
public class Caller
{{
    public void Run(Link link) {{ _ = {expression}; }}
}}
"#
        );
        let thread_source = source.clone();
        let thread_expression = expression.clone();
        let fixture = AnalyzerFixture::new_for_language(
            Language::CSharp,
            &[("Alternating.cs", &thread_source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "Alternating.cs");
        let tree = parse_tree_for_language(&file, Language::CSharp, &thread_source)
            .expect("alternating C# tree");
        let site = full_expression_site(&file, &thread_source, &thread_expression);
        let deep_budget = ReceiverAnalysisBudget {
            max_scope_nodes: 200_000,
            max_summary_expansions: 1_024,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = thread::Builder::new()
            .name("csharp-alternating-chain".to_string())
            .stack_size(512 * 1024)
            .spawn(move || {
                resolve_csharp_type_bounded(
                    fixture.analyzer.analyzer(),
                    &file,
                    &thread_source,
                    Some(&tree),
                    &site,
                    deep_budget,
                    None,
                )
            })
            .expect("spawn small-stack C# chain lookup")
            .join()
            .expect("alternating C# chain must not overflow");
        let (value, work) = match outcome {
            BoundedResolution::Complete { value, work } => (value, work),
            other => panic!("alternating chain should complete: {other:#?}"),
        };
        assert_eq!(value.status, TypeLookupStatus::Resolved, "{value:#?}");
        assert_eq!(value.types[0].fqn, "Demo.Link", "{value:#?}");
        assert!(
            work.scope_nodes > expression.matches('.').count(),
            "{work:#?}"
        );

        assert!(matches!(
            bounded_expression_lookup(
                "Alternating.cs",
                &source,
                &expression,
                ReceiverAnalysisBudget {
                    max_scope_nodes: 128,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            ),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == 128
        ));
        assert!(matches!(
            bounded_expression_lookup(
                "Alternating.cs",
                &source,
                &expression,
                deep_budget,
                Some(96),
            ),
            BoundedResolution::Cancelled { work } if work.scope_nodes > 0
        ));
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
