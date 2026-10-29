use crate::CSharpAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::test_support::AnalyzerFixture;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use brokk_bifrost_core::analyzer::{Language, ProjectFile};
use brokk_bifrost_csharp::graph::resolver::{
    seed_bindings_before, seed_bindings_before_in_session, seed_visible_bindings_at,
};
use brokk_bifrost_csharp::preprocessor::parse_csharp;
use brokk_bifrost_test_macros::hardwon;

fn assert_proven_usage_count(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    fqn: &str,
    expected: usize,
) {
    use crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch;
    use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;
    use brokk_bifrost_core::hash::HashSet;
    let target = analyzer
        .get_definitions(fqn)
        .into_iter()
        .find(|unit| unit.is_function())
        .expect("method declaration");
    let scope = AnalyzerQueryScope::new(analyzer);
    let roots = HashSet::from_iter([file.clone()]);
    let batch = CSharpAuthoritativeUsageBatch::new(analyzer, scope.token(), &roots)
        .expect("C# authoritative batch");
    let result = batch
        .find_usages(std::slice::from_ref(&target), &roots, 100)
        .into_fuzzy_result();
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = result
    else {
        panic!("{result:?}");
    };
    let hits = hits_by_overload
        .get(&target)
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(hits.len(), expected, "{fqn}: {hits:?}");
}

#[test]
#[hardwon(
    "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: nested initializer scopes leaked parameter bindings"
)]
fn completed_initializer_and_sibling_scopes_preserve_outer_bindings() {
    let source = r#"
class Widget { public void Touch() {} }
class Decoy { public void Touch() {} }
class C {
    void Earlier(Decoy alien) { }
    void M(Widget p, Widget unrelated) {
        System.Action<Decoy> f = (Decoy p) => {};
        { Decoy sibling = new Decoy(); }
        p.Touch(); unrelated.Touch();
    }
}
"#;
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Scopes.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "Scopes.cs");
    let tree = parse_csharp(source).unwrap();
    let cutoff = source.find("p.Touch();").unwrap();
    let mut ordinary = LocalInferenceEngine::default();
    seed_bindings_before(
        tree.root_node(),
        cutoff,
        csharp,
        scope.token(),
        &file,
        source,
        &mut ordinary,
    );
    let mut bounded = LocalInferenceEngine::default();
    seed_bindings_before_in_session(
        tree.root_node(),
        cutoff,
        csharp,
        scope.token(),
        &file,
        source,
        &mut bounded,
        &ResolutionSession::unbounded(),
    );
    for bindings in [&ordinary, &bounded] {
        assert!(bindings.resolve_symbol("sibling").is_unknown());
        assert!(bindings.resolve_symbol("alien").is_unknown());
        for name in ["p", "unrelated"] {
            let result = bindings.resolve_symbol(name);
            let types = result.as_precise().unwrap();
            assert!(
                types.len() == 1 && types.iter().next().unwrap().as_type_name() == "Widget",
                "{name}: {result:?}"
            );
        }
    }
    assert_proven_usage_count(analyzer, &file, "Widget.Touch", 2);
    assert_proven_usage_count(analyzer, &file, "Decoy.Touch", 0);
}

#[test]
#[hardwon(
    "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: var creation lookup selected a factory argument"
)]
fn factory_arguments_do_not_determine_initializer_type() {
    let source = r#"
class Foo { public void Touch() {} }
class Bar { public void Touch() {} }
class C {
    Bar Factory(Foo x) => new Bar();
    void M() { var value = Factory(new Foo()); value.Touch(); }
}
"#;
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Factory.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "Factory.cs");
    let tree = parse_csharp(source).unwrap();
    let cutoff = source.find("value.Touch()").unwrap();
    let target = tree
        .root_node()
        .named_descendant_for_byte_range(cutoff, cutoff + 5)
        .unwrap();
    let mut bindings = LocalInferenceEngine::default();
    seed_visible_bindings_at(
        tree.root_node(),
        target,
        csharp,
        scope.token(),
        &file,
        source,
        &mut bindings,
    );
    let result = bindings.resolve_symbol("value");
    assert_eq!(
        result
            .as_precise()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        ["Bar"],
        "{result:?}"
    );
    assert_proven_usage_count(analyzer, &file, "Bar.Touch", 1);
    assert_proven_usage_count(analyzer, &file, "Foo.Touch", 0);
}

#[test]
fn initializer_receiver_typing_preserves_checked_context_and_overload_arity() {
    let source = r#"
class Widget { public void Touch() {} }
class Decoy { public void Touch() {} }
class C {
    Widget Make() => new Widget();
    Decoy Make(int ignored) => new Decoy();
    void M(Widget first, Widget second) {
        var a = checked(Make());
        var b = unchecked(Make());
        var c = ((Make()));
        a.Touch(); b.Touch(); c.Touch(); first.Touch(); second.Touch();
    }
}
"#;
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Checked.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "Checked.cs");
    let tree = parse_csharp(source).unwrap();
    let cutoff = source.find("a.Touch()").unwrap();
    let target = tree
        .root_node()
        .named_descendant_for_byte_range(cutoff, cutoff + 1)
        .unwrap();
    let mut bindings = LocalInferenceEngine::default();
    seed_visible_bindings_at(
        tree.root_node(),
        target,
        csharp,
        scope.token(),
        &file,
        source,
        &mut bindings,
    );
    for name in ["a", "b", "c", "first", "second"] {
        let result = bindings.resolve_symbol(name);
        assert_eq!(
            result
                .as_precise()
                .unwrap()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            ["Widget"],
            "{name}: {result:?}"
        );
    }
    let mut bounded = LocalInferenceEngine::default();
    seed_bindings_before_in_session(
        tree.root_node(),
        cutoff,
        csharp,
        scope.token(),
        &file,
        source,
        &mut bounded,
        &ResolutionSession::unbounded(),
    );
    for name in ["first", "second"] {
        assert_eq!(
            bounded
                .resolve_symbol(name)
                .as_precise()
                .unwrap()
                .iter()
                .map(|ty| ty.as_type_name().to_owned())
                .collect::<Vec<_>>(),
            ["Widget"]
        );
    }
}

#[test]
fn unresolved_external_parameters_retain_spelling_without_claiming_identity() {
    use brokk_bifrost_csharp::graph::resolver::CSharpDeclaredType;
    let source = "class C { void M(External.Widget value) { value.Touch(); } }";
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("External.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "External.cs");
    let tree = parse_csharp(source).unwrap();
    let cutoff = source.find("value.Touch()").unwrap();
    let mut bindings = LocalInferenceEngine::default();
    seed_bindings_before_in_session(
        tree.root_node(),
        cutoff,
        csharp,
        scope.token(),
        &file,
        source,
        &mut bindings,
        &ResolutionSession::unbounded(),
    );
    let result = bindings.resolve_symbol("value");
    assert!(
        matches!(result.as_precise().unwrap().iter().next().unwrap(), CSharpDeclaredType::Spelling(name) if name == "External.Widget"),
        "{result:?}"
    );
}

#[test]
fn stored_return_and_collection_metadata_preserves_builtins_and_generic_shadowing() {
    use brokk_bifrost_csharp::graph::resolver::{
        member_declared_collection_element_type_fq_name,
        method_return_type_fq_name_for_arity_in_session,
    };
    let source = r#"
class T { public int Value; }
class Owner<T> { public System.Collections.Generic.List<T> Items; }
class Concrete<U> { public System.Collections.Generic.List<T> Items; }
class C { public int Number() => 1; public string Text() => "x"; }
"#;
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Returns.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "Returns.cs");
    let owner = analyzer
        .get_definitions("C")
        .into_iter()
        .find(|unit| unit.is_class())
        .unwrap();
    for (method, expected) in [("Number", "System.Int32"), ("Text", "System.String")] {
        let session = ResolutionSession::unbounded();
        assert_eq!(
            method_return_type_fq_name_for_arity_in_session(
                csharp,
                scope.token(),
                &file,
                &owner,
                method,
                Some(0),
                None,
                None,
                &session
            )
            .as_deref(),
            Some(expected)
        );
    }
    let declarations = analyzer.get_all_declarations();
    for (name, expected) in [("Owner", None), ("Concrete", Some("T"))] {
        let owner = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier().starts_with(name))
            .unwrap_or_else(|| panic!("{name}: {declarations:?}"));
        assert_eq!(
            member_declared_collection_element_type_fq_name(csharp, scope.token(), owner, "Items")
                .as_deref(),
            expected
        );
    }
}

#[test]
fn aliased_base_hierarchies_complete_under_bounded_forward_and_usage_queries() {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
    use brokk_bifrost_csharp::graph::{
        CSharpGraphSource, resolver::compatible_receiver_type_names,
    };
    let source =
        "using Parent = Lib.Base; namespace Lib { public class Base {} } class Derived : Parent {}";
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Bases.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    for usage in [false, true] {
        // Two physical declarations have one direct base between them. This
        // finite allowance completes their store reads once, but cannot pay
        // for expanding a duplicate owner appended to its persisted parts.
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 38,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let result = compatible_receiver_type_names(
            csharp,
            scope.token(),
            &CSharpGraphSource::from_source(csharp),
            &["Derived".to_owned()],
            usage,
            Some(&session),
        );
        assert!(result.contains("Lib.Base"), "usage={usage}: {result:?}");
        let outcome = session.finish(result);
        assert!(matches!(outcome, BoundedResolution::Complete { .. }));
    }
}

#[test]
fn ambiguous_constructors_have_no_proven_inverse_hits() {
    use crate::analyzer::usages::csharp_graph::CSharpAuthoritativeUsageBatch;
    use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;
    use brokk_bifrost_core::hash::HashSet;
    let source = r#"
using Left; using Right;
namespace Left { public class Widget { public Widget() {} } }
namespace Right { public class Widget { public Widget() {} } }
class C { void M() { _ = new Widget(); _ = new Left.Widget(); } }
"#;
    let fixture =
        AnalyzerFixture::new_for_language(Language::CSharp, &[("Constructors.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let scope = AnalyzerQueryScope::new(analyzer);
    let file = ProjectFile::new(fixture.project_root(), "Constructors.cs");
    let roots = HashSet::from_iter([file]);
    let batch = CSharpAuthoritativeUsageBatch::new(analyzer, scope.token(), &roots).unwrap();
    for (constructor, expected) in [("Left.Widget.Widget", 1), ("Right.Widget.Widget", 0)] {
        let target = analyzer
            .get_definitions(constructor)
            .into_iter()
            .find(|unit| unit.is_function())
            .unwrap_or_else(|| panic!("missing {constructor}"));
        let result = batch
            .find_usages(std::slice::from_ref(&target), &roots, 100)
            .into_fuzzy_result();
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            panic!("{result:?}");
        };
        let hits = hits_by_overload
            .get(&target)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(hits.len(), expected, "{constructor}: {hits:?}");
        for hit in hits {
            assert_eq!(&source[hit.start_offset..hit.end_offset], "Left.Widget");
        }
    }
}

#[test]
fn bounded_extension_return_preserves_forward_provider_accounting() {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
    use brokk_bifrost_csharp::graph::{
        CSharpGraphSource, resolver::extension_invocation_return_type_fq_name_in_session,
    };
    let source = "class Widget {} static class Extensions { public static Widget Build(this Widget x) => x; } class C { void M(Widget x) { x.Build(); } }";
    let fixture = AnalyzerFixture::new_for_language(Language::CSharp, &[("Extension.cs", source)]);
    let analyzer = fixture.analyzer.analyzer();
    let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer).unwrap();
    let scope = AnalyzerQueryScope::new(analyzer);
    let tree = parse_csharp(source).unwrap();
    let cutoff = source.find("x.Build()").unwrap();
    let site = tree
        .root_node()
        .named_descendant_for_byte_range(cutoff, cutoff + "x.Build()".len())
        .unwrap();
    let query = |session: &ResolutionSession| {
        extension_invocation_return_type_fq_name_in_session(
            csharp,
            scope.token(),
            &CSharpGraphSource::from_source(csharp),
            source,
            site,
            &["Widget".to_owned()],
            "Build",
            Some(0),
            None,
            None,
            false,
            session,
        )
    };
    let complete = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
    let result = query(&complete);
    assert_eq!(result.as_deref(), Some("Widget"));
    assert!(matches!(
        complete.finish(result),
        BoundedResolution::Complete { .. }
    ));

    // This forward store path charges 65 source/scope steps. The usage path
    // materializes candidates through uncapped providers and charges only 39;
    // routing a forward request there would incorrectly complete at this limit.
    let limited = ResolutionSession::bounded(
        ReceiverAnalysisBudget {
            max_scope_nodes: 48,
            ..ReceiverAnalysisBudget::default()
        },
        None,
    );
    let result = query(&limited);
    assert!(result.is_none(), "{result:?}");
    assert!(matches!(limited.finish(result), BoundedResolution::Exceeded {
        limit: brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit::ScopeNodes,
        ..
    }));
}
