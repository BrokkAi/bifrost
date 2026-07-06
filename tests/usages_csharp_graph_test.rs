mod common;

use brokk_bifrost::usages::{CSharpUsageGraphStrategy, FuzzyResult, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, Language};
use common::InlineTestProject;

fn csharp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, CSharpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::CSharp);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition_by<F>(analyzer: &CSharpAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C# declaration in {declarations:#?}"))
}

fn type_definition(analyzer: &CSharpAnalyzer, fq_name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name
    })
}

fn member_function(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn member_function_with_arity(
    analyzer: &CSharpAnalyzer,
    owner: &str,
    name: &str,
    arity: usize,
) -> CodeUnit {
    member_function_matching_signature(analyzer, owner, name, |actual| {
        if arity == 0 {
            actual == Some("()")
        } else {
            actual.is_some_and(|actual| count_signature_parameters(actual) == arity)
        }
    })
}

fn member_function_with_signature(
    analyzer: &CSharpAnalyzer,
    owner: &str,
    name: &str,
    signature: &str,
) -> CodeUnit {
    member_function_matching_signature(analyzer, owner, name, |actual| actual == Some(signature))
}

fn member_function_matching_signature<F>(
    analyzer: &CSharpAnalyzer,
    owner: &str,
    name: &str,
    signature_matches: F,
) -> CodeUnit
where
    F: Fn(Option<&str>) -> bool,
{
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && signature_matches(unit.signature())
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn member_field(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn count_signature_parameters(signature: &str) -> usize {
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    inner.split(", ").count()
}

fn graph_hits(
    analyzer: &CSharpAnalyzer,
    target: &CodeUnit,
) -> std::collections::BTreeSet<brokk_bifrost::usages::UsageHit> {
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    CSharpUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(target), &candidates, 1000)
        .into_either()
        .unwrap_or_else(|err| panic!("{} should resolve: {err}", target.fq_name()))
}

#[test]
fn usage_finder_routes_csharp_targets_through_graph_strategy() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Models/Target.cs",
            "namespace Models { public class Target { } }\n",
        ),
        (
            "Consumers/Consumer.cs",
            r#"
using Models;

namespace Consumers {
    public class Consumer {
        public void Run() {
            Target value = new Target();
        }
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Models.Target");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("csharp graph success");

    assert_eq!(2, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("Consumers/Consumer.cs"))
    );
}

#[test]
fn csharp_graph_covers_non_class_type_targets() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Types.cs",
            r#"
namespace Domain {
    public interface IService {}
    public struct Coordinate {}
    public record Marker();
    public class Service : IService {
        private Coordinate current;
        public void Accept(IService service, Coordinate coordinate, Marker marker) {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using System.Collections.Generic;
using Domain;

namespace App {
    public class Consumer {
        public List<Coordinate> Build(IService service, Marker marker) {
            Coordinate coordinate = new Coordinate();
            return new List<Coordinate> { coordinate };
        }
    }
}
"#,
        ),
    ]);

    let interface_target = type_definition(&analyzer, "Domain.IService");
    let struct_target = type_definition(&analyzer, "Domain.Coordinate");
    let record_target = type_definition(&analyzer, "Domain.Marker");

    assert!(
        graph_hits(&analyzer, &interface_target).len() >= 3,
        "interface target should be covered in inheritance and parameter positions"
    );
    assert!(
        graph_hits(&analyzer, &struct_target).len() >= 4,
        "struct target should be covered in field, parameter, generic, and construction positions"
    );
    assert!(
        graph_hits(&analyzer, &record_target).len() >= 2,
        "record target should be covered in parameter positions"
    );
}

#[test]
fn csharp_graph_resolves_using_fully_qualified_and_same_namespace_type_references() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Shared/Target.cs",
            "namespace Shared { public class Target { } }\n",
        ),
        (
            "Shared/Sibling.cs",
            r#"
namespace Shared {
    public class Sibling {
        private Target field;
    }
}
"#,
        ),
        (
            "Other/Consumer.cs",
            r#"
using Shared;

namespace Other {
    public class Consumer {
        public Target FromUsing(Target arg) => arg;
        public Shared.Target FullyQualified() => new Shared.Target();
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Shared.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = CSharpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("type references should resolve");

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Shared/Sibling.cs"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Other/Consumer.cs"))
    );
    assert!(
        hits.len() >= 3,
        "expected several structured type hits: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_routes_fully_qualified_type_references_without_using() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Shared/Target.cs",
            "namespace Shared { public class Target { } }\n",
        ),
        (
            "App/FqnConsumer.cs",
            r#"
namespace App {
    public class FqnConsumer {
        private Shared.Target field;
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Shared.Target");
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);

    assert!(
        query
            .candidate_files
            .contains(&project.file("App/FqnConsumer.cs")),
        "fully-qualified references should be routed without a using directive"
    );
    let hits = query.result.into_either().expect("csharp graph success");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("App/FqnConsumer.cs"))
    );
}

#[test]
fn usage_finder_csharp_routes_global_using_references() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Shared/Target.cs",
            "namespace Shared { public class Target { } }\n",
        ),
        ("GlobalUsings.cs", "global using Shared;\n"),
        (
            "App/GlobalConsumer.cs",
            r#"
namespace App {
    public class GlobalConsumer {
        private Target field;
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Shared.Target");
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);

    assert!(
        query
            .candidate_files
            .contains(&project.file("App/GlobalConsumer.cs")),
        "global using directives should apply project-wide during routing"
    );
    let hits = query.result.into_either().expect("csharp graph success");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("App/GlobalConsumer.cs"))
    );
}

#[test]
fn csharp_analyzer_caches_using_import_info_from_tree_sitter() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "App/Consumer.cs",
        r#"
global using Shared;
using System.Collections.Generic;
using Alias = Other.Target;
using static Shared.Target;

namespace App {
    public class Consumer {}
}
"#,
    )]);

    let file = project.file("App/Consumer.cs");
    let statements = analyzer.import_statements_of(&file);
    assert_eq!(
        vec![
            "global using Shared;",
            "using System.Collections.Generic;",
            "using Alias = Other.Target;",
            "using static Shared.Target;",
        ],
        statements
    );

    let provider = analyzer
        .import_analysis_provider()
        .expect("C# import provider");
    let imports: Vec<_> = provider
        .import_info_of(&file)
        .iter()
        .map(|info| {
            (
                info.raw_snippet.as_str(),
                info.identifier.as_deref(),
                info.alias.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        vec![
            ("global using Shared;", Some("Shared"), None),
            ("using System.Collections.Generic;", Some("Generic"), None),
            (
                "using Alias = Other.Target;",
                Some("Other.Target"),
                Some("Alias"),
            ),
        ],
        imports
    );
    assert_eq!(
        vec!["Shared", "System.Collections.Generic"],
        analyzer.using_namespaces_of(&file)
    );
}

#[test]
fn csharp_graph_counts_using_alias_constructor_as_target_type_usage() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Handlers.cs",
            r#"
namespace Example.Parity {
    public class ConsoleHandler {
        public ConsoleHandler() {}
    }
}
"#,
        ),
        (
            "src/Consumers.cs",
            r#"
using WorkerAlias = Example.Parity.ConsoleHandler;
using Example.Parity;
using SimpleAlias = ConsoleHandler;

class Consumer {
    void Run() {
        var w = new WorkerAlias();
        var s = new SimpleAlias();
        Example.Parity.ConsoleHandler direct = new Example.Parity.ConsoleHandler();
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Example.Parity.ConsoleHandler");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Consumers.cs")
                && hit
                    .snippet
                    .lines()
                    .any(|line| line.trim() == "var w = new WorkerAlias();")
        }),
        "alias constructor site should count as target type usage: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Consumers.cs")
                && hit
                    .snippet
                    .lines()
                    .any(|line| line.trim() == "var s = new SimpleAlias();")
        }),
        "simple alias constructor site should count as target type usage: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Consumers.cs")
                && hit
                    .snippet
                    .lines()
                    .any(|line| line.trim().contains("new Example.Parity.ConsoleHandler()"))
        }),
        "alias-free constructor site should remain a target type usage: {hits:#?}"
    );
}

#[test]
fn csharp_graph_does_not_leak_unrelated_using_alias_to_target_type() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Handlers.cs",
            r#"
namespace Example.Parity {
    public class ConsoleHandler {
        public ConsoleHandler() {}
    }
}
"#,
        ),
        (
            "src/Other.cs",
            r#"
namespace Example.Other {
    public class ConsoleHandler {
        public ConsoleHandler() {}
    }
}
"#,
        ),
        (
            "src/Consumers.cs",
            r#"
using WorkerAlias = Example.Other.ConsoleHandler;

class Consumer {
    void Run() {
        var w = new WorkerAlias();
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Example.Parity.ConsoleHandler");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        !hits.iter().any(|hit| hit
            .snippet
            .lines()
            .any(|line| line.trim() == "var w = new WorkerAlias();")),
        "alias to a different type must not count as target usage: {hits:#?}"
    );
}

#[test]
fn csharp_graph_keeps_constructor_and_method_overloads_narrow() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public Target() {}
        public Target(string name) {}
        public static Target Create() { return null; }
        public static Target Create(string name) { return null; }
        public void Run() {}
        public void Run(int count) {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute(Target target) {
            var first = new Target();
            var commented = new Target(/* constructor comment */);
            var second = new Target("named");
            Target.Create();
            Target.Create("named");
            target.Run();
            target.Run(/* method comment */);
            target.Run(1);
        }
    }
}
"#,
        ),
    ]);

    let ctor_zero = member_function_with_arity(&analyzer, "Domain.Target", "Target", 0);
    let ctor_one = member_function_with_arity(&analyzer, "Domain.Target", "Target", 1);
    let create_zero = member_function_with_arity(&analyzer, "Domain.Target", "Create", 0);
    let create_one = member_function_with_arity(&analyzer, "Domain.Target", "Create", 1);
    let run_zero = member_function_with_arity(&analyzer, "Domain.Target", "Run", 0);
    let run_one = member_function_with_arity(&analyzer, "Domain.Target", "Run", 1);

    assert_eq!(2, graph_hits(&analyzer, &ctor_zero).len());
    assert_eq!(1, graph_hits(&analyzer, &ctor_one).len());
    assert_eq!(1, graph_hits(&analyzer, &create_zero).len());
    assert_eq!(1, graph_hits(&analyzer, &create_one).len());
    assert_eq!(2, graph_hits(&analyzer, &run_zero).len());
    assert_eq!(1, graph_hits(&analyzer, &run_one).len());
}

#[test]
fn csharp_graph_counts_nested_argument_lists_for_overload_arity() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
using System.Collections.Generic;

namespace Domain {
    public class Target {
        public void Run(Dictionary<string, int> values) {}
        public void Run(Dictionary<string, int> values, int count) {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using System.Collections.Generic;
using Domain;

namespace App {
    public class Consumer {
        public void Execute(Target target) {
            target.Run(new Dictionary<string, int>());
            target.Run(new Dictionary<string, int>(), 1);
        }
    }
}
"#,
        ),
    ]);

    let run_one = member_function_with_signature(
        &analyzer,
        "Domain.Target",
        "Run",
        "(Dictionary<string, int>)",
    );
    let run_two = member_function_with_signature(
        &analyzer,
        "Domain.Target",
        "Run",
        "(Dictionary<string, int>, int)",
    );

    assert_eq!(1, graph_hits(&analyzer, &run_one).len());
    assert_eq!(1, graph_hits(&analyzer, &run_two).len());
}

#[test]
fn csharp_graph_finds_constructors_inheritance_and_generic_type_arguments() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Types.cs",
            r#"
namespace Domain {
    public interface IService {}
    public class Target {
        public Target() {}
    }
    public record Marker();
    public class Service : Target, IService {
        public Service(Target dependency) {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using System.Collections.Generic;
using Domain;

namespace App {
    public class Consumer {
        public List<Target> Build(Marker marker) {
            return new List<Target> { new Target() };
        }
    }
}
"#,
        ),
    ]);

    let target_type = type_definition(&analyzer, "Domain.Target");
    let record_type = type_definition(&analyzer, "Domain.Marker");
    let constructor = member_function(&analyzer, "Domain.Target", "Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CSharpUsageGraphStrategy::new();

    let type_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target_type),
            &candidates,
            1000,
        )
        .into_either()
        .expect("type graph success");
    assert!(
        type_hits.len() >= 4,
        "inheritance, parameter, generic, and object creation should count: {type_hits:#?}"
    );
    let record_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&record_type),
            &candidates,
            1000,
        )
        .into_either()
        .expect("record type graph success");
    assert_eq!(1, record_hits.len());

    let ctor_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("constructor graph success");
    assert_eq!(1, ctor_hits.len());
}

#[test]
fn csharp_graph_covers_var_receiver_inference() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public Target() {}
        public void Run() {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute() {
            var local = new Target();
            local.Run();
        }
    }
}
"#,
        ),
    ]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    assert_eq!(1, graph_hits(&analyzer, &run).len());
}

#[test]
fn csharp_graph_finds_extension_method_call_syntax_usages() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Extensions.cs",
            r#"
public static class HandlerExtensions {
    public static string Tag(this string value) {
        return "[" + value + "]";
    }
}
"#,
        ),
        (
            "src/Handlers.cs",
            r#"
public interface IHandler {
    string Handle(string value);
}

public class Other {
    public string Tag() {
        return "other";
    }
}
"#,
        ),
        (
            "src/Consumers.cs",
            r#"
public class Consumers {
    public void Run(IHandler handler, string name) {
        var t1 = name.Tag();
        var t2 = handler.Handle("Ada").Tag();
        var t3 = HandlerExtensions.Tag(name);
        var other = new Other();
        var t4 = other.Tag();
    }
}
"#,
        ),
    ]);

    let tag = member_function(&analyzer, "HandlerExtensions", "Tag");
    let hits = graph_hits(&analyzer, &tag);

    assert_eq!(
        3,
        hits.len(),
        "extension method query should find extension-call and static-call sites only: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("name.Tag()")),
        "string local extension call should resolve: {hits:#?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("handler.Handle(\"Ada\").Tag()")),
        "string-returning call-result extension call should resolve: {hits:#?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("HandlerExtensions.Tag(name)")),
        "direct static extension method call should still resolve: {hits:#?}"
    );
    assert!(
        !hits.iter().any(|hit| hit.snippet.contains("other.Tag()")),
        "unrelated same-name instance method must not be counted: {hits:#?}"
    );
}

#[test]
fn csharp_graph_receiver_method_calls_skip_precise_nonmatching_owners() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Handlers.cs",
            r#"
public interface IHandler {
    string Handle(string value);
}

public class ConsoleHandler : IHandler {
    public string Handle(string value) {
        return value;
    }
}
"#,
        ),
        (
            "src/Consumers.cs",
            r#"
public class Consumers {
    public void Run() {
        IHandler handler = new ConsoleHandler();
        var a = handler.Handle("Ada");
        ConsoleHandler concrete = new ConsoleHandler();
        var b = concrete.Handle("Ben");
    }
}
"#,
        ),
    ]);

    let interface_handle = member_function(&analyzer, "IHandler", "Handle");
    let concrete_handle = member_function(&analyzer, "ConsoleHandler", "Handle");

    let interface_hits = graph_hits(&analyzer, &interface_handle);
    assert_eq!(
        1,
        interface_hits.len(),
        "IHandler.Handle should include only the interface-typed receiver: {interface_hits:#?}"
    );
    assert!(
        interface_hits
            .iter()
            .any(|hit| hit.snippet.contains("handler.Handle(\"Ada\")")),
        "IHandler.Handle should include handler.Handle(\"Ada\"): {interface_hits:#?}"
    );

    let concrete_hits = graph_hits(&analyzer, &concrete_handle);
    assert_eq!(
        1,
        concrete_hits.len(),
        "ConsoleHandler.Handle should include only the concrete-typed receiver: {concrete_hits:#?}"
    );
    assert!(
        concrete_hits
            .iter()
            .any(|hit| hit.snippet.contains("concrete.Handle(\"Ben\")")),
        "ConsoleHandler.Handle should include concrete.Handle(\"Ben\"): {concrete_hits:#?}"
    );
}

#[test]
fn csharp_graph_keeps_receiver_bindings_method_scoped() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { public void Run() {} } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void First() {
            Target local = new Target();
        }

        public void Second() {
            local.Run();
        }
    }
}
"#,
        ),
    ]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "a receiver declared in another method must not prove this member hit"
    );
}

#[test]
fn csharp_graph_fails_when_inner_block_shadows_typed_receiver() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { public void Run() {} } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute(Target local) {
            if (local != null) {
                object local = new object();
                local.Run();
            }
        }
    }
}
"#,
        ),
    ]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "an inner unresolved declaration should shadow the typed receiver conservatively"
    );
}

#[test]
fn csharp_graph_does_not_use_forward_local_declarations() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { public void Run() {} } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute() {
            local.Run();
            Target local = new Target();
        }
    }
}
"#,
        ),
    ]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "locals declared after a member access must not prove receiver type"
    );
}

#[test]
fn csharp_graph_fails_on_unqualified_member_calls_for_fallback() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Domain/Target.cs",
        r#"
namespace Domain {
    public class Target {
        public void Run() {}
        public void Execute() {
            Run();
        }
    }
}
"#,
    )]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "unqualified member calls are unsupported in v1 and should fall back"
    );
}

#[test]
fn csharp_graph_finds_static_and_instance_member_references() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public static int Count;
        public static string Name { get; set; }
        public static void Configure() {}
        public int Value;
        public int Size { get; set; }
        public void Run() {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute(Target parameter) {
            Target.Configure();
            Target.Count = Target.Count + 1;
            var name = Target.Name;
            Target local = new Target();
            local.Run();
            local.Value = local.Value + 1;
            parameter.Size = parameter.Size + 1;
        }
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CSharpUsageGraphStrategy::new();
    for target in [
        member_function(&analyzer, "Domain.Target", "Configure"),
        member_field(&analyzer, "Domain.Target", "Count"),
        member_field(&analyzer, "Domain.Target", "Name"),
        member_function(&analyzer, "Domain.Target", "Run"),
        member_field(&analyzer, "Domain.Target", "Value"),
        member_field(&analyzer, "Domain.Target", "Size"),
    ] {
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .unwrap_or_else(|err| panic!("{} should resolve: {err}", target.fq_name()));
        assert!(
            !hits.is_empty(),
            "{} should have graph-backed member hits",
            target.fq_name()
        );
    }
}

#[test]
fn csharp_graph_counts_field_and_property_references_precisely() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public static int Count;
        public static string Name { get; set; }
        public int Value;
        public int Size { get; set; }
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute(Target parameter) {
            Target.Count = Target.Count + 1;
            var name = Target.Name;
            Target local = new Target();
            local.Value = local.Value + 1;
            parameter.Size = parameter.Size + 1;
        }
    }
}
"#,
        ),
    ]);

    let count = member_field(&analyzer, "Domain.Target", "Count");
    let name = member_field(&analyzer, "Domain.Target", "Name");
    let value = member_field(&analyzer, "Domain.Target", "Value");
    let size = member_field(&analyzer, "Domain.Target", "Size");

    assert_eq!(2, graph_hits(&analyzer, &count).len());
    assert_eq!(1, graph_hits(&analyzer, &name).len());
    assert_eq!(2, graph_hits(&analyzer, &value).len());
    assert_eq!(2, graph_hits(&analyzer, &size).len());
}

#[test]
fn csharp_graph_resolves_fully_qualified_static_member_references() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public static int Count;
        public static string Name { get; set; }
        public static void Configure() {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
namespace App {
    public class Consumer {
        public void Execute() {
            Domain.Target.Configure();
            Domain.Target.Count = Domain.Target.Count + 1;
            var name = Domain.Target.Name;
        }
    }
}
"#,
        ),
    ]);

    let configure = member_function(&analyzer, "Domain.Target", "Configure");
    let count = member_field(&analyzer, "Domain.Target", "Count");
    let name = member_field(&analyzer, "Domain.Target", "Name");

    assert_eq!(1, graph_hits(&analyzer, &configure).len());
    assert_eq!(2, graph_hits(&analyzer, &count).len());
    assert_eq!(1, graph_hits(&analyzer, &name).len());
}

#[test]
fn csharp_graph_resolves_nested_fully_qualified_member_owners() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Outer.cs",
            r#"
namespace Domain {
    public class Outer {
        public class Inner {
            public static int Count;
            public void Run() {}
        }
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
namespace App {
    public class Consumer {
        public void Execute() {
            Domain.Outer.Inner.Count = Domain.Outer.Inner.Count + 1;
            var local = new Domain.Outer.Inner();
            local.Run();
        }
    }
}
"#,
        ),
    ]);

    let count = member_field(&analyzer, "Domain.Outer$Inner", "Count");
    let run = member_function(&analyzer, "Domain.Outer$Inner", "Run");

    assert_eq!(2, graph_hits(&analyzer, &count).len());
    assert_eq!(1, graph_hits(&analyzer, &run).len());
}

#[test]
fn csharp_graph_fails_closed_for_deferred_using_member_forms() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public static void Configure() {}
    }
}
"#,
        ),
        (
            "App/UsingStaticConsumer.cs",
            r#"
using static Domain.Target;

namespace App {
    public class UsingStaticConsumer {
        public void Execute() {
            Configure();
        }
    }
}
"#,
        ),
    ]);

    let configure = member_function(&analyzer, "Domain.Target", "Configure");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&configure),
        &candidates,
        1000,
    );

    assert!(
        matches!(result, FuzzyResult::Failure { .. }),
        "using static member forms are deferred and should fall back when there are no proven hits"
    );
}

#[test]
fn csharp_graph_does_not_count_expression_identifiers_as_type_refs() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        private int Target;

        public void Execute(dynamic other) {
            System.Console.WriteLine(Target);
            other.Target = 1;
        }
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Domain.Target");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.is_empty(),
        "expression identifiers named like a visible type must not count as type references: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_candidate_routing_covers_using_and_same_namespace() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Shared/Target.cs",
            "namespace Shared { public class Target { } }\n",
        ),
        (
            "Shared/SameNamespace.cs",
            r#"
namespace Shared {
    public class SameNamespace {
        private Target same;
    }
}
"#,
        ),
        (
            "App/UsingConsumer.cs",
            r#"
using Shared;

namespace App {
    public class UsingConsumer {
        private Target imported;
    }
}
"#,
        ),
        (
            "Other/Unrelated.cs",
            "namespace Other { public class Unrelated { } }\n",
        ),
    ]);

    let target = type_definition(&analyzer, "Shared.Target");
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);

    assert!(
        query
            .candidate_files
            .contains(&project.file("Shared/Target.cs"))
    );
    assert!(
        query
            .candidate_files
            .contains(&project.file("Shared/SameNamespace.cs")),
        "same-namespace files should be routed to the C# graph"
    );
    assert!(
        query
            .candidate_files
            .contains(&project.file("App/UsingConsumer.cs")),
        "using-importing files should be routed to the C# graph"
    );
    assert!(
        !query
            .candidate_files
            .contains(&project.file("Other/Unrelated.cs")),
        "unrelated files should not be candidate files for this target"
    );

    let hits = query.result.into_either().expect("csharp graph success");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Shared/SameNamespace.cs"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("App/UsingConsumer.cs"))
    );
}

#[test]
fn csharp_graph_avoids_unrelated_same_name_symbols_and_fails_on_unsupported_receivers() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Alpha/Target.cs",
            "namespace Alpha { public class Target { public void Run() {} } }\n",
        ),
        (
            "Beta/Target.cs",
            "namespace Beta { public class Target { public void Run() {} } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Beta;

namespace App {
    public class Consumer {
        public void Execute(object unknown) {
            Target beta = new Target();
            beta.Run();
            unknown.Run();
        }
    }
}
"#,
        ),
    ]);

    let alpha = type_definition(&analyzer, "Alpha.Target");
    let alpha_run = member_function(&analyzer, "Alpha.Target", "Run");
    let beta = type_definition(&analyzer, "Beta.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CSharpUsageGraphStrategy::new();

    let alpha_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&alpha), &candidates, 1000)
        .into_either()
        .expect("unrelated target query should succeed empty");
    assert!(alpha_hits.is_empty());

    let beta_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&beta), &candidates, 1000)
        .into_either()
        .expect("beta target should resolve");
    assert!(!beta_hits.is_empty());

    let alpha_run_result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&alpha_run),
        &candidates,
        1000,
    );
    assert!(
        matches!(alpha_run_result, FuzzyResult::Failure { .. }),
        "unsupported same-name member receiver should fail so UsageFinder can fall back"
    );
}

#[test]
fn csharp_graph_fails_on_ambiguous_visible_type_names() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Alpha/Target.cs",
            "namespace Alpha { public class Target {} }\n",
        ),
        (
            "Beta/Target.cs",
            "namespace Beta { public class Target {} }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Alpha;
using Beta;

namespace App {
    public class Consumer {
        public void Execute() {
            Target target = null;
        }
    }
}
"#,
        ),
    ]);

    let alpha = type_definition(&analyzer, "Alpha.Target");
    let beta = type_definition(&analyzer, "Beta.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = CSharpUsageGraphStrategy::new();

    let alpha_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&alpha), &candidates, 1000)
        .into_either()
        .expect("ambiguous alpha type query should succeed empty");
    let beta_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&beta), &candidates, 1000)
        .into_either()
        .expect("ambiguous beta type query should succeed empty");

    assert!(alpha_hits.is_empty());
    assert!(beta_hits.is_empty());
}

#[test]
fn csharp_graph_returns_proven_hits_despite_unknown_same_name_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { public void Run() {} } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Known(Target known) {
            known.Run();
        }

        public void Unknown(object unknown) {
            unknown.Run();
        }
    }
}
"#,
        ),
    ]);

    let run = member_function(&analyzer, "Domain.Target", "Run");
    let hits = graph_hits(&analyzer, &run);

    assert_eq!(
        1,
        hits.len(),
        "the typed receiver hit must survive the unknown same-name receiver: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("App/Consumer.cs")),
        "{hits:#?}"
    );
}

#[test]
fn csharp_graph_reports_too_many_callsites() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            "namespace Domain { public class Target { } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public class Consumer {
        public void Execute() {
            Target one = new Target();
            Target two = new Target();
        }
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Domain.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    assert!(matches!(result, FuzzyResult::TooManyCallsites { .. }));
}

const FIELD_RECEIVER_FILES: &[(&str, &str)] = &[
    (
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public void Save(string value) { Last = value; }
}
public sealed class Service {
    private readonly Repository repository = new();
    public void Run(string value) { repository.Save(value); }
}
"#,
    ),
    (
        "src/Consumer.cs",
        r#"namespace Example;
public sealed class Consumer {
    public string ReadLast(Repository repository) { return repository.Last; }
}
"#,
    ),
];

#[test]
fn csharp_graph_resolves_member_method_through_class_level_field_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(FIELD_RECEIVER_FILES);

    let save = member_function(&analyzer, "Example.Repository", "Save");
    let hits = graph_hits(&analyzer, &save);

    assert_eq!(
        1,
        hits.len(),
        "field receiver repository.Save(value) should be a proven hit: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "the only call site lives in Service.cs: {hits:#?}"
    );
}

#[test]
fn csharp_graph_resolves_member_method_through_this_field_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public void Save(string value) {}
}
public sealed class Service {
    private readonly Repository repository = new();
    public void Run(string value) { this.repository.Save(value); }
}
"#,
    )]);

    let save = member_function(&analyzer, "Example.Repository", "Save");
    let hits = graph_hits(&analyzer, &save);

    assert_eq!(
        1,
        hits.len(),
        "explicit this.field receiver should resolve as a proven hit: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{hits:#?}"
    );
}

#[test]
fn csharp_graph_resolves_property_self_write_and_field_receiver_read() {
    let (project, analyzer) = csharp_analyzer_with_files(FIELD_RECEIVER_FILES);

    let last = member_field(&analyzer, "Example.Repository", "Last");
    let hits = graph_hits(&analyzer, &last);

    assert_eq!(
        2,
        hits.len(),
        "expected the self-write Last = value and the read repository.Last: {hits:#?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/Service.cs")),
        "the self-write Last = value lives in Service.cs: {hits:#?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/Consumer.cs")),
        "the read repository.Last lives in Consumer.cs: {hits:#?}"
    );
}

// `nameof(Last)` is a compile-time string, not a runtime member reference, so it
// must not be counted as a usage of the field.
#[test]
fn csharp_graph_excludes_nameof_field_argument() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public void Save(string value) { Last = value; }
    public string NameOfLast() { return nameof(Last); }
}
"#,
    )]);

    let last = member_field(&analyzer, "Example.Repository", "Last");
    let hits = graph_hits(&analyzer, &last);

    assert_eq!(
        1,
        hits.len(),
        "only the Last = value write is a usage; nameof(Last) is not: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{hits:#?}"
    );
}

#[test]
fn csharp_graph_excludes_qualified_nameof_field_argument() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public void Save(string value) { Last = value; }
}
public sealed class Service {
    private readonly Repository repository = new();
    public string NameOfLast() { return nameof(repository.Last); }
}
"#,
    )]);

    let last = member_field(&analyzer, "Example.Repository", "Last");
    let hits = graph_hits(&analyzer, &last);

    assert_eq!(
        1,
        hits.len(),
        "only the Last = value write is a usage; nameof(repository.Last) is not: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{hits:#?}"
    );
}

// A local of the same name in an unrelated method is provably not the field, so it
// must be skipped silently rather than poisoning the file's other proven hits.
#[test]
fn csharp_graph_local_shadow_does_not_discard_proven_field_hits() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public void Save(string value) { Last = value; }
    public string Unrelated() { string Last = "x"; return Last; }
}
"#,
    )]);

    let last = member_field(&analyzer, "Example.Repository", "Last");
    let hits = graph_hits(&analyzer, &last);

    assert_eq!(
        1,
        hits.len(),
        "the Last = value write must survive a same-named local in another method: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{hits:#?}"
    );
}

#[test]
fn csharp_graph_inner_block_shadow_does_not_hide_later_self_field_read() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public string Read(bool flag) {
        if (flag) {
            string Last = "shadow";
        }
        return Last;
    }
}
"#,
    )]);

    let last = member_field(&analyzer, "Example.Repository", "Last");
    let hits = graph_hits(&analyzer, &last);

    assert_eq!(
        1,
        hits.len(),
        "the out-of-scope nested local must not hide the later field read: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{hits:#?}"
    );
}

#[test]
fn csharp_graph_object_initializer_labels_resolve_to_initializer_type() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;
public sealed class Repository {
    public string Last { get; set; } = "";
    public Dto MakeDto() { return new Dto { Last = "x" }; }
    public Repository MakeRepository() { return new Repository { Last = "x" }; }
}
public sealed class Dto {
    public string Last { get; set; } = "";
}
"#,
    )]);

    let repository_last = member_field(&analyzer, "Example.Repository", "Last");
    let repository_hits = graph_hits(&analyzer, &repository_last);
    assert_eq!(
        1,
        repository_hits.len(),
        "only new Repository {{ Last = ... }} should count for Repository.Last: {repository_hits:#?}"
    );
    assert!(
        repository_hits
            .iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{repository_hits:#?}"
    );

    let dto_last = member_field(&analyzer, "Example.Dto", "Last");
    let dto_hits = graph_hits(&analyzer, &dto_last);
    assert_eq!(
        1,
        dto_hits.len(),
        "new Dto {{ Last = ... }} should count for Dto.Last: {dto_hits:#?}"
    );
    assert!(
        dto_hits
            .iter()
            .all(|hit| hit.file == project.file("src/Service.cs")),
        "{dto_hits:#?}"
    );
}

#[test]
fn csharp_partial_property_receiver_usages_share_one_type_surface() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Handlers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Name { get; set; }

    public EventRecord(string name)
    {
        Name = name;
    }
}
"#,
        ),
        (
            "src/Consumers.cs",
            r#"namespace Demo;

public partial class EventRecord
{
    public string Label()
    {
        return Name.Tag();
    }
}

public static class StringExtensions
{
    public static string Tag(this string value) => value;
}

public sealed class Consumer
{
    public string Render(EventRecord record)
    {
        return record.Name;
    }
}
"#,
        ),
    ]);

    let name = member_field(&analyzer, "Demo.EventRecord", "Name");
    let hits = graph_hits(&analyzer, &name);

    assert_eq!(3, hits.len(), "{hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Handlers.cs") && hit.snippet.contains("Name = name")
        }),
        "constructor assignment should resolve to EventRecord.Name: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Consumers.cs") && hit.snippet.contains("return Name.Tag")
        }),
        "unqualified receiver read in the other partial file should resolve to EventRecord.Name: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Consumers.cs") && hit.snippet.contains("record.Name")
        }),
        "typed external receiver should resolve to EventRecord.Name: {hits:#?}"
    );
}
