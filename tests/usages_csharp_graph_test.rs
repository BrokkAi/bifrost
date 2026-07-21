mod common;

use brokk_bifrost::usages::{
    CSharpUsageGraphStrategy, ExplicitCandidateProvider, FuzzyResult, UsageAnalyzer, UsageFinder,
};
use brokk_bifrost::{
    AnalyzerConfig, CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, Language, WorkspaceAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json, csharp_nested_partial_cacheinfo_project};
use serde_json::{Value, json};
use std::sync::Arc;

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

fn definition_lookup(
    root: &std::path::Path,
    path: &str,
    start_byte: usize,
    _end_byte: usize,
) -> Value {
    let source = std::fs::read_to_string(root.join(path)).expect("definition lookup source");
    let prefix = &source[..start_byte];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let request = json!({
        "references": [{
            "path": path,
            "line": line,
            "column": column,
        }]
    });
    call_search_tool_json(root, "get_definitions_by_location", &request.to_string())
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
fn csharp_graph_counts_static_qualifier_references_for_class_targets() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Target.cs",
            r#"
namespace Domain {
    public class Target {
        public const int Value = 7;
        public static Target Build() => new Target();
    }

    public class Other {
        public void Touch() {}
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
        public void Run() {
            Target.Build();
            var value = Target.Value;
            var Target = new Other();
            Target.Touch();
        }
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Domain.Target");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Target.Build()")),
        "expected static method qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Target.Value")),
        "expected static constant qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("Target.Touch()")),
        "local variable receiver must not count as class usage: {hits:#?}"
    );
}

#[test]
fn csharp_graph_resolves_nested_partial_type_references_in_sibling_file() {
    let project = csharp_nested_partial_cacheinfo_project().build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());

    let target = type_definition(&analyzer, "Dapper.SqlMapper$CacheInfo");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("Mapper.cs")
                && hit
                    .snippet
                    .lines()
                    .any(|line| line.trim() == "CacheInfo? info = null;")
        }),
        "bare nested nullable type should resolve through the partial enclosing class: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("Mapper.cs")
                && hit
                    .snippet
                    .lines()
                    .any(|line| line.trim() == "info = new CacheInfo();")
        }),
        "bare nested constructor type should resolve through the partial enclosing class: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_resolves_sibling_nested_constructor_in_enclosing_type() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Demo/Nested.cs",
        r#"namespace Demo;

public class Outer {
    public class Consumer {
        public object Build() => new Target(42);
    }

    public class Target(int value) {}
}

public class OtherOuter {
    public class Target(int value) {}
    public object Build() => new Target(7);
}
"#,
    )]);

    let consumer = project.file("Demo/Nested.cs");
    let source = consumer.read_to_string().expect("nested source");
    let outer_call = source
        .find("Target(42)")
        .expect("outer target construction");
    let other_call = source.find("Target(7)").expect("other target construction");
    let outer_target = type_definition(&analyzer, "Demo.Outer$Target");
    let other_target = type_definition(&analyzer, "Demo.OtherOuter$Target");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let forward = definition_lookup(
        project.root(),
        "Demo/Nested.cs",
        outer_call,
        outer_call + "Target".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.Outer$Target",
        "{forward}"
    );

    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&outer_target),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("targeted sibling-nested query should resolve");
    let whole_workspace = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&outer_target), 1000, 1000)
        .result
        .into_either()
        .expect("whole-workspace sibling-nested query should resolve");
    for hits in [&targeted, &whole_workspace] {
        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert!(hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= outer_call
                && outer_call + "Target".len() <= hit.end_offset
        }));
    }

    let unrelated_hits = graph_hits(&analyzer, &other_target);
    assert_eq!(unrelated_hits.len(), 1, "{unrelated_hits:#?}");
    assert!(unrelated_hits.iter().any(|hit| {
        hit.file == consumer
            && hit.start_offset <= other_call
            && other_call + "Target".len() <= hit.end_offset
    }));
}

#[test]
fn csharp_graph_nested_type_reference_respects_type_parameter_shadow() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Mapper.CacheInfo.cs",
            r#"
namespace Dapper {
    public static partial class SqlMapper {
        private sealed class CacheInfo {}
    }
}
"#,
        ),
        (
            "Mapper.cs",
            r#"
namespace Dapper {
    public static partial class SqlMapper {
        private static CacheInfo M<CacheInfo>(CacheInfo value) {
            CacheInfo? local = value;
            return default;
        }
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Dapper.SqlMapper$CacheInfo");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.iter().all(|hit| hit.file != project.file("Mapper.cs")),
        "type parameter CacheInfo should shadow the nested type in scan_usages: {hits:#?}"
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
fn usage_finder_csharp_finds_fully_qualified_attribute_in_authoritative_and_default_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        ),
        (
            "Runtime/PSArgumentCompleterAttribute.cs",
            r#"
namespace Microsoft.Azure.PowerShell.Cmdlets.NetworkCloud.Runtime {
    public sealed class PSArgumentCompleterAttribute : System.Attribute { }
}
"#,
        ),
        (
            "Generated/Model.cs",
            r#"
namespace Microsoft.Azure.PowerShell.Cmdlets.NetworkCloud.Models {
    public sealed class Model {
        [Microsoft.Azure.PowerShell.Cmdlets.NetworkCloud.Runtime.PSArgumentCompleterAttribute]
        public string Name { get; set; }
    }
}
"#,
        ),
    ]);

    let target = type_definition(
        &analyzer,
        "Microsoft.Azure.PowerShell.Cmdlets.NetworkCloud.Runtime.PSArgumentCompleterAttribute",
    );
    let consumer = project.file("Generated/Model.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let attribute_start = source
        .find("PSArgumentCompleterAttribute")
        .expect("fully-qualified attribute name");
    let attribute_end = attribute_start + "PSArgumentCompleterAttribute".len();

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        authoritative.candidate_files,
        std::iter::once(consumer.clone()).collect()
    );
    let authoritative_hits = authoritative
        .result
        .into_either()
        .expect("authoritative attribute query should resolve");
    assert!(
        authoritative_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= attribute_start
                && attribute_end <= hit.end_offset
        }),
        "authoritative inverse lookup should find the explicit attribute name: {authoritative_hits:#?}"
    );

    let default_query = UsageFinder::new().query(&analyzer, &[target], 1000, 1000);
    assert!(
        default_query.candidate_files.contains(&consumer),
        "persisted candidate routing should include the explicit attribute consumer"
    );
    let default_hits = default_query
        .result
        .into_either()
        .expect("default attribute query should resolve");
    assert!(
        default_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= attribute_start
                && attribute_end <= hit.end_offset
        }),
        "default inverse lookup should find the explicit attribute name: {default_hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_attribute_shorthand_targets_suffix_not_local_nonattribute() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        ),
        (
            "Automation/ParameterAttribute.cs",
            "namespace System.Management.Automation { public class ParameterAttribute : System.Attribute { } }\n",
        ),
        (
            "Generated/ExportProxyCmdlet.cs",
            r#"
using System.Management.Automation;

namespace Demo.Runtime.PowerShell {
    internal class Parameter { }

    [Parameter]
    public sealed class ExportProxyCmdlet { }
}
"#,
        ),
    ]);

    let attribute_target =
        type_definition(&analyzer, "System.Management.Automation.ParameterAttribute");
    let local_nonattribute = type_definition(&analyzer, "Demo.Runtime.PowerShell.Parameter");
    let consumer = project.file("Generated/ExportProxyCmdlet.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let attribute_start = source.find("Parameter]").expect("attribute shorthand");
    let attribute_end = attribute_start + "Parameter".len();

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&attribute_target),
            Some(&provider),
            1,
            1000,
        );
    let authoritative_hits = authoritative
        .result
        .into_either()
        .expect("authoritative shorthand attribute query should resolve");
    assert!(
        authoritative_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= attribute_start
                && attribute_end <= hit.end_offset
        }),
        "authoritative lookup should bind shorthand Parameter to ParameterAttribute: {authoritative_hits:#?}"
    );

    let default_query = UsageFinder::new().query(
        &analyzer,
        std::slice::from_ref(&attribute_target),
        1000,
        1000,
    );
    assert!(
        default_query.candidate_files.contains(&consumer),
        "persisted candidate routing should include a consumer that omits the Attribute suffix"
    );
    let default_hits = default_query
        .result
        .into_either()
        .expect("default shorthand attribute query should resolve");
    assert!(
        default_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= attribute_start
                && attribute_end <= hit.end_offset
        }),
        "default lookup should bind shorthand Parameter to ParameterAttribute: {default_hits:#?}"
    );

    let local_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &[local_nonattribute], Some(&provider), 1, 1000);
    let local_hits = local_query
        .result
        .into_either()
        .expect("local non-attribute query should resolve");
    assert!(
        local_hits.iter().all(|hit| {
            hit.file != consumer
                || hit.end_offset <= attribute_start
                || attribute_end <= hit.start_offset
        }),
        "the shorthand annotation must not count as a usage of the local non-attribute Parameter: {local_hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_partial_attribute_base_proves_shorthand_usage() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        ),
        (
            "Attributes/MarkerAttribute.First.cs",
            "namespace Demo.Attributes { public partial class MarkerAttribute { } }\n",
        ),
        (
            "Attributes/MarkerAttribute.Second.cs",
            "namespace Demo.Attributes { public partial class MarkerAttribute : System.Attribute { } }\n",
        ),
        (
            "Generated/Consumer.cs",
            r#"
using Demo.Attributes;

namespace Demo.Generated {
    [Marker]
    public sealed class Consumer { }
}
"#,
        ),
    ]);

    let targets = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "Demo.Attributes.MarkerAttribute"
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        targets.len(),
        2,
        "expected both partial attribute declarations"
    );
    let consumer = project.file("Generated/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let attribute_start = source.find("Marker]").expect("partial attribute shorthand");
    let attribute_end = attribute_start + "Marker".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    let hits = query
        .result
        .into_either()
        .expect("partial attribute usage query should resolve");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= attribute_start
                && attribute_end <= hit.end_offset
        }),
        "a base declared on one partial part should prove the shorthand attribute usage: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_ambiguous_attribute_name_is_not_a_proven_usage() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        ),
        (
            "Attributes/Marker.cs",
            r#"
namespace Demo.Attributes {
    public class Marker : System.Attribute { }
    public class MarkerAttribute : System.Attribute { }
}
"#,
        ),
        (
            "Generated/Consumer.cs",
            r#"
using Demo.Attributes;

namespace Demo.Generated {
    [Marker]
    public sealed class Consumer { }
}
"#,
        ),
    ]);

    let exact = type_definition(&analyzer, "Demo.Attributes.Marker");
    let suffixed = type_definition(&analyzer, "Demo.Attributes.MarkerAttribute");
    let consumer = project.file("Generated/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let attribute_start = source.find("Marker]").expect("ambiguous attribute");
    let attribute_end = attribute_start + "Marker".len();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for target in [exact, suffixed] {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(&analyzer, &[target], Some(&provider), 1, 1000);
        let hits = query
            .result
            .into_either()
            .expect("ambiguous attribute query should complete");
        assert!(
            hits.iter().all(|hit| {
                hit.file != consumer
                    || hit.end_offset <= attribute_start
                    || attribute_end <= hit.start_offset
            }),
            "ambiguous attribute syntax must not be a proven usage of either candidate: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_routes_namespace_alias_and_global_attribute_names_by_default() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        ),
        (
            "Runtime/PSArgumentCompleterAttribute.cs",
            r#"
namespace External.Runtime {
    public sealed class PSArgumentCompleterAttribute : System.Attribute { }
}
"#,
        ),
        (
            "AliasConsumer/Consumer.cs",
            r#"
using PS = External.Runtime;

namespace Demo.Generated {
    [PS::PSArgumentCompleterAttribute]
    public sealed class AliasConsumer { }
}
"#,
        ),
        (
            "GlobalConsumer/Consumer.cs",
            r#"
namespace Demo.Generated {
    [global::External.Runtime.PSArgumentCompleterAttribute]
    public sealed class GlobalConsumer { }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "External.Runtime.PSArgumentCompleterAttribute");
    let consumers = [
        project.file("AliasConsumer/Consumer.cs"),
        project.file("GlobalConsumer/Consumer.cs"),
    ];
    let attribute_spans = consumers
        .iter()
        .map(|consumer| {
            let source = consumer.read_to_string().expect("consumer source");
            let start = source
                .find("PSArgumentCompleterAttribute")
                .expect("qualified attribute name");
            (
                consumer.clone(),
                start,
                start + "PSArgumentCompleterAttribute".len(),
            )
        })
        .collect::<Vec<_>>();

    let provider = ExplicitCandidateProvider::new(Arc::new(consumers.iter().cloned().collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            2,
            1000,
        );
    let authoritative_hits = authoritative
        .result
        .into_either()
        .expect("authoritative qualified attribute query should resolve");
    for (consumer, start, end) in &attribute_spans {
        assert!(
            authoritative_hits.iter().any(|hit| {
                hit.file == *consumer && hit.start_offset <= *start && *end <= hit.end_offset
            }),
            "authoritative lookup should find both alias and global attribute names: {authoritative_hits:#?}"
        );
    }

    let default_query = UsageFinder::new().query(&analyzer, &[target], 1000, 1000);
    for consumer in &consumers {
        assert!(
            default_query.candidate_files.contains(consumer),
            "default routing must independently include {consumer}"
        );
    }
    let default_hits = default_query
        .result
        .into_either()
        .expect("default qualified attribute query should resolve");
    for (consumer, start, end) in attribute_spans {
        assert!(
            default_hits.iter().any(|hit| {
                hit.file == consumer && hit.start_offset <= start && end <= hit.end_offset
            }),
            "default lookup should find both alias and global attribute names: {default_hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_finds_fully_qualified_partial_type_in_authoritative_file_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Models/IReplicaSet.First.cs",
            r#"
namespace Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models {
    public partial interface IReplicaSet {
        string Name { get; }
    }
}
"#,
        ),
        (
            "Models/IReplicaSet.Second.cs",
            r#"
namespace Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models {
    public partial interface IReplicaSet {
        string Location { get; }
    }
}
"#,
        ),
        (
            "Generated/ReplicaSet.TypeConverter.cs",
            r#"
namespace Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models {
    public sealed class ReplicaSetTypeConverter {
        private Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models.IReplicaSet Convert(
            Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models.IReplicaSet value) => value;
    }
}
"#,
        ),
    ]);

    let target_fq_name = "Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models.IReplicaSet";
    let targets: Vec<_> = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class && unit.fq_name() == target_fq_name)
        .cloned()
        .collect();
    assert_eq!(
        targets.len(),
        2,
        "expected both partial interface declarations"
    );

    let consumer = project.file("Generated/ReplicaSet.TypeConverter.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "the explicit authoritative scope should contain only the consumer"
    );
    let hits = query
        .result
        .into_either()
        .expect("partial interface usage query should resolve");

    let source = consumer.read_to_string().expect("consumer source");
    let qualified_return = source
        .find("Microsoft.Azure.PowerShell.Cmdlets.ADDomainServices.Models.IReplicaSet Convert")
        .expect("fully-qualified return type");
    let segment_start = qualified_return + "Microsoft.Azure.PowerShell.Cmdlets.".len();
    let segment_end = segment_start + "ADDomainServices".len();
    assert!(
        hits.iter()
            .any(|hit| hit.start_offset <= segment_start && segment_end <= hit.end_offset),
        "the full qualified type usage should cover its nonterminal namespace segment {segment_start}..{segment_end}: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_finds_explicit_interface_owners_in_authoritative_file_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Contracts/IHasName.First.cs",
            r#"
namespace Demo.Contracts {
    public partial interface IHasName {
        string Name { get; }
    }
}
"#,
        ),
        (
            "Contracts/IHasName.Second.cs",
            r#"
namespace Demo.Contracts {
    public partial interface IHasName {
        void Reset();
    }
}
"#,
        ),
        (
            "Models/NamedThing.cs",
            r#"
namespace Demo.Models {
    public sealed class NamedThing : Demo.Contracts.IHasName {
        string Demo.Contracts.IHasName.Name => "Ada";
        void Demo.Contracts.IHasName.Reset() { }
    }
}
"#,
        ),
    ]);

    let targets: Vec<_> = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == "Demo.Contracts.IHasName"
        })
        .cloned()
        .collect();
    assert_eq!(
        targets.len(),
        2,
        "expected both partial interface declarations"
    );
    let implementer = project.file("Models/NamedThing.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(implementer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(implementer.clone()).collect(),
        "the explicit authoritative scope should contain only the implementer"
    );
    let hits = query
        .result
        .into_either()
        .expect("explicit interface owner usage query should resolve");

    let source = implementer.read_to_string().expect("implementer source");
    let property_owner = source
        .find("Demo.Contracts.IHasName.Name")
        .expect("explicit interface property owner");
    let method_owner = source
        .find("Demo.Contracts.IHasName.Reset")
        .expect("explicit interface method owner");
    for owner_start in [property_owner, method_owner] {
        let segment_start = owner_start + "Demo.".len();
        let segment_end = segment_start + "Contracts".len();
        assert!(
            hits.iter()
                .any(|hit| hit.start_offset <= segment_start && segment_end <= hit.end_offset),
            "explicit interface owner should cover its nonterminal segment {segment_start}..{segment_end}: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_finds_generic_method_type_arguments_in_authoritative_file_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Json/JsonString.First.cs",
            "namespace Demo.Json { public sealed partial class JsonString { } }\n",
        ),
        (
            "Json/JsonString.Second.cs",
            "namespace Demo.Json { public sealed partial class JsonString { } }\n",
        ),
        (
            "Runtime/Consumer.cs",
            r#"
namespace Demo.Other {
    public sealed class JsonString { }
}

namespace Demo.Runtime {
    public static class Helpers {
        public static T PropertyT<T>() => default(T);
        public static T JsonString<T>() => default(T);
    }

    public sealed class Generic<JsonString> { }

    public sealed class Consumer {
        public object Read() {
            var first = Helpers.PropertyT<Demo.Json.JsonString>();
            var second = Helpers.PropertyT<Demo.Json.JsonString>();
            var unrelated = Helpers.PropertyT<Demo.Other.JsonString>();
            var method = Helpers.JsonString<int>();
            return second;
        }
    }
}
"#,
        ),
    ]);

    let targets: Vec<_> = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == "Demo.Json.JsonString"
        })
        .cloned()
        .collect();
    assert_eq!(targets.len(), 2, "expected both partial type declarations");
    let consumer = project.file("Runtime/Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "the explicit authoritative scope should contain only the consumer"
    );
    let hits = query
        .result
        .into_either()
        .expect("generic method type argument usage query should resolve");

    let source = consumer.read_to_string().expect("consumer source");
    let positive_arguments: Vec<_> = source.match_indices("Demo.Json.JsonString").collect();
    assert_eq!(positive_arguments.len(), 2, "expected two positive calls");
    for (type_argument, _) in positive_arguments {
        let segment_start = type_argument + "Demo.".len();
        let segment_end = segment_start + "Json".len();
        assert!(
            hits.iter()
                .any(|hit| hit.start_offset <= segment_start && segment_end <= hit.end_offset),
            "generic method type argument should cover its nonterminal segment {segment_start}..{segment_end}: {hits:#?}"
        );
    }

    for unrelated in [
        source
            .find("Demo.Other.JsonString")
            .expect("unrelated qualified type"),
        source
            .find("JsonString<int>")
            .expect("same-named generic method"),
        source
            .find("JsonString> { }")
            .expect("same-named type parameter"),
    ] {
        let unrelated_end = unrelated + "JsonString".len();
        assert!(
            hits.iter()
                .all(|hit| { !(hit.start_offset <= unrelated && unrelated_end <= hit.end_offset) }),
            "unrelated same-named syntax must not become a target type hit: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_finds_explicit_generic_static_method_invocation() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/PsHelpers.cs",
            r#"
namespace Demo {
    public sealed class CommandInvocation { }
    public sealed class ScriptResult {
        public void ResultOnly() { }
    }

    public static class PsHelpers {
        public static T RunScript<T>(CommandInvocation command, string script) => default(T);
        public static object RunScript(CommandInvocation command, string script) => new object();
    }

    public static class Factory {
        public static T Create<T>() => default(T);
    }
}
"#,
        ),
        (
            "Demo/Consumer.cs",
            r#"
namespace Demo {
    public sealed class Consumer {
        public T Forward<T>(CommandInvocation command, string script) {
            return PsHelpers.RunScript<T>(command, script);
        }

        public void Chain(CommandInvocation command, string script) {
            Factory.Create<ScriptResult>().ResultOnly();
        }
    }
}
"#,
        ),
    ]);

    let mut run_script_signatures = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Function && unit.fq_name() == "Demo.PsHelpers.RunScript"
        })
        .filter_map(|unit| unit.signature().map(str::to_string))
        .collect::<Vec<_>>();
    run_script_signatures.sort();
    assert_eq!(
        run_script_signatures,
        vec![
            "(CommandInvocation, string)".to_string(),
            "`1(CommandInvocation, string)".to_string(),
        ],
        "generic arity must distinguish otherwise identical overloads"
    );
    let target = member_function_with_signature(
        &analyzer,
        "Demo.PsHelpers",
        "RunScript",
        "`1(CommandInvocation, string)",
    );
    let consumer = project.file("Demo/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let use_start = source.find("RunScript<T>").expect("explicit generic call");
    let chained_start = source.find("ResultOnly()").expect("chained generic return");
    let forward = definition_lookup(
        project.root(),
        "Demo/Consumer.cs",
        use_start,
        use_start + "RunScript".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "explicit generic arity should select one overload: {forward}"
    );
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.PsHelpers.RunScript",
        "{forward}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect()
    );
    let hits = query
        .result
        .into_either()
        .expect("explicit generic static method query should resolve");
    assert_eq!(1, hits.len(), "expected one exact inverse hit: {hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= use_start
                && use_start + "RunScript".len() <= hit.end_offset
        }),
        "inverse lookup should cover the generic method identifier: {hits:#?}"
    );

    drop(analyzer);
    let reopened = CSharpAnalyzer::from_project(project.project().clone());
    let mut persisted_signatures = reopened
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Function && unit.fq_name() == "Demo.PsHelpers.RunScript"
        })
        .filter_map(|unit| unit.signature().map(str::to_string))
        .collect::<Vec<_>>();
    persisted_signatures.sort();
    assert_eq!(
        persisted_signatures, run_script_signatures,
        "persisted declaration identity must retain both generic-arity overloads"
    );
    let chained = member_function_with_arity(&reopened, "Demo.ScriptResult", "ResultOnly", 0);
    let persisted_hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &reopened,
            std::slice::from_ref(&chained),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("persisted generic return query should resolve");
    assert!(
        persisted_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= chained_start
                && chained_start + "ResultOnly".len() <= hit.end_offset
        }),
        "persisted type-parameter metadata must retain chained return inference: {persisted_hits:#?}"
    );
}

#[test]
fn persisted_csharp_inverse_reuses_one_definition_index_without_candidate_queries() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Demo/GlobalUsings.cs", "global using Demo;\n")
        .file(
            "Demo/Widget.Part1.cs",
            r#"
namespace Demo {
    public partial class Widget<T> {
        public void Touch() {}
    }
}
"#,
        )
        .file(
            "Demo/Widget.Part2.cs",
            r#"
namespace Demo {
    public partial class Widget<T> {
        public void Touch() {}
    }
}
"#,
        )
        .file(
            "Consumers/AliasConsumer.cs",
            r#"
using Alias = Demo.Widget<int>;
namespace Consumers {
    public class AliasConsumer {
        public void Run() {
            Alias value = new Alias();
            value.Touch();
        }
    }
}
"#,
        )
        .file(
            "Consumers/GlobalConsumer.cs",
            r#"
namespace Consumers {
    public class GlobalConsumer {
        public void Run() {
            Widget<string> value = new Widget<string>();
            value.Touch();
        }
    }
}
"#,
        )
        .file(
            "Consumers/UnrelatedConsumer.cs",
            r#"
namespace Other {
    public class Widget<T> {
        public void Touch() {}
    }
}
namespace Consumers {
    public class UnrelatedConsumer {
        public void Run() {
            Other.Widget<int> value = new Other.Widget<int>();
            value.Touch();
        }
    }
}
"#,
        )
        .build();
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted C# analyzer should build");
    let analyzer = workspace.analyzer();
    let declarations = analyzer.get_all_declarations();
    let mut targets = declarations
        .iter()
        .filter(|unit| unit.is_function() && unit.identifier() == "Touch")
        .filter(|unit| {
            analyzer
                .parent_of(unit)
                .is_some_and(|owner| owner.package_name() == "Demo")
        })
        .cloned()
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    assert_eq!(
        2,
        targets.len(),
        "expected both physical partial members: {declarations:#?}"
    );

    analyzer.reset_global_usage_definition_index_build_count_for_test();
    analyzer.reset_definition_candidates_query_count_for_test();
    let target_fqn = targets[0].fq_name();
    assert!(targets.iter().all(|target| target.fq_name() == target_fqn));
    let forward = analyzer.definitions(&target_fqn).collect::<Vec<_>>();
    assert_eq!(2, forward.len(), "persisted forward lookup parity");
    assert_eq!(
        0,
        analyzer.global_usage_definition_index_build_count_for_test(),
        "ordinary forward definitions must not hydrate the global usage index"
    );
    assert!(
        analyzer.definition_candidates_query_count_for_test() > 0,
        "the forward assertion must exercise bounded persisted candidate SQL"
    );

    let alias_consumer = project.file("Consumers/AliasConsumer.cs");
    let global_consumer = project.file("Consumers/GlobalConsumer.cs");
    let unrelated_consumer = project.file("Consumers/UnrelatedConsumer.cs");
    let candidate_files = Arc::new(
        [
            alias_consumer.clone(),
            global_consumer.clone(),
            unrelated_consumer.clone(),
        ]
        .into_iter()
        .collect(),
    );
    let provider = ExplicitCandidateProvider::new(Arc::clone(&candidate_files));
    analyzer.reset_definition_candidates_query_count_for_test();
    for attempt in 0..2 {
        let hits = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                analyzer,
                &targets,
                Some(&provider),
                candidate_files.len(),
                100,
            )
            .result
            .into_either()
            .expect("partial member inverse query should resolve");
        assert_eq!(2, hits.len(), "attempt {attempt}: {hits:#?}");
        assert!(
            hits.iter().any(|hit| hit.file == alias_consumer),
            "attempt {attempt}: alias-qualified consumer missing: {hits:#?}"
        );
        assert!(
            hits.iter().any(|hit| hit.file == global_consumer),
            "attempt {attempt}: global-using consumer missing: {hits:#?}"
        );
        assert!(
            hits.iter().all(|hit| hit.file != unrelated_consumer),
            "attempt {attempt}: same-named unrelated owner leaked: {hits:#?}"
        );
    }
    assert_eq!(
        1,
        analyzer.global_usage_definition_index_build_count_for_test(),
        "the generation-scoped inverse definition index should be shared"
    );
    assert_eq!(
        0,
        analyzer.definition_candidates_query_count_for_test(),
        "inverse resolution must not return to persisted definition-candidate SQL after build"
    );
}

#[test]
fn usage_finder_csharp_resolves_unqualified_and_inherited_generic_methods() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Base.cs",
            r#"
namespace Demo {
    public class Base {
        protected T Pick<T>(int value) => default(T);
    }
}
"#,
        ),
        (
            "Demo/Consumer.cs",
            r#"
namespace Demo {
    public sealed class Consumer : Base {
        protected object Pick(int value) => new object();
        private T Identity<T>(T value) => value;

        public T Run<T>(T value) {
            var inherited = Pick<T>(1);
            return Identity(value);
        }
    }
}
"#,
        ),
    ]);
    let inherited = member_function_with_signature(&analyzer, "Demo.Base", "Pick", "`1(int)");
    let inferred = member_function_with_signature(&analyzer, "Demo.Consumer", "Identity", "`1(T)");
    let consumer = project.file("Demo/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let inherited_start = source.find("Pick<T>").expect("inherited generic call");
    let inferred_start = source
        .find("Identity(value)")
        .expect("inferred generic call");

    let forward = definition_lookup(
        project.root(),
        "Demo/Consumer.cs",
        inherited_start,
        inherited_start + "Pick".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.Base.Pick",
        "a nearer wrong-generic-arity member must not hide the matching base method: {forward}"
    );

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    for (target, expected_start) in [(inherited, inherited_start), (inferred, inferred_start)] {
        let hits = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result
            .into_either()
            .expect("generic method query should resolve");
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= expected_start
                    && expected_start + target.identifier().len() <= hit.end_offset
            }),
            "inverse lookup should find the generic call for {target:?}: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_resolves_explicit_generic_extension_and_chained_return_type() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Declarations.cs",
            r#"
namespace Demo {
    public sealed class Source {
        public void Select(int value) { }
    }

    public sealed class BlockedSource {
        public void Filter<T>(T value) { }
    }

    public sealed class GenericResult {
        public void GenericOnly() { }
    }

    public sealed class Box<T> {
        public void BoxOnly() { }
    }

    public sealed class PlainResult { }

    public static class Factory {
        public static T Create<T>() => default(T);
        public static T[] CreateArray<T>() => new T[0];
        public static Box<T> CreateBox<T>() => new Box<T>();
        public static GenericResult? CreateNullable() => new GenericResult();
        public static PlainResult Create() => new PlainResult();
    }

    public class BaseFactory {
        public sealed class NestedResult {
            public void NestedOnly() { }
        }

        protected NestedResult Build<T>() => new NestedResult();
    }
}

namespace Imported {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
        public static T Filter<T>(this Demo.BlockedSource source, T value) => value;
    }
}

namespace Other {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
    }
}
"#,
        ),
        (
            "Demo/Consumer.cs",
            r#"
using Imported;

namespace Demo {
    public sealed class Consumer {
        public void Run(Source source, BlockedSource blocked) {
            source.Select<int>(1);
            blocked.Filter<int>(1);
            Factory.Create<GenericResult>().GenericOnly();
            Factory.CreateArray<GenericResult>().GenericOnly();
            Factory.CreateBox<GenericResult>().BoxOnly();
            Factory.CreateNullable().GenericOnly();
        }
    }

    public sealed class DerivedFactory : BaseFactory {
        public void Run() {
            Build<int>().NestedOnly();
        }
    }
}
"#,
        ),
    ]);
    let extension = member_function_matching_signature(
        &analyzer,
        "Imported.Extensions",
        "Select",
        |signature| signature.is_some_and(|signature| signature.contains("Demo.Source")),
    );
    let blocked_extension = member_function_matching_signature(
        &analyzer,
        "Imported.Extensions",
        "Filter",
        |signature| signature.is_some_and(|signature| signature.contains("Demo.BlockedSource")),
    );
    let hidden_extension =
        member_function_matching_signature(&analyzer, "Other.Extensions", "Select", |signature| {
            signature.is_some_and(|signature| signature.starts_with("`1("))
        });
    let chained = member_function_with_arity(&analyzer, "Demo.GenericResult", "GenericOnly", 0);
    let boxed = member_function_with_arity(&analyzer, "Demo.Box`1", "BoxOnly", 0);
    let inherited_chained =
        member_function_with_arity(&analyzer, "Demo.BaseFactory$NestedResult", "NestedOnly", 0);
    let consumer = project.file("Demo/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let extension_start = source.find("Select<int>").expect("generic extension call");
    let blocked_start = source
        .find("blocked.Filter<int>")
        .map(|start| start + "blocked.".len())
        .expect("instance-precedence call");
    let chained_start = source.find("GenericOnly()").expect("chained member call");
    let wrapped_start = source
        .find("CreateArray<GenericResult>().GenericOnly()")
        .map(|start| start + "CreateArray<GenericResult>().".len())
        .expect("wrapped generic return call");
    let boxed_start = source.find("BoxOnly()").expect("constructed return call");
    let nullable_start = source
        .find("CreateNullable().GenericOnly()")
        .map(|start| start + "CreateNullable().".len())
        .expect("nullable return call");
    let inherited_start = source.find("NestedOnly()").expect("inherited chained call");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for (expected_start, expected_fqn) in [
        (extension_start, "Imported.Extensions.Select"),
        (blocked_start, "Demo.BlockedSource.Filter"),
        (chained_start, "Demo.GenericResult.GenericOnly"),
        (boxed_start, "Demo.Box`1.BoxOnly"),
        (nullable_start, "Demo.GenericResult.GenericOnly"),
        (inherited_start, "Demo.BaseFactory$NestedResult.NestedOnly"),
    ] {
        let forward = definition_lookup(
            project.root(),
            "Demo/Consumer.cs",
            expected_start,
            expected_start + expected_fqn.rsplit('.').next().unwrap().len(),
        );
        assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
        assert_eq!(
            forward["results"][0]["definitions"][0]["fqn"], expected_fqn,
            "{forward}"
        );
    }

    let wrapped_forward = definition_lookup(
        project.root(),
        "Demo/Consumer.cs",
        wrapped_start,
        wrapped_start + "GenericOnly".len(),
    );
    assert_eq!(
        wrapped_forward["results"][0]["status"], "no_definition",
        "an array-wrapped method type parameter must not be substituted as bare T: {wrapped_forward}"
    );

    for (target, expected_start) in [
        (extension, extension_start),
        (chained.clone(), chained_start),
        (boxed, boxed_start),
        (inherited_chained, inherited_start),
    ] {
        let hits = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result
            .into_either()
            .expect("generic call query should resolve");
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= expected_start
                    && expected_start + target.identifier().len() <= hit.end_offset
            }),
            "inverse lookup should find the generic call for {target:?}: {hits:#?}"
        );
    }

    let blocked_extension_hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&blocked_extension),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("blocked extension query should resolve");
    assert!(
        blocked_extension_hits.is_empty(),
        "an applicable instance method must take precedence over an imported extension: {blocked_extension_hits:#?}"
    );

    let chained_hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&chained),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("chained member query should resolve");
    assert!(
        chained_hits.iter().all(|hit| {
            hit.file != consumer
                || wrapped_start + "GenericOnly".len() <= hit.start_offset
                || hit.end_offset <= wrapped_start
        }),
        "a T[] return must not create a GenericResult member hit: {chained_hits:#?}"
    );
    assert!(
        chained_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= nullable_start
                && nullable_start + "GenericOnly".len() <= hit.end_offset
        }),
        "nullable concrete return facts must retain chained receiver typing: {chained_hits:#?}"
    );

    let hidden_hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&hidden_extension),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("nonvisible extension query should resolve");
    assert!(
        hidden_hits.is_empty(),
        "an extension outside the consumer import scope must not be proven: {hidden_hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_scopes_extensions_to_the_call_site_namespace() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Declarations.cs",
            r#"
namespace Demo {
    public sealed class Source { }
}

namespace Imported {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
    }
}
"#,
        ),
        (
            "Demo/Consumers.cs",
            r#"
namespace Shared {
    using Imported;

    public sealed class ImportedConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(1);
        }
    }
}

namespace Shared {
    public sealed class SiblingConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(2);
        }
    }
}

namespace Other {
    public sealed class OtherConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(3);
        }
    }
}
"#,
        ),
    ]);
    let extension = member_function_matching_signature(
        &analyzer,
        "Imported.Extensions",
        "Select",
        |signature| signature.is_some_and(|signature| signature.starts_with("`1(")),
    );
    let consumers = project.file("Demo/Consumers.cs");
    let source = consumers.read_to_string().expect("consumer source");
    let calls = source
        .match_indices("Select<int>")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 3);

    for (index, expected_status) in ["resolved", "no_definition", "no_definition"]
        .into_iter()
        .enumerate()
    {
        let forward = definition_lookup(
            project.root(),
            "Demo/Consumers.cs",
            calls[index],
            calls[index] + "Select".len(),
        );
        assert_eq!(
            forward["results"][0]["status"], expected_status,
            "call-site namespace scope should control extension visibility: {forward}"
        );
    }

    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumers.clone()).collect()));
    let hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&extension),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("namespace-scoped extension query should resolve");
    assert_eq!(
        hits.len(),
        1,
        "only the importing namespace may prove a hit"
    );
    let hit = hits.iter().next().expect("one imported extension hit");
    assert!(
        hit.start_offset <= calls[0] && calls[0] + "Select".len() <= hit.end_offset,
        "the proven hit should be the call in the importing namespace: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_extension_visibility_handles_file_scoped_namespace_frames() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Declarations.cs",
            r#"
namespace Demo {
    public sealed class Source { }
}

namespace RootImported {
    public static class Extensions {
        public static T RootOnly<T>(this Demo.Source source, T value) => value;
    }
}

namespace File.Scope {
    public static class Extensions {
        public static T SameOnly<T>(this Demo.Source source, T value) => value;
    }
}

namespace File {
    public static class Extensions {
        public static T ParentOnly<T>(this Demo.Source source, T value) => value;
    }
}

namespace PostImported {
    public static class Extensions {
        public static T PostOnly<T>(this Demo.Source source, T value) => value;
    }
}

namespace GlobalImported {
    public static class Extensions {
        public static T GlobalOnly<T>(this Demo.Source source, T value) => value;
    }
}
"#,
        ),
        (
            "Demo/GlobalUsings.cs",
            "global using global::GlobalImported;\n",
        ),
        (
            "Demo/FileScoped.cs",
            r#"
using RootImported;
namespace File.Scope;
using PostImported;

public sealed class Consumer {
    public void Run(Demo.Source source) {
        source.RootOnly<int>(1);
        source.SameOnly<int>(2);
        source.ParentOnly<int>(3);
        source.PostOnly<int>(4);
        source.GlobalOnly<int>(5);
    }
}
"#,
        ),
    ]);
    let consumer = project.file("Demo/FileScoped.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for (namespace, method) in [
        ("RootImported", "RootOnly"),
        ("File.Scope", "SameOnly"),
        ("File", "ParentOnly"),
        ("PostImported", "PostOnly"),
        ("GlobalImported", "GlobalOnly"),
    ] {
        let target = member_function_matching_signature(
            &analyzer,
            &format!("{namespace}.Extensions"),
            method,
            |signature| signature.is_some_and(|signature| signature.starts_with("`1(")),
        );
        let start = source
            .find(&format!("{method}<int>"))
            .expect("file-scoped extension call");
        let forward = definition_lookup(
            project.root(),
            "Demo/FileScoped.cs",
            start,
            start + method.len(),
        );
        assert_eq!(
            forward["results"][0]["status"], "resolved",
            "{method} should resolve through its lexical extension frame: {forward}"
        );
        assert_eq!(
            forward["results"][0]["definitions"][0]["fqn"],
            format!("{namespace}.Extensions.{method}"),
            "{forward}"
        );
        let hits = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result
            .into_either()
            .expect("file-scoped extension query should resolve");
        assert!(
            hits.iter().any(|hit| {
                hit.file == consumer
                    && hit.start_offset <= start
                    && start + method.len() <= hit.end_offset
            }),
            "{method} should be proven from the same lexical frame: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_finds_as_expression_type_in_authoritative_and_default_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Runtime/IAsyncCommandRuntimeExtensions.First.cs",
            "namespace Demo.Runtime.PowerShell { internal partial interface IAsyncCommandRuntimeExtensions { } }\n",
        ),
        (
            "Runtime/IAsyncCommandRuntimeExtensions.Second.cs",
            "namespace Demo.Runtime.PowerShell { internal partial interface IAsyncCommandRuntimeExtensions { } }\n",
        ),
        (
            "Other/IAsyncCommandRuntimeExtensions.cs",
            "namespace Other { internal interface IAsyncCommandRuntimeExtensions { } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
namespace App {
    public sealed class Consumer {
        public object CommandRuntime { get; set; }

        public void Run() {
            object IAsyncCommandRuntimeExtensions = this.CommandRuntime;
            var unrelated = IAsyncCommandRuntimeExtensions as Other.IAsyncCommandRuntimeExtensions;
            var runtime = this.CommandRuntime as Demo.Runtime.PowerShell.IAsyncCommandRuntimeExtensions;
        }
    }
}
"#,
        ),
    ]);

    let targets: Vec<_> = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "Demo.Runtime.PowerShell.IAsyncCommandRuntimeExtensions"
        })
        .cloned()
        .collect();
    assert_eq!(targets.len(), 2, "expected both partial type declarations");
    let consumer = project.file("App/Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    let authoritative_hits = authoritative
        .result
        .into_either()
        .expect("authoritative as-expression type query should resolve");

    let source = consumer.read_to_string().expect("consumer source");
    let positive_start = source
        .find("Demo.Runtime.PowerShell.IAsyncCommandRuntimeExtensions")
        .expect("positive as-expression type");
    let positive_end =
        positive_start + "Demo.Runtime.PowerShell.IAsyncCommandRuntimeExtensions".len();
    assert!(
        authoritative_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= positive_start
                && positive_end <= hit.end_offset
        }),
        "as-expression RHS type should be a proven structural reference: {authoritative_hits:#?}"
    );

    let unrelated_start = source
        .find("Other.IAsyncCommandRuntimeExtensions")
        .expect("unrelated RHS type");
    let unrelated_end = unrelated_start + "Other.IAsyncCommandRuntimeExtensions".len();
    let left_start = source
        .find("IAsyncCommandRuntimeExtensions as Other")
        .expect("same-named left expression");
    let left_end = left_start + "IAsyncCommandRuntimeExtensions".len();
    for (start, end) in [(unrelated_start, unrelated_end), (left_start, left_end)] {
        assert!(
            authoritative_hits
                .iter()
                .all(|hit| !(hit.start_offset <= start && end <= hit.end_offset)),
            "unrelated RHS and left expressions must not match the target: {authoritative_hits:#?}"
        );
    }

    let routed = UsageFinder::new().query(&analyzer, &targets, 1000, 1000);
    assert!(
        routed.candidate_files.contains(&consumer),
        "persisted type identifiers must route the as-expression consumer"
    );
    let routed_hits = routed
        .result
        .into_either()
        .expect("default as-expression type query should resolve");
    assert!(
        routed_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= positive_start
                && positive_end <= hit.end_offset
        }),
        "default routing should preserve the as-expression type hit: {routed_hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_finds_using_static_type_in_authoritative_and_default_scope() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Runtime/Extensions.First.cs",
            "namespace Demo.Runtime { public static partial class Extensions { } }\n",
        ),
        (
            "Runtime/Extensions.Second.cs",
            "namespace Demo.Runtime { public static partial class Extensions { } }\n",
        ),
        (
            "Runtime/Extensions.Third.cs",
            "namespace Demo.Runtime { public static partial class Extensions { } }\n",
        ),
        (
            "Other/Extensions.cs",
            "namespace Other { public static class Extensions { } }\n",
        ),
        (
            "App/Consumer.cs",
            r#"
using static Demo.Runtime.Extensions;
using Other;
using Alias = Other.Extensions;
using static Other.Extensions;

namespace App {
    public sealed class Consumer { }
}
"#,
        ),
    ]);

    let targets: Vec<_> = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class && unit.fq_name() == "Demo.Runtime.Extensions"
        })
        .cloned()
        .collect();
    assert_eq!(targets.len(), 3, "expected all partial type declarations");
    let consumer = project.file("App/Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &targets, Some(&provider), 1, 1000);
    let authoritative_hits = authoritative
        .result
        .into_either()
        .expect("authoritative using-static type query should resolve");

    let source = consumer.read_to_string().expect("consumer source");
    let positive_start = source
        .find("Demo.Runtime.Extensions")
        .expect("positive using-static type");
    let positive_end = positive_start + "Demo.Runtime.Extensions".len();
    assert!(
        authoritative_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= positive_start
                && positive_end <= hit.end_offset
        }),
        "using-static type should be a proven structural reference: {authoritative_hits:#?}"
    );
    for unrelated_start in source
        .match_indices("Other.Extensions")
        .map(|(index, _)| index)
    {
        let unrelated_end = unrelated_start + "Other.Extensions".len();
        assert!(
            authoritative_hits.iter().all(|hit| {
                !(hit.start_offset <= unrelated_start && unrelated_end <= hit.end_offset)
            }),
            "unrelated alias/static imports must not match the target: {authoritative_hits:#?}"
        );
    }

    let routed = UsageFinder::new().query(&analyzer, &targets, 1000, 1000);
    assert!(
        routed.candidate_files.contains(&consumer),
        "persisted type identifiers must route the using-static consumer"
    );
    let routed_hits = routed
        .result
        .into_either()
        .expect("default using-static type query should resolve");
    assert!(
        routed_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= positive_start
                && positive_end <= hit.end_offset
        }),
        "default routing should preserve the using-static type hit: {routed_hits:#?}"
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
    let statements = analyzer.import_statements(&file);
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
        .into_iter()
        .map(|info| (info.raw_snippet, info.identifier, info.alias))
        .collect();
    assert_eq!(
        vec![
            (
                "global using Shared;".to_string(),
                Some("Shared".to_string()),
                None
            ),
            (
                "using System.Collections.Generic;".to_string(),
                Some("Generic".to_string()),
                None
            ),
            (
                "using Alias = Other.Target;".to_string(),
                Some("Other.Target".to_string()),
                Some("Alias".to_string()),
            ),
            (
                "using static Shared.Target;".to_string(),
                Some("Shared.Target".to_string()),
                None,
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

    for overloads in [
        vec![run_zero.clone(), run_one.clone()],
        vec![run_one, run_zero],
    ] {
        let hits = UsageFinder::new()
            .find_usages_default(&analyzer, &overloads)
            .into_either()
            .expect("grouped overload query should resolve");
        assert_eq!(
            3,
            hits.len(),
            "grouped overload order changed hits: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_accepts_optional_and_params_arity_ranges() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Service.cs",
            r#"
namespace Domain {
    public sealed class Service {
        public Service(string label = "default") {}
        public void Send(int required, string note = "default") {}
        public void Pack(string head, params object[] tail) {}
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public sealed class Consumer {
        public void Run(Service service) {
            new Service();
            new Service("named");
            new Service("too", "many");
            service.Send(1);
            service.Send(1, "note");
            service.Send();
            service.Send(1, "note", "extra");
            service.Pack("head");
            service.Pack("head", 1, 2);
            service.Pack();
        }
    }
}
"#,
        ),
    ]);

    let constructor = member_function(&analyzer, "Domain.Service", "Service");
    let send = member_function(&analyzer, "Domain.Service", "Send");
    let pack = member_function(&analyzer, "Domain.Service", "Pack");
    let consumer = project.file("App/Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let source = consumer.read_to_string().expect("consumer source");
    let constructor_offsets = source
        .match_indices("new Service")
        .map(|(start, _)| start + "new ".len())
        .collect::<Vec<_>>();
    let send_offsets = source
        .match_indices("service.Send")
        .map(|(start, _)| start + "service.".len())
        .collect::<Vec<_>>();
    let pack_offsets = source
        .match_indices("service.Pack")
        .map(|(start, _)| start + "service.".len())
        .collect::<Vec<_>>();

    for (target, expected_offsets, rejected_offsets) in [
        (
            constructor,
            constructor_offsets[..2].to_vec(),
            constructor_offsets[2..].to_vec(),
        ),
        (send, send_offsets[..2].to_vec(), send_offsets[2..].to_vec()),
        (pack, pack_offsets[..2].to_vec(), pack_offsets[2..].to_vec()),
    ] {
        let query = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            );
        assert_eq!(
            query.candidate_files,
            std::iter::once(consumer.clone()).collect()
        );
        let hits = query
            .result
            .into_either()
            .unwrap_or_else(|error| panic!("{} should resolve: {error}", target.fq_name()));
        assert_eq!(
            hits.len(),
            expected_offsets.len(),
            "{} accepted the wrong arity sites: {hits:#?}",
            target.fq_name()
        );
        for offset in expected_offsets {
            assert!(
                hits.iter()
                    .any(|hit| hit.start_offset <= offset && offset < hit.end_offset),
                "{} omitted byte {offset}: {hits:#?}",
                target.fq_name()
            );
        }
        for offset in rejected_offsets {
            assert!(
                hits.iter()
                    .all(|hit| !(hit.start_offset <= offset && offset < hit.end_offset)),
                "{} accepted invalid-arity byte {offset}: {hits:#?}",
                target.fq_name()
            );
        }
    }
}

#[test]
fn usage_finder_csharp_optional_extension_distinguishes_call_syntax() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Extensions.cs",
            r#"
namespace Domain {
    public static class Extensions {
        public static string Tag(this string value, string suffix = "") => value + suffix;
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;

namespace App {
    public sealed class Consumer {
        public void Run(string name) {
            name.Tag();
            name.Tag("x");
            Extensions.Tag(name);
            Extensions.Tag();
            name.Tag("x", "y");
        }
    }
}
"#,
        ),
    ]);

    let target = member_function(&analyzer, "Domain.Extensions", "Tag");
    let consumer = project.file("App/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let offsets = source
        .match_indices("Tag")
        .map(|(start, _)| start)
        .collect::<Vec<_>>();
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("optional extension query should resolve");

    assert_eq!(
        3,
        hits.len(),
        "only valid extension calls should match: {hits:#?}"
    );
    for offset in &offsets[..3] {
        assert!(
            hits.iter()
                .any(|hit| hit.start_offset <= *offset && *offset < hit.end_offset),
            "valid extension call at byte {offset} was omitted: {hits:#?}"
        );
    }
    for offset in &offsets[3..] {
        assert!(
            hits.iter()
                .all(|hit| !(hit.start_offset <= *offset && *offset < hit.end_offset)),
            "invalid extension call at byte {offset} was accepted: {hits:#?}"
        );
    }
}

#[test]
fn csharp_graph_optional_factory_call_seeds_receiver_type() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Types.cs",
            r#"
namespace Domain {
    public sealed class Product {
        public void Use() {}
    }
    public sealed class Factory {
        public Product Create(string label = "") => new Product();
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
using Domain;
namespace App {
    public sealed class Consumer {
        public void Run(Factory factory) {
            var product = factory.Create();
            product.Use();
        }
    }
}
"#,
        ),
    ]);

    let target = member_function(&analyzer, "Domain.Product", "Use");
    let consumer = project.file("App/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let use_offset = source.find("Use").expect("Use call");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("optional factory return should type its receiver");

    assert!(
        hits.iter()
            .any(|hit| hit.start_offset <= use_offset && use_offset < hit.end_offset),
        "optional factory return did not seed Product receiver: {hits:#?}"
    );
}

#[test]
fn csharp_graph_factory_return_keeps_overlapping_arity_untyped() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "App.cs",
        r#"
namespace App {
    public sealed class ExactProduct { public void Use() {} }
    public sealed class OptionalProduct { public void Use() {} }
    public sealed class FixedProduct { public void Use() {} }
    public sealed class ParamsProduct { public void Use() {} }
    public sealed class Factory {
        public ExactProduct Create() => new ExactProduct();
        public OptionalProduct Create(int count = 0) => new OptionalProduct();
        public FixedProduct Make(string head, object tail) => new FixedProduct();
        public ParamsProduct Make(string head, params object[] tail) => new ParamsProduct();
    }
    public sealed class Consumer {
        public void Exact(Factory factory) {
            var product = factory.Create();
            product.Use();
        }
        public void Fixed(Factory factory) {
            var product = factory.Make("head", "tail");
            product.Use();
        }
    }
}
"#,
    )]);

    assert!(
        graph_hits(
            &analyzer,
            &member_function(&analyzer, "App.ExactProduct", "Use")
        )
        .is_empty(),
        "overlapping exact and optional overloads need argument-type evidence"
    );
    assert!(
        graph_hits(
            &analyzer,
            &member_function(&analyzer, "App.OptionalProduct", "Use")
        )
        .is_empty(),
        "overlapping exact and optional overloads must remain conservatively untyped"
    );
    assert!(
        graph_hits(
            &analyzer,
            &member_function(&analyzer, "App.FixedProduct", "Use")
        )
        .is_empty(),
        "equal-total fixed and params overloads need argument-type evidence"
    );
    assert!(
        graph_hits(
            &analyzer,
            &member_function(&analyzer, "App.ParamsProduct", "Use")
        )
        .is_empty(),
        "equal-total fixed and params overloads must remain conservatively untyped"
    );
}

#[test]
fn csharp_graph_authoritative_scope_keeps_generic_local_receiver_identity() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Types.cs",
            r#"
namespace Domain {
    public class Box {
        public void Read() {}
    }

    public partial class Box<T> {
        public void Read() {}
    }
}
"#,
        ),
        (
            "Domain/GenericBox.Partial.cs",
            r#"
namespace Domain {
    public partial class Box<T> {
        public T Value { get; set; }
    }
}
"#,
        ),
        (
            "App/Consumer.cs",
            r#"
namespace App {
    public class Consumer {
        public void Execute(Domain.Box<string> parameter) {
            parameter.Read();
            var inferred = new global::Domain.Box<string>();
            inferred.Read();
            Domain.Box<string> box = new global::Domain.Box<string>();
            box.Read();
        }
    }
}
"#,
        ),
    ]);

    let generic_read = member_function_with_arity(&analyzer, "Domain.Box`1", "Read", 0);
    let ordinary_read = member_function_with_arity(&analyzer, "Domain.Box", "Read", 0);
    let consumer = project.file("App/Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let generic_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &[generic_read], Some(&provider), 1, 1000);
    assert_eq!(
        generic_query.candidate_files,
        std::iter::once(consumer.clone()).collect()
    );
    let generic_hits = generic_query
        .result
        .into_either()
        .expect("generic local receiver query should resolve");
    assert_eq!(3, generic_hits.len(), "{generic_hits:#?}");
    assert!(
        generic_hits
            .iter()
            .any(|hit| hit.snippet.contains("box.Read()"))
    );
    assert!(
        generic_hits
            .iter()
            .any(|hit| hit.snippet.contains("parameter.Read()"))
    );
    assert!(
        generic_hits
            .iter()
            .any(|hit| hit.snippet.contains("inferred.Read()"))
    );

    let ordinary_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &[ordinary_read], Some(&provider), 1, 1000);
    let ordinary_hits = ordinary_query
        .result
        .into_either()
        .expect("ordinary local receiver query should resolve");
    assert!(ordinary_hits.is_empty(), "{ordinary_hits:#?}");
}

#[test]
fn csharp_default_candidates_keep_generic_reference_arity() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Legacy/Box.cs",
            "namespace Domain { public class Box {} }\n",
        ),
        (
            "Domain/GenericBox.cs",
            "namespace Domain { public class Box<T> {} }\n",
        ),
        (
            "App/Consumer.cs",
            "namespace App { public class Consumer { Domain.Box<string> value; } }\n",
        ),
        (
            "App/LegacyConsumer.cs",
            "namespace App { public class LegacyConsumer { Domain.Box value; } }\n",
        ),
    ]);
    let generic = type_definition(&analyzer, "Domain.Box`1");
    assert_eq!(generic.source(), &project.file("Domain/GenericBox.cs"));
    let referencing = analyzer
        .import_analysis_provider()
        .expect("C# import analysis")
        .referencing_files_of(generic.source());
    assert!(
        !referencing.contains(&project.file("Legacy/Box.cs")),
        "generic reverse-reference index included nongeneric declaration: {referencing:#?}"
    );
    let query = UsageFinder::new().query(&analyzer, &[generic], 1000, 1000);
    assert!(
        query
            .candidate_files
            .contains(&project.file("App/Consumer.cs")),
        "{:#?}",
        query.candidate_files
    );
    assert!(
        !query
            .candidate_files
            .contains(&project.file("Legacy/Box.cs")),
        "nongeneric declaration file was routed for a generic target: {:#?}",
        query.candidate_files
    );
    assert!(
        !query
            .candidate_files
            .contains(&project.file("App/LegacyConsumer.cs")),
        "nongeneric reference was routed for a generic target: {:#?}",
        query.candidate_files
    );
}

#[test]
fn csharp_default_candidates_cover_each_namespace_declared_in_one_file() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Targets/First.cs",
            "namespace First { public class FirstTarget {} }\n",
        )
        .file(
            "Targets/Second.cs",
            "namespace Second { public class SecondTarget {} }\n",
        )
        .file(
            "Consumers/MultiNamespace.cs",
            r#"
namespace First {
    public class FirstConsumer {
        FirstTarget value;
    }
}

namespace Second {
    public class SecondConsumer {
        SecondTarget value;
    }
}
"#,
        )
        .build();
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted multi-namespace C# project should build");
    let analyzer = workspace.analyzer();
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.is_class() && unit.fq_name() == "Second.SecondTarget")
        .expect("second namespace target declaration");
    let consumer = project.file("Consumers/MultiNamespace.cs");

    let referencing = analyzer
        .import_analysis_provider()
        .expect("C# import analysis")
        .referencing_files_of(target.source());
    assert!(
        referencing.contains(&consumer),
        "multi-namespace reverse index omitted the second namespace: {referencing:#?}"
    );

    let query = UsageFinder::new().query(analyzer, &[target], 1000, 1000);
    assert!(
        query.candidate_files.contains(&consumer),
        "default routing omitted the second namespace: {:#?}",
        query.candidate_files
    );
    let hits = query
        .result
        .into_either()
        .expect("multi-namespace type query should resolve");
    assert_eq!(1, hits.len(), "{hits:#?}");
    let hit = hits.iter().next().expect("one multi-namespace usage");
    assert_eq!(consumer, hit.file);
    assert!(hit.snippet.contains("SecondTarget value"), "{hit:#?}");
}

#[test]
fn csharp_issue701_persisted_inverse_fallback_preserves_arity_and_physical_types() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Collections/ICollection.First.cs",
            "namespace System.Collections { public partial interface ICollection { void CopyTo(); } }\n",
        )
        .file(
            "Collections/ICollection.Second.cs",
            "namespace System.Collections { public partial interface ICollection { int Count { get; } } }\n",
        )
        .file(
            "Collections/GenericICollection.cs",
            "namespace System.Collections.Generic { public interface ICollection<T> { } }\n",
        )
        .file(
            "Contracts/Nested.First.cs",
            "namespace Contracts { public partial class Outer { public partial class Nested { } } }\n",
        )
        .file(
            "Contracts/Nested.Second.cs",
            "namespace Contracts { public partial class Outer { public partial class Nested { } } }\n",
        )
        .file(
            "Consumers/RuntimeShape.cs",
            r#"
using System.Collections;
using System.Collections.Generic;
namespace App {
    public class RuntimeShape : ICollection {
        void ICollection.CopyTo() { }
        public ICollection Echo(ICollection value) => value;
        public ICollection<int> Generic;
    }
}
"#,
        )
        .file(
            "Consumers/MonoShape.cs",
            r#"
using System.Collections;
namespace System.Collections.Generic {
    public class MonoShape : ICollection {
        void ICollection.CopyTo() { }
    }
}
"#,
        )
        .file(
            "Consumers/NestedShape.cs",
            "namespace App { public class NestedShape { Contracts.Outer.Nested Value; } }\n",
        )
        .build();
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted arity project should build");
    let analyzer = workspace.analyzer();
    let declarations = analyzer.get_all_declarations();
    let targets = |fq_name: &str| {
        declarations
            .iter()
            .filter(|unit| unit.is_class() && unit.fq_name() == fq_name)
            .cloned()
            .collect::<Vec<_>>()
    };

    let nongeneric = targets("System.Collections.ICollection");
    assert_eq!(2, nongeneric.len(), "physical partial declarations");
    let generic = targets("System.Collections.Generic.ICollection`1");
    assert_eq!(1, generic.len(), "generic collision declaration");
    let nested = targets("Contracts.Outer$Nested");
    assert_eq!(2, nested.len(), "physical dotted nested declarations");

    let runtime = project.file("Consumers/RuntimeShape.cs");
    let mono = project.file("Consumers/MonoShape.cs");
    let nested_consumer = project.file("Consumers/NestedShape.cs");
    let candidate_files = Arc::new(
        [runtime.clone(), mono.clone(), nested_consumer.clone()]
            .into_iter()
            .collect(),
    );
    let provider = ExplicitCandidateProvider::new(Arc::clone(&candidate_files));
    let query = |query_targets: &[CodeUnit]| {
        UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                analyzer,
                query_targets,
                Some(&provider),
                candidate_files.len(),
                1000,
            )
            .result
            .into_either()
            .expect("persisted inverse query should resolve")
    };

    let nongeneric_hits = query(&nongeneric);
    assert!(
        nongeneric_hits
            .iter()
            .any(|hit| hit.file == runtime && hit.snippet.contains("ICollection Echo")),
        "runtime-shaped imports should resolve the nongeneric type: {nongeneric_hits:#?}"
    );
    assert!(
        nongeneric_hits
            .iter()
            .any(|hit| hit.file == mono && hit.snippet.contains(": ICollection")),
        "the current generic namespace must fall through to the nongeneric using: {nongeneric_hits:#?}"
    );
    assert!(
        {
            let source = runtime.read_to_string().expect("runtime consumer source");
            let start = source.find("ICollection<int>").expect("generic reference");
            nongeneric_hits.iter().all(|hit| {
                !(hit.file == runtime
                    && hit.start_offset <= start
                    && start + "ICollection<int>".len() <= hit.end_offset)
            })
        },
        "generic references must not collide with nongeneric targets: {nongeneric_hits:#?}"
    );

    let generic_hits = query(&generic);
    assert_eq!(1, generic_hits.len(), "{generic_hits:#?}");
    assert!(
        generic_hits
            .iter()
            .all(|hit| hit.snippet.contains("ICollection<int>"))
    );

    let nested_hits = query(&nested);
    assert_eq!(1, nested_hits.len(), "{nested_hits:#?}");
    assert!(nested_hits.iter().all(|hit| hit.file == nested_consumer));

    let default_query = UsageFinder::new().query(analyzer, &nested, 1000, 1000);
    assert!(
        default_query.candidate_files.contains(&nested_consumer),
        "dotted nested identity should route its consumer: {:#?}",
        default_query.candidate_files
    );
}

#[test]
fn csharp_issue701_structured_type_roles_cover_alias_receivers_and_patterns_without_values() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Types.cs",
            r#"
namespace Demo {
    public interface Marker { void Touch(); }
    public class PatternType { }
    public class OtherType { }
    public class InheritedPattern { }
    public enum Mode { Enabled }
    public class Generic<T> { public static int Value; }
    public class Holder { public int Nested; }
    public class InheritedOuter { public class Nested { public static int Value; } }
    public class Outer { public class Nested { public static int Value; } }
}
namespace Other {
    public class Outer { public class Nested { public static int Value; } }
}
namespace App {
    public class Constants { public class Globals { public static int Value; } }
}
namespace Imported {
    public class ImportedOwner { public class Nested { public static int Value; } }
}
namespace Imported.System {
    public class String { }
}
namespace System {
    public class String { }
}
"#,
        ),
        (
            "Consumer.cs",
            r#"
using Alias = Demo.Outer.Nested;
using Nested = Demo.OtherType;
using Demo;
using Imported;
namespace App {
    public class Base {
        protected Holder InheritedOuter;
        protected const int InheritedPattern = 1;
    }
    public class Consumer : Base, Marker {
        private Holder Outer;
        public const int LocalConstant = 2;
        public Marker Echo(Marker value, object member) {
            var aliasValue = Alias.Value;
            var nestedValue = Demo.Outer.Nested.Value;
            var genericValue = Generic<int>.Value;
            var relativeNestedValue = Constants.Globals.Value;
            var importedNestedValue = ImportedOwner.Nested.Value;
            System.String globalString = null;
            var unrelated = Other.Outer.Nested.Value;
            var unresolved = Missing.Nested.Value;
            var fieldValue = Outer.Nested;
            if (member is PatternType || member is OtherType) { }
            return value;
        }
        void Marker.Touch() { }
        public bool Shadowed(object member, int PatternType) => member is PatternType;
        public bool Switched(object member) => member switch { PatternType => true, _ => false };
        public bool Constant(object member) => member is Mode.Enabled;
        public bool BareConstant(object member) => member is LocalConstant;
        public bool Inherited(object member) {
            var value = InheritedOuter.Nested;
            return member is InheritedPattern;
        }
        public int Local(Holder Outer) => Outer.Nested;
    }
}
"#,
        ),
    ]);
    let consumer = project.file("Consumer.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = |target: CodeUnit| {
        UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(&analyzer, &[target], Some(&provider), 1, 1000)
            .result
            .into_either()
            .expect("structured type query should resolve")
    };
    let nested = definition_by(&analyzer, |unit| {
        unit.is_class() && unit.fq_name() == "Demo.Outer$Nested"
    });
    let nested_hits = query(nested.clone());
    let source = consumer.read_to_string().expect("consumer source");
    let alias_lhs = source.find("Nested = Demo.OtherType").expect("alias lhs");
    assert!(
        nested_hits
            .iter()
            .any(|hit| hit.snippet.contains("using Alias")),
        "alias RHS should count: {nested_hits:#?}"
    );
    assert!(
        nested_hits
            .iter()
            .any(|hit| hit.snippet.contains("Alias.Value")),
        "alias receiver should count: {nested_hits:#?}"
    );
    assert!(
        nested_hits
            .iter()
            .any(|hit| hit.snippet.contains("Demo.Outer.Nested.Value")),
        "intermediate nested receiver should count: {nested_hits:#?}"
    );
    assert!(
        nested_hits
            .iter()
            .all(|hit| !(hit.start_offset <= alias_lhs
                && alias_lhs + "Nested".len() <= hit.end_offset)),
        "alias LHS must not count: {nested_hits:#?}"
    );
    assert!(
        [
            source
                .find("Other.Outer.Nested.Value")
                .expect("unrelated nested receiver")
                + "Other.Outer.".len(),
            source
                .find("var fieldValue = Outer.Nested;")
                .expect("field receiver")
                + "var fieldValue = Outer.".len(),
            source
                .rfind("=> Outer.Nested;")
                .expect("parameter receiver")
                + "=> Outer.".len(),
        ]
        .into_iter()
        .all(|start| nested_hits.iter().all(|hit| {
            !(hit.start_offset <= start && start + "Nested".len() <= hit.end_offset)
        })),
        "unrelated and value receivers must not count: {nested_hits:#?}"
    );
    let raw_result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&nested),
        &std::iter::once(consumer.clone()).collect(),
        1000,
    );
    let unresolved_start = source
        .find("Missing.Nested.Value")
        .expect("unresolved receiver");
    match raw_result {
        FuzzyResult::Success {
            unproven_by_overload,
            ..
        } => assert!(
            unproven_by_overload.values().flatten().any(|hit| {
                hit.start_offset <= unresolved_start
                    && unresolved_start + "Missing.Nested".len() <= hit.end_offset
            }),
            "an unresolved structured receiver should retain unproven completeness evidence"
        ),
        other => panic!("structured receiver query should succeed: {other:#?}"),
    }

    let generic = type_definition(&analyzer, "Demo.Generic`1");
    let generic_hits = query(generic);
    assert_eq!(1, generic_hits.len(), "{generic_hits:#?}");
    assert!(
        generic_hits
            .iter()
            .all(|hit| hit.snippet.contains("Generic<int>.Value"))
    );

    let relative_nested = type_definition(&analyzer, "App.Constants$Globals");
    let relative_nested_hits = query(relative_nested.clone());
    assert_eq!(1, relative_nested_hits.len(), "{relative_nested_hits:#?}");
    assert!(
        relative_nested_hits
            .iter()
            .all(|hit| hit.snippet.contains("Constants.Globals.Value")),
        "a dotted nested type must resolve relative to the file namespace: {relative_nested_hits:#?}"
    );

    let imported_nested = type_definition(&analyzer, "Imported.ImportedOwner$Nested");
    let imported_nested_hits = query(imported_nested);
    assert_eq!(1, imported_nested_hits.len(), "{imported_nested_hits:#?}");
    assert!(
        imported_nested_hits
            .iter()
            .all(|hit| hit.snippet.contains("ImportedOwner.Nested.Value")),
        "a using namespace should expose a nested type whose outer type is declared directly in that namespace: {imported_nested_hits:#?}"
    );

    let global_string = type_definition(&analyzer, "System.String");
    let global_string_hits = query(global_string);
    assert_eq!(1, global_string_hits.len(), "{global_string_hits:#?}");
    assert!(
        global_string_hits
            .iter()
            .all(|hit| hit.snippet.contains("System.String globalString")),
        "a using namespace must not import a same-named child namespace: {global_string_hits:#?}"
    );
    let imported_child_string = type_definition(&analyzer, "Imported.System.String");
    assert!(
        query(imported_child_string).is_empty(),
        "using Imported must not make Imported.System visible as System"
    );

    let pattern = type_definition(&analyzer, "Demo.PatternType");
    let pattern_hits = query(pattern);
    assert!(
        pattern_hits
            .iter()
            .any(|hit| hit.snippet.contains("is PatternType ||")),
        "constant-pattern binary left spine should count: {pattern_hits:#?}"
    );
    assert!(
        pattern_hits
            .iter()
            .any(|hit| hit.snippet.contains("switch { PatternType")),
        "switch constant pattern should count: {pattern_hits:#?}"
    );
    assert!(
        {
            let start = source
                .rfind("member is PatternType")
                .expect("shadowed pattern")
                + "member is ".len();
            pattern_hits.iter().all(|hit| {
                !(hit.start_offset <= start && start + "PatternType".len() <= hit.end_offset)
            })
        },
        "value-shadowed pattern must not count: {pattern_hits:#?}"
    );

    let marker = type_definition(&analyzer, "Demo.Marker");
    let marker_hits = query(marker);
    assert!(
        marker_hits
            .iter()
            .any(|hit| hit.snippet.contains("Base, Marker"))
    );
    assert!(
        marker_hits
            .iter()
            .any(|hit| hit.snippet.contains("Marker Echo"))
    );
    assert!(
        marker_hits
            .iter()
            .any(|hit| hit.snippet.contains("Echo(Marker"))
    );
    assert!(
        marker_hits
            .iter()
            .any(|hit| hit.snippet.contains("Marker.Touch"))
    );

    let enabled = definition_by(&analyzer, |unit| {
        unit.is_field() && unit.fq_name() == "Demo.Mode.Enabled"
    });
    let enabled_hits = query(enabled);
    assert_eq!(1, enabled_hits.len(), "{enabled_hits:#?}");
    assert!(
        enabled_hits
            .iter()
            .all(|hit| hit.snippet.contains("member is Mode.Enabled")),
        "qualified constant patterns should retain direct field hits: {enabled_hits:#?}"
    );

    let local_constant = definition_by(&analyzer, |unit| {
        unit.is_field() && unit.fq_name() == "App.Consumer.LocalConstant"
    });
    let local_constant_hits = CSharpUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&local_constant),
            &std::iter::once(consumer.clone()).collect(),
            1000,
        )
        .all_hits_including_imports();
    assert_eq!(1, local_constant_hits.len(), "{local_constant_hits:#?}");
    assert!(
        local_constant_hits
            .iter()
            .all(|hit| hit.snippet.contains("member is LocalConstant")),
        "bare constant patterns should retain direct self-field hits: {local_constant_hits:#?}"
    );

    let inherited_constant = definition_by(&analyzer, |unit| {
        unit.is_field() && unit.fq_name() == "App.Base.InheritedPattern"
    });
    let inherited_constant_hits = query(inherited_constant);
    assert_eq!(
        1,
        inherited_constant_hits.len(),
        "{inherited_constant_hits:#?}"
    );
    assert!(
        inherited_constant_hits
            .iter()
            .all(|hit| hit.snippet.contains("member is InheritedPattern")),
        "bare inherited constants should retain direct field hits: {inherited_constant_hits:#?}"
    );

    let inherited_nested = type_definition(&analyzer, "Demo.InheritedOuter$Nested");
    let inherited_nested_hits = query(inherited_nested);
    assert!(
        inherited_nested_hits
            .iter()
            .all(|hit| !hit.snippet.contains("InheritedOuter.Nested")),
        "an inherited field receiver must not become a type hit: {inherited_nested_hits:#?}"
    );
    let inherited_pattern = type_definition(&analyzer, "Demo.InheritedPattern");
    let inherited_pattern_hits = query(inherited_pattern);
    assert!(
        inherited_pattern_hits
            .iter()
            .all(|hit| !hit.snippet.contains("member is InheritedPattern")),
        "an inherited constant must not become a type hit: {inherited_pattern_hits:#?}"
    );

    let default_query = UsageFinder::new().query(&analyzer, &[nested], 1000, 1000);
    assert!(
        default_query.candidate_files.contains(&consumer),
        "shared declaration routing should retain expression receiver candidates"
    );
    let relative_default_query =
        UsageFinder::new().query(&analyzer, &[relative_nested], 1000, 1000);
    assert!(
        relative_default_query.candidate_files.contains(&consumer),
        "shared declaration routing should retain relative nested receiver candidates"
    );
}

#[test]
fn csharp_issue701_constant_pattern_matches_all_physical_partial_type_declarations() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "TypeBuilderInstantiation.cs",
            "namespace System.Reflection.Emit { internal sealed partial class TypeBuilderInstantiation { } }\n",
        )
        .file(
            "TypeBuilderInstantiation.Mono.cs",
            "namespace System.Reflection.Emit { internal partial class TypeBuilderInstantiation { } }\n",
        )
        .file(
            "RuntimeModuleBuilder.Mono.cs",
            r#"
namespace System.Reflection.Emit {
    internal class RuntimeModuleBuilder {
        internal bool IsTransient(object member) {
            if (member is TypeBuilderInstantiation || member is OtherType)
                return true;
            return false;
        }
    }
    internal class OtherType { }
}
"#,
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let targets = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| {
            unit.is_class() && unit.fq_name() == "System.Reflection.Emit.TypeBuilderInstantiation"
        })
        .collect::<Vec<_>>();
    assert_eq!(2, targets.len(), "{targets:#?}");
    let consumer = project.file("RuntimeModuleBuilder.Mono.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(analyzer, &targets, Some(&provider), 1, 1000)
        .result
        .into_either()
        .expect("partial type pattern query should resolve");
    assert_eq!(1, hits.len(), "{hits:#?}");
    assert!(
        hits.iter()
            .all(|hit| hit.snippet.contains("member is TypeBuilderInstantiation")),
        "the constant pattern should resolve to the logical partial type: {hits:#?}"
    );
    let default_query = UsageFinder::new().query(analyzer, &targets, 1000, 1000);
    assert!(
        default_query.candidate_files.contains(&consumer),
        "the is-expression type role should route the consumer by default"
    );
    assert_eq!(
        1,
        default_query
            .result
            .into_either()
            .expect("default partial pattern query should resolve")
            .len()
    );
}

#[test]
fn csharp_tuple_element_type_is_a_usage_but_its_declaration_name_is_not() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Configuration/MapperConfiguration.cs",
            "namespace Configuration { public class MapperConfiguration { } }\n",
        ),
        (
            "MapperGenerator.cs",
            r#"
using Configuration;

namespace Generators;

public class MapperGenerator {
    private static (MapperConfiguration MapperConfiguration, int Diagnostics) BuildDefaults() {
        return default;
    }
}
"#,
        ),
    ]);

    let target = type_definition(&analyzer, "Configuration.MapperConfiguration");
    let hits = graph_hits(&analyzer, &target);
    let consumer = project.file("MapperGenerator.cs");
    let source = consumer.read_to_string().expect("tuple consumer source");
    let type_start = source
        .find("(MapperConfiguration")
        .expect("tuple element type")
        + 1;
    let name_start = source
        .find("MapperConfiguration,")
        .expect("tuple element declaration name");

    assert_eq!(
        1,
        hits.len(),
        "only the tuple element type should count: {hits:#?}"
    );
    let hit = hits.iter().next().expect("tuple type hit");
    assert_eq!(consumer, hit.file);
    assert!(
        hit.start_offset <= type_start
            && type_start + "MapperConfiguration".len() <= hit.end_offset,
        "tuple type token should be returned: {hit:#?}"
    );
    assert!(
        !(hit.start_offset <= name_start
            && name_start + "MapperConfiguration".len() <= hit.end_offset),
        "tuple element declaration name must stay excluded: {hit:#?}"
    );
}

#[test]
fn csharp_graph_distinguishes_generic_and_nongeneric_constructor_owners() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Domain/Exceptions.cs",
            r#"
namespace Domain {
    public class Response {}
    public class Error {}
    public class RestException {
        public RestException(Response response, Error body) {}
        public Error Body { get; set; }
    }
    public partial class RestException<T> {
        public RestException(Response response, T body) {}
        public T Body { get; set; }
    }
    public partial class RestException<T> {
        public T Read() => Body;
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
        public void Execute(Response response, Error error) {
            var ordinary = new RestException(response, error);
            var generic = new RestException<Error>(response, error);
            var initializedOrdinary = new RestException(response, error) { Body = error };
            var initializedGeneric = new RestException<Error>(response, error) { Body = error };
            var read = new RestException<Error>(response, error).Read();
        }
    }
}
"#,
        ),
        (
            "App/FullyQualified.cs",
            r#"
namespace App {
    public class FullyQualified {
        public void Execute(Domain.Response response, Domain.Error error) {
            var generic = new global::Domain.RestException<Domain.Error>(response, error);
        }
    }
}
"#,
        ),
        (
            "App/Aliased.cs",
            r#"
using Failure = Domain.RestException<Domain.Error>;

namespace App {
    public class Aliased {
        public void Execute(Domain.Response response, Domain.Error error) {
            var generic = new Failure(response, error);
        }
    }
}
"#,
        ),
    ]);

    let ordinary = member_function_with_signature(
        &analyzer,
        "Domain.RestException",
        "RestException",
        "(Response, Error)",
    );
    let generic = member_function_with_signature(
        &analyzer,
        "Domain.RestException`1",
        "RestException",
        "(Response, T)",
    );
    let ordinary_body = member_field(&analyzer, "Domain.RestException", "Body");
    let generic_body = member_field(&analyzer, "Domain.RestException`1", "Body");

    let ordinary_hits = graph_hits(&analyzer, &ordinary);
    assert_eq!(2, ordinary_hits.len(), "{ordinary_hits:#?}");
    assert!(
        ordinary_hits
            .iter()
            .next()
            .expect("ordinary constructor hit")
            .snippet
            .contains("new RestException(response, error)"),
        "{ordinary_hits:#?}"
    );
    let generic_hits = graph_hits(&analyzer, &generic);
    assert_eq!(5, generic_hits.len(), "{generic_hits:#?}");
    assert!(
        generic_hits.iter().any(|hit| hit
            .snippet
            .contains("new RestException<Error>(response, error)")),
        "{generic_hits:#?}"
    );
    assert!(
        generic_hits.iter().any(|hit| hit
            .snippet
            .contains("new global::Domain.RestException<Domain.Error>(response, error)")),
        "{generic_hits:#?}"
    );
    assert!(
        generic_hits
            .iter()
            .any(|hit| hit.snippet.contains("new Failure(response, error)")),
        "{generic_hits:#?}"
    );

    let routed = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&generic))
        .into_either()
        .expect("default generic constructor routing");
    assert_eq!(5, routed.len(), "{routed:#?}");

    let ordinary_body_hits = graph_hits(&analyzer, &ordinary_body);
    assert_eq!(1, ordinary_body_hits.len(), "{ordinary_body_hits:#?}");
    let generic_body_hits = graph_hits(&analyzer, &generic_body);
    assert_eq!(2, generic_body_hits.len(), "{generic_body_hits:#?}");
    assert!(
        generic_body_hits
            .iter()
            .any(|hit| hit.line == 10 && hit.snippet.contains("initializedGeneric")),
        "{generic_body_hits:#?}"
    );
    assert!(
        generic_body_hits
            .iter()
            .any(|hit| hit.line == 14 && hit.snippet.contains("public T Read() => Body")),
        "the sibling partial self-read should retain the exact generic owner identity: {generic_body_hits:#?}"
    );
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
fn csharp_graph_resolves_conditional_member_receiver_shapes_and_overloads() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Lib/Service.cs",
            r#"
namespace Lib;
public class Service {
    public void Run() {}
    public void Run(int value) {}
    public void Run<T>(int first, int second) {}
    public Service Child => this;
    public Service GetChild() => this;
}
"#,
        ),
        (
            "App/Controller.cs",
            r#"
using Lib;
namespace App;
public class Controller {
    private readonly Service _service = new();
    public void FromParameter(Service service) => service?.Run();
    public void FromParenthesized(Service service) => ((service))?.Run(1);
    public void FromCast(object raw) => ((Service)raw)?.Run<string>(1, 2);
    public void FromField() => _service?.Run();
    public void FromConditionalProperty(Service service) => service?.Child?.Run();
    public void FromConditionalReturn(Service service) => service?.GetChild()?.Run();
    public void FromAs(object raw) => (raw as Service)?.Run();
}
"#,
        ),
        (
            "Model.Json.cs",
            r#"
namespace Example;
public partial class Model {
    private string _value = "";
    public string Serialize() => (((object)_value)?.ToString());
    public string Format() => (((object)_value)?.Format());
}
"#,
        ),
        (
            "Model.PowerShell.cs",
            r#"
namespace Example;
public partial class Model {
    public override string ToString() => "model";
}
"#,
        ),
        (
            "Extensions.cs",
            r#"
namespace Example;
public static class Extensions {
    public static string ToString(this Model value) => "wrong";
    public static string Format(this object value) => "matched";
}
"#,
        ),
    ]);

    let run_zero = member_function_with_signature(&analyzer, "Lib.Service", "Run", "()");
    let run_one = member_function_with_signature(&analyzer, "Lib.Service", "Run", "(int)");
    let run_generic =
        member_function_with_signature(&analyzer, "Lib.Service", "Run", "`1(int, int)");

    let zero_hits = graph_hits(&analyzer, &run_zero);
    assert_eq!(5, zero_hits.len(), "{zero_hits:#?}");
    assert_eq!(1, graph_hits(&analyzer, &run_one).len());
    assert_eq!(1, graph_hits(&analyzer, &run_generic).len());

    let consumer = project.file("App/Controller.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let authoritative = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&run_generic),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        authoritative.candidate_files,
        std::iter::once(consumer.clone()).collect()
    );
    assert_eq!(
        1,
        authoritative
            .result
            .into_either()
            .expect("authoritative conditional access query")
            .len()
    );

    let model_to_string =
        member_function_with_signature(&analyzer, "Example.Model", "ToString", "()");
    let model_hits = graph_hits(&analyzer, &model_to_string);
    assert!(
        model_hits.is_empty(),
        "the explicit object cast must not target the enclosing partial model override: {model_hits:#?}"
    );

    let model_consumer = project.file("Model.Json.cs");
    let model_provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(model_consumer.clone()).collect()));
    let authoritative_model = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&model_to_string),
            Some(&model_provider),
            1,
            1000,
        );
    assert_eq!(
        authoritative_model.candidate_files,
        std::iter::once(model_consumer).collect()
    );
    let authoritative_model_hits = authoritative_model
        .result
        .into_either()
        .expect("authoritative object-cast query");
    assert!(
        authoritative_model_hits.is_empty(),
        "the consumer-only authoritative query must retain the explicit object cast instead of routing to the other partial declaration: {authoritative_model_hits:#?}"
    );

    let wrong_extension =
        member_function_with_signature(&analyzer, "Example.Extensions", "ToString", "(Model)");
    assert!(
        graph_hits(&analyzer, &wrong_extension).is_empty(),
        "the explicit object cast must not target an incompatible Model extension"
    );

    let object_extension =
        member_function_with_signature(&analyzer, "Example.Extensions", "Format", "(object)");
    let object_extension_hits = graph_hits(&analyzer, &object_extension);
    assert_eq!(
        1,
        object_extension_hits.len(),
        "the explicit object cast should resolve the matching builtin extension receiver: {object_extension_hits:#?}"
    );
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

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&run)
                    .is_none_or(|hits| hits.is_empty()),
                "a receiver declared in another method must not prove this member hit"
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&run),
                "method-scoped unknown receiver should be reported as unproven"
            );
        }
        other => panic!("expected success with unproven receiver site, got {other:#?}"),
    }
}

#[test]
fn csharp_graph_skips_inner_builtin_shadow_of_typed_receiver() {
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

    let hits = result
        .into_either()
        .expect("builtin object shadow should be a known nonmatching receiver");
    assert!(
        hits.is_empty(),
        "inner object local should disprove, not prove, the Target.Run receiver"
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

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&run)
                    .is_none_or(|hits| hits.is_empty()),
                "locals declared after a member access must not prove receiver type"
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&run),
                "forward local declaration gap should be reported as unproven"
            );
        }
        other => panic!("expected success with unproven forward-local site, got {other:#?}"),
    }
}

#[test]
fn csharp_graph_finds_unqualified_same_class_member_calls() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
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

    let hits = result
        .into_either()
        .unwrap_or_else(|err| panic!("same-class unqualified call should resolve: {err}"));
    assert_eq!(1, hits.len());
    assert!(hits.iter().any(|hit| {
        hit.file == project.file("Domain/Target.cs") && hit.snippet.contains("Run();")
    }));
}

#[test]
fn usage_finder_csharp_finds_same_class_field_initializer_reads_across_physical_owners() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Reference/Options.cs",
            r#"
namespace Runtime;

public static class Options {
    public const int Tick = 1;
    public static readonly int Minute = Tick;
    public const int Counter = Tick;
}
"#,
        )
        .file(
            "Implementation/Options.cs",
            r#"
namespace Runtime;

public static class Options {
    public const int Tick = 1;
    public static readonly int Minute = Tick;
    public const int Counter = Tick;
}
"#,
        )
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let mut targets = analyzer
        .get_all_declarations()
        .iter()
        .filter(|unit| unit.is_field() && unit.fq_name() == "Runtime.Options.Tick")
        .cloned()
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    assert_eq!(2, targets.len(), "expected duplicate physical fields");

    let candidate_files = Arc::new(analyzer.get_analyzed_files().into_iter().collect());
    let provider = ExplicitCandidateProvider::new(Arc::clone(&candidate_files));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            &targets,
            Some(&provider),
            candidate_files.len(),
            100,
        );
    let hits = query
        .result
        .into_either()
        .expect("same-class field initializer query should resolve");
    assert_eq!(
        4,
        hits.len(),
        "each physical owner has two structured field reads: {hits:#?}"
    );
    assert!(
        hits.iter().all(|hit| hit.snippet.contains("= Tick")),
        "declaration names must not be counted as reads: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_finds_precise_local_and_intermediate_field_receivers() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Reference/List.cs",
            r#"
namespace System.Collections.Generic;

public class List<T> {
    public T[] ToArray() => null;
    public void Reverse() {}
}
"#,
        )
        .file(
            "Implementation/List.cs",
            r#"
namespace System.Collections.Generic;

public class List<T> {
    public T[] ToArray() => null;
    public void Reverse() {}
}
"#,
        )
        .file(
            "RuntimeTests/Regression/List.cs",
            r#"
public class List<T> {}
"#,
        )
        .file(
            "RuntimeTests/Loader/List.cs",
            r#"
public class List<T> {}
"#,
        )
        .file(
            "Reference/NodeFactory.cs",
            r#"
namespace Runtime;

public class TargetDetails { public int Architecture { get; } }
public class OtherTargetDetails { public int Architecture { get; } }
public class NodeFactory { public TargetDetails Target { get; } }
public class ConflictingFactory { public TargetDetails Target { get; } }
"#,
        )
        .file(
            "Implementation/NodeFactory.cs",
            r#"
namespace Runtime;

public class TargetDetails { public int Architecture { get; } }
public class OtherTargetDetails { public int Architecture { get; } }
public class NodeFactory { public TargetDetails Target { get; } }
public class ConflictingFactory { public OtherTargetDetails Target { get; } }
"#,
        )
        .file(
            "Consumer.cs",
            r#"
using System.Collections.Generic;
using Runtime;

public class Consumer {
    private NodeFactory factory;

    public void UseList() {
        var parts = new List<string>();
        List<string> argNames = new List<string>();
        string[] values = argNames.ToArray();
        parts.Reverse();
    }

    public int UseTarget(NodeFactory factory) => factory.Target.Architecture;
    public int UseConflicting(ConflictingFactory conflict) => conflict.Target.Architecture;
    public int UseShadowed(TargetDetails factory) => factory.Target.Architecture;

    public int UseUnknownShadow() {
        var factory = MissingFactory();
        return factory.Target.Architecture;
    }
}
"#,
        )
        .build();
    let workspace =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted C# receiver project should build");
    let analyzer = workspace.analyzer();
    let declarations = analyzer.get_all_declarations();
    let targets_for = |fq_name: &str| {
        let mut targets = declarations
            .iter()
            .filter(|unit| unit.fq_name() == fq_name)
            .cloned()
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        assert_eq!(2, targets.len(), "expected duplicate physical {fq_name}");
        targets
    };
    let candidate_files = Arc::new(analyzer.get_analyzed_files().into_iter().collect());
    let provider = ExplicitCandidateProvider::new(Arc::clone(&candidate_files));
    let expected = [
        ("System.Collections.Generic.List`1.ToArray", "ToArray"),
        ("System.Collections.Generic.List`1.Reverse", "Reverse"),
        ("Runtime.NodeFactory.Target", "Target"),
        ("Runtime.TargetDetails.Architecture", "Architecture"),
    ];

    analyzer.reset_global_usage_definition_index_build_count_for_test();
    analyzer.reset_definition_candidates_query_count_for_test();
    for (fq_name, snippet) in expected {
        let targets = targets_for(fq_name);
        let hits = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                analyzer,
                &targets,
                Some(&provider),
                candidate_files.len(),
                100,
            )
            .result
            .into_either()
            .unwrap_or_else(|error| panic!("{fq_name} query should resolve: {error}"));
        assert_eq!(1, hits.len(), "{fq_name}: {hits:#?}");
        assert!(
            hits.iter().all(|hit| hit.snippet.contains(snippet)),
            "{fq_name}: {hits:#?}"
        );
    }
    assert_eq!(
        1,
        analyzer.global_usage_definition_index_build_count_for_test(),
        "all receiver queries should share the generation-scoped definition index"
    );
    assert_eq!(
        0,
        analyzer.definition_candidates_query_count_for_test(),
        "inverse receiver resolution must not fall back to persisted candidate SQL"
    );
}

#[test]
fn usage_finder_csharp_persisted_imported_constructor_beats_global_list_collision() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Collections/List.cs",
            r#"
namespace System.Collections.Generic;

public class List<T> {
    public List() {}
    public List(int capacity) {}
}
"#,
        )
        .file(
            "RuntimeTests/GlobalList.cs",
            r#"
public class List<T> {
    public List() {}
}

public class List {
    public List() {}
}

public class Fallback<T> {
    public Fallback() {}
}
"#,
        )
        .file(
            "Xml/Fallback.cs",
            r#"
namespace System.Xml;

public class Fallback<T> {
    public Fallback() {}
}
"#,
        )
        .file(
            "Xml/Consumer.cs",
            r#"
using System.Collections.Generic;

namespace System.Xml.Serialization {
    public class Consumer {
        public void Run() {
            var importedZero = new List<string>();
            var importedOne = new List<string>(4);
            var wrongArity = new List<string>(4, 8);
            var globalGeneric = new global::List<string>();
            var globalOrdinary = new global::List();
            var enclosingFallback = new Fallback<string>();
            var globalFallback = new global::Fallback<string>();
        }
    }
}
"#,
        )
        .build();
    {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted constructor precedence project should build");
        assert!(
            workspace
                .analyzer()
                .get_all_declarations()
                .iter()
                .any(|unit| unit.fq_name() == "System.Collections.Generic.List`1.List"),
            "persisted workspace should contain the imported generic constructors"
        );
    }

    let reopened =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted constructor precedence project should reopen");
    let analyzer = reopened.analyzer();
    let declarations = analyzer.get_all_declarations();
    let constructor = |owner: &str, name: &str, arity: usize| {
        declarations
            .iter()
            .find(|unit| {
                unit.kind() == CodeUnitType::Function
                    && unit.identifier() == name
                    && unit.signature().is_some_and(|signature| {
                        if arity == 0 {
                            signature == "()"
                        } else {
                            count_signature_parameters(signature) == arity
                        }
                    })
                    && analyzer
                        .parent_of(unit)
                        .is_some_and(|parent| parent.fq_name() == owner)
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!("missing persisted {owner}.{name} constructor with arity {arity}")
            })
    };
    let imported_zero = constructor("System.Collections.Generic.List`1", "List", 0);
    let imported_one = constructor("System.Collections.Generic.List`1", "List", 1);
    let global_generic = constructor("List`1", "List", 0);
    let global_ordinary = constructor("List", "List", 0);
    let enclosing_fallback = constructor("System.Xml.Fallback`1", "Fallback", 0);
    let global_fallback = constructor("Fallback`1", "Fallback", 0);
    let graph_hits = |target: &CodeUnit| {
        let candidates = analyzer.get_analyzed_files().into_iter().collect();
        CSharpUsageGraphStrategy::new()
            .find_usages(analyzer, std::slice::from_ref(target), &candidates, 1000)
            .into_either()
            .expect("persisted constructor usage query should resolve")
    };

    let imported_zero_hits = graph_hits(&imported_zero);
    assert_eq!(1, imported_zero_hits.len(), "{imported_zero_hits:#?}");
    assert!(
        imported_zero_hits
            .iter()
            .all(|hit| hit.snippet.contains("new List<string>()")),
        "the global generic constructor and wrong-arity call must not match: {imported_zero_hits:#?}"
    );
    let routed_imported_zero = UsageFinder::new()
        .find_usages_default(analyzer, std::slice::from_ref(&imported_zero))
        .into_either()
        .expect("default imported constructor query should resolve");
    assert_eq!(
        imported_zero_hits, routed_imported_zero,
        "default routing must retain the namespace-imported constructor site"
    );

    let imported_one_hits = graph_hits(&imported_one);
    assert_eq!(1, imported_one_hits.len(), "{imported_one_hits:#?}");
    assert!(
        imported_one_hits
            .iter()
            .all(|hit| hit.snippet.contains("new List<string>(4)")),
        "only the imported one-argument constructor should match: {imported_one_hits:#?}"
    );

    let global_generic_hits = graph_hits(&global_generic);
    assert_eq!(1, global_generic_hits.len(), "{global_generic_hits:#?}");
    assert!(
        global_generic_hits
            .iter()
            .all(|hit| hit.snippet.contains("new global::List<string>()")),
        "unqualified generic construction must remain on the imported owner: {global_generic_hits:#?}"
    );

    let global_ordinary_hits = graph_hits(&global_ordinary);
    assert_eq!(1, global_ordinary_hits.len(), "{global_ordinary_hits:#?}");
    assert!(
        global_ordinary_hits
            .iter()
            .all(|hit| hit.snippet.contains("new global::List()")),
        "generic and nongeneric global constructors must remain distinct: {global_ordinary_hits:#?}"
    );

    let enclosing_fallback_hits = graph_hits(&enclosing_fallback);
    assert_eq!(
        1,
        enclosing_fallback_hits.len(),
        "{enclosing_fallback_hits:#?}"
    );
    assert!(
        enclosing_fallback_hits.iter().all(|hit| hit
            .snippet
            .lines()
            .any(|line| { line.trim() == "var enclosingFallback = new Fallback<string>();" })),
        "the nearest enclosing namespace must beat the global fallback: {enclosing_fallback_hits:#?}"
    );

    let global_fallback_hits = graph_hits(&global_fallback);
    assert_eq!(1, global_fallback_hits.len(), "{global_fallback_hits:#?}");
    assert!(
        global_fallback_hits
            .iter()
            .all(|hit| hit.snippet.lines().any(|line| {
                line.trim() == "var globalFallback = new global::Fallback<string>();"
            })),
        "explicit global qualification must bypass the enclosing namespace: {global_fallback_hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_finds_event_and_delegate_assignment_method_groups() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Demo/Subscriber.cs",
        r#"
namespace Demo;

public delegate void Handler(int value);

public sealed class Source {
    public event Handler Changed;
}

public sealed class Subscriber {
    private Handler saved;

    private void OnChanged(int value) {}

    public void Wire(Source source) {
        source.Changed += OnChanged;
        saved = OnChanged;
        Handler local = OnChanged;
        Handler wrapped = ((Handler)OnChanged!);
    }

    public void WireShadowed(Source source, Handler OnChanged) {
        source.Changed += OnChanged;
        saved = OnChanged;
    }
}
"#,
    )]);

    let target = member_function_with_arity(&analyzer, "Demo.Subscriber", "OnChanged", 1);
    let consumer = project.file("Demo/Subscriber.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let event_start = source
        .find("source.Changed += OnChanged")
        .expect("event method group")
        + "source.Changed += ".len();
    let forward = definition_lookup(
        project.root(),
        "Demo/Subscriber.cs",
        event_start,
        event_start + "OnChanged".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.Subscriber.OnChanged",
        "{forward}"
    );

    let hits = graph_hits(&analyzer, &target);
    assert_eq!(
        4,
        hits.len(),
        "event, assignment, initializer, and wrapped initializer should resolve; shadowed values should not: {hits:#?}"
    );
    for expected_start in [
        event_start,
        source
            .find("saved = OnChanged")
            .expect("delegate assignment")
            + "saved = ".len(),
        source
            .find("Handler local = OnChanged")
            .expect("delegate initializer")
            + "Handler local = ".len(),
        source
            .find("Handler wrapped = ((Handler)OnChanged!)")
            .expect("wrapped delegate initializer")
            + "Handler wrapped = ((Handler)".len(),
    ] {
        assert!(
            hits.iter().any(|hit| {
                hit.start_offset <= expected_start
                    && expected_start + "OnChanged".len() <= hit.end_offset
            }),
            "missing inverse method-group hit at byte {expected_start}: {hits:#?}"
        );
    }
    for shadowed_start in [
        source
            .rfind("source.Changed += OnChanged")
            .expect("shadowed event method group")
            + "source.Changed += ".len(),
        source
            .rfind("saved = OnChanged")
            .expect("shadowed delegate assignment")
            + "saved = ".len(),
    ] {
        assert!(
            hits.iter().all(|hit| {
                !(hit.start_offset <= shadowed_start
                    && shadowed_start + "OnChanged".len() <= hit.end_offset)
            }),
            "parameter-shadowed method-group value must not count at byte {shadowed_start}: {hits:#?}"
        );
    }
}

#[test]
fn usage_finder_csharp_finds_unique_private_method_group_argument() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Demo/Command.cs",
        r#"
namespace Demo {
    public sealed class Response {}
    public sealed class Reply {}
    public delegate void Handler(Response response, Reply reply);

    public sealed class Command {
        private void onDefault(Response response, Reply reply) {}
        private void Accept(int marker, Handler callback, object state) {}
        private bool TryGet(out Handler handler) { handler = null; return false; }

        public void Run() {
            Accept(1, onDefault, this);
        }

        public void RunWrapped() {
            Accept(1, ((Handler)onDefault), this);
        }

        public void RunShadowed(Handler onDefault) {
            Accept(1, onDefault, this);
        }

        public void RunPattern(object value) {
            if (value is Handler onDefault) { Accept(1, onDefault, this); }
        }

        public void RunForeach(Handler[] handlers) {
            foreach (Handler onDefault in handlers) { Accept(1, onDefault, this); }
        }

        public void RunCatch() {
            try {} catch (System.Exception onDefault) { Accept(1, onDefault, this); }
        }

        public void RunDeconstruction((Handler, Handler) handlers) {
            var (onDefault, other) = handlers;
            Accept(1, onDefault, this);
        }

        public void RunOut() {
            if (TryGet(out Handler onDefault)) { Accept(1, onDefault, this); }
        }

        public void RunLocal() {
            void onDefault(Response response, Reply reply) {}
            Accept(1, onDefault, this);
        }

        public void RunSwitch(int value) {
            switch (value) {
                case 0:
                    void onDefault(Response response, Reply reply) {}
                    Accept(1, onDefault, this);
                    break;
            }
        }
    }
}
"#,
    )]);

    let target = member_function_with_arity(&analyzer, "Demo.Command", "onDefault", 2);
    let consumer = project.file("Demo/Command.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let source = consumer.read_to_string().expect("consumer source");
    let use_start = source
        .find("Accept(1, onDefault, this)")
        .expect("method-group argument")
        + "Accept(1, ".len();
    let forward = definition_lookup(
        project.root(),
        "Demo/Command.cs",
        use_start,
        use_start + "onDefault".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "the reduced method group must remain forward-resolved: {forward}"
    );
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.Command.onDefault",
        "{forward}"
    );
    let wrapped_start = source
        .find("((Handler)onDefault)")
        .expect("wrapped method-group argument")
        + "((Handler)".len();

    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect()
    );
    let hits = query
        .result
        .into_either()
        .expect("unique private method-group query should resolve");
    assert_eq!(
        2,
        hits.len(),
        "structured local bindings must shadow the member method group: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= use_start
                && use_start + "onDefault".len() <= hit.end_offset
        }),
        "inverse lookup should find the structurally unique private method-group argument: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= wrapped_start
                && wrapped_start + "onDefault".len() <= hit.end_offset
        }),
        "inverse lookup should follow transparent method-group wrappers: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_follows_null_forgiving_method_group_arguments() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Runtime/VolatileEnlistmentMultiplexing.cs",
        r#"
namespace Runtime;

public delegate void WaitCallback(object state);

public sealed class VolatileEnlistmentMultiplexing {
    private void PoolableCommit(object state) {}
    private void Accept(WaitCallback callback) {}

    public void Run() {
        Accept(new WaitCallback(PoolableCommit!));
    }

    public void RunParenthesized() {
        Accept((PoolableCommit!));
    }

    public void RunShadowed(WaitCallback PoolableCommit) {
        Accept(new WaitCallback(PoolableCommit!));
    }
}

public sealed class AmbiguousMultiplexing {
    private void PoolableCommit(object state) {}
    private void PoolableCommit(string state) {}
    private void Accept(WaitCallback callback) {}

    public void Run() {
        Accept(PoolableCommit!);
    }
}
"#,
    )]);
    let consumer = project.file("Runtime/VolatileEnlistmentMultiplexing.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let unique = member_function_with_signature(
        &analyzer,
        "Runtime.VolatileEnlistmentMultiplexing",
        "PoolableCommit",
        "(object)",
    );
    let hits = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&unique),
            Some(&provider),
            1,
            100,
        )
        .result
        .into_either()
        .expect("unique null-forgiving method group should resolve");
    assert_eq!(
        2,
        hits.len(),
        "shadowed argument must be excluded: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.snippet.contains("PoolableCommit!"))
    );

    let ambiguous = member_function_with_signature(
        &analyzer,
        "Runtime.AmbiguousMultiplexing",
        "PoolableCommit",
        "(object)",
    );
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&ambiguous),
        &analyzer.get_analyzed_files().into_iter().collect(),
        100,
    );
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&ambiguous)
                    .is_none_or(|hits| hits.is_empty()),
                "ambiguous overload must not be proven"
            );
            assert_eq!(Some(&1), unproven_total_by_overload.get(&ambiguous));
        }
        other => panic!("expected ambiguous method group evidence, got {other:#?}"),
    }
}

#[test]
fn csharp_method_group_overloads_remain_unproven_without_delegate_parameter_resolution() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "Demo/Command.cs",
        r#"
namespace Demo {
    public sealed class Response {}
    public sealed class Reply {}
    public delegate void Handler(Response response, Reply reply);

    public sealed class Command {
        private void onDefault(Response response) {}
        private void onDefault(Response response, Reply reply) {}
        private void Accept(int marker, Handler callback, object state) {}

        public void Run() {
            Accept(1, onDefault, this);
        }
    }
}
"#,
    )]);

    let target = member_function_with_arity(&analyzer, "Demo.Command", "onDefault", 2);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = CSharpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&target)
                    .is_none_or(|hits| hits.is_empty()),
                "delegate parameter typing is required to prove one overload"
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&target),
                "the ambiguous method group should remain visible as unproven"
            );
        }
        other => panic!("expected an unproven overload group, got {other:#?}"),
    }
}

#[test]
fn usage_finder_csharp_finds_unique_inherited_method_group_argument() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Base.cs",
            r#"
namespace Demo {
    public delegate void Handler(int value);

    public class BaseCommand {
        protected void onDefault(int value) {}
    }
}
"#,
        ),
        (
            "Demo/Command.Part1.cs",
            r#"
namespace Demo {
    public sealed partial class Command {
        private void Accept(Handler callback) {}

        public void Run() {
            Accept(onDefault);
        }
    }

    public sealed class HiddenCommand : BaseCommand {
        private Handler onDefault;
        private void Accept(Handler callback) {}

        public void Run() {
            Accept(onDefault);
        }
    }
}
"#,
        ),
        (
            "Demo/Command.Part2.cs",
            "namespace Demo { public sealed partial class Command : BaseCommand {} }\n",
        ),
    ]);

    let target = member_function_with_arity(&analyzer, "Demo.BaseCommand", "onDefault", 1);
    let consumer = project.file("Demo/Command.Part1.cs");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(&analyzer, &[target], Some(&provider), 1, 1000);
    let hits = query
        .result
        .into_either()
        .expect("unique inherited method-group query should resolve");
    assert_eq!(1, hits.len(), "{hits:#?}");
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Accept(onDefault)"))
    );
}

#[test]
fn usage_finder_csharp_finds_inherited_member_access_on_precise_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Base.cs",
            r#"
namespace Demo {
    public class Base {
        protected void Report(int value) {}
    }
}
"#,
        ),
        (
            "Demo/Intermediate.cs",
            "namespace Demo { public class Intermediate : Base {} }\n",
        ),
        (
            "Demo/PartialIntermediate.Part1.cs",
            "namespace Demo { public partial class PartialIntermediate {} }\n",
        ),
        (
            "Demo/PartialIntermediate.Part2.cs",
            "namespace Demo { public partial class PartialIntermediate : Base {} }\n",
        ),
        (
            "Demo/Consumer.cs",
            r#"
namespace Demo {
    public sealed class Consumer : Intermediate {
        public void RunQualified() {
            this.Report(1);
        }

        public void RunUnqualified() {
            Report(2);
        }

        public void RunParameter(System.Action<int> Report) {
            Report(5);
        }

        public void RunLocal() {
            void Report(int value) {}
            Report(6);
        }
    }
}
"#,
        ),
        (
            "Demo/HiddenConsumer.cs",
            r#"
namespace Demo {
    public sealed class HiddenConsumer : Intermediate {
        private void Report(int value) {}

        public void Run() {
            this.Report(3);
        }
    }
}
"#,
        ),
        (
            "Demo/PartialConsumer.cs",
            r#"
namespace Demo {
    public sealed class PartialConsumer : PartialIntermediate {
        public void Run() {
            this.Report(4);
        }
    }
}
"#,
        ),
    ]);

    let target = member_function_with_arity(&analyzer, "Demo.Base", "Report", 1);
    let consumer = project.file("Demo/Consumer.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let use_start = source.find("Report(1)").expect("inherited member call");
    let forward = definition_lookup(
        project.root(),
        "Demo/Consumer.cs",
        use_start,
        use_start + "Report".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.Base.Report",
        "{forward}"
    );

    let hidden_consumer = project.file("Demo/HiddenConsumer.cs");
    let partial_consumer = project.file("Demo/PartialConsumer.cs");
    let provider = ExplicitCandidateProvider::new(Arc::new(
        [consumer.clone(), hidden_consumer, partial_consumer]
            .into_iter()
            .collect(),
    ));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            3,
            1000,
        );
    match &query.result {
        FuzzyResult::Success {
            unproven_total_by_overload,
            ..
        } => assert!(
            unproven_total_by_overload
                .get(&target)
                .is_none_or(|count| *count == 0),
            "proven parameter and local-function shadows must not be emitted as unproven target hits: {:#?}",
            query.result
        ),
        other => panic!("expected inherited member query success, got {other:#?}"),
    }
    let hits = query
        .result
        .into_either()
        .expect("inherited member query should resolve");
    assert_eq!(3, hits.len(), "{hits:#?}");
    assert!(
        hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= use_start
                && use_start + "Report".len() <= hit.end_offset
        }),
        "inverse lookup should find the inherited member on the precise derived receiver: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Report(2)")),
        "inverse lookup should find the inherited unqualified call: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Report(4)")),
        "inverse lookup should follow inheritance declared on a sibling partial type: {hits:#?}"
    );
}

#[test]
fn usage_finder_csharp_resolves_base_receiver_to_logical_direct_class_base() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Demo/Hierarchy.cs",
            r#"namespace Demo;

public interface AFirstContract {}

public class RootMapping {
    protected virtual void BuildBody(int value) {}
    protected virtual void BuildBody(int value, int other) {}
}

public partial class BaseMapping : RootMapping {
    protected override void BuildBody(int value) {}
}
"#,
        ),
        (
            "Demo/BaseMapping.Part.cs",
            r#"namespace Demo;

public partial class BaseMapping {}
"#,
        ),
        (
            "Demo/DerivedMapping.Base.cs",
            r#"namespace Demo;

public sealed partial class DerivedMapping : BaseMapping {}
"#,
        ),
        (
            "Demo/DerivedMapping.Calls.cs",
            r#"namespace Demo;

public sealed partial class DerivedMapping : AFirstContract {
    protected override void BuildBody(int value, int other) {}

    public void Run() {
        base.BuildBody(1, 2);
        this.BuildBody(3, 4);
        BuildBody(5, 6);
    }
}

public sealed class UnrelatedMapping {
    private void BuildBody(int value, int other) {}
    public void Run() => this.BuildBody(7, 8);
}
"#,
        ),
    ]);

    let consumer = project.file("Demo/DerivedMapping.Calls.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let base_call = source.find("base.BuildBody").expect("base call") + "base.".len();
    let this_call = source.find("this.BuildBody").expect("this call") + "this.".len();
    let unqualified_call = source.find("BuildBody(5, 6)").expect("unqualified call");
    let unrelated_call =
        source.find("this.BuildBody(7, 8)").expect("unrelated call") + "this.".len();

    let base_target = member_function_with_arity(&analyzer, "Demo.RootMapping", "BuildBody", 2);
    let derived_target =
        member_function_with_arity(&analyzer, "Demo.DerivedMapping", "BuildBody", 2);
    let unrelated_target =
        member_function_with_arity(&analyzer, "Demo.UnrelatedMapping", "BuildBody", 2);
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    let forward = definition_lookup(
        project.root(),
        "Demo/DerivedMapping.Calls.cs",
        base_call,
        base_call + "BuildBody".len(),
    );
    assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
    assert_eq!(
        forward["results"][0]["definitions"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{forward}"
    );
    assert_eq!(
        forward["results"][0]["definitions"][0]["fqn"], "Demo.RootMapping.BuildBody",
        "{forward}"
    );
    assert_eq!(
        forward["results"][0]["definitions"][0]["signature"], "(int, int)",
        "{forward}"
    );

    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&base_target),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("targeted base-qualified query should resolve");
    let whole_workspace = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&base_target), 1000, 1000)
        .result
        .into_either()
        .expect("whole-workspace base-qualified query should resolve");
    for hits in [&targeted, &whole_workspace] {
        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert!(hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= base_call
                && base_call + "BuildBody".len() <= hit.end_offset
        }));
    }

    let derived_hits = graph_hits(&analyzer, &derived_target);
    assert_eq!(derived_hits.len(), 2, "{derived_hits:#?}");
    for expected in [this_call, unqualified_call] {
        assert!(derived_hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= expected
                && expected + "BuildBody".len() <= hit.end_offset
        }));
    }

    let unrelated_hits = graph_hits(&analyzer, &unrelated_target);
    assert_eq!(unrelated_hits.len(), 1, "{unrelated_hits:#?}");
    assert!(unrelated_hits.iter().any(|hit| {
        hit.file == consumer
            && hit.start_offset <= unrelated_call
            && unrelated_call + "BuildBody".len() <= hit.end_offset
    }));
}

#[test]
fn csharp_graph_finds_unqualified_same_class_async_member_calls_with_arguments() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "MudTabs.cs",
        r#"
namespace MudBlazor {
    public class MudPanel {}

    public class MudTabs {
        private System.Threading.Tasks.Task ActivatePanelClickAsync(MudPanel panel, object args) {
            return System.Threading.Tasks.Task.CompletedTask;
        }

        private async System.Threading.Tasks.Task HandleTabKeyDownAsync(MudPanel panel, object args) {
            await ActivatePanelClickAsync(panel, args);
        }
    }
}
"#,
    )]);

    let activate =
        member_function_with_arity(&analyzer, "MudBlazor.MudTabs", "ActivatePanelClickAsync", 2);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = CSharpUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&activate),
            &candidates,
            1000,
        )
        .into_either()
        .unwrap_or_else(|err| panic!("same-class async call should resolve: {err}"));

    assert_eq!(1, hits.len());
    assert!(hits.iter().any(|hit| {
        hit.file == project.file("MudTabs.cs")
            && hit
                .snippet
                .contains("await ActivatePanelClickAsync(panel, args)")
    }));
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
fn csharp_graph_resolves_static_generic_factory_calls_on_class_receiver() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[(
        "DownloadClients.cs",
        r#"
namespace NzbDrone.Core.Download {
    public interface IProviderConfig {}
    public class DownloadClientBase<TSettings> {}
    public class TorrentSettings : IProviderConfig {}
    public class UsenetSettings : IProviderConfig {}
    public class DownloadClientItem {
        public DownloadClientItemClientInfo DownloadClientInfo { get; set; }
    }

    public class DownloadClientItemClientInfo {
        public static DownloadClientItemClientInfo FromDownloadClient<TSettings>(
            DownloadClientBase<TSettings> downloadClient,
            bool hasPostImportCategory)
            where TSettings : IProviderConfig, new() {
            return new DownloadClientItemClientInfo();
        }
    }

    public class TorrentBlackhole : DownloadClientBase<TorrentSettings> {
        public void GetItems() {
            var queueItem = new DownloadClientItem {
                DownloadClientInfo = DownloadClientItemClientInfo.FromDownloadClient(this, false),
            };
        }
    }

    public class UsenetBlackhole : DownloadClientBase<UsenetSettings> {
        public void GetItems() {
            var queueItem = new DownloadClientItem {
                DownloadClientInfo = DownloadClientItemClientInfo.FromDownloadClient(this, false),
            };
        }
    }
}
"#,
    )]);

    let target = member_function_with_arity(
        &analyzer,
        "NzbDrone.Core.Download.DownloadClientItemClientInfo",
        "FromDownloadClient",
        2,
    );
    assert_eq!(2, graph_hits(&analyzer, &target).len());
}

#[test]
fn csharp_graph_resolves_static_calls_when_namespace_and_class_share_name() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "Parser.cs",
            r#"
namespace NzbDrone.Core.Parser {
    public static class Parser {
        public static void ParseMovieTitle(string title) {}
        public static string ParseReleaseGroup(string title) { return title; }
    }
}
"#,
        ),
        (
            "Consumer.cs",
            r#"
using NzbDrone.Core.Parser;

namespace App {
    public class Consumer {
        public void Run() {
            Parser.ParseMovieTitle("Alien");
            var group = Parser.ParseReleaseGroup("GROUP");
        }
    }
}
"#,
        ),
    ]);

    let parse_movie_title = member_function_with_arity(
        &analyzer,
        "NzbDrone.Core.Parser.Parser",
        "ParseMovieTitle",
        1,
    );
    let parse_release_group = member_function_with_arity(
        &analyzer,
        "NzbDrone.Core.Parser.Parser",
        "ParseReleaseGroup",
        1,
    );

    assert_eq!(1, graph_hits(&analyzer, &parse_movie_title).len());
    assert_eq!(1, graph_hits(&analyzer, &parse_release_group).len());
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

    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            assert!(
                hits_by_overload
                    .get(&configure)
                    .is_none_or(|hits| hits.is_empty()),
                "using static member forms are deferred and should not be proven"
            );
            assert_eq!(
                Some(&1),
                unproven_total_by_overload.get(&configure),
                "deferred using static member form should be reported as unproven"
            );
        }
        other => panic!("expected success with unproven using-static site, got {other:#?}"),
    }
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
fn usage_finder_csharp_finds_nameof_type_roles_with_persisted_parity() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "src/NameofTypes.cs",
            r#"namespace Example;

public sealed class Target {
    public const string Value = "";
}

public sealed class Other {
    public const string Value = "";
}

public sealed class Consumer {
    public enum Nested { Value }

    public string Direct() => nameof(Target);
    public string FullyQualified() => nameof(Example.Target);
    public string GlobalQualified() => nameof(global::Example.Target);
    public string QualifiedOwner() => nameof(Target.Value);
    public string NestedType() => nameof(Nested);
    public string QualifiedNestedType() => nameof(Consumer.Nested);
    public string FullyQualifiedNestedType() => nameof(global::Example.Consumer.Nested);
    public string NestedOwner() => nameof(Nested.Value);
    public string OtherType() => nameof(Other);

    public string ShadowedDirect() {
        object Target = new();
        return nameof(Target);
    }

    public string ShadowedQualified() {
        object Target = new();
        return nameof(Target.ToString);
    }
}
"#,
        )
        .build();
    let consumer = project.file("src/NameofTypes.cs");
    let source = consumer.read_to_string().expect("nameof type source");
    let direct = source.find("nameof(Target);").expect("direct nameof type") + "nameof(".len();
    let qualified = source
        .find("nameof(Target.Value)")
        .expect("qualified nameof owner")
        + "nameof(".len();
    let fully_qualified = source
        .find("nameof(Example.Target)")
        .expect("fully-qualified nameof type")
        + "nameof(Example.".len();
    let global_qualified = source
        .find("nameof(global::Example.Target)")
        .expect("global-qualified nameof type")
        + "nameof(global::Example.".len();
    let nested = source.find("nameof(Nested)").expect("nested nameof type") + "nameof(".len();
    let qualified_nested = source
        .find("nameof(Consumer.Nested)")
        .expect("qualified nested nameof type")
        + "nameof(Consumer.".len();
    let fully_qualified_nested = source
        .find("nameof(global::Example.Consumer.Nested)")
        .expect("fully-qualified nested nameof type")
        + "nameof(global::Example.Consumer.".len();
    let nested_owner = source
        .find("nameof(Nested.Value)")
        .expect("nested nameof owner")
        + "nameof(".len();
    let other = source.find("nameof(Other)").expect("other nameof type") + "nameof(".len();
    let shadowed_direct = source
        .rfind("nameof(Target);")
        .expect("shadowed direct nameof value")
        + "nameof(".len();
    let shadowed_qualified = source
        .find("nameof(Target.ToString)")
        .expect("shadowed qualified nameof value")
        + "nameof(".len();

    let assert_queries = |analyzer: &dyn IAnalyzer| {
        let type_target = |fq_name: &str| {
            analyzer
                .get_all_declarations()
                .iter()
                .find(|unit| unit.kind() == CodeUnitType::Class && unit.fq_name() == fq_name)
                .cloned()
                .unwrap_or_else(|| panic!("missing C# type {fq_name}"))
        };
        let provider =
            ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
        let query = |target: &CodeUnit| {
            let targeted = UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    analyzer,
                    std::slice::from_ref(target),
                    Some(&provider),
                    1,
                    1000,
                )
                .result
                .into_either()
                .expect("targeted nameof type query should resolve");
            let whole_workspace = UsageFinder::new()
                .query(analyzer, std::slice::from_ref(target), 1000, 1000)
                .result
                .into_either()
                .expect("whole-workspace nameof type query should resolve");
            (targeted, whole_workspace)
        };

        let target = type_target("Example.Target");
        let (targeted, whole_workspace) = query(&target);
        for hits in [&targeted, &whole_workspace] {
            assert_eq!(hits.len(), 4, "{hits:#?}");
            for expected in [direct, qualified, fully_qualified, global_qualified] {
                assert!(
                    hits.iter().any(|hit| {
                        hit.start_offset <= expected && expected + "Target".len() <= hit.end_offset
                    }),
                    "missing Target at {expected}: {hits:#?}"
                );
            }
            for shadowed in [shadowed_direct, shadowed_qualified] {
                assert!(
                    hits.iter().all(|hit| {
                        !(hit.start_offset <= shadowed
                            && shadowed + "Target".len() <= hit.end_offset)
                    }),
                    "a local value named Target must not become a type usage: {hits:#?}"
                );
            }
        }

        let nested_target = type_target("Example.Consumer$Nested");
        let (targeted, whole_workspace) = query(&nested_target);
        for hits in [&targeted, &whole_workspace] {
            assert_eq!(hits.len(), 4, "{hits:#?}");
            for expected in [
                nested,
                qualified_nested,
                fully_qualified_nested,
                nested_owner,
            ] {
                assert!(
                    hits.iter().any(|hit| {
                        hit.start_offset <= expected && expected + "Nested".len() <= hit.end_offset
                    }),
                    "missing nested type at {expected}: {hits:#?}"
                );
            }
        }

        let other_target = type_target("Example.Other");
        let (targeted, whole_workspace) = query(&other_target);
        for hits in [&targeted, &whole_workspace] {
            assert_eq!(hits.len(), 1, "{hits:#?}");
            assert!(
                hits.iter().any(|hit| {
                    hit.start_offset <= other && other + "Other".len() <= hit.end_offset
                }),
                "missing Other nameof type: {hits:#?}"
            );
        }
    };

    {
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .expect("persisted nameof project should build");
        assert_queries(workspace.analyzer());
    }
    let reopened =
        WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
            .expect("persisted nameof project should reopen");
    assert_queries(reopened.analyzer());
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
fn csharp_graph_avoids_unrelated_same_name_symbols_and_builtin_nonmatching_receivers() {
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
    let alpha_run_hits = alpha_run_result
        .into_either()
        .expect("builtin object receiver should be a known nonmatch");
    assert!(
        alpha_run_hits.is_empty(),
        "Beta.Target and object receivers should not count as Alpha.Target.Run usages"
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

#[test]
fn csharp_graph_attributes_nameof_receiver_to_nongeneric_owner_with_matching_member() {
    let source = r#"namespace Demo;

[System.Runtime.CompilerServices.CollectionBuilder(
    typeof(ImmutableEquatableArray),
    nameof(ImmutableEquatableArray.Create))]
public sealed class ImmutableEquatableArray<T>
{
    public ImmutableEquatableArray(T value) {}
}

public static class ImmutableEquatableArray
{
    public static ImmutableEquatableArray<T> Create<T>(T value) => new(value);
}
"#;
    let (_project, analyzer) =
        csharp_analyzer_with_files(&[("ImmutableEquatableArray.cs", source)]);
    let nongeneric = type_definition(&analyzer, "Demo.ImmutableEquatableArray");
    let generic = type_definition(&analyzer, "Demo.ImmutableEquatableArray`1");
    let receiver = source
        .find("ImmutableEquatableArray.Create")
        .expect("nameof receiver");
    let receiver_end = receiver + "ImmutableEquatableArray".len();

    let nongeneric_hits = graph_hits(&analyzer, &nongeneric);
    assert!(
        nongeneric_hits
            .iter()
            .any(|hit| hit.start_offset == receiver && hit.end_offset == receiver_end),
        "nameof receiver should resolve to the non-generic owner: {nongeneric_hits:#?}"
    );

    let generic_hits = graph_hits(&analyzer, &generic);
    assert!(
        generic_hits
            .iter()
            .all(|hit| hit.start_offset != receiver || hit.end_offset != receiver_end),
        "nameof receiver must not resolve to the same-named generic owner: {generic_hits:#?}"
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
fn usage_finder_csharp_resolves_implicit_new_initializer_owner_from_declarator() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/ImplicitNew.cs",
        r#"namespace Example;

public sealed class Key {}

public class BaseShortcut {
    public string Key { get; set; } = "";
}

public sealed class Shortcut : BaseShortcut {
    public string Title { get; set; } = "";
}

public sealed class OtherShortcut {
    public string Key { get; set; } = "";
}

public static class Consumer {
    // Keep the newer field-backed-property syntax: tree-sitter recovers the
    // following implicit-new declaration inside an ERROR node, as in Terminal.Gui.
    public static bool Toggle { get => field; set => field = value; }

    public static void Build() {
        Shortcut shortcut = new () { Key = "target", Title = "show" };
        OtherShortcut other = new () { Key = "other" };
    }
}
"#,
    )]);

    let consumer = project.file("src/ImplicitNew.cs");
    let source = consumer.read_to_string().expect("implicit-new source");
    let target_label = source.find("Key = \"target\"").expect("target label");
    let other_label = source.find("Key = \"other\"").expect("other label");
    let target = member_field(&analyzer, "Example.BaseShortcut", "Key");
    let other = member_field(&analyzer, "Example.OtherShortcut", "Key");
    let same_named_type = type_definition(&analyzer, "Example.Key");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for (offset, expected_fqn) in [
        (target_label, "Example.BaseShortcut.Key"),
        (other_label, "Example.OtherShortcut.Key"),
    ] {
        let forward = definition_lookup(
            project.root(),
            "src/ImplicitNew.cs",
            offset,
            offset + "Key".len(),
        );
        assert_eq!(forward["results"][0]["status"], "resolved", "{forward}");
        assert_eq!(
            forward["results"][0]["definitions"][0]["fqn"], expected_fqn,
            "{forward}"
        );
    }

    let targeted = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            1000,
        )
        .result
        .into_either()
        .expect("targeted implicit-new initializer query should resolve");
    let whole_workspace = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&target), 1000, 1000)
        .result
        .into_either()
        .expect("whole-workspace implicit-new initializer query should resolve");
    for hits in [&targeted, &whole_workspace] {
        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert!(hits.iter().any(|hit| {
            hit.file == consumer
                && hit.start_offset <= target_label
                && target_label + "Key".len() <= hit.end_offset
        }));
    }

    let other_hits = graph_hits(&analyzer, &other);
    assert_eq!(other_hits.len(), 1, "{other_hits:#?}");
    assert!(other_hits.iter().any(|hit| {
        hit.file == consumer
            && hit.start_offset <= other_label
            && other_label + "Key".len() <= hit.end_offset
    }));
    assert!(
        graph_hits(&analyzer, &same_named_type).is_empty(),
        "initializer labels must not resolve as same-named types"
    );
}

#[test]
fn usage_finder_csharp_finds_inherited_object_initializer_labels_in_all_scopes() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Descriptors.cs",
            r#"namespace Example;

public record BaseDescriptor {
    public string Kind { get; set; } = "";
}
public record GalleryDescriptor : BaseDescriptor;
public record HidingDescriptor : BaseDescriptor {
    public new string Kind { get; set; } = "";
}
public sealed class UnrelatedDescriptor {
    public string Kind { get; set; } = "";
}

public class ExportFragment {
    public string IntegrityTag { get; set; } = "";
}
public sealed class PassThroughFragment : ExportFragment;
"#,
        ),
        (
            "src/Consumers.cs",
            r#"namespace Example;

public static class Consumers {
    public static void Build() {
        var gallery = new GalleryDescriptor { Kind = "gallery" };
        gallery.Kind = "ordinary assignment";
        _ = new HidingDescriptor { Kind = "hidden" };
        _ = new UnrelatedDescriptor { Kind = "unrelated" };
        _ = new PassThroughFragment { IntegrityTag = "integrity" };
    }
}
"#,
        ),
    ]);

    let consumer = project.file("src/Consumers.cs");
    let source = consumer.read_to_string().expect("consumer source");
    let gallery_label = source.find("Kind = \"gallery\"").expect("gallery label");
    let ordinary_assignment = source
        .find("gallery.Kind")
        .expect("ordinary inherited assignment")
        + "gallery.".len();
    let integrity_label = source
        .find("IntegrityTag = \"integrity\"")
        .expect("integrity label");
    let hidden_label = source.find("Kind = \"hidden\"").expect("hidden label");

    let base_kind = member_field(&analyzer, "Example.BaseDescriptor", "Kind");
    let base_integrity = member_field(&analyzer, "Example.ExportFragment", "IntegrityTag");
    let hidden_kind = member_field(&analyzer, "Example.HidingDescriptor", "Kind");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));

    for (target, expected_offsets) in [
        (base_kind.clone(), vec![gallery_label, ordinary_assignment]),
        (base_integrity, vec![integrity_label]),
    ] {
        let targeted = UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                1000,
            )
            .result
            .into_either()
            .expect("targeted inherited initializer query should resolve");
        let whole_workspace = UsageFinder::new()
            .query(&analyzer, std::slice::from_ref(&target), 1000, 1000)
            .result
            .into_either()
            .expect("whole-workspace inherited initializer query should resolve");

        for hits in [&targeted, &whole_workspace] {
            assert_eq!(hits.len(), expected_offsets.len(), "{target:#?}: {hits:#?}");
            for expected in &expected_offsets {
                assert!(
                    hits.iter().any(|hit| {
                        hit.file == consumer
                            && hit.start_offset <= *expected
                            && *expected + target.identifier().len() <= hit.end_offset
                    }),
                    "{} should include byte {expected}: {hits:#?}",
                    target.fq_name()
                );
            }
        }
    }

    let hidden_hits = graph_hits(&analyzer, &hidden_kind);
    assert_eq!(hidden_hits.len(), 1, "{hidden_hits:#?}");
    assert!(hidden_hits.iter().any(|hit| {
        hit.file == consumer
            && hit.start_offset <= hidden_label
            && hidden_label + "Kind".len() <= hit.end_offset
    }));
}

#[test]
fn csharp_graph_object_initializer_label_matches_logical_partial_type() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/HttpPipeline.cs",
            r#"namespace Example;
public partial class HttpPipeline {
    public object Terminal { get; set; } = new object();
}
"#,
        ),
        (
            "src/ISendAsync.cs",
            r#"namespace Example;
public partial class HttpPipeline {
    private object pipeline = new object();
    public HttpPipeline Clone() => new HttpPipeline { pipeline = this.pipeline };
}
"#,
        ),
    ]);

    let pipeline = member_field(&analyzer, "Example.HttpPipeline", "pipeline");
    let hits = graph_hits(&analyzer, &pipeline);
    let source = project.file("src/ISendAsync.cs").read_to_string().unwrap();
    let initializer_start = source
        .find("pipeline = this.pipeline")
        .expect("initializer assignment");
    let receiver_start = initializer_start + "pipeline = this.".len();

    for expected_start in [initializer_start, receiver_start] {
        assert!(
            hits.iter().any(|hit| {
                hit.file == project.file("src/ISendAsync.cs")
                    && hit.start_offset <= expected_start
                    && expected_start + "pipeline".len() <= hit.end_offset
            }),
            "both initializer-label and ordinary field references should resolve across physical parts of the same logical partial type: {hits:#?}"
        );
    }
}

#[test]
fn csharp_graph_partial_type_name_does_not_beat_pascal_case_value_receiver() {
    let (_project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/A.cs",
            r#"namespace Example;
public partial class HttpPipeline {}
"#,
        ),
        (
            "src/B.cs",
            r#"namespace Example;
public partial class HttpPipeline {
    public void Run() {}
}
"#,
        ),
        (
            "src/Consumer.cs",
            r#"namespace Example;
public sealed class Other {
    public void Run() {}
}
public sealed class Consumer {
    public void Invoke(Other HttpPipeline) { HttpPipeline.Run(); }
}
"#,
        ),
    ]);

    let target = member_function(&analyzer, "Example.HttpPipeline", "Run");
    let hits = graph_hits(&analyzer, &target);

    assert!(
        hits.is_empty(),
        "a value binding must beat a same-spelled visible partial type: {hits:#?}"
    );
}

#[test]
fn csharp_definition_resolves_object_initializer_label_to_property() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[(
        "src/Service.cs",
        r#"namespace Example;

public sealed class Repository {
    public string Last { get; set; } = "";
}

public sealed class Consumer {
    public Repository Build() {
        return new Repository { Last = "x" };
    }
}
"#,
    )]);

    let source = project.file("src/Service.cs").read_to_string().unwrap();
    let start = source.find("Last = \"x\"").expect("initializer label");
    let value = definition_lookup(project.root(), "src/Service.cs", start, start + 4);

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Example.Repository.Last",
        "{value}"
    );
}

#[test]
fn csharp_definition_resolves_unqualified_partial_property_member() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[
        (
            "src/EventRecord.Part1.cs",
            r#"namespace Demo;

public partial class EventRecord {
    public string Name { get; set; } = "";
}
"#,
        ),
        (
            "src/EventRecord.Part2.cs",
            r#"namespace Demo;

public partial class EventRecord {
    public void Rename(string value) {
        Name = value;
    }
}
"#,
        ),
    ]);

    let source = project
        .file("src/EventRecord.Part2.cs")
        .read_to_string()
        .unwrap();
    let start = source.find("Name = value").expect("property write");
    let value = definition_lookup(project.root(), "src/EventRecord.Part2.cs", start, start + 4);

    assert_eq!(value["results"][0]["status"], "resolved", "{value}");
    assert_eq!(
        value["results"][0]["definitions"][0]["fqn"], "Demo.EventRecord.Name",
        "{value}"
    );
}

#[test]
fn csharp_definition_does_not_resolve_named_argument_label_as_member() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[(
        "src/Consumer.cs",
        r#"namespace Demo;

public sealed class Consumer {
    public string Name { get; set; } = "";

    public void Run(string value) {
        Configure(Name: value);
    }

    private void Configure(string Name) {}
}
"#,
    )]);

    let source = project.file("src/Consumer.cs").read_to_string().unwrap();
    let start = source.find("Name: value").expect("named argument label");
    let value = definition_lookup(project.root(), "src/Consumer.cs", start, start + 4);

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
}

#[test]
fn csharp_definition_does_not_resolve_ambiguous_object_initializer_label() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[
        (
            "src/Alpha.cs",
            r#"namespace Alpha;

public sealed class Widget {
    public string Name { get; set; } = "";
}
"#,
        ),
        (
            "src/Beta.cs",
            r#"namespace Beta;

public sealed class Widget {
    public string Name { get; set; } = "";
}
"#,
        ),
        (
            "src/Consumer.cs",
            r#"using Alpha;
using Beta;

namespace Demo;
public sealed class Consumer {
    public object Build() {
        return new Widget { Name = "x" };
    }
}
"#,
        ),
    ]);

    let source = project.file("src/Consumer.cs").read_to_string().unwrap();
    let start = source.find("Name = \"x\"").expect("initializer label");
    let value = definition_lookup(project.root(), "src/Consumer.cs", start, start + 4);

    assert_eq!(value["results"][0]["status"], "no_definition", "{value}");
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

#[test]
fn csharp_graph_should_find_extension_method_on_primitive_long_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        (
            "src/NzbDrone.Common/Extensions/NumberExtensions.cs",
            r#"
namespace NzbDrone.Common.Extensions
{
    public static class NumberExtensions
    {
        public static string SizeSuffix(this long bytes)
        {
            if (bytes < 0) { return "-" + SizeSuffix(-bytes); }
            return bytes.ToString();
        }
    }
}
"#,
        ),
        (
            "src/NzbDrone.Core/Consumer.cs",
            r#"
using NzbDrone.Common.Extensions;

namespace NzbDrone.Core
{
    public class Consumer
    {
        public string Render(long size)
        {
            return size.SizeSuffix();
        }
    }
}
"#,
        ),
        (
            "src/NzbDrone.Common/Extensions/NumberExtensions.razor",
            r#"
<div>Razor markup is not analyzed as C#.</div>
"#,
        ),
    ]);

    let size_suffix = member_function(
        &analyzer,
        "NzbDrone.Common.Extensions.NumberExtensions",
        "SizeSuffix",
    );
    let hits = graph_hits(&analyzer, &size_suffix);

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/NzbDrone.Core/Consumer.cs")
                && hit.snippet.contains("size.SizeSuffix()")
        }),
        "long receiver extension call should resolve to NumberExtensions.SizeSuffix: {hits:#?}"
    );
}

#[test]
fn csharp_graph_should_find_generic_extension_method_on_constructed_receiver() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "src/Precision.cs",
        r#"
namespace Precision;

public sealed class Registered {}

public static class Extensions {
    public static T Echo<T>(this T value) => value;
}

public static class Consumer {
    public static Registered Run() => new Registered().Echo();
}
"#,
    )]);

    let echo = member_function(&analyzer, "Precision.Extensions", "Echo");
    let hits = graph_hits(&analyzer, &echo);

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/Precision.cs")
                && hit.snippet.contains("new Registered().Echo()")
        }),
        "constructed receiver should prove the generic extension call: {hits:#?}"
    );
}

#[test]
fn csharp_scan_usages_target_anchor_should_find_primitive_extension_receiver_usage() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[
        (
            "src/NzbDrone.Common/Extensions/NumberExtensions.cs",
            r#"
namespace NzbDrone.Common.Extensions
{
    public static class NumberExtensions
    {
        public static string SizeSuffix(this long bytes)
        {
            if (bytes < 0) { return "-" + SizeSuffix(-bytes); }
            return bytes.ToString();
        }
    }
}
"#,
        ),
        (
            "src/NzbDrone.Core/Consumer.cs",
            r#"
using NzbDrone.Common.Extensions;

namespace NzbDrone.Core
{
    public class Consumer
    {
        public string Render(long size)
        {
            return size.SizeSuffix();
        }
    }
}
"#,
        ),
    ]);

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_location",
        &json!({
            "targets": [{
                "path": "src/NzbDrone.Common/Extensions/NumberExtensions.cs",
                "line": 6
            }]
        })
        .to_string(),
    );

    assert!(
        result["results"]
            .as_array()
            .is_some_and(|entries| entries.iter().all(|entry| entry["status"] != "failure")),
        "{result}"
    );
    assert!(
        result["summary"]["total_hits"].as_u64().unwrap_or_default() > 0,
        "definition-site target selector should recover primitive extension usage: {result}"
    );
}

#[test]
fn csharp_scan_usages_dynamic_extension_receiver_returns_unproven_without_failure() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[
        (
            "src/NzbDrone.Common/Extensions/NumberExtensions.cs",
            r#"
namespace NzbDrone.Common.Extensions
{
    public static class NumberExtensions
    {
        public static string SizeSuffix(this long bytes)
        {
            return bytes.ToString();
        }
    }
}
"#,
        ),
        (
            "src/NzbDrone.Core/Consumer.cs",
            r#"
using NzbDrone.Common.Extensions;

namespace NzbDrone.Core
{
    public class Consumer
    {
        public string Render(dynamic size)
        {
            return size.SizeSuffix();
        }
    }
}
"#,
        ),
        (
            "src/NzbDrone.Common/Extensions/NumberExtensions.razor",
            r#"
<div>Razor markup is not analyzed as C#.</div>
"#,
        ),
    ]);

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_location",
        &json!({
            "targets": [{
                "path": "src/NzbDrone.Common/Extensions/NumberExtensions.cs",
                "line": 6
            }]
        })
        .to_string(),
    );

    let entry = &result["results"][0];
    assert_eq!("unverified_absent", entry["status"], "{result}");
    assert_eq!(0, entry["total_hits"], "{result}");
    assert_eq!(1, entry["unproven_hits"], "{result}");
    assert!(
        entry["absence_caveats"]
            .as_array()
            .is_some_and(|caveats| caveats.iter().any(|c| c == "unproven_matches")),
        "unproven sites must prevent verified_absent: {result}"
    );
    assert!(
        entry["absence_caveats"]
            .as_array()
            .is_some_and(|caveats| caveats.iter().any(|c| c == "reference_only_siblings")),
        "reference-only sibling files must remain a caveat alongside unproven matches: {result}"
    );
    assert!(
        entry["unproven_files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("size.SizeSuffix()")),
        "dynamic extension call should render in unproven_files: {result}"
    );
}

#[test]
fn csharp_scan_usages_complete_zero_reports_verified_absent() {
    let (project, _analyzer) = csharp_analyzer_with_files(&[(
        "Service.cs",
        r#"
namespace App
{
    public class Service
    {
        public void Run() {}
    }
}
"#,
    )]);

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["App.Service.Run"],
            "include_tests": true
        })
        .to_string(),
    );

    let entry = &result["results"][0];
    assert_eq!("verified_absent", entry["status"], "{result}");
    assert_eq!(0, entry["total_hits"], "{result}");
    assert_eq!(0, entry["unproven_hits"], "{result}");
    assert!(entry["complete"].is_null(), "{result}");
    assert_eq!(1, result["summary"]["resolved"], "{result}");
}

#[test]
fn csharp_scan_usages_zero_with_razor_sibling_does_not_report_verified_absent() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            r#"
namespace App
{
    public class Service
    {
        public void Run() {}
    }
}
"#,
        )
        .file(
            "Service.razor",
            r#"
<div>Razor markup is not analyzed as C#.</div>
"#,
        )
        .build();

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["App.Service.Run"],
            "include_tests": true
        })
        .to_string(),
    );

    let entry = &result["results"][0];
    assert_eq!("unverified_absent", entry["status"], "{result}");
    assert_eq!(0, entry["total_hits"], "{result}");
    assert_eq!(0, entry["unproven_hits"], "{result}");
    assert!(
        entry["absence_caveats"]
            .as_array()
            .is_some_and(|caveats| caveats.iter().any(|c| c == "reference_only_siblings")),
        "Razor sibling files must prevent verified_absent: {result}"
    );
    let notes = entry["notes"].as_array().cloned().unwrap_or_default();
    assert!(
        notes.iter().any(|note| note
            .as_str()
            .is_some_and(|note| note.contains(".razor files"))),
        "{result}"
    );
}

#[test]
fn csharp_scan_usages_truncated_scan_does_not_report_verified_absent() {
    let mut builder = InlineTestProject::with_language(Language::CSharp).file(
        "Service.cs",
        r#"
namespace App
{
    public class Service
    {
        public void Target() {}
    }
}
"#,
    );
    for idx in 0..1005 {
        builder = builder.file(
            format!("Decoy{idx:04}.cs"),
            format!(
                "namespace Noise {{ public class Decoy{idx:04} {{ public void Call(dynamic value) {{ value.Target(); }} }} }}\n"
            ),
        );
    }
    let project = builder.build();

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["App.Service.Target"],
            "include_tests": true
        })
        .to_string(),
    );

    assert!(
        result["summary"]["partial"].as_bool() == Some(true),
        "{result}"
    );
    let entry = &result["results"][0];
    assert_eq!("unverified_absent", entry["status"], "{result}");
    assert!(entry["complete"].as_bool() == Some(false), "{result}");
    assert!(
        entry["absence_caveats"].as_array().is_some_and(|caveats| {
            caveats.iter().any(|c| c == "unproven_matches")
                && caveats.iter().any(|c| c == "candidate_files_truncated")
        }),
        "truncated zero-hit scan should carry truncation evidence: {result}"
    );
}
