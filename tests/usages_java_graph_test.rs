mod common;

use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, JavaUsageGraphStrategy, ScalaUsageGraphStrategy,
    UsageAnalyzer, UsageFinder, UsageHit, UsageHitKind,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ScalaAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json, line_of};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

fn definition(analyzer: &JavaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn java_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, JavaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Java);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn mixed_jvm_analyzer_with_files(
    files: &[(&str, &str)],
) -> (
    common::BuiltInlineTestProject,
    JavaAnalyzer,
    ScalaAnalyzer,
    MultiAnalyzer,
) {
    let mut builder = InlineTestProject::new();
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let java = JavaAnalyzer::from_project(project.project().clone());
    let scala = ScalaAnalyzer::from_project(project.project().clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (Language::Java, AnalyzerDelegate::Java(java.clone())),
        (Language::Scala, AnalyzerDelegate::Scala(scala.clone())),
    ]));
    (project, java, scala, multi)
}

fn scala_definition(analyzer: &ScalaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Scala definition for {fq_name}"))
}

fn hits(result: FuzzyResult) -> Vec<UsageHit> {
    result
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .collect()
}

/// Same-owner (self/this receiver, implicit-this) hits — excluded from the
/// external usage surface but visible to the editor find-references surface
/// (#1014 facet B).
fn self_receiver_hits(result: &FuzzyResult) -> Vec<UsageHit> {
    result
        .all_hits_including_imports()
        .into_iter()
        .filter(|hit| hit.kind == UsageHitKind::SelfReceiver)
        .collect()
}

fn assert_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().any(|hit| hit.snippet.contains(needle)),
        "expected hit containing {needle:?}, got {hits:#?}"
    );
}

fn assert_no_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().all(|hit| !hit.snippet.contains(needle)),
        "expected no hit containing {needle:?}, got {hits:#?}"
    );
}

fn assert_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().any(|hit| hit.line == line),
        "expected hit on line {line}, got {hits:#?}"
    );
}

fn assert_no_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().all(|hit| hit.line != line),
        "expected no hit on line {line}, got {hits:#?}"
    );
}

fn assert_success_counts(
    result: FuzzyResult,
    target: &CodeUnit,
    proven_count: usize,
    unproven_count: usize,
) {
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = result
    else {
        panic!("expected success, got {result:?}");
    };
    assert_eq!(
        proven_count,
        hits_by_overload
            .get(target)
            .map(|hits| hits.len())
            .unwrap_or_default(),
        "proven hits: {hits_by_overload:#?}"
    );
    assert_eq!(
        unproven_count,
        unproven_total_by_overload
            .get(target)
            .copied()
            .unwrap_or_default(),
        "unproven hits: {unproven_total_by_overload:#?}"
    );
}

#[test]
fn usage_finder_routes_java_targets_through_graph_strategy() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Target target) {
        target.run();
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "com.example.Target.run");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("java graph success");
    assert_eq!(1, hits.len());
}

#[test]
fn java_import_hits_are_editor_visible_but_external_usage_free() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Target.java",
            "package app;\n\npublic class Target {}\n",
        ),
        (
            "app/UseTarget.java",
            "package app;\n\nimport app.Target;\n\npublic class UseTarget { Target value; }\n",
        ),
    ]);

    let target = definition(&analyzer, "app.Target");
    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    let external_hits = result.all_hits();
    let editor_hits = result.all_hits_including_imports();

    assert!(
        external_hits
            .iter()
            .all(|hit| !hit.snippet.contains("import app.Target")),
        "external usage surface must exclude import hits: {external_hits:#?}"
    );
    assert!(
        editor_hits
            .iter()
            .any(|hit| hit.snippet.contains("import app.Target")),
        "editor surface should include import hit: {editor_hits:#?}"
    );
}

#[test]
fn java_graph_counts_static_qualifier_references_for_class_targets() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public static final int VALUE = 7;
    public static Target build() { return new Target(); }
}
"#,
        ),
        (
            "com/example/Other.java",
            r#"
package com.example;

public class Other {
    public void touch() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void run() {
        Target.build();
        int value = Target.VALUE;
        Other Target = new Other();
        Target.touch();
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "com.example.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_hit_contains(&hits, "Target.build()");
    assert_hit_contains(&hits, "Target.VALUE");
    assert_no_hit_contains(&hits, "Target.touch()");
}

#[test]
fn java_graph_strategy_finds_method_constructor_field_and_type_usages() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public Target() {}
    public String field;
    public void run() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    private Target target;

    Target make() {
        target = new Target();
        target.field = "x";
        return target;
    }

    void call(Target other) {
        other.run();
        String copy = other.field;
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = JavaUsageGraphStrategy::new();

    let method_target = definition(&analyzer, "com.example.Target.run");
    let constructor_target = definition(&analyzer, "com.example.Target.Target");
    let field_target = definition(&analyzer, "com.example.Target.field");
    let class_target = definition(&analyzer, "com.example.Target");

    let method_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("method success");
    assert!(
        method_hits
            .iter()
            .any(|hit| hit.file == project.file("com/example/Consumer.java"))
    );

    let constructor_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&constructor_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("constructor success");
    assert_eq!(1, constructor_hits.len());

    let field_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&field_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("field success");
    assert_eq!(2, field_hits.len());

    let class_hits = strategy
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("type success");
    assert!(
        class_hits
            .iter()
            .any(|hit| hit.file == project.file("com/example/Consumer.java"))
    );
}

#[test]
fn java_type_usage_scan_filters_unrelated_ast_names_before_definition_lookup() {
    let mut consumer = String::from(
        "package consumer; import target.Wanted; public class Consumer { Wanted wanted;\n",
    );
    for index in 0..128 {
        consumer.push_str(&format!("Noise{index} noise{index};\n"));
    }
    consumer.push('}');
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "target/Wanted.java",
            "package target; public class Wanted {}",
        )
        .file("consumer/Consumer.java", consumer)
        .build();
    let analyzer = JavaAnalyzer::new(project.project_dyn()).update_all();
    let target = definition(&analyzer, "target.Wanted");
    let candidates = [project.file("consumer/Consumer.java")]
        .into_iter()
        .collect();

    analyzer.reset_definition_query_count_for_test();
    let type_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_eq!(1, type_hits.len());
    assert_eq!(
        0,
        analyzer.definition_query_count_for_test(),
        "usage scanning must resolve type names from the in-memory definition index"
    );
}

#[test]
fn java_graph_strategy_resolves_inline_constructor_receiver_method_call() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public void run() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call() {
        new Target().run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(&analyzer, &[method_target], &candidates, 1000)
        .into_either()
        .expect("inline constructor receiver success");

    assert_eq!(1, hits.len());
    assert!(hits.iter().any(|hit| hit.snippet.contains("run()")));
}

#[test]
fn java_graph_strategy_handles_nested_type_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Outer.java",
            r#"
package com.example;

public class Outer {
    public static class Inner {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Outer.Inner build() {
        return new Outer.Inner();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let class_target = definition(&analyzer, "com.example.Outer.Inner");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("nested type success");
    assert!(!hits.is_empty());
}

#[test]
fn java_graph_strategy_records_expression_selector_type_segments_exactly() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Selectors.java",
            r#"
package app;

public class Selectors {
    public static class Feature {
        public static final int TERMINAL = 1;
        public static void call() {}
    }

    public static class Media {
        public static class Player {
            public static final int JAVA = 1;
        }
    }

    public static class Conf {
        public static String getProperty() { return ""; }
    }
}
"#,
        ),
        (
            "app/Media.java",
            r#"
package app;

public class Media {
    public void setHeight(int height) {}
}
"#,
        ),
        (
            "app/HeightSetter.java",
            r#"
package app;

interface HeightSetter {
    void accept(Media media, int height);
}
"#,
        ),
        (
            "app/Base.java",
            r#"
package app;

public class Base {
    protected Class<?> instanceType;
}
"#,
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer extends Base {
    void run() {
        int terminal = Selectors.Feature.TERMINAL; // field-access-selector
        Selectors.Feature.call(); // invocation-selector
        Runnable nestedReference = Selectors.Feature::call; // nested-method-reference-selector
        HeightSetter directReference = Media::setHeight; // direct-method-reference-selector
        int deep = Selectors.Media.Player.JAVA; // deep-field-access-selector
        String property = Selectors.Conf.getProperty(); // invocation-object-selector
        Object value = instanceType.newInstance(); // inherited-field-receiver-selector
    }
}
"#,
        ),
    ]);
    let candidates = [project.file("app/Consumer.java")].into_iter().collect();
    let scan = |fq_name: &str| {
        let target = definition(&analyzer, fq_name);
        hits(JavaUsageGraphStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        ))
    };

    let feature_hits = scan("app.Selectors.Feature");
    assert_eq!(3, feature_hits.len(), "{feature_hits:#?}");
    assert_hit_contains(&feature_hits, "field-access-selector");
    assert_hit_contains(&feature_hits, "invocation-selector");
    assert_hit_contains(&feature_hits, "nested-method-reference-selector");
    assert!(
        feature_hits
            .iter()
            .all(|hit| hit.start_offset + "Feature".len() == hit.end_offset),
        "nested-type hits must retain the exact focused token: {feature_hits:#?}"
    );

    let direct_reference_hits = scan("app.Media");
    assert_eq!(1, direct_reference_hits.len(), "{direct_reference_hits:#?}");
    assert_hit_contains(&direct_reference_hits, "direct-method-reference-selector");

    let media_hits = scan("app.Selectors.Media");
    assert_eq!(1, media_hits.len(), "{media_hits:#?}");
    assert_hit_contains(&media_hits, "deep-field-access-selector");

    let player_hits = scan("app.Selectors.Media.Player");
    assert_eq!(1, player_hits.len(), "{player_hits:#?}");
    assert_hit_contains(&player_hits, "deep-field-access-selector");

    let conf_hits = scan("app.Selectors.Conf");
    assert_eq!(1, conf_hits.len(), "{conf_hits:#?}");
    assert_hit_contains(&conf_hits, "invocation-object-selector");

    let inherited_field_hits = scan("app.Base.instanceType");
    assert_eq!(1, inherited_field_hits.len(), "{inherited_field_hits:#?}");
    assert_hit_contains(&inherited_field_hits, "inherited-field-receiver-selector");
}

#[test]
fn java_graph_strategy_filters_same_file_self_calls() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Target.java",
        r#"
package com.example;

public class Target {
    public void run() {
        run();
    }
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("self call success");
    assert!(
        hits.is_empty(),
        "self calls should be filtered from final hits"
    );
}

#[test]
fn java_graph_strategy_handles_extends_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Base.java",
            "package com.example; public class Base { public void run() {} }\n",
        ),
        (
            "com/example/Derived.java",
            r#"
package com.example;

public class Derived extends Base {
    void call(Base base) {
        base.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let class_target = definition(&analyzer, "com.example.Base");
    let method_target = definition(&analyzer, "com.example.Base.run");

    let class_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("extends success");
    assert!(!class_hits.is_empty());

    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("typed receiver success");
    assert_eq!(1, method_hits.len());
}

#[test]
fn java_graph_strategy_handles_interface_references_and_receivers() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            "package com.example; public interface Service { void run(); }\n",
        ),
        (
            "com/example/ServiceImpl.java",
            r#"
package com.example;

public class ServiceImpl implements Service {
    @Override
    public void run() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Service service) {
        service.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let interface_target = definition(&analyzer, "com.example.Service");
    let method_target = definition(&analyzer, "com.example.Service.run");

    let interface_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&interface_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("interface type success");
    assert!(
        interface_hits.len() >= 2,
        "expected implements and parameter type references"
    );

    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("interface receiver success");
    assert_eq!(2, method_hits.len());
}

#[test]
fn java_graph_strategy_separates_interface_calls_from_concrete_overrides() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            "package com.example; public interface Service { void run(); }\n",
        ),
        (
            "com/example/ServiceImpl.java",
            r#"
package com.example;

public class ServiceImpl implements Service {
    @Override
    public void run() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Service service, ServiceImpl impl) {
        service.run();
        impl.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Service.run");
    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("interface method family success");
    let snippets = method_hits
        .iter()
        .map(|hit| hit.snippet.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        2,
        method_hits.len(),
        "expected override plus interface call"
    );
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("void run()")),
        "override declaration should be a reference: {snippets:#?}"
    );
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("service.run()")),
        "interface-typed receiver call should be a reference: {snippets:#?}"
    );
    assert_eq!(
        1,
        method_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .count(),
        "only the interface-typed call belongs to the interface method: {method_hits:#?}"
    );
}

#[test]
fn java_graph_method_declaration_hits_validate_the_visited_overload_signature() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/AbstractAverageSpeedParser.java",
            r#"
package com.example;

public abstract class AbstractAverageSpeedParser {
    public abstract void handleWayTags(int edgeId, ReaderWay way, IntsRef relationFlags);



    public void handleWayTags(int edgeId, ReaderWay way, IntsRef relationFlags, String unrelated) {}
}
"#,
        ),
        (
            "com/example/BikeCommonAverageSpeedParser.java",
            r#"
package com.example;

public class BikeCommonAverageSpeedParser extends AbstractAverageSpeedParser {
    @Override
    public void handleWayTags(int edgeId, ReaderWay way, IntsRef relationFlags) {}
}
"#,
        ),
        (
            "com/example/ReaderWay.java",
            "package com.example; public class ReaderWay {}\n",
        ),
        (
            "com/example/IntsRef.java",
            "package com.example; public class IntsRef {}\n",
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(
        &analyzer,
        "com.example.BikeCommonAverageSpeedParser.handleWayTags",
    );
    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("subclass method family success");
    let snippets = method_hits
        .iter()
        .map(|hit| hit.snippet.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        1,
        method_hits.len(),
        "expected only the matching abstract declaration, got {method_hits:#?}"
    );
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("abstract void handleWayTags")),
        "matching abstract declaration should be a usage: {snippets:#?}"
    );
    assert!(
        snippets
            .iter()
            .all(|snippet| !snippet.contains("String unrelated")),
        "unrelated overload must not be swept in: {snippets:#?}"
    );
    assert_eq!(
        Some(UsageHitKind::OverrideDeclaration),
        method_hits.iter().map(|hit| hit.kind).next()
    );
}

#[test]
fn java_graph_strategy_resolves_singleton_return_receiver_calls() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "org/example/ProcessOperationLockRegistry.java",
            r#"
package org.example;

public final class ProcessOperationLockRegistry {
    private static final ProcessOperationLockRegistry INSTANCE =
            new ProcessOperationLockRegistry();

    public static ProcessOperationLockRegistry getInstance() {
        return INSTANCE;
    }

    public void notify(String processId) {}

    public void waitUntilReleaseReady(String processId, long timeoutMillis) {}
}
"#,
        ),
        (
            "org/example/Consumer.java",
            r#"
package org.example;

public class Consumer {
    void lock(String processId) {
        ProcessOperationLockRegistry.getInstance().notify(processId);
        ProcessOperationLockRegistry.getInstance().waitUntilReleaseReady(processId, 10L);
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let notify = definition(&analyzer, "org.example.ProcessOperationLockRegistry.notify");
    let wait_until_release_ready = definition(
        &analyzer,
        "org.example.ProcessOperationLockRegistry.waitUntilReleaseReady",
    );

    analyzer.reset_full_declaration_scan_count_for_test();
    let notify_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&notify),
        &candidates,
        1000,
    ));
    assert_hit_contains(&notify_hits, "getInstance().notify(processId)");

    let wait_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&wait_until_release_ready),
        &candidates,
        1000,
    ));
    assert_hit_contains(
        &wait_hits,
        "getInstance().waitUntilReleaseReady(processId, 10L)",
    );
    assert_eq!(
        0,
        analyzer.full_declaration_scan_count_for_test(),
        "targeted Java return-receiver inference must not build the workspace-wide usage-facts index"
    );

    let scan = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": [
                "org.example.ProcessOperationLockRegistry.notify",
                "org.example.ProcessOperationLockRegistry.waitUntilReleaseReady"
            ],
            "include_tests": true
        })
        .to_string(),
    );
    for symbol in [
        "org.example.ProcessOperationLockRegistry.notify",
        "org.example.ProcessOperationLockRegistry.waitUntilReleaseReady",
    ] {
        let entry = scan["results"]
            .as_array()
            .and_then(|results| results.iter().find(|entry| entry["input"] == symbol))
            .unwrap_or_else(|| panic!("missing scan_usages result for {symbol}: {scan}"));
        assert_eq!("found", entry["status"], "{scan}");
        assert_eq!(1, entry["total_hits"], "{scan}");
        assert_eq!(0, entry["unproven_hits"], "{scan}");
    }
}

#[test]
fn authoritative_java_return_receiver_resolves_nested_type_from_declaring_scope() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "p/Outer.java",
            r#"
package p;

public class Outer {
    public static class Inner {
        public void run() {}
    }

    public static Inner make() {
        return new Inner();
    }

    public static class Layer {
        public static class Deep {
            public static Inner make() {
                return new Inner();
            }
        }
    }
}
"#,
        ),
        (
            "p/Inner.java",
            "package p; public class Inner { public void run() {} }\n",
        ),
        (
            "p/Consumer.java",
            r#"
package p;

import p.Outer.Layer.Deep;

public class Consumer {
    void call() {
        Outer.make().run();
        Deep.make().run();
    }
}
"#,
        ),
    ]);
    let consumer = project.file("p/Consumer.java");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let nested_run = definition(&analyzer, "p.Outer.Inner.run");

    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&nested_run),
            Some(&provider),
            1,
            100,
        );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!(
            "expected authoritative Java usage success, got {:#?}",
            query.result
        );
    };
    let nested_hits = hits_by_overload
        .get(&nested_run)
        .expect("nested run should have a proven-hit bucket");
    assert_eq!(
        2,
        nested_hits.len(),
        "nested receiver hits: {nested_hits:#?}"
    );
    assert!(nested_hits.iter().all(|hit| hit.file == consumer));
    assert_eq!(
        0,
        unproven_total_by_overload
            .get(&nested_run)
            .copied()
            .unwrap_or_default(),
        "lexically resolved nested return receivers must be precise"
    );

    let package_run = definition(&analyzer, "p.Inner.run");
    let package_query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&package_run),
            Some(&provider),
            1,
            100,
        );
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = package_query.result
    else {
        panic!(
            "expected package-level Java usage success, got {:#?}",
            package_query.result
        );
    };
    assert!(
        hits_by_overload
            .get(&package_run)
            .is_none_or(|hits| hits.is_empty()),
        "the same-package type must not capture the lexically nested return type"
    );
}

#[test]
fn java_graph_strategy_budgets_deep_return_receiver_chains() {
    let deep_receiver = (0..80).fold(
        "ProcessOperationLockRegistry.getInstance()".to_string(),
        |receiver, _| format!("{receiver}.next()"),
    );
    let consumer = format!(
        r#"
package org.example;

public class Consumer {{
    void lock(String processId) {{
        {deep_receiver}.notify(processId);
    }}
}}
"#
    );
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "org/example/ProcessOperationLockRegistry.java",
            r#"
package org.example;

public final class ProcessOperationLockRegistry {
    private static final ProcessOperationLockRegistry INSTANCE =
            new ProcessOperationLockRegistry();

    public static ProcessOperationLockRegistry getInstance() {
        return INSTANCE;
    }

    public ProcessOperationLockRegistry next() {
        return this;
    }

    public void notify(String processId) {}
}
"#,
        ),
        ("org/example/Consumer.java", &consumer),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let notify = definition(&analyzer, "org.example.ProcessOperationLockRegistry.notify");
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&notify),
        &candidates,
        1000,
    );

    assert_success_counts(result, &notify, 0, 1);
}

#[test]
fn java_graph_strategy_keeps_concrete_override_receiver_proof_narrow() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            "package com.example; public interface Service { void run(String arg); }\n",
        ),
        (
            "com/example/ServiceImpl.java",
            r#"
package com.example;

public class ServiceImpl implements Service {
    @Override
    public void run(String arg) {}
}
"#,
        ),
        (
            "com/example/Base.java",
            r#"
package com.example;

public abstract class Base implements Service {
    public abstract void run(Object arg);
}
"#,
        ),
        (
            "com/example/Mid.java",
            "package com.example; public abstract class Mid implements Service { public abstract void run(Object arg); }\n",
        ),
        (
            "com/example/Leaf.java",
            "package com.example; public abstract class Leaf extends Mid {}\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Service service, ServiceImpl impl, Base base, Leaf leaf) {
        service.run("x");
        impl.run("x");
        base.run(new Object());
        base.run("x");
        leaf.run(new Object());
        leaf.run("x");
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let interface_target = analyzer
        .get_definitions("com.example.Service.run")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("missing interface method");
    let concrete_target = analyzer
        .get_definitions("com.example.ServiceImpl.run")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("missing concrete method");

    let interface_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&interface_target),
        &candidates,
        1000,
    );
    assert_success_counts(interface_result.clone(), &interface_target, 2, 4);
    let interface_hits = hits(interface_result);
    assert_hit_contains(&interface_hits, "void run(String arg)");
    assert_hit_contains(&interface_hits, "service.run(\"x\")");
    assert_eq!(
        1,
        interface_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .count(),
        "only the interface-typed call belongs to the interface method: {interface_hits:#?}"
    );
    assert_no_hit_contains(&interface_hits, "void run(Object arg)");
    assert!(
        interface_hits.iter().all(|hit| hit.line != 8),
        "base.run(Object) should not be an interface run(String) usage: {interface_hits:#?}"
    );
    assert!(
        interface_hits.iter().all(|hit| hit.line != 9),
        "the inherited overload call should stay unproven until argument types are resolved: {interface_hits:#?}"
    );

    let concrete_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&concrete_target),
        &candidates,
        1000,
    );
    assert_success_counts(concrete_result.clone(), &concrete_target, 2, 0);
    let concrete_hits = hits(concrete_result);
    assert_hit_contains(&concrete_hits, "impl.run(\"x\")");
    assert!(
        concrete_hits.iter().all(|hit| hit.line != 6),
        "interface-typed receiver should not prove a concrete implementation usage: {concrete_hits:#?}"
    );
    assert!(
        concrete_hits.iter().all(|hit| hit.line != 8),
        "base.run(Object) should not be a concrete run(String) usage: {concrete_hits:#?}"
    );
}

#[test]
fn java_graph_strategy_respects_candidate_files() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Target target) {
        target.run();
    }
}
"#,
        ),
        (
            "com/example/Other.java",
            "package com.example; public class Other {}\n",
        ),
    ]);

    let candidates = [project.file("com/example/Other.java")]
        .into_iter()
        .collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("candidate restriction success");
    assert!(hits.is_empty());
}

#[test]
fn java_graph_strategy_does_not_match_shadowed_receiver_name() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public static void run() {} }\n",
        ),
        (
            "com/example/Other.java",
            "package com.example; public class Other { public static void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call() {
        Other Target = new Other();
        Target.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method_target),
        &candidates,
        1000,
    );
    assert_success_counts(result, &method_target, 0, 0);
}

#[test]
fn java_graph_strategy_counts_enum_type_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Mode.java",
            "package com.example; public enum Mode { ON, OFF }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    private Mode mode = Mode.ON;

    Mode current() {
        return mode;
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let enum_target = definition(&analyzer, "com.example.Mode");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&enum_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("enum type success");
    assert!(
        hits.len() >= 2,
        "expected enum declaration-site type references in field and return"
    );
}

#[test]
fn java_graph_strategy_counts_record_type_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Payload.java",
            "package com.example; public record Payload(int value) {}\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Payload build() {
        return new Payload(1);
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let record_target = definition(&analyzer, "com.example.Payload");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&record_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("record type success");
    assert!(
        !hits.is_empty(),
        "expected record return or constructor type reference"
    );
}

#[test]
fn java_graph_strategy_counts_generic_type_arguments_as_type_usages() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import java.util.List;

public class Consumer {
    private List<Target> targets;

    List<Target> get() {
        return targets;
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let class_target = definition(&analyzer, "com.example.Target");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("generic type argument success");
    assert!(
        hits.len() >= 2,
        "expected field and return generic type references"
    );
}

#[test]
fn java_graph_strategy_counts_lambda_body_method_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Runnable build(Target target) {
        return () -> target.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("lambda body success");
    assert_eq!(1, hits.len());
}

#[test]
fn scan_usages_proves_unqualified_private_method_calls_inside_lambdas() {
    let (project, analyzer) = java_analyzer_with_files(&[(
        "com/example/ClusterProcessPersistService.java",
        r#"
package com.example;

import java.util.Collection;

public class ClusterProcessPersistService {
    void getProcessList(String taskId, Collection<String> triggerPaths) {
        waitUntilReleaseReady(taskId, () -> isReady(triggerPaths));
    }

    void killProcess(String processId, Collection<String> triggerPaths) {
        waitUntilReleaseReady(processId, () -> isReady(triggerPaths));
    }

    private boolean isReady(Collection<String> paths) {
        return paths.isEmpty();
    }

    private void waitUntilReleaseReady(String id, ReadyCheck check) {}

    interface ReadyCheck {
        boolean isReady();
    }
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(
        &analyzer,
        "com.example.ClusterProcessPersistService.isReady",
    );
    let anonymous = analyzer
        .all_declarations()
        .find(|unit| unit.is_anonymous() && unit.short_name().contains("getProcessList"))
        .expect("missing lambda declaration");
    let anonymous_parent = analyzer
        .parent_of(&anonymous)
        .expect("missing lambda parent");
    let anonymous_owner = analyzer
        .parent_of(&anonymous_parent)
        .expect("missing lambda owner");
    assert_eq!(
        "com.example.ClusterProcessPersistService",
        anonymous_owner.fq_name(),
        "lambda ancestry: {anonymous:?} -> {anonymous_parent:?} -> {anonymous_owner:?}"
    );
    assert_eq!(
        "com.example.ClusterProcessPersistService",
        analyzer.parent_of(&target).expect("target owner").fq_name(),
        "target: {target:?}"
    );
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    // The unqualified `isReady(triggerPaths)` calls are implicit-this same-owner
    // sites under #1014 facet B: excluded from external usages, but still proven
    // and visible on the editor find-references surface as self-receiver hits.
    let direct_hits = self_receiver_hits(&result);
    assert_eq!(2, direct_hits.len(), "{direct_hits:#?}");
    assert!(
        direct_hits
            .iter()
            .all(|hit| hit.snippet.contains("() -> isReady(triggerPaths)")),
        "{direct_hits:#?}"
    );
    assert!(
        hits(result).is_empty(),
        "unqualified same-owner calls must not be external usages"
    );

    let scan = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["com.example.ClusterProcessPersistService.isReady"],
            "include_tests": true
        })
        .to_string(),
    );
    let entry = &scan["results"][0];
    // The two unqualified calls are same-owner sites: zero external usages with
    // two same-owner sites reports `no_external_usages` (#1014 facet B), never
    // `verified_absent`.
    assert_eq!("no_external_usages", entry["status"], "{scan}");
    assert_eq!(0, entry["total_hits"], "{scan}");
    assert_eq!(2, entry["same_owner_sites"], "{scan}");
    assert_eq!(0, entry["unproven_hits"], "{scan}");
}

#[test]
fn java_graph_strategy_excludes_incompatible_anonymous_return_receivers() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Handler.java",
            "package com.example; public interface Handler { String handle(String value); }\n",
        ),
        (
            "com/example/ConsoleHandler.java",
            r#"
package com.example;

public class ConsoleHandler implements Handler {
    @Override
    public String handle(String value) { return value.trim(); }
}
"#,
        ),
        (
            "com/example/UnrelatedHandler.java",
            r#"
package com.example;

public class UnrelatedHandler {
    public String handle(String value) { return value.toUpperCase(); }
}
"#,
        ),
        (
            "com/example/Runner.java",
            r#"
package com.example;

public class Runner {
    public Handler makeAnonymous() {
        return new Handler() {
            @Override
            public String handle(String value) { return value.toLowerCase(); }
        };
    }

    public String run() {
        Handler handler = new ConsoleHandler();
        ConsoleHandler direct = new ConsoleHandler();
        handler.handle("Interface"); // interface-handler
        direct.handle("Console"); // direct-console-handler
        new UnrelatedHandler().handle("Other"); // incompatible-concrete-handler
        return makeAnonymous().handle("Anonymous"); // anonymous-handler-return
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let console_handle = definition(&analyzer, "com.example.ConsoleHandler.handle");
    let concrete_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&console_handle),
        &candidates,
        1000,
    );
    assert_success_counts(concrete_result.clone(), &console_handle, 2, 0);
    let concrete_hits = hits(concrete_result);
    assert_eq!(
        1,
        concrete_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .count(),
        "only the direct ConsoleHandler call should be a concrete method reference: {concrete_hits:#?}"
    );
    assert_hit_contains(&concrete_hits, "direct-console-handler");

    let handler_handle = definition(&analyzer, "com.example.Handler.handle");
    let interface_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&handler_handle),
        &candidates,
        1000,
    ));
    assert_hit_contains(&interface_hits, "interface-handler");
    assert_hit_contains(&interface_hits, "anonymous-handler-return");
    assert_no_hit_line(&interface_hits, 16);
    assert_eq!(
        2,
        interface_hits
            .iter()
            .filter(|hit| hit.kind == UsageHitKind::Reference)
            .count(),
        "only the two interface-contract calls should be references: {interface_hits:#?}"
    );
}

#[test]
fn java_graph_strategy_preserves_inherited_and_anonymous_subclass_receivers() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Handler.java",
            "package com.example; public interface Handler { String handle(String value); }\n",
        ),
        (
            "com/example/ConsoleHandler.java",
            r#"
package com.example;

public class ConsoleHandler implements Handler {
    @Override
    public String handle(String value) { return value.trim(); }
}
"#,
        ),
        (
            "com/example/Factory.java",
            "package com.example; public interface Factory { Handler make(); }\n",
        ),
        (
            "com/example/FactoryImpl.java",
            r#"
package com.example;

public class FactoryImpl implements Factory {
    @Override
    public Handler make() {
        return new ConsoleHandler() {};
    }
}
"#,
        ),
        (
            "com/example/Base.java",
            "package com.example; public class Base { public int value; public void run() {} }\n",
        ),
        (
            "com/example/Child.java",
            "package com.example; public class Child extends Base {}\n",
        ),
        (
            "com/example/Runner.java",
            r#"
package com.example;

public class Runner {
    String runHandler() {
        return new FactoryImpl().make().handle("anonymous-console-subclass");
    }

    int runInherited() {
        new Child().run(); // inherited-method
        return new Child().value; // inherited-field
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let console_handle = definition(&analyzer, "com.example.ConsoleHandler.handle");
    let console_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&console_handle),
        &candidates,
        1000,
    );
    assert_success_counts(console_result.clone(), &console_handle, 2, 0);
    assert_hit_contains(&hits(console_result), "anonymous-console-subclass");

    let base_run = definition(&analyzer, "com.example.Base.run");
    let base_run_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&base_run),
        &candidates,
        1000,
    );
    assert_success_counts(base_run_result.clone(), &base_run, 1, 0);
    assert_hit_contains(&hits(base_run_result), "inherited-method");

    let base_value = definition(&analyzer, "com.example.Base.value");
    let base_value_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&base_value),
        &candidates,
        1000,
    );
    assert_success_counts(base_value_result, &base_value, 0, 1);
}

#[test]
fn java_graph_strategy_counts_anonymous_class_and_super_method_usages() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Base.java",
            "package com.example; public class Base { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void execute() {
        Base base = new Base() {
            @Override
            public void run() {
                super.run();
            }
        };
        base.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Base.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("anonymous class success");
    assert_eq!(2, hits.len(), "expected super.run() and base.run()");
}

#[test]
fn java_graph_strategy_counts_this_field_and_method_usages() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Target.java",
        r#"
package com.example;

public class Target {
    public int field;

    public void run() {
        this.field = 1;
        this.run();
    }
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field_target = definition(&analyzer, "com.example.Target.field");
    let method_target = definition(&analyzer, "com.example.Target.run");

    let field_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&field_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("this field success");
    assert_eq!(1, field_hits.len());

    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("this method success");
    assert!(
        method_hits.is_empty(),
        "self-recursive this.run should still be filtered"
    );
}

#[test]
fn java_usage_finder_finds_bare_inherited_field_read_and_excludes_local_shadows() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "p/Base.java",
            r#"
package p;

public class Base {
    protected static final int YEAR = 2026;
}
"#,
        ),
        (
            "p/Child.java",
            r#"
package p;

public class Child extends Base {
    int inherited() {
        return YEAR; // positive-inherited-read
    }

    int localShadow() {
        int YEAR = 1;
        return YEAR; // negative-local-shadow
    }

    int parameterShadow(int YEAR) {
        return YEAR; // negative-parameter-shadow
    }
}
"#,
        ),
        (
            "p/ShadowChild.java",
            r#"
package p;

public class ShadowChild extends Base {
    int YEAR = 1;

    int inheritedFieldShadow() {
        return YEAR; // negative-derived-field-shadow
    }
}
"#,
        ),
        (
            "p/MiddleShadow.java",
            r#"
package p;

public class MiddleShadow extends Base {
    protected static final int YEAR = 1;
}
"#,
        ),
        (
            "p/GrandChild.java",
            r#"
package p;

public class GrandChild extends MiddleShadow {
    int inheritedFieldShadow() {
        return YEAR; // negative-intermediate-field-shadow
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "p.Base.YEAR");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_eq!(1, hits.len(), "expected only the inherited bare field read");
    assert_hit_contains(&hits, "positive-inherited-read");
    assert_no_hit_contains(&hits, "negative-local-shadow");
    assert_no_hit_contains(&hits, "negative-parameter-shadow");
    assert_no_hit_contains(&hits, "negative-derived-field-shadow");
    assert_no_hit_contains(&hits, "negative-intermediate-field-shadow");
}

#[test]
fn java_usage_finder_finds_bare_inherited_field_write_and_excludes_shadows() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "p/VoiceStatus.java",
            r#"
package p;

public class VoiceStatus {
    protected boolean active;
}
"#,
        ),
        (
            "p/SoftVoice.java",
            r#"
package p;

public class SoftVoice extends VoiceStatus {
    Object controller = new Object() {
        boolean active = false;

        void update() {
            active = true; // negative-anonymous-class-field
        }
    };

    void activate(boolean enabled) {
        if (enabled) {
            active = true; // positive-inherited-write
        }
    }

    void localShadow() {
        boolean active = false;
        active = true; // negative-local-shadow
    }

    void parameterShadow(boolean active) {
        active = true; // negative-parameter-shadow
    }
}
"#,
        ),
        (
            "p/ShadowSoftVoice.java",
            r#"
package p;

public class ShadowSoftVoice extends VoiceStatus {
    boolean active;

    void activateShadow() {
        active = true; // negative-derived-field-shadow
    }
}
"#,
        ),
        (
            "p/MiddleShadow.java",
            r#"
package p;

public class MiddleShadow extends VoiceStatus {
    protected boolean active;
}
"#,
        ),
        (
            "p/GrandChild.java",
            r#"
package p;

public class GrandChild extends MiddleShadow {
    void activateShadow() {
        active = true; // negative-intermediate-field-shadow
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "p.VoiceStatus.active");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_eq!(
        1,
        hits.len(),
        "expected only the inherited bare field write"
    );
    assert_hit_contains(&hits, "positive-inherited-write");
    assert_no_hit_contains(&hits, "negative-local-shadow");
    assert_no_hit_contains(&hits, "negative-parameter-shadow");
    assert_no_hit_contains(&hits, "negative-anonymous-class-field");
    assert_no_hit_contains(&hits, "negative-derived-field-shadow");
    assert_no_hit_contains(&hits, "negative-intermediate-field-shadow");
}

#[test]
fn java_usage_finder_finds_bare_inherited_method_call_and_excludes_self_and_wrong_owner() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "p/Base.java",
            r#"
package p;

public class Base {
    protected void ping(String left, String right) {}
}
"#,
        ),
        (
            "p/Pingable.java",
            r#"
package p;

public interface Pingable {
    void ping(String left, String right);
}
"#,
        ),
        (
            "p/Child.java",
            r#"
package p;

public class Child extends Base implements Pingable {
    void inherited() {
        ping("left", "right"); // positive-inherited-call
    }
}
"#,
        ),
        (
            "p/OverrideChild.java",
            r#"
package p;

public class OverrideChild extends Base {
    @Override
    protected void ping(String left, String right) {}

    void selfCall() {
        ping("left", "right"); // negative-self-call
    }
}
"#,
        ),
        (
            "p/WrongOwner.java",
            r#"
package p;

public class WrongOwner {
    void ping(String left, String right) {}

    void localCall() {
        ping("left", "right"); // negative-wrong-owner
    }
}
"#,
        ),
        (
            "p/MiddleOverride.java",
            r#"
package p;

public class MiddleOverride extends Base {
    @Override
    protected void ping(String left, String right) {}
}
"#,
        ),
        (
            "p/GrandChild.java",
            r#"
package p;

public class GrandChild extends MiddleOverride {
    void inheritedOverrideCall() {
        ping("left", "right"); // negative-intermediate-override
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "p.Base.ping");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let all_hits = hits(result.clone());
    let reference_hits: Vec<_> = all_hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .cloned()
        .collect();

    // Under #1014 facet B an unqualified inherited call is an implicit-this
    // same-owner site, so it is no longer an external Reference hit — it moves to
    // the self-receiver (editor) surface. The wrong-owner and intermediate-override
    // negatives remain excluded from both surfaces.
    assert!(
        reference_hits.is_empty(),
        "bare same-owner call must not be an external reference: {reference_hits:#?}"
    );
    let self_hits = self_receiver_hits(&result);
    assert_hit_contains(&self_hits, "positive-inherited-call");
    assert_no_hit_contains(&self_hits, "negative-wrong-owner");
    assert_no_hit_contains(&self_hits, "negative-intermediate-override");
    assert_no_hit_contains(&all_hits, "negative-wrong-owner");
    assert_no_hit_contains(&all_hits, "negative-intermediate-override");
}

#[test]
fn java_graph_strategy_counts_annotation_type_references_without_same_name_confusion() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "target/Tag.java",
            r#"
package target;

public @interface Tag {
    String value() default "";
}
"#,
        ),
        (
            "target/Outer.java",
            r#"
package target;

public class Outer {
    public @interface Nested {}
}
"#,
        ),
        (
            "other/Tag.java",
            r#"
package other;

public @interface Tag {}
"#,
        ),
        (
            "app/Consumer.java",
            r#"
package app;

import target.Outer;
import target.Tag;

@Tag("ordinary") // positive-ordinary-annotation
@Tag // positive-marker-annotation
@Outer.Nested // positive-nested-annotation
@target.Outer.Nested // positive-qualified-nested-annotation
@other.Tag // negative-unrelated-same-name
public class Consumer {}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let tag_target = definition(&analyzer, "target.Tag");
    let tag_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&tag_target),
        &candidates,
        1000,
    ));
    assert_eq!(
        2,
        tag_hits.len(),
        "expected only the target.Tag annotations"
    );
    assert_hit_contains(&tag_hits, "positive-ordinary-annotation");
    assert_hit_contains(&tag_hits, "positive-marker-annotation");
    assert_no_hit_line(&tag_hits, 10);

    let nested_target = definition(&analyzer, "target.Outer.Nested");
    let nested_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&nested_target),
        &candidates,
        1000,
    ));
    assert_eq!(
        2,
        nested_hits.len(),
        "expected both nested annotation forms"
    );
    assert_hit_contains(&nested_hits, "positive-nested-annotation");
    assert_hit_contains(&nested_hits, "positive-qualified-nested-annotation");
    assert_no_hit_line(&nested_hits, 11);
}

#[test]
fn java_graph_strategy_accepts_varargs_expanded_and_array_calls_but_rejects_wrong_arity() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "p/Target.java",
            r#"
package p;

public class Target<T> {
    public void join(String left) {}
    public void join(String left, String right, String... rest) {}
    public void receive(Target<T> this, String value) {}

    public Target(String left) {}
    public Target(String left, String right, String... rest) {}
}
"#,
        ),
        (
            "p/Consumer.java",
            r#"
package p;

public class Consumer {
    void call(Target target) {
        target.join("a", "b", "c"); // positive-varargs-expanded-method
        target.join("a", "b", new String[]{"c"}); // positive-varargs-array-method
        target.join("a"); // negative-non-varargs-method
        target.receive("a"); // positive-explicit-receiver-method

        new Target<>("a", "b", "c"); // positive-varargs-expanded-ctor
        new Target<>("a", "b", new String[]{"c"}); // positive-varargs-array-ctor
        new Target<>("a"); // negative-non-varargs-ctor
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let varargs_method = analyzer
        .get_definitions("p.Target.join")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String, String, String[])"))
        .expect("missing varargs join overload");
    let varargs_constructor = analyzer
        .get_definitions("p.Target.Target")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String, String, String[])"))
        .expect("missing varargs constructor overload");
    let receiver_method = definition(&analyzer, "p.Target.receive");

    let method_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&varargs_method),
        &candidates,
        1000,
    ));
    assert_eq!(2, method_hits.len(), "expected both varargs method calls");
    assert_hit_contains(&method_hits, "positive-varargs-expanded-method");
    assert_hit_contains(&method_hits, "positive-varargs-array-method");
    assert_no_hit_line(&method_hits, 8);

    let receiver_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&receiver_method),
        &candidates,
        1000,
    ));
    assert_eq!(
        1,
        receiver_hits.len(),
        "receiver parameter is not a call argument"
    );
    assert_hit_contains(&receiver_hits, "positive-explicit-receiver-method");

    let constructor_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&varargs_constructor),
        &candidates,
        1000,
    ));
    assert_eq!(
        2,
        constructor_hits.len(),
        "expected both varargs constructor calls"
    );
    assert_hit_contains(&constructor_hits, "positive-varargs-expanded-ctor");
    assert_hit_contains(&constructor_hits, "positive-varargs-array-ctor");
    assert_no_hit_line(&constructor_hits, 13);
}

#[test]
fn java_graph_strategy_counts_annotated_spread_parameter_calls_precisely() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "org/example/Fixtures.java",
        r#"
package org.example;

@interface N {}

public class JavaCompilerBundle {
    public static String message(String key, Object @N ... params) { return key; }
}

public class TokenSet {
    public static TokenSet create(String @N ... tokens) { return new TokenSet(); }
}

public class Consumer {
    void call() {
        JavaCompilerBundle.message("days"); // positive-message-zero-spread
        JavaCompilerBundle.message("weeks", 1, "x"); // positive-message-expanded
        JavaCompilerBundle.message(); // negative-message-too-few

        TokenSet.create(); // positive-create-zero-spread
        TokenSet.create("A", "B"); // positive-create-expanded
    }
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let message_target = analyzer
        .get_definitions("org.example.JavaCompilerBundle.message")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String, Object[])"))
        .expect("missing annotated-spread message overload");
    let message_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&message_target),
        &candidates,
        1000,
    ));

    assert_eq!(
        2,
        message_hits.len(),
        "expected zero and expanded annotated-spread message calls"
    );
    assert_hit_contains(&message_hits, "positive-message-zero-spread");
    assert_hit_contains(&message_hits, "positive-message-expanded");
    assert_no_hit_line(&message_hits, 18);

    let create_target = analyzer
        .get_definitions("org.example.TokenSet.create")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String[])"))
        .expect("missing annotated-spread create overload");
    let create_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&create_target),
        &candidates,
        1000,
    ));
    assert_eq!(
        2,
        create_hits.len(),
        "expected zero and expanded annotated-spread create calls"
    );
    assert_hit_contains(&create_hits, "positive-create-zero-spread");
    assert_hit_contains(&create_hits, "positive-create-expanded");
}

#[test]
fn java_graph_strategy_counts_static_field_usages() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public static final int VALUE = 1; }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.VALUE;

public class Consumer {
    int readQualified() {
        return Target.VALUE;
    }

    int readImported() {
        return VALUE;
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field_target = definition(&analyzer, "com.example.Target.VALUE");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&field_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("static field success");
    assert_eq!(
        2,
        hits.len(),
        "expected qualified and imported static field reads"
    );
}

#[test]
fn java_graph_strategy_counts_static_wildcard_imported_field_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public static final int VALUE = 1; }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.*;

public class Consumer {
    int readImported() {
        return VALUE;
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field_target = definition(&analyzer, "com.example.Target.VALUE");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&field_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("static wildcard field success");
    assert_eq!(1, hits.len());
}

#[test]
fn java_graph_strategy_keeps_static_wildcard_field_visible_with_unrelated_wildcards() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Flags.java",
            "package com.example; public class Flags { public static final int FINAL = 1; }\n",
        ),
        (
            "com/example/Names.java",
            "package com.example; public class Names { public static final int OTHER = 2; }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Flags.*;
import static com.example.Names.*;

public class Consumer {
    int readImported() {
        return FINAL; // positive-target-only
    }
}
"#,
        ),
        (
            "com/example/OtherFlags.java",
            "package com.example; public class OtherFlags { public static final int FINAL = 3; }\n",
        ),
        (
            "com/example/AmbiguousConsumer.java",
            r#"
package com.example;

import static com.example.Flags.*;
import static com.example.OtherFlags.*;

public class AmbiguousConsumer {
    int readImported() {
        return FINAL; // negative-colliding-wildcard
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "com.example.Flags.FINAL");

    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let proven_hits: Vec<_> = result
        .clone()
        .into_either()
        .expect("static wildcard field success")
        .into_iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .collect();
    assert_hit_contains(&proven_hits, "positive-target-only");
    assert_no_hit_contains(&proven_hits, "negative-colliding-wildcard");
    assert_success_counts(result, &target, 1, 0);
}

#[test]
fn java_graph_strategy_counts_static_imported_method_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public static void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.run;

public class Consumer {
    void call() {
        run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("static import success");
    assert_eq!(1, hits.len());
}

#[test]
fn java_graph_strategy_records_exact_static_import_references_for_fields_and_methods() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "java/time/temporal/ChronoUnit.java",
            "package java.time.temporal; public class ChronoUnit { public static final ChronoUnit WEEKS = new ChronoUnit(); }\n",
        ),
        (
            "app/Strings.java",
            "package app; public class Strings { public static String trimEnd(String value) { return value; } public static String trimEnd(String value, String suffix) { return value + suffix; } }\n",
        ),
        (
            "app/Consumer.java",
            r#"
package app;

import static java.time.temporal.ChronoUnit.WEEKS;
import static app.Strings.trimEnd;

public class Consumer {
    ChronoUnit unit = WEEKS;
    String value = trimEnd("x");
}
"#,
        ),
    ]);

    let weeks_target = definition(&analyzer, "java.time.temporal.ChronoUnit.WEEKS");
    let weeks_result = UsageFinder::new().find_usages_default(&analyzer, &[weeks_target]);
    let weeks_hits = weeks_result
        .all_hits_including_imports()
        .into_iter()
        .collect::<Vec<_>>();
    assert_hit_contains(
        &weeks_hits,
        "import static java.time.temporal.ChronoUnit.WEEKS",
    );

    let trim_end_target = analyzer
        .get_definitions("app.Strings.trimEnd")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("trimEnd(String) overload");
    let trim_end_result = UsageFinder::new().find_usages_default(&analyzer, &[trim_end_target]);
    let trim_end_hits = trim_end_result
        .all_hits_including_imports()
        .into_iter()
        .collect::<Vec<_>>();
    assert_hit_contains(&trim_end_hits, "import static app.Strings.trimEnd");
}

#[test]
fn java_graph_strategy_falls_back_on_ambiguous_static_imported_method_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Alpha.java",
            "package com.example; public class Alpha { public static void run() {} }\n",
        ),
        (
            "com/example/Beta.java",
            "package com.example; public class Beta { public static void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Alpha.run;
import static com.example.Beta.run;

public class Consumer {
    void call() {
        run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Alpha.run");
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method_target),
        &candidates,
        1000,
    );
    assert_success_counts(result, &method_target, 1, 1);
}

#[test]
fn java_graph_strategy_counts_static_wildcard_imported_method_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public static void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.*;

public class Consumer {
    void call() {
        run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("static wildcard import success");
    assert_eq!(1, hits.len());
}

#[test]
fn java_graph_strategy_keeps_overloaded_static_import_method_usage_narrow() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public static void run() {}
    public static void run(String arg) {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Target.run;

public class Consumer {
    void call() {
        run();
        run("x");
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let zero_arg_target = analyzer
        .get_definitions("com.example.Target.run")
        .into_iter()
        .find(|cu| cu.signature() == Some("()"))
        .expect("missing zero-arg overload");
    let one_arg_target = analyzer
        .get_definitions("com.example.Target.run")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("missing one-arg overload");

    let zero_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&zero_arg_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("zero-arg overload success");
    let one_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&one_arg_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("one-arg overload success");

    assert_eq!(1, zero_hits.len(), "zero-arg overload should stay narrow");
    assert_eq!(1, one_hits.len(), "one-arg overload should stay narrow");
}

#[test]
fn java_graph_strategy_matches_method_references_only_when_owner_and_overload_are_proven() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/GridUtil.java",
            "package app; public class GridUtil { public static void suggestPlugin() {} }\n",
        ),
        (
            "app/OtherGridUtil.java",
            "package app; public class OtherGridUtil { public static void suggestPlugin() {} }\n",
        ),
        (
            "app/Formatter.java",
            "package app; public class Formatter { public String trim() { return \"\"; } public String replace(String value) { return value; } public String replace(Object value) { return String.valueOf(value); } }\n",
        ),
        (
            "app/BaseFormatter.java",
            "package app; public class BaseFormatter { public String inheritedTrim() { return \"\"; } }\n",
        ),
        (
            "app/ChildFormatter.java",
            "package app; public class ChildFormatter extends BaseFormatter {}\n",
        ),
        (
            "app/Helper.java",
            "package app; public class Helper { public void suggestPlugin() {} }\n",
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer {
    void call(Helper helper) {
        Runnable staticRef = GridUtil::suggestPlugin; // positive-static-reference
        java.util.function.Function<Formatter, String> instanceRef = Formatter::trim; // positive-instance-reference
        java.util.function.Function<ChildFormatter, String> inheritedRef = ChildFormatter::inheritedTrim; // positive-inherited-reference
        Runnable wrongOwner = OtherGridUtil::suggestPlugin; // negative-wrong-owner
        Runnable shadowed = helper::suggestPlugin; // negative-local-shadow
        java.util.function.BiFunction<Formatter, Object, String> ambiguous = Formatter::replace; // negative-ambiguous-overload
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let static_target = definition(&analyzer, "app.GridUtil.suggestPlugin");
    let static_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&static_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&static_hits, "positive-static-reference");
    assert_no_hit_contains(&static_hits, "negative-wrong-owner");
    assert_no_hit_contains(&static_hits, "negative-local-shadow");

    let instance_target = definition(&analyzer, "app.Formatter.trim");
    let instance_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&instance_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&instance_hits, "positive-instance-reference");

    let inherited_target = definition(&analyzer, "app.BaseFormatter.inheritedTrim");
    let inherited_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&inherited_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&inherited_hits, "positive-inherited-reference");

    let ambiguous_target = analyzer
        .get_definitions("app.Formatter.replace")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("replace(String) overload");
    let ambiguous_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&ambiguous_target),
        &candidates,
        1000,
    );
    assert_success_counts(ambiguous_result, &ambiguous_target, 0, 1);
}

#[test]
fn java_graph_strategy_resolves_nested_type_method_reference_receivers() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Settings.java",
            r#"
package app;

public class Settings {
    public static class Basic {
        public boolean enabled() { return true; }
    }

    public static class OtherBasic {
        public boolean enabled() { return false; }
    }
}
"#,
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer {
    java.util.function.Function<Settings.Basic, Boolean> reference() {
        return Settings.Basic::enabled; // positive-nested-reference
    }

    java.util.function.Function<Settings.OtherBasic, Boolean> wrongOwner() {
        return Settings.OtherBasic::enabled; // negative-wrong-nested-owner
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "app.Settings.Basic.enabled");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let nested_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_hit_contains(&nested_hits, "positive-nested-reference");
    assert_no_hit_contains(&nested_hits, "negative-wrong-nested-owner");
}

#[test]
fn java_graph_strategy_matches_this_and_super_method_references_selector_accurately() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/BaseFormatter.java",
            r#"
package app;

public class BaseFormatter {
    public String inheritedTrim() { return ""; }
}
"#,
        ),
        (
            "app/Helper.java",
            r#"
package app;

public class Helper {
    public void suggestPlugin() {}
}
"#,
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer extends BaseFormatter {
    public String trim() { return ""; }
    public void suggestPlugin() {}
    public String replace(String value) { return value; }
    public String replace(Object value) { return String.valueOf(value); }

    void call() {
        java.util.function.Supplier<String> currentThis = this::trim; // positive-this-current-class
        java.util.function.Supplier<String> inheritedThis = this::inheritedTrim; // positive-this-inherited
        java.util.function.Supplier<String> inheritedSuper = super::inheritedTrim; // positive-super-reference
        Runnable localOwner = this::suggestPlugin; // negative-wrong-owner
        java.util.function.Function<Object, String> ambiguous = this::replace; // negative-ambiguous-this-overload
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let current_this_target = definition(&analyzer, "app.Consumer.trim");
    let current_this_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&current_this_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&current_this_hits, "positive-this-current-class");

    let inherited_target = definition(&analyzer, "app.BaseFormatter.inheritedTrim");
    let inherited_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&inherited_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&inherited_hits, "positive-this-inherited");
    assert_hit_contains(&inherited_hits, "positive-super-reference");

    let wrong_owner_target = definition(&analyzer, "app.Helper.suggestPlugin");
    let wrong_owner_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&wrong_owner_target),
        &candidates,
        1000,
    ));
    assert_no_hit_contains(&wrong_owner_hits, "negative-wrong-owner");

    let ambiguous_target = analyzer
        .get_definitions("app.Consumer.replace")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("replace(String) overload");
    let ambiguous_result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&ambiguous_target),
        &candidates,
        1000,
    );
    assert_success_counts(ambiguous_result, &ambiguous_target, 0, 1);
}

#[test]
fn java_graph_strategy_keeps_overloaded_constructor_usage_narrow() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public Target() {}
    public Target(String arg) {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Target buildEmpty() {
        return new Target();
    }

    Target buildNamed() {
        return new Target("x");
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let zero_arg_target = analyzer
        .get_definitions("com.example.Target.Target")
        .into_iter()
        .find(|cu| cu.signature() == Some("()"))
        .expect("missing zero-arg constructor");
    let one_arg_target = analyzer
        .get_definitions("com.example.Target.Target")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("missing one-arg constructor");

    let zero_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&zero_arg_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("zero-arg constructor success");
    let one_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&one_arg_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("one-arg constructor success");

    assert_eq!(
        1,
        zero_hits.len(),
        "zero-arg constructor should stay narrow"
    );
    assert_eq!(1, one_hits.len(), "one-arg constructor should stay narrow");
}

#[test]
fn java_graph_strategy_finds_constructor_method_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Request.java",
            "package app; public class Request { public Request(String value) {} }\n",
        ),
        (
            "app/Other.java",
            "package app; public class Other { public Other(String value) {} }\n",
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer {
    Request direct(String value) {
        return new Request(value); // positive-object-creation
    }

    java.util.function.Function<String, Request> factory() {
        return Request::new; // positive-constructor-reference
    }

    java.util.function.Function<String, Other> otherFactory() {
        return Other::new; // negative-wrong-owner
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "app.Request.Request");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let constructor_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_eq!(2, constructor_hits.len(), "{constructor_hits:#?}");
    assert_hit_contains(&constructor_hits, "positive-object-creation");
    assert_hit_contains(&constructor_hits, "positive-constructor-reference");
    assert_no_hit_contains(&constructor_hits, "negative-wrong-owner");

    let request_type = definition(&analyzer, "app.Request");
    let type_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&request_type),
        &candidates,
        1000,
    ));
    assert_hit_contains(&type_hits, "positive-constructor-reference");
    assert_no_hit_contains(&type_hits, "negative-wrong-owner");
}

#[test]
fn java_graph_strategy_ignores_comment_extra_nodes_when_matching_java_overloads() {
    let parser_source = r#"
package org.telegram;

public class HlsPlaylistParser {
    ParserException factoryOneArg() {
        return ParserException.createForMalformedManifest(
                /* positive-factory-one message= */ "one");
    }

    ParserException factoryTwoArg() {
        return ParserException.createForMalformedManifest(
                /* positive-factory-two message= */ "two",
                // cause=
                null);
    }

    ParserException factoryThreeArg() {
        return ParserException.createForMalformedManifest(
                /* wrong-arity-factory-two message= */ "three",
                /* cause= */ null,
                /* code= */ 3);
    }

    ParserException ctorOneArg() {
        return new ParserException(
                /* positive-ctor-one message= */ "one");
    }

    ParserException ctorTwoArg() {
        return new ParserException(
                /* positive-ctor-two message= */ "two",
                // cause=
                null);
    }

    ParserException ctorThreeArg() {
        return new ParserException(
                /* wrong-arity-ctor-two message= */ "three",
                /* cause= */ null,
                /* code= */ 3);
    }
}
"#;
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "org/telegram/ParserException.java",
            r#"
package org.telegram;

public class ParserException {
    public ParserException(String message) {}
    public ParserException(String message, Throwable cause) {}
    public ParserException(String message, Throwable cause, int code) {}

    public static ParserException createForMalformedManifest(String message) {
        return new ParserException(message);
    }

    public static ParserException createForMalformedManifest(String message, Throwable cause) {
        return new ParserException(message, cause);
    }

    public static ParserException createForMalformedManifest(
            String message,
            Throwable cause,
            int code) {
        return new ParserException(message, cause, code);
    }
}
"#,
        ),
        ("org/telegram/HlsPlaylistParser.java", parser_source),
    ]);

    let candidates = [project.file("org/telegram/HlsPlaylistParser.java")]
        .into_iter()
        .collect();
    let one_arg_factory = analyzer
        .get_definitions("org.telegram.ParserException.createForMalformedManifest")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String)"))
        .expect("missing one-arg factory overload");
    let two_arg_factory = analyzer
        .get_definitions("org.telegram.ParserException.createForMalformedManifest")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String, Throwable)"))
        .expect("missing two-arg factory overload");
    let two_arg_constructor = analyzer
        .get_definitions("org.telegram.ParserException.ParserException")
        .into_iter()
        .find(|cu| cu.signature() == Some("(String, Throwable)"))
        .expect("missing two-arg constructor overload");

    let one_arg_factory_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&one_arg_factory),
        &candidates,
        1000,
    ));
    assert_eq!(
        1,
        one_arg_factory_hits.len(),
        "one-arg factory overload should stay narrow"
    );
    assert_hit_contains(&one_arg_factory_hits, "positive-factory-one");
    assert_no_hit_contains(&one_arg_factory_hits, "positive-factory-two");
    assert_no_hit_contains(&one_arg_factory_hits, "wrong-arity-factory-two");

    let two_arg_factory_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&two_arg_factory),
        &candidates,
        1000,
    ));
    assert_eq!(
        1,
        two_arg_factory_hits.len(),
        "two-arg factory overload should ignore comment extra nodes"
    );
    assert_hit_contains(&two_arg_factory_hits, "positive-factory-two");
    assert_no_hit_contains(&two_arg_factory_hits, "positive-factory-one");
    assert_no_hit_contains(&two_arg_factory_hits, "wrong-arity-factory-two");

    let two_arg_constructor_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&two_arg_constructor),
        &candidates,
        1000,
    ));
    assert_hit_contains(&two_arg_constructor_hits, "positive-ctor-two");
    assert_no_hit_contains(&two_arg_constructor_hits, "positive-ctor-one");
    assert_no_hit_contains(&two_arg_constructor_hits, "wrong-arity-ctor-two");
}

#[test]
fn java_graph_strategy_keeps_nested_constructor_usage_narrow() {
    let service_test_source = r#"
package com.example;

public class ServiceTest {
    public void runsService() {
        Service.Repository repository = new Service.Repository();
        Service service = new Service(repository);
        String prefix = Service.DEFAULT_PREFIX;
    }
}
"#;
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            r#"
package com.example;

public class Service {
    public static final String DEFAULT_PREFIX = "service";
    public Service(Repository repository) {}

    public static class Repository {
        public Repository() {}
    }
}
"#,
        ),
        ("com/example/ServiceTest.java", service_test_source),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let service_test_file = project.file("com/example/ServiceTest.java");
    let service_type = definition(&analyzer, "com.example.Service");
    let repository_type = definition(&analyzer, "com.example.Service.Repository");
    let service_constructor = definition(&analyzer, "com.example.Service.Service");
    let repository_constructor = definition(&analyzer, "com.example.Service.Repository.Repository");

    let outer_qualifier_line = line_of(service_test_source, "Service.Repository repository");
    let service_type_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&service_type),
        &candidates,
        1000,
    ));
    let service_qualifier_hits: Vec<_> = service_type_hits
        .iter()
        .filter(|hit| hit.file == service_test_file && hit.line == outer_qualifier_line)
        .collect();
    assert_eq!(
        2,
        service_qualifier_hits.len(),
        "both outer Service qualifiers should be distinct usages: {service_type_hits:#?}"
    );
    for hit in service_qualifier_hits {
        assert_eq!(
            "Service",
            &service_test_source[hit.start_offset..hit.end_offset],
            "outer qualifier hit must retain its exact token range"
        );
    }
    assert_hit_contains(
        &service_type_hits,
        "Service service = new Service(repository)",
    );
    assert_hit_contains(&service_type_hits, "Service.DEFAULT_PREFIX");

    let repository_type_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&repository_type),
        &candidates,
        1000,
    ));
    let repository_qualifier_hits: Vec<_> = repository_type_hits
        .iter()
        .filter(|hit| hit.file == service_test_file && hit.line == outer_qualifier_line)
        .collect();
    assert_eq!(
        2,
        repository_qualifier_hits.len(),
        "nested type should retain only its Repository leaf tokens: {repository_type_hits:#?}"
    );
    for hit in repository_qualifier_hits {
        assert_eq!(
            "Repository",
            &service_test_source[hit.start_offset..hit.end_offset],
            "nested type hit must retain its exact leaf range"
        );
    }

    let service_hits: Vec<_> = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&service_constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("service constructor success")
        .into_iter()
        .collect();
    assert_eq!(
        1,
        service_hits.len(),
        "service constructor should stay narrow"
    );
    assert_hit_contains(&service_hits, "new Service(repository)");
    assert_no_hit_line(&service_hits, 6);

    let repository_hits: Vec<_> = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&repository_constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("repository constructor success")
        .into_iter()
        .collect();
    assert_eq!(
        1,
        repository_hits.len(),
        "repository constructor should be found"
    );
    assert_hit_line(&repository_hits, 6);
}

#[test]
fn java_graph_strategy_resolves_each_scoped_type_segment_by_identity() {
    let consumer_source = r#"
package consumer;

import app.Service;
import java.util.List;

public class Consumer {
    Service.Repository imported;
    app.Service.Repository qualified;
    List<Service.Repository> generic;
    Service.Missing.Repository malformed;
    other.Service.Repository unrelated;
}
"#;
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Service.java",
            r#"
package app;

public class Service {
    public static class Repository {}
}
"#,
        ),
        (
            "other/Service.java",
            r#"
package other;

public class Service {
    public static class Repository {}
}
"#,
        ),
        ("consumer/Consumer.java", consumer_source),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let service = definition(&analyzer, "app.Service");
    let repository = definition(&analyzer, "app.Service.Repository");
    let service_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&service),
        &candidates,
        1000,
    ));

    for marker in [
        "Service.Repository imported",
        "app.Service.Repository qualified",
        "List<Service.Repository> generic",
    ] {
        let line = line_of(consumer_source, marker);
        let line_hits: Vec<_> = service_hits.iter().filter(|hit| hit.line == line).collect();
        assert_eq!(
            1,
            line_hits.len(),
            "expected one app.Service qualifier hit for {marker:?}: {service_hits:#?}"
        );
        assert_eq!(
            "Service",
            &consumer_source[line_hits[0].start_offset..line_hits[0].end_offset],
            "outer type hit must retain its exact token range"
        );
    }
    assert_no_hit_line(
        &service_hits,
        line_of(consumer_source, "other.Service.Repository unrelated"),
    );

    let repository_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&repository),
        &candidates,
        1000,
    ));
    for marker in [
        "Service.Repository imported",
        "app.Service.Repository qualified",
        "List<Service.Repository> generic",
    ] {
        let line = line_of(consumer_source, marker);
        let line_hits: Vec<_> = repository_hits
            .iter()
            .filter(|hit| hit.line == line)
            .collect();
        assert_eq!(
            1,
            line_hits.len(),
            "expected one app.Service.Repository leaf hit for {marker:?}: {repository_hits:#?}"
        );
        assert_eq!(
            "Repository",
            &consumer_source[line_hits[0].start_offset..line_hits[0].end_offset],
            "nested type hit must retain its exact token range"
        );
    }
    assert_no_hit_line(
        &repository_hits,
        line_of(consumer_source, "other.Service.Repository unrelated"),
    );
    assert_no_hit_line(
        &repository_hits,
        line_of(consumer_source, "Service.Missing.Repository malformed"),
    );
}

#[test]
fn java_usage_graph_persists_outer_and_nested_scoped_type_edges() {
    let (project, _analyzer) = java_analyzer_with_files(&[
        (
            "app/Service.java",
            r#"
package app;

public class Service {
    public static class Repository {}
}
"#,
        ),
        (
            "consumer/Consumer.java",
            r#"
package consumer;

import app.Service;

public class Consumer {
    void use() {
        Service.Repository repository = new Service.Repository();
    }
}
"#,
        ),
        (
            "local/Outer.java",
            r#"
package local;

public class Outer {
    static class Service {
        static class Repository {}
    }

    void use() {
        Service.Repository repository = new Service.Repository();
    }
}
"#,
        ),
        (
            "app/Marker.java",
            r#"
package app;

public class Marker {
    public @interface Nested {}
}
"#,
        ),
        (
            "consumer/Annotated.java",
            r#"
package consumer;

import app.Marker;

@Marker.Nested
public class Annotated {}
"#,
        ),
    ]);

    let graph = call_search_tool_json(project.root(), "usage_graph", "{}");
    let has_edge = |to: &str| {
        graph["edges"].as_array().is_some_and(|edges| {
            edges
                .iter()
                .any(|edge| edge["from"] == "consumer.Consumer.use" && edge["to"] == to)
        })
    };
    assert!(
        has_edge("app.Service"),
        "persisted graph should retain the outer Service reference: {graph}"
    );
    assert!(
        has_edge("app.Service.Repository"),
        "persisted graph should retain the nested Repository reference: {graph}"
    );
    let has_local_edge = |to: &str| {
        graph["edges"].as_array().is_some_and(|edges| {
            edges
                .iter()
                .any(|edge| edge["from"] == "local.Outer.use" && edge["to"] == to)
        })
    };
    assert!(
        has_local_edge("local.Outer.Service"),
        "persisted graph should retain the lexically resolved outer Service reference: {graph}"
    );
    assert!(
        has_local_edge("local.Outer.Service.Repository"),
        "persisted graph should retain the lexically resolved nested Repository reference: {graph}"
    );
    let has_annotation_edge = |to: &str| {
        graph["edges"].as_array().is_some_and(|edges| {
            edges
                .iter()
                .any(|edge| edge["from"] == "consumer.Annotated" && edge["to"] == to)
        })
    };
    assert!(
        has_annotation_edge("app.Marker"),
        "persisted graph should retain the outer annotation type reference: {graph}"
    );
    assert!(
        has_annotation_edge("app.Marker.Nested"),
        "persisted graph should retain the nested annotation type reference: {graph}"
    );
}

#[test]
fn java_graph_strategy_resolves_absolute_dotted_type_before_nested_fallback() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/external/Widget.java",
            r#"
package com.external;

public class Widget {
    public Widget() {}
}
"#,
        ),
        (
            "com/example/com/external/Widget.java",
            r#"
package com.example.com.external;

public class Widget {
    public Widget() {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    public Widget build() {
        return new com.external.Widget();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let absolute_constructor = definition(&analyzer, "com.external.Widget.Widget");
    let same_package_subpackage_constructor =
        definition(&analyzer, "com.example.com.external.Widget.Widget");

    let absolute_hits: Vec<_> = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&absolute_constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("absolute constructor success")
        .into_iter()
        .collect();
    assert_eq!(1, absolute_hits.len(), "absolute FQN should win");
    assert_hit_contains(&absolute_hits, "new com.external.Widget()");

    let subpackage_hits: Vec<_> = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&same_package_subpackage_constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("subpackage constructor success")
        .into_iter()
        .collect();
    assert!(
        subpackage_hits.is_empty(),
        "subpackage lookalike must not capture absolute FQN: {subpackage_hits:#?}"
    );
}

#[test]
fn java_graph_strategy_counts_same_package_implicit_type_and_method_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    private Target target;

    void call(Target value) {
        target = new Target();
        value.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let class_target = definition(&analyzer, "com.example.Target");
    let method_target = definition(&analyzer, "com.example.Target.run");

    let class_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&class_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("same-package type success");
    assert!(
        class_hits.len() >= 3,
        "expected declaration, param, and constructor type references"
    );

    let method_hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("same-package method success");
    assert_eq!(1, method_hits.len());
}

#[test]
fn java_graph_strategy_counts_generated_same_file_type_and_field_references() {
    let (_project, analyzer) = java_analyzer_with_files(&[(
        "com/example/Generated.java",
        r#"
package com.example;

public class Generated {
    private static Generated DEFAULT_INSTANCE;
    static {
        DEFAULT_INSTANCE = new Generated();
    }

    public static final class Builder {
        public static Builder newBuilder() {
            return new Builder();
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public com.example.Generated self() {
        return this;
    }

    public enum Mode {
        READY,
        UNRECOGNIZED;

        public Mode fallback() {
            return UNRECOGNIZED;
        }
    }
}
"#,
    )]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = JavaUsageGraphStrategy::new();

    let builder = definition(&analyzer, "com.example.Generated.Builder");
    let builder_hits: Vec<_> = strategy
        .find_usages(&analyzer, &[builder], &candidates, 1000)
        .into_either()
        .expect("builder usages")
        .into_iter()
        .collect();
    assert_hit_contains(&builder_hits, "Builder newBuilder()");
    assert_hit_contains(&builder_hits, "Builder builder()");

    let generated = definition(&analyzer, "com.example.Generated");
    let generated_hits: Vec<_> = strategy
        .find_usages(&analyzer, &[generated], &candidates, 1000)
        .into_either()
        .expect("generated usages")
        .into_iter()
        .collect();
    assert_hit_contains(&generated_hits, "com.example.Generated self()");

    let default_instance = definition(&analyzer, "com.example.Generated.DEFAULT_INSTANCE");
    let default_hits: Vec<_> = strategy
        .find_usages(&analyzer, &[default_instance], &candidates, 1000)
        .into_either()
        .expect("default instance usages")
        .into_iter()
        .collect();
    assert_hit_contains(&default_hits, "DEFAULT_INSTANCE = new Generated()");

    let unrecognized = definition(&analyzer, "com.example.Generated.Mode.UNRECOGNIZED");
    let enum_hits: Vec<_> = strategy
        .find_usages(&analyzer, &[unrecognized], &candidates, 1000)
        .into_either()
        .expect("enum constant usages")
        .into_iter()
        .collect();
    assert_hit_contains(&enum_hits, "return UNRECOGNIZED");
}

#[test]
fn java_graph_strategy_counts_generated_static_instance_and_fluent_calls() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Formatter.java",
            r#"
package com.example;

public class Formatter {
    public static class Pair<Left, Right> {}

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Formatter create(Pair<String, String> value) {
        return new Formatter();
    }

    public static class Builder {
        public Builder setPath(String path, Pair<String, String> value) {
            return this;
        }

        public Builder setQuery(Pair<String, String> query) {
            return this;
        }
    }

    public void write(Pair<String, String> value) {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    private final Formatter formatter = Formatter.create(null);

    void call() {
        Formatter.create(null);
        formatter.write(null);
        Formatter.newBuilder().setPath("path", null).setQuery(null);
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    for (target, expected) in [
        ("com.example.Formatter.create", "Formatter.create(null)"),
        ("com.example.Formatter.write", "formatter.write"),
        ("com.example.Formatter.Builder.setQuery", ".setQuery"),
    ] {
        let target = definition(&analyzer, target);
        let hits = hits(JavaUsageGraphStrategy::new().find_usages(
            &analyzer,
            &[target],
            &candidates,
            1000,
        ));
        assert_hit_contains(&hits, expected);
    }
}

#[test]
fn java_graph_strategy_accepts_any_supplied_overload_arity() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Factory.java",
            r#"
package com.example;

public class Factory {
    public static Factory create(String first) { return new Factory(); }
    public static Factory create(String first, String second) { return new Factory(); }
    public static Factory create(int first) { return new Factory(); }
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Factory value = Factory.create("first", "second");
}
"#,
        ),
    ]);

    let targets: Vec<_> = analyzer
        .get_definitions("com.example.Factory.create")
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect();
    assert_eq!(3, targets.len());
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits =
        hits(JavaUsageGraphStrategy::new().find_usages(&analyzer, &targets, &candidates, 1000));
    assert_hit_contains(&hits, "Factory.create(\"first\", \"second\")");
}

#[test]
fn java_graph_strategy_counts_static_imported_nested_type() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Owner.java",
            r#"
package com.example;

public class Owner {
    public static class Nested {}
}
"#,
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

import static com.example.Owner.Nested;

public class Consumer {
    Nested value;
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "com.example.Owner.Nested");
    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    assert!(
        result.all_hits_including_imports().iter().any(|hit| hit
            .snippet
            .contains("import static com.example.Owner.Nested")),
        "the structured static import path should be retained as editor-visible evidence"
    );
}

#[test]
fn java_graph_strategy_uses_java_fqn_identity_across_duplicate_source_copies() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "copy-one/com/example/Owner.java",
            "package com.example; public class Owner { public Owner() {} public static void create() {} }\n",
        ),
        (
            "copy-two/com/example/Owner.java",
            "package com.example; public class Owner { public Owner() {} public static void create() {} }\n",
        ),
        (
            "consumer/com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    Owner value = new Owner();

    void call() {
        Owner.create();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let owners: Vec<_> = analyzer
        .get_definitions("com.example.Owner")
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect();
    let creates: Vec<_> = analyzer
        .get_definitions("com.example.Owner.create")
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect();
    let constructors: Vec<_> = analyzer
        .get_definitions("com.example.Owner.Owner")
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect();
    assert_eq!(2, owners.len());
    assert_eq!(2, creates.len());
    assert_eq!(2, constructors.len());

    for owner in owners {
        let hits =
            hits(JavaUsageGraphStrategy::new().find_usages(&analyzer, &[owner], &candidates, 1000));
        assert_hit_contains(&hits, "Owner value");
    }
    for create in creates {
        let hits = hits(JavaUsageGraphStrategy::new().find_usages(
            &analyzer,
            &[create],
            &candidates,
            1000,
        ));
        assert_hit_contains(&hits, "Owner.create()");
    }
    for constructor in constructors {
        let hits = hits(JavaUsageGraphStrategy::new().find_usages(
            &analyzer,
            &[constructor],
            &candidates,
            1000,
        ));
        assert_hit_contains(&hits, "new Owner()");
    }
}

#[test]
fn java_graph_strategy_counts_anonymous_class_typed_receiver_usage() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Base.java",
            "package com.example; public class Base { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void execute() {
        Base base = new Base() {
            void helper() {
                this.run();
            }
        };
        base.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Base.run");
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method_target),
        &candidates,
        1000,
    );
    // `base.run()` (a distinct instance) is an external usage; `this.run()` inside
    // the anonymous class is a same-owner site, editor-only under #1014 facet B.
    let external = result
        .clone()
        .into_either()
        .expect("typed receiver success");
    assert_eq!(1, external.len(), "expected only base.run(): {external:#?}");
    assert!(
        external
            .iter()
            .all(|hit| hit.snippet.contains("base.run()")),
        "{external:#?}"
    );
    assert_eq!(
        1,
        self_receiver_hits(&result).len(),
        "expected this.run() as a same-owner hit"
    );
}

#[test]
fn java_graph_strategy_reports_too_many_callsites_for_high_fanout_symbol() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target { public void run() {} }\n",
        ),
        (
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Target target) {
        target.run();
        target.run();
        target.run();
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let method_target = definition(&analyzer, "com.example.Target.run");
    let result = JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method_target),
        &candidates,
        1,
    );

    match result {
        FuzzyResult::TooManyCallsites {
            short_name,
            total_callsites,
            limit,
            ..
        } => {
            assert_eq!("Target.run", short_name);
            assert_eq!(1, limit);
            assert!(total_callsites > limit);
        }
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn java_graph_finds_java_type_usages_from_scala_source() {
    let consumer_source = r#"
package app

import com.example.Target

class ScalaConsumer {
  val annotated: Target = new Target()
}

class ScalaChild extends Target

class ScalaFq {
  val fq: com.example.Target = new com.example.Target()
}
"#;
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public void run() {}
}
"#,
        ),
        ("app/ScalaConsumer.scala", consumer_source),
    ]);

    let target = definition(&java, "com.example.Target");
    let result = UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target));
    let hits = hits(result);

    assert_hit_contains(&hits, "annotated: Target");
    assert_hit_contains(&hits, "new Target()");
    assert_hit_contains(&hits, "extends Target");
    assert_hit_contains(&hits, "com.example.Target");

    assert_hit_line(&hits, line_of(consumer_source, "val annotated"));
    assert_hit_line(&hits, line_of(consumer_source, "class ScalaChild"));
    assert_hit_line(&hits, line_of(consumer_source, "val fq"));
}

#[test]
fn java_type_usage_lookup_merges_java_and_scala_source_hits() {
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        (
            "com/example/JavaConsumer.java",
            r#"
package com.example;

public class JavaConsumer {
    Target target;
}
"#,
        ),
        (
            "app/ScalaConsumer.scala",
            r#"
package app

import com.example.Target

class ScalaConsumer {
  val target: Target = new Target()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Target");
    let hits = hits(UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target)));

    assert_hit_contains(&hits, "Target target");
    assert_hit_contains(&hits, "target: Target");
}

#[test]
fn java_type_usage_lookup_handles_same_package_and_wildcard_scala_imports() {
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        (
            "com/example/SamePackage.scala",
            r#"
package com.example

class SamePackage {
  val target: Target = new Target()
}
"#,
        ),
        (
            "app/WildcardConsumer.scala",
            r#"
package app

import com.example._

class WildcardConsumer {
  val target: Target = new Target()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Target");
    let hits = hits(UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target)));

    assert_hit_contains(&hits, "class SamePackage");
    assert_hit_contains(&hits, "class WildcardConsumer");
}

#[test]
fn java_type_usage_lookup_respects_usage_finder_file_filter_for_scala_hits() {
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        (
            "app/Included.scala",
            r#"
package app

import com.example.Target

class Included {
  val target: Target = new Target()
}
"#,
        ),
        (
            "app/Excluded.scala",
            r#"
package app

import com.example.Target

class Excluded {
  val target: Target = new Target()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Target");
    let hits = hits(
        UsageFinder::new()
            .with_file_filter(|file| !file.rel_path().to_string_lossy().contains("Excluded.scala"))
            .find_usages_default(&multi, std::slice::from_ref(&target)),
    );

    assert_hit_contains(&hits, "class Included");
    assert_no_hit_contains(&hits, "class Excluded");
}

#[test]
fn java_type_usage_lookup_ignores_scala_local_type_shadowing() {
    let consumer_source = r#"
package app

import com.example.Target

class Consumer {
  class Target
  val shadowed: Target = new Target()
  val fq: com.example.Target = new com.example.Target()
}
"#;
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            "package com.example; public class Target {}\n",
        ),
        ("app/Consumer.scala", consumer_source),
    ]);

    let target = definition(&java, "com.example.Target");
    let hits = hits(UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target)));

    assert_no_hit_line(&hits, line_of(consumer_source, "shadowed: Target"));
    assert_hit_contains(&hits, "com.example.Target");
}

#[test]
fn java_nested_type_usage_lookup_requires_import_or_qualification_in_scala() {
    let same_package_source = r#"
package com.example

class SamePackage {
  val plain: Inner = ???
  val qualified: Outer.Inner = new Outer.Inner()
}
"#;
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Outer.java",
            r#"
package com.example;

public class Outer {
    public static class Inner {}
}
"#,
        ),
        ("com/example/SamePackage.scala", same_package_source),
        (
            "app/Imported.scala",
            r#"
package app

import com.example.Outer.Inner

class Imported {
  val imported: Inner = new Inner()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Outer.Inner");
    let hits = hits(UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target)));

    assert_no_hit_line(&hits, line_of(same_package_source, "plain: Inner"));
    assert_hit_contains(&hits, "qualified: Outer.Inner");
    assert_hit_contains(&hits, "imported: Inner");
}

#[test]
fn java_member_usage_lookup_does_not_claim_scala_source_hits() {
    let (_project, java, _scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
    public void run() {}
}
"#,
        ),
        (
            "app/ScalaConsumer.scala",
            r#"
package app

import com.example.Target

class ScalaConsumer {
  def call(target: Target): Unit = target.run()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Target.run");
    let hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &multi,
        std::slice::from_ref(&target),
        &multi.get_analyzed_files().into_iter().collect(),
        1000,
    ));

    assert_no_hit_contains(&hits, "target.run()");
}

#[test]
fn scala_target_usage_lookup_does_not_scan_java_source() {
    let (_project, _java, scala, multi) = mixed_jvm_analyzer_with_files(&[
        (
            "pkg/ScalaTarget.scala",
            r#"
package pkg

class ScalaTarget
"#,
        ),
        (
            "com/example/JavaConsumer.java",
            r#"
package com.example;

public class JavaConsumer {
    Object target = new ScalaTarget();
}
"#,
        ),
    ]);

    let target = scala_definition(&scala, "pkg.ScalaTarget");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &multi,
        std::slice::from_ref(&target),
        &multi.get_analyzed_files().into_iter().collect(),
        1000,
    ));

    assert_no_hit_contains(&hits, "new ScalaTarget()");
}

#[test]
fn java_graph_strategy_types_try_resource_receivers_without_leaking_the_binding() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "other/Indexer.java",
            "package other; public class Indexer { public void run() {} }\n",
        ),
        (
            "app/SentenceSourceIndexer.java",
            r#"
package app;

import other.Indexer;

public class SentenceSourceIndexer implements AutoCloseable {
    private Indexer indexer;

    public void execute() throws Exception {
        try (SentenceSourceIndexer indexer = new SentenceSourceIndexer()) {
            indexer.run(); // resource-receiver
        }
        indexer.run(); // field-receiver-after-try
    }

    public void run() {}
    public void close() {}
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let local_run = definition(&analyzer, "app.SentenceSourceIndexer.run");
    let local_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&local_run),
        &candidates,
        1000,
    ));
    assert_hit_contains(&local_hits, "resource-receiver");
    assert_no_hit_contains(&local_hits, "field-receiver-after-try");

    let imported_run = definition(&analyzer, "other.Indexer.run");
    let imported_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&imported_run),
        &candidates,
        1000,
    ));
    assert_hit_contains(&imported_hits, "field-receiver-after-try");
    assert_no_hit_contains(&imported_hits, "resource-receiver");
}

#[test]
fn java_graph_strategy_maps_lombok_accessor_usages_back_to_fields() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "app/Accessors.java",
            r#"
package app;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Accessors {
    String name;
    boolean ready;
}
"#,
        ),
        (
            "app/Shadowed.java",
            r#"
package app;

import lombok.Getter;

@Getter
public class Shadowed {
    String name;

    public String getName() {
        return name;
    }
}
"#,
        ),
        (
            "app/Plain.java",
            r#"
package app;

public class Plain {
    String name;
}
"#,
        ),
        (
            "app/Consumer.java",
            r#"
package app;

public class Consumer {
    void call(Accessors accessors, Shadowed shadowed, Plain plain) {
        accessors.getName(); // generated-getter-call
        accessors.setName("value"); // generated-setter-call
        accessors.isReady(); // generated-boolean-getter-call
        java.util.function.Function<Accessors, String> getter = Accessors::getName; // generated-getter-reference
        java.util.function.BiConsumer<Accessors, String> setter = Accessors::setName; // generated-setter-reference
        java.util.function.Predicate<Accessors> ready = Accessors::isReady; // generated-boolean-getter-reference

        accessors.isName(); // rejected-non-boolean-is-getter
        accessors.getName("unexpected"); // rejected-getter-arity
        accessors.setName(); // rejected-setter-arity
        shadowed.getName(); // rejected-declared-method-shadow
        java.util.function.Function<Shadowed, String> shadowedRef = Shadowed::getName; // rejected-declared-method-reference
        plain.getName(); // rejected-without-lombok
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = JavaUsageGraphStrategy::new();

    let name = definition(&analyzer, "app.Accessors.name");
    let name_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&name), &candidates, 1000));
    assert_hit_contains(&name_hits, "generated-getter-call");
    assert_hit_contains(&name_hits, "generated-setter-call");
    assert_hit_contains(&name_hits, "generated-getter-reference");
    assert_hit_contains(&name_hits, "generated-setter-reference");
    assert_no_hit_contains(&name_hits, "rejected-non-boolean-is-getter");
    assert_no_hit_contains(&name_hits, "rejected-getter-arity");
    assert_no_hit_contains(&name_hits, "rejected-setter-arity");

    let ready = definition(&analyzer, "app.Accessors.ready");
    let ready_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&ready), &candidates, 1000));
    assert_hit_contains(&ready_hits, "generated-boolean-getter-call");
    assert_hit_contains(&ready_hits, "generated-boolean-getter-reference");

    let shadowed = definition(&analyzer, "app.Shadowed.name");
    let shadowed_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&shadowed),
        &candidates,
        1000,
    ));
    assert_no_hit_contains(&shadowed_hits, "rejected-declared-method-shadow");
    assert_no_hit_contains(&shadowed_hits, "rejected-declared-method-reference");

    let plain = definition(&analyzer, "app.Plain.name");
    let plain_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&plain), &candidates, 1000));
    assert_no_hit_contains(&plain_hits, "rejected-without-lombok");
}
