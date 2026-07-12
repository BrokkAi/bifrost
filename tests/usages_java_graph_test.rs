mod common;

use brokk_bifrost::usages::FuzzyResult;
use brokk_bifrost::usages::{
    JavaUsageGraphStrategy, ScalaUsageGraphStrategy, UsageAnalyzer, UsageFinder, UsageHit,
    UsageHitKind,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ScalaAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json};
use serde_json::json;
use std::collections::BTreeMap;

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

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|line| line + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
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
fn java_graph_strategy_connects_interface_methods_to_overrides_and_concrete_calls() {
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

    assert_eq!(3, method_hits.len(), "expected override plus two calls");
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
    assert!(
        snippets
            .iter()
            .any(|snippet| snippet.contains("impl.run()")),
        "concrete receiver call should be a reference: {snippets:#?}"
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
            "com/example/Consumer.java",
            r#"
package com.example;

public class Consumer {
    void call(Service service, ServiceImpl impl, Base base) {
        service.run("x");
        impl.run("x");
        base.run(new Object());
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

    let interface_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&interface_target),
        &candidates,
        1000,
    ));
    assert_hit_contains(&interface_hits, "void run(String arg)");
    assert_hit_contains(&interface_hits, "service.run(\"x\")");
    assert_hit_contains(&interface_hits, "impl.run(\"x\")");
    assert_no_hit_contains(&interface_hits, "void run(Object arg)");
    assert!(
        interface_hits.iter().all(|hit| hit.line != 8),
        "base.run(Object) should not be an interface run(String) usage: {interface_hits:#?}"
    );

    let concrete_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&concrete_target),
        &candidates,
        1000,
    ));
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
    assert_success_counts(result, &method_target, 0, 1);
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
    let direct_hits = hits(JavaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));
    assert_eq!(2, direct_hits.len(), "{direct_hits:#?}");
    assert!(
        direct_hits
            .iter()
            .all(|hit| hit.snippet.contains("() -> isReady(triggerPaths)")),
        "{direct_hits:#?}"
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
    assert_eq!("found", entry["status"], "{scan}");
    assert_eq!(2, entry["total_hits"], "{scan}");
    assert_eq!(0, entry["unproven_hits"], "{scan}");
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
    assert_success_counts(result, &method_target, 0, 1);
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
fn java_graph_strategy_keeps_nested_constructor_usage_narrow() {
    let (_project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Service.java",
            r#"
package com.example;

public class Service {
    public Service(Repository repository) {}

    public static class Repository {
        public Repository() {}
    }
}
"#,
        ),
        (
            "com/example/ServiceTest.java",
            r#"
package com.example;

public class ServiceTest {
    public void runsService() {
        Service.Repository repository = new Service.Repository();
        Service service = new Service(repository);
    }
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let service_constructor = definition(&analyzer, "com.example.Service.Service");
    let repository_constructor = definition(&analyzer, "com.example.Service.Repository.Repository");

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
    let hits = JavaUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&method_target),
            &candidates,
            1000,
        )
        .into_either()
        .expect("anonymous typed receiver success");
    assert_eq!(
        2,
        hits.len(),
        "expected this.run() inside anon class and base.run()"
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
