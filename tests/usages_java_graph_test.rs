mod common;

use brokk_bifrost::usages::FuzzyResult;
use brokk_bifrost::usages::{
    JavaUsageGraphStrategy, ScalaUsageGraphStrategy, UsageAnalyzer, UsageFinder, UsageHit,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ScalaAnalyzer,
};
use common::InlineTestProject;
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
fn java_graph_strategy_finds_method_constructor_field_and_type_usages() {
    let (project, analyzer) = java_analyzer_with_files(&[
        (
            "com/example/Target.java",
            r#"
package com.example;

public class Target {
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
    assert_eq!(1, method_hits.len());
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
    assert!(
        result.into_either().is_err(),
        "unproven shadowed call should fall back"
    );
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
    assert!(
        result.into_either().is_err(),
        "ambiguous static import should fall back instead of proving a hit"
    );
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
        } => {
            assert_eq!("Target.run", short_name);
            assert_eq!(1, limit);
            assert!(total_callsites > limit);
        }
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn java_type_usage_lookup_includes_proven_scala_source_hits() {
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
  val annotated: Target = new Target()
}
"#,
        ),
        (
            "app/ScalaChild.scala",
            r#"
package app

import com.example.Target

class ScalaChild extends Target
"#,
        ),
        (
            "app/ScalaFq.scala",
            r#"
package app

class ScalaFq {
  val fq: com.example.Target = new com.example.Target()
}
"#,
        ),
    ]);

    let target = definition(&java, "com.example.Target");
    let result = UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target));
    let hits = hits(result);

    assert_hit_contains(&hits, "Target target");
    assert_hit_contains(&hits, "annotated: Target");
    assert_hit_contains(&hits, "new Target()");
    assert_hit_contains(&hits, "extends Target");
    assert_hit_contains(&hits, "com.example.Target");
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
