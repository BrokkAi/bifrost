mod common;

use brokk_bifrost::usages::{FuzzyResult, PhpUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, PhpAnalyzer};
use common::InlineTestProject;

fn definition(analyzer: &PhpAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn php_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, PhpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Php);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn usage_finder_routes_php_targets_through_graph_strategy() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function build(): Target {
    return new Target();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "App.Target");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("php graph success");
    assert_eq!(2, hits.len());
}

#[test]
fn php_graph_resolves_same_namespace_fully_qualified_and_aliased_types() {
    let (project, analyzer) = php_analyzer_with_files(&[
        (
            "Service/Target.php",
            r#"<?php
namespace App\Service;
class Target {}
"#,
        ),
        (
            "SameNamespace.php",
            r#"<?php
namespace App\Service;
function same(Target $target): Target {
    return new Target();
}
"#,
        ),
        (
            "Qualified.php",
            r#"<?php
namespace App\Other;
function qualified(\App\Service\Target $target): \App\Service\Target {
    return new \App\Service\Target();
}
"#,
        ),
        (
            "Aliased.php",
            r#"<?php
namespace App\Other;
use App\Service\Target as ServiceTarget;
function aliased(ServiceTarget $target): ServiceTarget {
    return new ServiceTarget();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "App.Service.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PhpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("type graph success");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("SameNamespace.php"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Qualified.php"))
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Aliased.php"))
    );
}

#[test]
fn php_graph_finds_constructors_static_methods_and_constants() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public const VALUE = 1;
    public function __construct() {}
    public static function make(): Target { return new Target(); }
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(): void {
    new Target();
    Target::make();
    echo Target::VALUE;
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let constructor = definition(&analyzer, "App.Target.__construct");
    let constructor_hits = PhpUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&constructor),
            &candidates,
            1000,
        )
        .into_either()
        .expect("constructor success");
    assert_eq!(2, constructor_hits.len());

    let method = definition(&analyzer, "App.Target.make");
    let method_hits = PhpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("static method success");
    assert_eq!(1, method_hits.len());

    let constant = definition(&analyzer, "App.Target.VALUE");
    let const_hits = PhpUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&constant),
            &candidates,
            1000,
        )
        .into_either()
        .expect("constant success");
    assert_eq!(1, const_hits.len());
}

#[test]
fn php_graph_finds_instance_methods_and_properties_with_local_receiver_types() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public string $name;
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(Target $target): void {
    $target->run();
    $target->name = 'x';
    echo $target->name;
    $local = new Target();
    $local->run();
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let method = definition(&analyzer, "App.Target.run");
    let method_hits = PhpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&method), &candidates, 1000)
        .into_either()
        .expect("instance method success");
    assert_eq!(2, method_hits.len());

    let property = definition(&analyzer, "App.Target.name");
    let property_hits = PhpUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&property),
            &candidates,
            1000,
        )
        .into_either()
        .expect("property success");
    assert_eq!(2, property_hits.len());
}

#[test]
fn php_graph_finds_global_and_namespace_qualified_function_calls() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "functions.php",
            r#"<?php
namespace App\Service;
function helper(): void {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App\Service;
function consume(): void {
    helper();
    \App\Service\helper();
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "App.Service.helper");
    let hits = PhpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("function success");
    assert_eq!(2, hits.len());
}

#[test]
fn php_graph_ignores_unrelated_same_name_symbols_in_other_namespaces() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App\Service;
class Target {
    public function run(): void {}
}
"#,
        ),
        (
            "OtherTarget.php",
            r#"<?php
namespace App\Other;
class Target {
    public function run(): void {}
}
function consume(Target $target): void {
    $target->run();
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "App.Service.Target.run");
    let hits = PhpUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("negative success");
    assert!(hits.is_empty());
}

#[test]
fn php_graph_honors_max_usages() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(Target $a, Target $b): void {
    new Target();
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "App.Target");
    let result = PhpUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );
    assert!(matches!(result, FuzzyResult::TooManyCallsites { .. }));
}
