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

fn graph_hits(
    analyzer: &PhpAnalyzer,
    fq_name: &str,
) -> std::collections::BTreeSet<brokk_bifrost::usages::UsageHit> {
    let target = definition(analyzer, fq_name);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    PhpUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .unwrap_or_else(|err| panic!("usage query failed for {fq_name}: {err}"))
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
    assert!(
        method_hits
            .iter()
            .any(|hit| hit.snippet.contains("$target->run();"))
    );
    assert!(
        method_hits
            .iter()
            .any(|hit| hit.snippet.contains("$local->run();"))
    );

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

#[test]
fn php_graph_resolves_grouped_unaliased_function_and_const_imports() {
    let (project, analyzer) = php_analyzer_with_files(&[
        (
            "Lib.php",
            r#"<?php
namespace Vendor\Package;
class Target {}
function helper(): void {}
const LIMIT = 10;
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
use Vendor\Package\{Target, helper as run_helper, LIMIT};
function consume(): void {
    new Target();
    run_helper();
    echo LIMIT;
}
"#,
        ),
    ]);

    let type_hits = graph_hits(&analyzer, "Vendor.Package.Target");
    assert!(
        type_hits
            .iter()
            .any(|hit| hit.file == project.file("Consumer.php"))
    );

    let function_hits = graph_hits(&analyzer, "Vendor.Package.helper");
    assert_eq!(1, function_hits.len());

    let const_hits = graph_hits(&analyzer, "Vendor.Package._module_.LIMIT");
    assert_eq!(1, const_hits.len());
}

#[test]
fn php_graph_resolves_imported_namespace_alias_suffixes() {
    let (project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace Vendor\Package;
class Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
use Vendor\Package as Pkg;
function consume(): void {
    new Pkg\Target();
}
"#,
        ),
    ]);

    let hits = graph_hits(&analyzer, "Vendor.Package.Target");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("Consumer.php"))
    );
}

#[test]
fn php_graph_counts_inheritance_trait_and_rich_type_references() {
    let (project, analyzer) = php_analyzer_with_files(&[
        (
            "Types.php",
            r#"<?php
namespace App\Contracts;
interface Service {}
trait SharedTrait {}
class Base {}
class Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App\Feature;
use App\Contracts\Base;
use App\Contracts\Service;
use App\Contracts\SharedTrait;
use App\Contracts\Target;

class Child extends Base implements Service {
    use SharedTrait;
    private ?Target $nullable;
    public Target|Base $union;
    public Target&Service $intersection;

    public function consume(Target $target): ?Target {
        return $target;
    }
}
"#,
        ),
    ]);

    let base_hits = graph_hits(&analyzer, "App.Contracts.Base");
    assert!(
        base_hits
            .iter()
            .any(|hit| hit.file == project.file("Consumer.php"))
    );

    let interface_hits = graph_hits(&analyzer, "App.Contracts.Service");
    assert!(
        interface_hits
            .iter()
            .any(|hit| hit.file == project.file("Consumer.php"))
    );

    let trait_hits = graph_hits(&analyzer, "App.Contracts.SharedTrait");
    assert!(
        trait_hits
            .iter()
            .any(|hit| hit.file == project.file("Consumer.php"))
    );

    let target_hits = graph_hits(&analyzer, "App.Contracts.Target");
    assert!(
        target_hits
            .iter()
            .filter(|hit| hit.file == project.file("Consumer.php"))
            .count()
            >= 4,
        "expected nullable/property/parameter/return Target references, got {target_hits:?}"
    );
}

#[test]
fn php_graph_does_not_treat_class_trait_use_as_namespace_import() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App\Real;
class SharedTrait {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App\Feature;
class Consumer {
    use SharedTrait;

    public function call(SharedTrait $trait): void {
        $trait->run();
    }
}
"#,
        ),
    ]);

    let hits = graph_hits(&analyzer, "App.Real.SharedTrait.run");
    assert!(
        hits.is_empty(),
        "class trait-use should not import App.Real.SharedTrait"
    );
}

#[test]
fn php_graph_resolves_this_self_static_and_parent_member_references() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Target.php",
        r#"<?php
namespace App;
class Base {
    public static function inherited(): void {}
}
class Target extends Base {
    public static string $label;
    public const VALUE = 1;
    public function run(): void {}

    public function callThis(): void {
        $this->run();
        $this->label = 'x';
    }

    public static function callStatic(): void {
        self::VALUE;
        static::$label;
        parent::inherited();
    }
}
"#,
    )]);

    assert_eq!(1, graph_hits(&analyzer, "App.Target.run").len());
    assert_eq!(2, graph_hits(&analyzer, "App.Target.label").len());
    assert_eq!(1, graph_hits(&analyzer, "App.Target.VALUE").len());
    assert_eq!(1, graph_hits(&analyzer, "App.Base.inherited").len());
}

#[test]
fn php_graph_counts_inherited_and_concrete_interface_receivers() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Service.php",
            r#"<?php
namespace App;
interface Service {
    public function run(): void;
}
class Target implements Service {
    public function run(): void {}
}
class Child extends Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function byInterface(Service $service): void {
    $service->run();
}
function byChild(Child $child): void {
    $child->run();
}
"#,
        ),
    ]);

    assert_eq!(1, graph_hits(&analyzer, "App.Target.run").len());
    assert_eq!(1, graph_hits(&analyzer, "App.Service.run").len());
}

#[test]
fn php_graph_counts_interface_member_when_concrete_receiver_is_proven() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Service.php",
            r#"<?php
namespace App;
interface Service {
    public function run(): void;
}
class Target implements Service {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(): void {
    $target = new Target();
    $target->run();
}
"#,
        ),
    ]);

    assert_eq!(1, graph_hits(&analyzer, "App.Service.run").len());
}

#[test]
fn php_graph_keeps_interface_typed_receiver_unproven() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Service.php",
            r#"<?php
namespace App;
interface Service {
    public function run(): void;
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(Service $service): void {
    $service->run();
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Service.run").is_empty());
}

#[test]
fn php_graph_blocks_shadowed_reassigned_unknown_and_sibling_receivers() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
}
class Other {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function shadow(Target $target): void {
    $target = new Other();
    $target->run();
}
function unknown($target): void {
    $target->run();
}
function sibling(Target $target): void {}
function otherSibling($target): void {
    $target->run();
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
}

#[test]
fn php_graph_scopes_receiver_facts_to_enclosing_functions() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function first(Target $target): void {
}
function second($target): void {
    $target->run();
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
}

#[test]
fn php_graph_invalidates_receiver_after_unknown_reassignment() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(Target $target, mixed $other): void {
    $target = $other;
    $target->run();
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
}

#[test]
fn php_graph_resolves_simple_local_receiver_aliases() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function consume(Target $target): void {
    $alias = $target;
    $alias->run();
}
"#,
        ),
    ]);

    assert_eq!(1, graph_hits(&analyzer, "App.Target.run").len());
}

#[test]
fn php_graph_ignores_dynamic_class_function_and_member_forms() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
    public string $name;
}
function helper(): void {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function dynamic(): void {
    $class = Target::class;
    new $class();
    $method = 'run';
    $property = 'name';
    $target = new Target();
    $target->$method();
    echo $target->$property;
    $fn = 'helper';
    $fn();
    include 'Target.php';
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
    assert!(graph_hits(&analyzer, "App.Target.name").is_empty());
    assert!(graph_hits(&analyzer, "App.helper").is_empty());
}

#[test]
fn php_graph_ignores_magic_methods_and_properties_as_dynamic_dispatch() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {
    public function run(): void {}
    public string $name;
}
"#,
        ),
        (
            "MagicProxy.php",
            r#"<?php
namespace App;
class MagicProxy {
    public function __call(string $name, array $args): mixed {
        return null;
    }

    public function __get(string $name): mixed {
        return null;
    }
}
function consume(MagicProxy $proxy): void {
    $proxy->run();
    echo $proxy->name;
}
"#,
        ),
    ]);

    assert!(graph_hits(&analyzer, "App.Target.run").is_empty());
    assert!(graph_hits(&analyzer, "App.Target.name").is_empty());
}
