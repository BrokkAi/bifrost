mod common;

use brokk_bifrost::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, TypeHierarchyProvider};
use common::{BuiltInlineTestProject, InlineTestProject};
use std::collections::BTreeSet;

fn php_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, PhpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Php);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &PhpAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

#[test]
fn php_class_extends_resolves_direct_ancestor() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Types.php",
        r#"<?php
namespace App;
class Base {}
class Child extends Base {}
"#,
    )]);

    let child = definition(&analyzer, "App.Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["App.Base".to_string()])
    );
}

#[test]
fn php_class_implements_resolves_direct_interface_ancestors() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Types.php",
        r#"<?php
namespace App;
interface Runnable {}
interface Serializable {}
class Worker implements Runnable, Serializable {}
"#,
    )]);

    let worker = definition(&analyzer, "App.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["App.Runnable".to_string(), "App.Serializable".to_string()])
    );
}

#[test]
fn php_interface_extends_resolves_direct_ancestors() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Types.php",
        r#"<?php
namespace App;
interface ParentContract {}
interface ChildContract extends ParentContract {}
"#,
    )]);

    let child = definition(&analyzer, "App.ChildContract");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["App.ParentContract".to_string()])
    );
}

#[test]
fn php_direct_descendants_are_not_transitive() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Types.php",
        r#"<?php
namespace App;
class Base {}
class Child extends Base {}
class Grandchild extends Child {}
"#,
    )]);

    let base = definition(&analyzer, "App.Base");
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&base)),
        BTreeSet::from(["App.Child".to_string()])
    );
}

#[test]
fn php_hierarchy_resolves_aliased_and_fully_qualified_parents() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Contracts.php",
            r#"<?php
namespace Vendor\Contracts;
interface Runnable {}
class BaseWorker {}
"#,
        ),
        (
            "Worker.php",
            r#"<?php
namespace App;
use Vendor\Contracts\Runnable as RunContract;
class Worker extends \Vendor\Contracts\BaseWorker implements RunContract {}
"#,
        ),
    ]);

    let worker = definition(&analyzer, "App.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from([
            "Vendor.Contracts.BaseWorker".to_string(),
            "Vendor.Contracts.Runnable".to_string()
        ])
    );
}

#[test]
fn php_hierarchy_uses_declaring_namespace_in_multi_namespace_file() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Types.php",
        r#"<?php
namespace A {
    class Base {}
}
namespace B {
    class Base {}
    class Child extends Base {}
}
"#,
    )]);

    let child = definition(&analyzer, "B.Child");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&child)),
        BTreeSet::from(["B.Base".to_string()])
    );
}

#[test]
fn php_hierarchy_uses_aliases_scoped_to_declaring_namespace() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Bases.php",
            r#"<?php
namespace Lib\One {
    class Base {}
}
namespace Lib\Two {
    class Base {}
}
"#,
        ),
        (
            "Types.php",
            r#"<?php
namespace A {
    use Lib\One\Base as SharedBase;
    class First extends SharedBase {}
}
namespace B {
    use Lib\Two\Base as SharedBase;
    class Second extends SharedBase {}
}
"#,
        ),
    ]);

    let first = definition(&analyzer, "A.First");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&first)),
        BTreeSet::from(["Lib.One.Base".to_string()])
    );

    let second = definition(&analyzer, "B.Second");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&second)),
        BTreeSet::from(["Lib.Two.Base".to_string()])
    );
}
