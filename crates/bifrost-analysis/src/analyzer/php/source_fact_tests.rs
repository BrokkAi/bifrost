use super::PhpAnalyzer;
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, Language, OverlayProject, ProjectFile, resolve_analyzer,
};
use crate::inline_project::InlineTestProject;
use crate::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::php_facts::{
    PhpDeclarationKind, PhpDeclaredSourceType, PhpFieldWriteKind,
};
use brokk_bifrost_php::aliases::PhpDeclaredType;
use brokk_bifrost_php::graph::syntax::{
    canonical_declared_type, canonical_doc_element_type, canonical_doc_nominal_type,
    canonical_field_element_type, canonical_inferred_field_type,
};
use brokk_bifrost_php::graph_support::{php_direct_declared_class_parent, php_is_trait};
use brokk_bifrost_php::source_facts::PhpSourceFactProvider;
use std::collections::BTreeSet;
use std::sync::Arc;

const CANONICAL_SOURCE: &str = r#"<?php
namespace App;

class ParentService {}
class Value {}
trait Timestamped {}

class Service extends ParentService {
    use Timestamped;

    public Value $value;

    /** @var array<string, Value> */
    public array $values;

    /** @return Value */
    public function documented(): self {
        return new Value();
    }

    /** @param array<string, Value> $values */
    public function __construct(Value $value, array $values) {
        $this->value = $value;
        $this->values = $values;
    }
}
"#;

const TYPE_A_SOURCE: &str = r#"<?php
namespace App;

class A {}

class Service {
    public A $value;

    /** @return A */
    public function documented(): A {
        return new A();
    }

    public function __construct(A $value) {
        $this->value = $value;
    }
}
"#;

const TYPE_B_SOURCE: &str = r#"<?php
namespace App;

class B {}

class Service {
    public B $value;

    /** @return B */
    public function documented(): B {
        return new B();
    }

    public function __construct(B $value) {
        $this->value = $value;
    }
}
"#;

fn php_analyzer(workspace: &WorkspaceAnalyzer) -> &PhpAnalyzer {
    resolve_analyzer::<PhpAnalyzer>(workspace.analyzer()).expect("workspace has a PHP analyzer")
}

fn unit(php: &PhpAnalyzer, fqn: &str) -> CodeUnit {
    let mut definitions = php.definitions(fqn);
    let unit = definitions
        .next()
        .unwrap_or_else(|| panic!("missing PHP definition {fqn}"));
    assert!(
        definitions.next().is_none(),
        "expected one PHP definition for {fqn}"
    );
    unit
}

fn build_fixture(source: &str) -> (crate::inline_project::BuiltInlineTestProject, ProjectFile) {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("src/Service.php", source)
        .build();
    let file = fixture.file("src/Service.php");
    (fixture, file)
}

fn assert_canonical_properties(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    expected_type: &str,
    expected_declared_type: &str,
) {
    let php = php_analyzer(workspace);
    let service = unit(php, "App.Service");
    let value = unit(php, "App.Service.value");
    let documented = unit(php, "App.Service.documented");

    assert_eq!(
        canonical_declared_type(php, &documented),
        PhpDeclaredType::Nominal(vec![expected_declared_type.to_owned()]),
        "declared return type for {expected_type}"
    );
    assert_eq!(
        canonical_doc_nominal_type(php, &documented).as_deref(),
        Some(expected_type),
        "PHPDoc return type for {expected_type}"
    );
    assert_eq!(
        canonical_inferred_field_type(php, &value).as_deref(),
        Some(expected_type),
        "constructor field inference for {expected_type}"
    );

    let facts = php
        .php_source_facts(file)
        .expect("canonical PHP source facts should be available");
    let service_fact = facts
        .declarations_for(&service)
        .find(|declaration| declaration.kind == PhpDeclarationKind::Class)
        .expect("Service declaration fact");
    assert!(facts.facts.writes.iter().any(|write| {
        write.class == service_fact.declaration
            && write.field == "value"
            && write.kind == PhpFieldWriteKind::Instance
            && write.directly_in_constructor
            && write.value_type == PhpDeclaredSourceType::Nominal(vec![expected_type.to_owned()])
    }));
}

fn assert_context_properties(workspace: &WorkspaceAnalyzer, file: &ProjectFile) {
    let php = php_analyzer(workspace);
    let service = unit(php, "App.Service");
    let values = unit(php, "App.Service.values");
    let parent = unit(php, "App.ParentService");
    let trait_unit = unit(php, "App.Timestamped");

    assert_eq!(
        canonical_doc_element_type(php, &values).as_deref(),
        Some("App.Value")
    );
    assert_eq!(
        canonical_field_element_type(php, &values).as_deref(),
        Some("App.Value")
    );
    assert_eq!(
        php_direct_declared_class_parent(php, &service),
        Some(parent)
    );
    assert!(php_is_trait(php, &trait_unit));

    let facts = php
        .php_source_facts(file)
        .expect("canonical PHP source facts should be available");
    assert!(
        facts
            .declarations_for(&service)
            .any(|declaration| declaration.has_trait_use)
    );
}

#[test]
fn canonical_php_properties_survive_persisted_reopen_and_dirty_overlay() {
    let (fixture, file) = build_fixture(CANONICAL_SOURCE);
    let disk_workspace =
        WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
            .expect("persisted PHP workspace should build");
    let php = php_analyzer(&disk_workspace);
    let documented = unit(php, "App.Service.documented");

    assert_eq!(
        canonical_declared_type(php, &documented),
        PhpDeclaredType::Nominal(vec!["App.Service".to_owned()])
    );
    assert_eq!(
        canonical_doc_nominal_type(php, &documented).as_deref(),
        Some("App.Value")
    );
    assert_context_properties(&disk_workspace, &file);
    assert_canonical_properties(&disk_workspace, &file, "App.Value", "App.Service");
    drop(disk_workspace);

    let reopened =
        WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
            .expect("persisted PHP workspace should reopen");
    assert_context_properties(&reopened, &file);
    assert_canonical_properties(&reopened, &file, "App.Value", "App.Service");
    drop(reopened);

    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(file.abs_path(), TYPE_B_SOURCE.to_owned()));
    let overlay_workspace = WorkspaceAnalyzer::build_persisted(overlay, AnalyzerConfig::default())
        .expect("dirty PHP overlay workspace should build");
    let overlay_php = php_analyzer(&overlay_workspace);
    let overlay_documented = unit(overlay_php, "App.Service.documented");
    assert_eq!(
        canonical_declared_type(overlay_php, &overlay_documented),
        PhpDeclaredType::Nominal(vec!["App.B".to_owned()])
    );
    assert_eq!(
        canonical_doc_nominal_type(overlay_php, &overlay_documented).as_deref(),
        Some("App.B")
    );

    drop(overlay_workspace);
    let disk_after_overlay =
        WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
            .expect("disk workspace should reopen after a dirty overlay");
    assert_canonical_properties(&disk_after_overlay, &file, "App.Value", "App.Service");
}

#[test]
fn canonical_php_properties_follow_update_from_a_to_b_to_a() {
    let (fixture, file) = build_fixture(TYPE_A_SOURCE);
    let workspace_a =
        WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
            .expect("initial persisted PHP workspace should build");
    assert_canonical_properties(&workspace_a, &file, "App.A", "App.A");

    file.write(TYPE_B_SOURCE).expect("write PHP B revision");
    let workspace_b = workspace_a.update(&BTreeSet::from([file.clone()]));
    assert_canonical_properties(&workspace_b, &file, "App.B", "App.B");

    file.write(TYPE_A_SOURCE).expect("restore PHP A revision");
    let workspace_again = workspace_b.update(&BTreeSet::from([file.clone()]));
    assert_canonical_properties(&workspace_again, &file, "App.A", "App.A");
}
