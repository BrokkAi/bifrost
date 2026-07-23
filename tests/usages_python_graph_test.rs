mod common;

use brokk_bifrost::usages::{PythonExportUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, PythonAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json};
use serde_json::json;
use std::collections::BTreeMap;

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn assert_single_python_member_hit(service: &str, consumer: &str) {
    assert_single_python_member_hit_for("service.Foo.bar", service, consumer);
}

fn assert_single_python_member_hit_for(fq_name: &str, service: &str, consumer: &str) {
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", service)
        .file("consumer.py", consumer)
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, fq_name);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve Python member usage");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.py"))
    );
}

fn assert_no_python_member_hit(service: &str, consumer: &str) {
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", service)
        .file("consumer.py", consumer)
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Foo.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should return success for member query");
    assert!(hits.is_empty(), "member query should not find proven hits");
}

#[test]
fn constructor_keyword_argument_is_a_field_usage() {
    assert_single_python_member_hit(
        "class Foo:\n    bar: int\n",
        "from service import Foo\n\nvalue = Foo(bar=1)\n",
    );
}

#[test]
fn subclass_constructor_keyword_argument_is_an_inherited_field_usage() {
    assert_single_python_member_hit_for(
        "service.Base.bar",
        "class Base:\n    bar: int\n\nclass Child(Base):\n    pass\n",
        "from service import Child\n\nvalue = Child(bar=1)\n",
    );
}

#[test]
fn call_result_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        "class Foo:\n    bar: int\n\ndef build() -> Foo:\n    return Foo()\n",
        "from service import build\n\nbuild().bar = 1\n",
    );
}

#[test]
fn shadowed_bare_factory_does_not_resolve_member_usage() {
    assert_no_python_member_hit(
        "class Foo:\n    bar: int\n\ndef build() -> Foo:\n    return Foo()\n",
        "from service import build\n\ndef read(build):\n    return build().bar\n",
    );
}

#[test]
fn imported_alias_annotation_resolves_receiver_member_usage() {
    assert_single_python_member_hit(
        "class Foo:\n    bar: int\n",
        "from service import Foo as Alias\n\ndef read(value: Alias):\n    return value.bar\n",
    );
}

#[test]
fn reexported_class_used_as_base_is_a_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/service.py", "class _Mixin:\n    pass\n")
        .file("pkg/__init__.py", "from .service import _Mixin\n")
        .file(
            "consumer.py",
            "from pkg import _Mixin\n\nclass Child(_Mixin):\n    pass\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service._Mixin");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve the re-exported class base");

    assert_eq!(
        hits.len(),
        1,
        "expected the class-base reference: {hits:#?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn private_class_is_not_reexported_by_wildcard() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/service.py", "class _Mixin:\n    pass\n")
        .file("pkg/__init__.py", "from .service import *\n")
        .file(
            "consumer.py",
            "from pkg import _Mixin\n\nclass Child(_Mixin):\n    pass\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service._Mixin");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should return success for a private wildcard query");

    assert!(
        hits.is_empty(),
        "wildcard must not expose private names: {hits:#?}"
    );
}

#[test]
fn absolute_import_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve absolute import");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn aliased_import_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service as ApiService

def run():
    return ApiService()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve aliased import");
    assert_eq!(hits.len(), 1);
}

#[test]
fn private_module_function_resolves_same_file_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def _helper():
    return "ok"

def run():
    return _helper()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service._helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve private same-file function usage");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(hit.file, project.file("service.py"));
    assert!(hit.snippet.contains("_helper()"), "{hit:#?}");
}

#[test]
fn private_module_function_resolves_explicit_import_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def _helper():
    return "ok"
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import _helper

def run():
    return _helper()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service._helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve private explicitly imported function usage");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(hit.snippet.contains("_helper()"), "{hit:#?}");
}

#[test]
fn reexported_class_alias_receiver_resolves_member_usages() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/shop/models.py",
            "from dataclasses import dataclass\n@dataclass\nclass User:\n    @classmethod\n    def guest(cls) -> \"User\":\n        return cls(\"guest\")\n    @staticmethod\n    def format_name(name: str) -> str:\n        return name.title()\n",
        )
        .file("src/shop/__init__.py", "from .models import User as Account\n")
        .file(
            "tests/test_models.py",
            "from shop import Account\nuser = Account.guest()\nAccount.format_name(\"ada\")\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    for (fqn, snippets) in [
        (
            "shop.models.User",
            vec!["Account.guest()", "Account.format_name"],
        ),
        ("shop.models.User.guest", vec!["Account.guest()"]),
        ("shop.models.User.format_name", vec!["Account.format_name"]),
    ] {
        let target = definition(&analyzer, fqn);
        let result = PythonExportUsageGraphStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        );
        let hits = result
            .into_either()
            .unwrap_or_else(|_| panic!("graph should resolve usages for {fqn}"));
        assert_eq!(hits.len(), snippets.len(), "{fqn}: {hits:#?}");
        assert!(
            hits.iter()
                .all(|hit| hit.file == project.file("tests/test_models.py")),
            "{fqn}: {hits:#?}"
        );
        for snippet in snippets {
            assert!(
                hits.iter().any(|hit| hit.snippet.contains(snippet)),
                "{fqn}: expected {snippet:?}, got {hits:#?}"
            );
        }
    }
}

#[test]
fn python_graph_counts_static_qualifier_references_for_class_targets() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Target:
    LIMIT = 7

    @staticmethod
    def static_helper():
        return Target.LIMIT

class Other:
    def touch(self):
        pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Target, Other

def run():
    Target.static_helper()
    value = Target.LIMIT

def shadowed():
    Target = Other()
    Target.touch()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Target");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve class-target static qualifiers");

    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Target.static_helper()")),
        "expected staticmethod qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Target.LIMIT")),
        "expected class attribute qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter()
            .all(|hit| !hit.snippet.contains("Target.touch()")),
        "local variable receiver must not count as class usage: {hits:#?}"
    );
}

#[test]
fn imported_factory_return_receiver_resolves_member_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/example/service.py",
            r#"
class Service:
    def execute(self, name):
        return name

def build_service():
    return Service()
"#,
        )
        .file(
            "src/example/__init__.py",
            "from .service import Service, build_service\n",
        )
        .file(
            "tests/test_service.py",
            r#"
from example import Service, build_service

def test_service_execution():
    service = build_service()
    service.execute(" Ada ")
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "example.service.Service.execute");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve imported factory return receiver");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(hit.file, project.file("tests/test_service.py"));
    assert!(hit.snippet.contains("service.execute"), "{hit:#?}");
}

#[test]
fn imported_classmethod_factory_return_receiver_resolves_property_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/shop/models.py",
            r#"
from dataclasses import dataclass

@dataclass
class User:
    name: str

    @property
    def normalized_name(self) -> str:
        return self.name.lower()

    @classmethod
    def guest(cls) -> "User":
        return cls("guest")

    @staticmethod
    def format_name(name: str) -> str:
        return name.title()

class DynamicConfig:
    def __getattr__(self, key: str) -> str:
        return key
"#,
        )
        .file(
            "src/shop/__init__.py",
            "from .models import User as Account\n",
        )
        .file(
            "tests/test_models.py",
            "from shop import Account\nfrom shop.models import DynamicConfig\nuser = Account.guest()\nAccount.format_name(\"ada\")\nuser.normalized_name\nconfig = DynamicConfig()\nconfig.theme\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "shop.models.User.normalized_name");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve classmethod factory return receiver");
    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(hit.file, project.file("tests/test_models.py"));
    assert!(hit.snippet.contains("user.normalized_name"), "{hit:#?}");
}

#[test]
fn classmethod_attribute_callee_return_resolves_member_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "config.py",
            r#"
class RTDETRConfig:
    input_size: int

    @classmethod
    def from_name(cls, name: str) -> "RTDETRConfig":
        return cls()
"#,
        )
        .file(
            "consumer.py",
            "from config import RTDETRConfig as Alias\n\nsize = Alias.from_name(\"r18\").input_size\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "config.RTDETRConfig.input_size");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve classmethod attribute-callee return usage");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(
        hit.snippet.contains("Alias.from_name(\"r18\").input_size"),
        "{hit:#?}"
    );
}

#[test]
fn classmethod_attribute_callee_return_does_not_match_unknown_factory_return() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "config.py",
            r#"
class RTDETRConfig:
    input_size: int

    @classmethod
    def from_name(cls, name: str):
        return cls()
"#,
        )
        .file(
            "consumer.py",
            "from config import RTDETRConfig\n\nsize = RTDETRConfig.from_name(\"r18\").input_size\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "config.RTDETRConfig.input_size");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for unknown factory returns");

    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn classmethod_attribute_callee_return_does_not_match_different_owner() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "config.py",
            r#"
class RTDETRConfig:
    input_size: int

class OtherConfig:
    input_size: int

    @classmethod
    def from_name(cls, name: str) -> "OtherConfig":
        return cls()
"#,
        )
        .file(
            "consumer.py",
            "from config import OtherConfig\n\nsize = OtherConfig.from_name(\"r18\").input_size\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "config.RTDETRConfig.input_size");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for different-owner factory returns");

    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn shadowed_class_name_does_not_match_attribute_callee_return_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "config.py",
            r#"
class RTDETRConfig:
    input_size: int

    @classmethod
    def from_name(cls, name: str) -> "RTDETRConfig":
        return cls()

class OtherConfig:
    @classmethod
    def from_name(cls, name: str) -> "OtherConfig":
        return cls()
"#,
        )
        .file(
            "consumer.py",
            "from config import RTDETRConfig, OtherConfig\n\n\
def shadow():\n    RTDETRConfig = OtherConfig\n    return RTDETRConfig.from_name(\"r18\").input_size\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "config.RTDETRConfig.input_size");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for shadowed class-name receivers");

    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn relative_import_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "pkg/consumer.py",
            r#"
from .service import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve relative import");
    assert_eq!(hits.len(), 1);
}

#[test]
fn package_barrel_reexport_resolves_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .service import Service
"#,
        )
        .file(
            "consumer.py",
            r#"
from pkg import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve barrel re-export");
    assert_eq!(hits.len(), 1);
}

#[test]
fn public_scoped_barrel_usage_does_not_parse_or_leak_transitive_files() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            "class Foo:\n    def bar(self):\n        pass\n",
        )
        .file("pkg/__init__.py", "from .service import Foo\n")
        .file(
            "in_scope.py",
            "from pkg import Foo\n\ndef run():\n    Foo().bar()\n",
        )
        .file(
            "out_of_scope.py",
            "from pkg import Foo\n\ndef run():\n    Foo().bar()\n",
        )
        .file("unknown.py", "def run(value):\n    value.bar()\n")
        .build();

    let proven = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["pkg.service.Foo"],
            "include_tests": true,
            "paths": ["in_scope.py"]
        })
        .to_string(),
    );
    let proven_result = &proven["results"][0];
    assert_eq!(1, proven_result["total_hits"], "{proven}");
    assert_eq!(0, proven_result["unproven_hits"], "{proven}");
    assert_eq!("in_scope.py", proven_result["files"][0]["path"], "{proven}");

    let unproven = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["pkg.service.Foo.bar"],
            "include_tests": true,
            "paths": ["unknown.py"]
        })
        .to_string(),
    );
    let unproven_result = &unproven["results"][0];
    assert_eq!(0, unproven_result["total_hits"], "{unproven}");
    assert_eq!(1, unproven_result["unproven_hits"], "{unproven}");
    assert_eq!(
        "unknown.py", unproven_result["unproven_files"][0]["path"],
        "{unproven}"
    );
}

#[test]
fn nested_package_barrel_resolves_through_init_chain() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/internal/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "pkg/internal/__init__.py",
            r#"
from .service import Service

__all__ = ["Service"]
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .internal import Service

__all__ = ["Service"]
"#,
        )
        .file(
            "consumer.py",
            r#"
from pkg import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.internal.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve nested package barrel chain");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn import_cycle_terminates_and_reports_proven_hits() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
from cycle_b import Other

class Service:
    pass
"#,
        )
        .file(
            "cycle_b.py",
            r#"
from service import Service

class Other:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from cycle_b import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should terminate on import cycle");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn dotted_namespace_import_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
import pkg.service

def run():
    return pkg.service.Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve dotted namespace import");
    assert_eq!(hits.len(), 1);
}

#[test]
fn dotted_namespace_alias_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
import pkg.service as svc

def run():
    return svc.Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve dotted namespace alias");
    assert_eq!(hits.len(), 1);
}

#[test]
fn imported_module_target_reports_qualifier_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/expression.py",
            r#"
class Expression:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
import pkg.expression as expression

def run():
    return expression.Expression()

def shadow(expression):
    return expression.Expression()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.expression");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should retain the imported module's usage seed");
    assert_eq!(
        hits.len(),
        1,
        "module qualifier should be a usage: {hits:#?}"
    );
    let hit = hits.iter().next().expect("one module qualifier hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(hit.snippet.contains("expression.Expression()"), "{hit:#?}");
}

#[test]
fn imported_package_submodule_qualifier_reports_module_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/image.py", "VALUE = 1\n")
        .file("pkg/__init__.py", "from . import image\n")
        .file("consumer.py", "import pkg as K\n\nvalue = K.image.VALUE\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.image");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should retain the intermediate package qualifier");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one module qualifier hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(hit.snippet.contains("K.image.VALUE"), "{hit:#?}");
}

#[test]
fn from_imported_submodule_qualifier_reports_module_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("api/v2/metrics_pb2.py", "VALUE = 1\n")
        .file("api/v2/__init__.py", "from . import metrics_pb2\n")
        .file("api/__init__.py", "from . import v2\n")
        .file(
            "consumer.py",
            "from api import v2\n\nvalue = v2.metrics_pb2.VALUE\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "api.v2.metrics_pb2");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should retain the imported submodule qualifier");

    assert_eq!(hits.len(), 1, "{hits:#?}");
    let hit = hits.iter().next().expect("one module qualifier hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(hit.snippet.contains("v2.metrics_pb2.VALUE"), "{hit:#?}");
}

#[test]
fn shadowed_root_does_not_report_imported_submodule_qualifier_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("pkg/image.py", "VALUE = 1\n")
        .file("pkg/__init__.py", "from . import image\n")
        .file(
            "consumer.py",
            "import pkg as K\n\n\
def shadow(K):\n    return K.image.VALUE\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.image");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for a shadowed imported submodule qualifier");

    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn from_package_imported_submodule_qualifier_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "cassandra/timestamps.py",
            r#"
class MonotonicTimestampGenerator:
    pass
"#,
        )
        .file("cassandra/__init__.py", "")
        .file(
            "tests/unit/test_timestamps.py",
            r#"
from cassandra import timestamps

def run():
    return timestamps.MonotonicTimestampGenerator()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(
        &analyzer,
        "cassandra.timestamps.MonotonicTimestampGenerator",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve package-imported submodule qualifier");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("tests/unit/test_timestamps.py"))
    );
}

#[test]
fn relative_same_package_imported_submodule_qualifier_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file("pkg/__init__.py", "")
        .file(
            "pkg/consumer.py",
            r#"
from . import service

def run():
    return service.Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve same-package imported submodule qualifier");
    assert_eq!(hits.len(), 1);
}

#[test]
fn relative_parent_imported_submodule_qualifier_resolves_export_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file("pkg/__init__.py", "")
        .file("pkg/tests/__init__.py", "")
        .file(
            "pkg/tests/consumer.py",
            r#"
from .. import service

def run():
    return service.Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve parent-package imported submodule qualifier");
    assert_eq!(hits.len(), 1);
}

#[test]
fn static_wildcard_barrel_resolves_through_all() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
__all__ = ["Service"]

class Service:
    pass
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .service import *
"#,
        )
        .file(
            "consumer.py",
            r#"
from pkg import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve wildcard barrel re-export");
    assert_eq!(hits.len(), 1);
}

#[test]
fn local_shadowing_of_imported_name_does_not_count_as_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

class Service:
    pass

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result.into_either().expect("graph should return success");
    assert!(
        hits.is_empty(),
        "shadowed imported name should not count as usage"
    );
}

#[test]
fn usage_finder_routes_python_through_graph_strategy() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("UsageFinder should find Python graph usages");
    assert_eq!(hits.len(), 1);
}

#[test]
fn usage_finder_routes_python_through_graph_strategy_with_multi_analyzer() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    return Service()
"#,
        )
        .build();
    let python = PythonAnalyzer::from_project(project.project().clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Python,
        AnalyzerDelegate::Python(python.clone()),
    )]));
    let target = definition(&python, "service.Service");

    let result = UsageFinder::new().find_usages_default(&multi, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("UsageFinder should find Python graph usages through MultiAnalyzer");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn graph_strategy_returns_too_many_callsites_when_limit_is_exceeded() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "first.py",
            r#"
from service import Service

def first():
    return Service()
"#,
        )
        .file(
            "second.py",
            r#"
from service import Service

def second():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );
    match result {
        brokk_bifrost::usages::FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            assert_eq!(limit, 1);
            assert!(total_callsites > limit);
        }
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn same_short_name_in_other_file_does_not_collide_into_target_seeds() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "other_service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from other_service import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve same-name exports without collision");
    assert!(
        hits.is_empty(),
        "usages of other_service.Service must not match"
    );
}

#[test]
fn bare_owner_references_do_not_count_as_member_usages() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    def ping(self):
        return 1
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    x: Service | None = None
    return Service
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service.ping");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("member query should still return success");
    assert!(hits.is_empty(), "bare owner references must not count");
}

#[test]
fn member_query_counts_true_member_access_only() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    def ping(self):
        return 1
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    return Service.ping(Service())
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service.ping");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("member access should be counted");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer.py"))
    );
}

#[test]
fn typed_local_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run():
    x: Foo
    x.bar()
"#,
    );
}

#[test]
fn typed_parameter_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run(x: Foo):
    x.bar()
"#,
    );
}

#[test]
fn typed_instance_attribute_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

class Holder:
    def __init__(self):
        self.x: Foo

    def run(self):
        self.x.bar()
"#,
    );
}

#[test]
fn constructed_local_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run():
    x = Foo()
    x.bar()
"#,
    );
}

#[test]
fn multiline_constructed_local_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run():
    x = Foo(
    )
    x.bar()
"#,
    );
}

#[test]
fn simple_alias_receiver_resolves_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run():
    x = Foo()
    y = x
    y.bar()
"#,
    );
}

#[test]
fn namespace_qualified_annotation_resolves_member_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Foo:
    def bar(self):
        pass
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .service import Foo
"#,
        )
        .file(
            "consumer.py",
            r#"
import pkg as p

def run():
    x: p.Foo
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Foo.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should resolve namespace-qualified annotation receiver");
    assert_eq!(hits.len(), 1);
}

#[test]
fn unseeded_receiver_does_not_count_as_member_usage() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
def run(x):
    x.bar()
"#,
    );
}

#[test]
fn unknown_constructor_does_not_count_as_member_usage() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
def run():
    x = Unknown()
    x.bar()
"#,
    );
}

#[test]
fn local_class_name_shadow_blocks_imported_constructor_receiver() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def run():
    Foo = object
    x = Foo()
    x.bar()
"#,
    );
}

#[test]
fn ambiguous_annotation_beyond_cap_does_not_count_as_member_usage() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
class Bar:
    def bar(self):
        pass
class Baz:
    def bar(self):
        pass
class Qux:
    def bar(self):
        pass
class Quux:
    def bar(self):
        pass
"#,
        r#"
from service import Foo, Bar, Baz, Qux, Quux

def run():
    x: Foo | Bar | Baz | Qux | Quux
    x.bar()
"#,
    );
}

#[test]
fn receiver_type_facts_do_not_leak_across_functions() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def typed(x: Foo):
    pass

def run(x):
    x.bar()
"#,
    );
}

#[test]
fn shadowing_in_one_function_does_not_block_sibling_receiver_inference() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

def shadow():
    Foo = object

def run(x: Foo):
    x.bar()
"#,
    );
}

#[test]
fn function_local_shadow_does_not_count_as_imported_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Service

def run():
    Service = object
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should succeed for function-local shadow case");
    assert!(
        hits.is_empty(),
        "function-local shadow should block imported usage"
    );
}

#[test]
fn python_graph_success_with_no_hits_does_not_fallback_to_regex() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Widget:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
# Widget appears only in a comment.
note = "Widget appears only in a string"
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Widget");

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("graph should return a successful empty result");
    assert!(
        hits.is_empty(),
        "text mentions should not trigger regex fallback"
    );
}

#[test]
fn inherited_base_member_counts_for_subclass_receiver() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Base:
    def bar(self):
        pass

class Child(Base):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Base.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should count inherited base member usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn overriding_subclass_member_counts_for_base_member_query() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Base:
    def bar(self):
        pass

class Child(Base):
    def bar(self):
        pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Base.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should count overriding subclass member usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn multi_level_inherited_member_counts_for_grandchild_receiver() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Base:
    def bar(self):
        pass

class Child(Base):
    pass

class GrandChild(Child):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import GrandChild

def run(x: GrandChild):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Base.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should count multi-level inherited member usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn cross_file_inherited_member_counts_for_subclass_receiver() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "base.py",
            r#"
class Base:
    def bar(self):
        pass
"#,
        )
        .file(
            "child.py",
            r#"
from base import Base

class Child(Base):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from child import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "base.Base.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should count cross-file inherited member usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn python_usage_graph_caches_invalidate_changed_files_on_update() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let service_file = project.file("service.py");

    assert_eq!(analyzer.get_definitions("service.Service").len(), 1);

    service_file
        .write(
            r#"
class Renamed:
    pass
"#,
        )
        .expect("should rewrite service.py");
    let changed = std::collections::BTreeSet::from([service_file.clone()]);
    let updated = analyzer.update(&changed);

    assert!(updated.get_definitions("service.Service").is_empty());
    assert_eq!(updated.get_definitions("service.Renamed").len(), 1);
}

#[test]
fn export_resolution_cache_invalidates_when_reexport_target_changes() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .service import Service
"#,
        )
        .file(
            "consumer.py",
            r#"
from pkg import Service

def run():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let initial = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("initial graph result should succeed");
    assert_eq!(initial.len(), 1);

    let init_file = project.file("pkg/__init__.py");
    init_file.write("").expect("should rewrite pkg/__init__.py");
    let changed = std::collections::BTreeSet::from([init_file.clone()]);
    let updated = analyzer.update(&changed);
    let target = definition(&updated, "pkg.service.Service");
    let candidates = updated.get_analyzed_files().into_iter().collect();
    let after_update = PythonExportUsageGraphStrategy::new()
        .find_usages(&updated, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("updated graph result should succeed");

    assert!(after_update.is_empty());
}

#[test]
fn unrelated_same_member_name_does_not_match_target_member() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    def ping(self):
        return 1
"#,
        )
        .file(
            "other.py",
            r#"
class Other:
    def ping(self):
        return 2
"#,
        )
        .file(
            "consumer.py",
            r#"
from other import Other

def run():
    return Other.ping(Other())
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service.ping");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should disambiguate unrelated owners");
    assert!(
        hits.is_empty(),
        "unrelated owner member access must not match"
    );
}

#[test]
fn graph_strategy_respects_candidate_file_boundary() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Service:
    pass
"#,
        )
        .file(
            "consumer_a.py",
            r#"
from service import Service

def run_a():
    return Service()
"#,
        )
        .file(
            "consumer_b.py",
            r#"
from service import Service

def run_b():
    return Service()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Service");
    let candidates = [project.file("service.py"), project.file("consumer_a.py")]
        .into_iter()
        .collect();

    let result = PythonExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result
        .into_either()
        .expect("graph should honor bounded candidate input");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("consumer_a.py"))
    );
}

#[test]
fn usage_finder_graph_finds_same_file_function_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def helper():
    return 1

def run():
    return helper()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.helper");

    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 1000, 1000);
    assert!(query.graph_failure.is_none(), "query: {:?}", query.result);
    let hits = query.result.into_either().expect("graph success");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("service.py")),
        "UsageFinder should use graph hits for same-file functions"
    );
}

#[test]
fn parity_optional_type_argument_resolves_receiver_member_usage() {
    assert_single_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from typing import Optional
from service import Foo

def run():
    x: Optional[Foo]
    x.bar()
"#,
    );
}

#[test]
fn parity_qualified_optional_type_argument_resolves_receiver_member_usage() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            r#"
class Foo:
    def bar(self):
        pass
"#,
        )
        .file(
            "pkg/__init__.py",
            r#"
from .service import Foo
"#,
        )
        .file(
            "consumer.py",
            r#"
from typing import Optional
import pkg as p

def run():
    x: Optional[p.Foo]
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "pkg.service.Foo.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should resolve qualified optional receiver usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn parity_multiple_inheritance_member_counts_when_one_parent_provides_member() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Left:
    pass

class Right:
    def bar(self):
        pass

class Child(Left, Right):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Right.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should count inherited member from one matching parent");
    assert_eq!(hits.len(), 1);
}

#[test]
fn parity_subclass_receiver_does_not_count_for_different_base_member_name() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Base:
    def baz(self):
        pass

class Child(Base):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Base.baz");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for subclass negative case");
    assert!(hits.is_empty());
}

#[test]
fn parity_unresolved_superclass_does_not_create_member_hierarchy_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Base:
    def bar(self):
        pass

class Child(UnknownBase):
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Child

def run(x: Child):
    x.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Base.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for unresolved-superclass negative case");
    assert!(hits.is_empty());
}

#[test]
fn parity_same_name_from_sibling_module_does_not_match_target() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "target_mod.py",
            r#"
class Foo:
    pass
"#,
        )
        .file(
            "sibling.py",
            r#"
class Foo:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from sibling import Foo

def run():
    return Foo()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "target_mod.Foo");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for sibling-module same-name case");
    assert!(hits.is_empty());
}

#[test]
fn parity_self_attribute_type_facts_do_not_leak_across_classes() {
    assert_no_python_member_hit(
        r#"
class Foo:
    def bar(self):
        pass
"#,
        r#"
from service import Foo

class A:
    def __init__(self):
        self.x: Foo = Foo()

class B:
    def run(self):
        self.x.bar()
"#,
    );
}

#[test]
fn parity_local_parameter_shadows_exported_class_attribute_candidate() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Foo:
    def bar(self):
        pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Foo

def run(Foo):
    Foo.bar()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Foo.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should succeed for parameter-shadow case");
    assert!(hits.is_empty());
}

#[test]
fn parity_default_argument_call_counts_as_usage_instead_of_parameter_shadow() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Widget:
    pass
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import Widget

def run(x=Widget()):
    pass
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Widget");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should count default-argument constructor usage");
    assert_eq!(hits.len(), 1);
}

#[test]
fn parity_deep_attribute_expression_does_not_overflow() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
class Foo:
    def bar(self):
        pass
"#,
        )
        .file(
            "consumer.py",
            format!(
                "\nfrom service import Foo\n\ndef run(root):\n    return root.{}.bar()\n",
                vec!["child"; 300].join(".")
            ),
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Foo.bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let _ = PythonExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph should not overflow on deep attribute expressions");
}

// --- Same-file member-usage regressions (Bug 2a / Bug 2b) ---

/// UsageFinder hit count for `fq` defined and used within a single file `m.py`.
fn single_file_member_hits(src: &str, fq: &str) -> usize {
    let project = InlineTestProject::with_language(Language::Python)
        .file("m.py", src)
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, fq);
    UsageFinder::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), 100, 100)
        .all_hits()
        .len()
}

// Bug 2a: `self` is implicitly typed as the enclosing class, so a `self.bar()`
// call in a sibling method counts as a usage of `bar`.
#[test]
fn self_receiver_resolves_same_file_member_usage() {
    assert_eq!(
        single_file_member_hits(
            "class Foo:\n    def bar(self):\n        pass\n\n    def baz(self):\n        self.bar()\n",
            "m.Foo.bar",
        ),
        1,
    );
}

// Bug 2a: an inherited `self.bar()` in a subclass resolves through the hierarchy.
#[test]
fn self_receiver_resolves_inherited_member_usage() {
    assert_eq!(
        single_file_member_hits(
            "class A:\n    def bar(self):\n        pass\n\nclass B(A):\n    def baz(self):\n        self.bar()\n",
            "m.A.bar",
        ),
        1,
    );
}

// Bug 2b: a constructed local at module scope is seeded with its type, so
// `f.bar()` resolves the same way it does inside a function body.
#[test]
fn module_level_constructed_local_resolves_member_usage() {
    assert_eq!(
        single_file_member_hits(
            "class Foo:\n    def bar(self):\n        pass\n\nf = Foo()\nf.bar()\n",
            "m.Foo.bar",
        ),
        1,
    );
}

// Bug: a bare reference to a member in the class body (the Python class
// namespace) — e.g. `alias = method` — is a usage of that member. Inside a
// method body a bare name would NOT reach the member (you need `self.`).
#[test]
fn class_body_bare_member_reference_resolves() {
    assert_eq!(
        single_file_member_hits(
            "class C:\n    def foo(self):\n        pass\n\n    alias = foo\n",
            "m.C.foo",
        ),
        1,
    );
}

#[test]
fn bare_member_name_inside_method_is_not_a_usage() {
    // `foo` here is an unrelated local, not the method C.foo.
    assert_eq!(
        single_file_member_hits(
            "class C:\n    def foo(self):\n        pass\n\n    def bar(self):\n        foo = 1\n        return foo\n",
            "m.C.foo",
        ),
        0,
    );
}

// A constructor call `C()` invokes `__init__`, so it is a usage of `__init__`.
// Passing the class as a value (`print(C)`) is not.
#[test]
fn constructor_call_is_a_usage_of_init() {
    assert_eq!(
        single_file_member_hits(
            "class C:\n    def __init__(self):\n        pass\n\nc = C()\nprint(C)\n",
            "m.C.__init__",
        ),
        1,
    );
}

// A bare member used as the object of an attribute access in the class body
// (e.g. a property's `@x.setter` / `@x.deleter` decorators) is a usage of `x`.
#[test]
fn class_body_decorator_member_reference_resolves() {
    assert_eq!(
        single_file_member_hits(
            "class C:\n    @property\n    def x(self):\n        return self._x\n\n    @x.setter\n    def x(self, value):\n        self._x = value\n\n    @x.deleter\n    def x(self):\n        del self._x\n",
            "m.C.x",
        ),
        2,
    );
}

// Same-file best-effort: an un-inferrable receiver (`q` untyped) resolves
// `q.member` to the target when the member name is unique to one local class.
#[test]
fn untyped_receiver_resolves_unique_same_file_member() {
    assert_eq!(
        single_file_member_hits(
            "class Foo:\n    def unique_member(self):\n        pass\n\ndef run(q):\n    q.unique_member()\n",
            "m.Foo.unique_member",
        ),
        1,
    );
}

// The uniqueness gate: when two local classes declare the member, an untyped
// `q.member` is ambiguous and is NOT attributed to either.
#[test]
fn untyped_receiver_does_not_resolve_ambiguous_same_file_member() {
    assert_eq!(
        single_file_member_hits(
            "class Foo:\n    def shared(self):\n        pass\n\nclass Bar:\n    def shared(self):\n        pass\n\ndef run(q):\n    q.shared()\n",
            "m.Foo.shared",
        ),
        0,
    );
}

#[test]
fn chained_attribute_receiver_method_match_is_unproven_not_verified_absent() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            "class Foo:\n    def bar(self):\n        pass\n",
        )
        .file("app/consumer.py", "def run(obj):\n    obj.field.bar()\n")
        .build();

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["pkg.service.Foo.bar"],
            "include_tests": true
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
        "unproven chained receiver must prevent verified_absent: {result}"
    );
    assert!(
        entry["unproven_files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("obj.field.bar()")),
        "expected chained receiver call in unproven files: {result}"
    );
}

#[test]
fn unknown_simple_receiver_method_match_is_unproven_not_verified_absent() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "pkg/service.py",
            "class Foo:\n    def bar(self):\n        pass\n",
        )
        .file("app/consumer.py", "def run(param):\n    param.bar()\n")
        .build();

    let result = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["pkg.service.Foo.bar"],
            "include_tests": true
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
        "unproven simple receiver must prevent verified_absent: {result}"
    );
    assert!(
        entry["unproven_files"][0]["hits"][0]["snippet"]
            .as_str()
            .is_some_and(|snippet| snippet.contains("param.bar()")),
        "expected simple receiver call in unproven files: {result}"
    );
}

// Bug (regression from the module-scope seeding fix): a same-file bare-name read
// of a module-level field is a usage. A module-level assignment of the target's
// own name is its definition, not a shadow that should hide its usages.
#[test]
fn module_level_field_same_file_read_resolves() {
    assert_eq!(
        single_file_member_hits("SOME_CONST = 1\nprint(SOME_CONST)\n", "m.SOME_CONST"),
        1,
    );
}

#[test]
fn module_level_field_resolves_despite_reassignment() {
    assert_eq!(
        single_file_member_hits(
            "SOME_CONST = 1\nif cond:\n    SOME_CONST = 2\nprint(SOME_CONST)\n",
            "m.SOME_CONST",
        ),
        1,
    );
}

// The `from service import Widget` binding is an Import-kind hit: excluded from
// the call-graph hit set (all_hits / into_either) but included by the IDE
// find-references accessor (all_hits_including_imports).
#[test]
fn import_binding_is_import_kind_hit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "class Widget:\n    pass\n")
        .file(
            "consumer.py",
            "from service import Widget\n\ndef run():\n    return Widget()\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.Widget");
    let result = UsageFinder::new().find_usages(&analyzer, std::slice::from_ref(&target), 100, 100);
    // Call-graph surfaces: only the `Widget()` construction.
    assert_eq!(result.all_hits().len(), 1);
    // find-references: also the `from service import Widget` binding.
    assert_eq!(result.all_hits_including_imports().len(), 2);
}

#[test]
fn namespace_import_resolves_reexported_function_alias() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "proto/modules.py",
            "def define_module():\n    return None\n",
        )
        .file(
            "proto/__init__.py",
            "from .modules import define_module as module\n",
        )
        .file("consumer.py", "import proto\n\nvalue = proto.module()\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "proto.modules.define_module");

    let hits = UsageFinder::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), 100, 100)
        .all_hits();

    assert_eq!(hits.len(), 1, "re-export alias should resolve: {hits:#?}");
    let hit = hits.iter().next().expect("one re-export alias hit");
    assert_eq!(hit.file, project.file("consumer.py"));
    assert!(hit.snippet.contains("proto.module()"), "{hit:#?}");
}

#[test]
fn nested_class_bare_reference_in_owner_body_resolves() {
    assert_eq!(
        single_file_member_hits(
            "class Outer:\n    class Inner:\n        pass\n\n    alias = Inner\n",
            "m.Outer$Inner",
        ),
        1,
    );
}

#[test]
fn imported_name_before_later_module_rebinding_resolves_only_before_rebind() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "TOKEN = object()\n")
        .file(
            "consumer.py",
            concat!(
                "from service import TOKEN\n",
                "before = TOKEN\n",
                "TOKEN = object()\n",
                "after = TOKEN\n",
            ),
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.TOKEN");

    let hits = UsageFinder::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), 100, 100)
        .all_hits();

    assert_eq!(
        hits.len(),
        1,
        "only the pre-rebind read is imported: {hits:#?}"
    );
    let hit = hits.iter().next().expect("one pre-rebind hit");
    assert!(hit.snippet.contains("before = TOKEN"), "{hit:#?}");
}

#[test]
fn deferred_function_body_observes_later_module_rebinding() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("service.py", "TOKEN = object()\n")
        .file(
            "consumer.py",
            concat!(
                "from service import TOKEN\n",
                "def read():\n",
                "    return TOKEN\n",
                "TOKEN = object()\n",
            ),
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(&analyzer, "service.TOKEN");

    let hits = UsageFinder::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), 100, 100)
        .all_hits();

    assert!(
        hits.is_empty(),
        "a deferred body observes the final module binding: {hits:#?}"
    );
}

#[test]
fn call_initialized_module_container_is_not_shadowed_by_its_definition() {
    assert_eq!(
        single_file_member_hits(
            "REGISTRY = dict()\nREGISTRY[\"rest\"] = object()\n",
            "m.REGISTRY",
        ),
        1,
    );
}

#[test]
fn nested_package_module_field_resolves_after_redeclaration() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "packages/google-cloud-example/setup.py",
            concat!(
                "import os\n",
                "package_root = os.getcwd()\n",
                "package_root = os.getcwd()\n",
                "readme = os.path.join(package_root, \"README.rst\")\n",
            ),
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let target = definition(
        &analyzer,
        "packages.google-cloud-example.setup.package_root",
    );
    let hits = UsageFinder::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), 100, 100)
        .all_hits();

    assert_eq!(
        hits.len(),
        1,
        "nested module field read should resolve: {hits:#?}"
    );
    let hit = hits.iter().next().expect("one nested module-field hit");
    assert!(
        hit.snippet.contains("package_root, \"README.rst\""),
        "{hit:#?}"
    );
}

#[test]
fn class_field_default_argument_resolves_in_owner_class_scope() {
    assert_eq!(
        single_file_member_hits(
            concat!(
                "class Transport:\n",
                "    DEFAULT_HOST = \"localhost\"\n",
                "    def __init__(self, host=DEFAULT_HOST):\n",
                "        return DEFAULT_HOST\n",
            ),
            "m.Transport.DEFAULT_HOST",
        ),
        1,
        "the default is evaluated in the class body; the method body is not",
    );
}
