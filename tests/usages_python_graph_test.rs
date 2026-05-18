mod common;

use brokk_analyzer::usages::{PythonExportUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, PythonAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeMap;

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn assert_single_python_member_hit(service: &str, consumer: &str) {
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
        brokk_analyzer::usages::FuzzyResult::TooManyCallsites {
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
fn usage_finder_falls_back_to_regex_for_same_file_unseeded_function() {
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

    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("UsageFinder should fall back to regex for unseeded same-file functions");
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("service.py"))
    );
}
