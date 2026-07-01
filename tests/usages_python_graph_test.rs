mod common;

use brokk_bifrost::usages::{PythonExportUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_bifrost::{
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

#[test]
#[ignore = "Brokk parity marker: cachedDefinitionsByIdentifierFindsBareTopLevelFunction"]
fn parity_cached_definitions_by_identifier_finds_bare_top_level_function() {
    // No direct bifrost helper yet; keep as a parity marker until a Rust-side helper
    // equivalent exists or this assertion is folded into another public-facing surface.
    panic!("parity marker only");
}

#[test]
#[ignore = "Brokk parity marker: cachedDefinitionsByIdentifierFindsMemberIdentifierFallback"]
fn parity_cached_definitions_by_identifier_finds_member_identifier_fallback() {
    panic!("parity marker only");
}

#[test]
#[ignore = "Brokk parity marker: cachedExactMemberResolvesOnlyWithinSourceFile"]
fn parity_cached_exact_member_resolves_only_within_source_file() {
    panic!("parity marker only");
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
