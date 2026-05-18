mod common;

use brokk_analyzer::usages::{PythonExportUsageGraphStrategy, UsageAnalyzer, UsageFinder};
use brokk_analyzer::{CodeUnit, IAnalyzer, Language, PythonAnalyzer};
use common::InlineTestProject;

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
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
