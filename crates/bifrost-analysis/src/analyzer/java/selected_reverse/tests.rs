use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::java::native_usages::JavaNativeUsageStrategy;
use crate::analyzer::structural::reference_edges::{
    SelectedInverseIndexOutcome, SelectedInverseReferenceProvider,
};
use crate::analyzer::usages::{FuzzyResult, JavaUsageGraphStrategy, UsageAnalyzer};
use crate::analyzer::{Project, QueryScope};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use crate::path_utils::rel_path_string;
use std::collections::BTreeSet;

const BASE: &str = "src/main/java/model/Base.java";
const SAME: &str = "src/main/java/model/SamePackage.java";
const IMPORTED: &str = "src/main/java/client/Imported.java";
const QUALIFIED: &str = "src/main/java/qualified/Qualified.java";
const STATIC: &str = "src/main/java/client/StaticUse.java";
const CHILD: &str = "src/main/java/child/Child.java";
const INHERITED: &str = "src/main/java/client/Inherited.java";

const BASE_SOURCE: &str = r#"package model;
public class Base {
    public int field;
    private int secret;
    public static int staticField;
    public Base() {}
    public Base(int value) {}
    public void method() {}
    public static void staticMethod() {}
    protected void protectedMethod() {}
    void packageMethod() {}
    void useSecret() { int value = secret; }
}
"#;

fn fixture() -> (BuiltInlineTestProject, JavaAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(
            "pom.xml",
            "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>java-native-usages</artifactId><version>1</version></project>",
        )
        .file(BASE, BASE_SOURCE)
        .file(
            SAME,
            "package model; class SamePackage { void use() { Base b = new Base(1); int x = b.field; b.method(); b.packageMethod(); b.protectedMethod(); } }",
        )
        .file(
            IMPORTED,
            "package client; import model.Base; class Imported { void use(Base b) { int x = b.field; b.method(); } Base make() { return new Base(2); } }",
        )
        .file(
            QUALIFIED,
            "package qualified; class Qualified { void use(model.Base b) { int x = b.field; b.method(); } model.Base make() { return new model.Base(3); } }",
        )
        .file(
            STATIC,
            "package client; import static model.Base.staticMethod; import static model.Base.staticField; class StaticUse { void use() { staticMethod(); int x = staticField; } }",
        )
        .file(
            CHILD,
            "package child; public class Child extends model.Base { void use(Child receiver) { receiver.protectedMethod(); } }",
        )
        .file(
            INHERITED,
            "package client; import child.Child; class Inherited { void use(Child c) { c.method(); int x = c.field; } }",
        )
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for file in analyzer.get_analyzed_files() {
        assert!(
            analyzer
                .inner
                .write_live_file_to_store_for_test(&file)
                .is_some(),
            "persist Java resolution facts for {file}"
        );
    }
    (fixture, analyzer)
}

fn fixture_with_java_sources(files: &[(&str, &str)]) -> (BuiltInlineTestProject, JavaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Java).file(
        "pom.xml",
        "<project><modelVersion>4.0.0</modelVersion><groupId>test</groupId><artifactId>java-rename</artifactId><version>1</version></project>",
    );
    for (path, source) in files {
        builder = builder.file(path, *source);
    }
    let fixture = builder.build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for file in analyzer.get_analyzed_files() {
        assert!(
            analyzer
                .inner
                .write_live_file_to_store_for_test(&file)
                .is_some(),
            "persist Java resolution facts for {file}"
        );
    }
    (fixture, analyzer)
}

fn target(
    analyzer: &JavaAnalyzer,
    fixture: &BuiltInlineTestProject,
    path: &str,
    terminal_name: &str,
    kind: crate::analyzer::CodeUnitType,
) -> CodeUnit {
    analyzer
        .declarations(&fixture.file(path))
        .into_iter()
        .find(|unit| unit.terminal_name() == terminal_name && unit.kind() == kind)
        .unwrap_or_else(|| {
            panic!(
                "missing Java target {terminal_name:?} ({kind:?}) in {path}: {:#?}",
                analyzer.declarations(&fixture.file(path))
            )
        })
}

fn inverse(analyzer: &JavaAnalyzer, target: &CodeUnit) -> EdgeDerivationResult {
    match java_selected_inverse_for(analyzer, target, &CancellationToken::new()) {
        JavaSelectedReverseOutcome::Ready(answer) => answer,
        outcome => panic!("selected Java inverse query failed: {outcome:?}"),
    }
}

fn edge_paths(answer: &EdgeDerivationResult) -> BTreeSet<String> {
    answer
        .edges
        .iter()
        .map(|edge| rel_path_string(&edge.site.file))
        .collect()
}

fn usage_sites(result: FuzzyResult) -> BTreeSet<(std::path::PathBuf, usize, usize)> {
    let (proven, unproven) = match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => (hits_by_overload, unproven_by_overload),
        result => panic!("usage differential has no call-site inventory: {result:?}"),
    };
    proven
        .into_values()
        .chain(unproven.into_values())
        .flatten()
        .map(|hit| {
            (
                hit.file.rel_path().to_path_buf(),
                hit.start_offset,
                hit.end_offset,
            )
        })
        .collect()
}

fn normalized_rename_edits(
    files: &[crate::symbol_rename::RenameFileEdits],
) -> BTreeSet<(std::path::PathBuf, usize, usize, String)> {
    files
        .iter()
        .flat_map(|file| {
            file.edits.iter().map(|edit| {
                (
                    file.file.rel_path().to_path_buf(),
                    edit.start_byte,
                    edit.end_byte,
                    edit.new_text.clone(),
                )
            })
        })
        .collect()
}

#[test]
fn java_native_selected_inverse_confirms_types_fields_methods_constructors_and_static_imports() {
    let (fixture, analyzer) = fixture();
    let class = target(
        &analyzer,
        &fixture,
        BASE,
        "Base",
        crate::analyzer::CodeUnitType::Class,
    );
    let type_edges = inverse(&analyzer, &class);
    let type_paths = edge_paths(&type_edges);
    assert!(type_paths.contains(SAME), "{type_edges:#?}");
    assert!(type_paths.contains(IMPORTED), "{type_edges:#?}");
    assert!(type_paths.contains(QUALIFIED), "{type_edges:#?}");
    assert!(
        matches!(type_edges.completeness, EdgeCompleteness::Incomplete { .. }),
        "unresolved imported routes stay explicitly open even in a pure-Java workspace: {type_edges:#?}"
    );

    let field = target(
        &analyzer,
        &fixture,
        BASE,
        "field",
        crate::analyzer::CodeUnitType::Field,
    );
    let field_edges = inverse(&analyzer, &field);
    let field_paths = edge_paths(&field_edges);
    assert!(field_paths.contains(SAME), "{field_edges:#?}");
    assert!(field_paths.contains(IMPORTED), "{field_edges:#?}");
    assert!(field_paths.contains(QUALIFIED), "{field_edges:#?}");
    assert!(field_paths.contains(INHERITED), "{field_edges:#?}");

    let method = target(
        &analyzer,
        &fixture,
        BASE,
        "method",
        crate::analyzer::CodeUnitType::Function,
    );
    let method_edges = inverse(&analyzer, &method);
    let method_paths = edge_paths(&method_edges);
    assert!(method_paths.contains(SAME), "{method_edges:#?}");
    assert!(method_paths.contains(IMPORTED), "{method_edges:#?}");
    assert!(method_paths.contains(QUALIFIED), "{method_edges:#?}");
    assert!(method_paths.contains(INHERITED), "{method_edges:#?}");

    let constructor = analyzer
        .declarations(&fixture.file(BASE))
        .into_iter()
        .find(|unit| {
            unit.kind() == crate::analyzer::CodeUnitType::Function
                && unit.owner_is_type_scope()
                && unit.signature() == Some("(int)")
        })
        .expect("explicit Java constructor target");
    let constructor_edges = inverse(&analyzer, &constructor);
    let constructor_paths = edge_paths(&constructor_edges);
    assert!(constructor_paths.contains(SAME), "{constructor_edges:#?}");
    assert!(
        constructor_paths.contains(IMPORTED),
        "{constructor_edges:#?}"
    );
    assert!(
        constructor_paths.contains(QUALIFIED),
        "{constructor_edges:#?}"
    );

    let static_method = target(
        &analyzer,
        &fixture,
        BASE,
        "staticMethod",
        crate::analyzer::CodeUnitType::Function,
    );
    let static_edges = inverse(&analyzer, &static_method);
    assert!(
        edge_paths(&static_edges).contains(STATIC),
        "single static import and unqualified call must be confirmed: {static_edges:#?}"
    );

    let static_field = target(
        &analyzer,
        &fixture,
        BASE,
        "staticField",
        crate::analyzer::CodeUnitType::Field,
    );
    let static_field_edges = inverse(&analyzer, &static_field);
    assert!(
        edge_paths(&static_field_edges).contains(STATIC),
        "single static field import must be confirmed: {static_field_edges:#?}"
    );

    let protected = target(
        &analyzer,
        &fixture,
        BASE,
        "protectedMethod",
        crate::analyzer::CodeUnitType::Function,
    );
    let protected_edges = inverse(&analyzer, &protected);
    assert!(
        edge_paths(&protected_edges).contains(SAME),
        "same-package protected references must remain candidates: {protected_edges:#?}"
    );
    assert!(
        edge_paths(&protected_edges).contains(CHILD),
        "cross-package subclass references must be admitted by selected hierarchy rows: {protected_edges:#?}"
    );
    assert!(
        !edge_paths(&protected_edges).contains(INHERITED),
        "unrelated cross-package callers must be excluded from protected candidates: {protected_edges:#?}"
    );

    let package_method = target(
        &analyzer,
        &fixture,
        BASE,
        "packageMethod",
        crate::analyzer::CodeUnitType::Function,
    );
    let package_method_edges = inverse(&analyzer, &package_method);
    assert_eq!(
        edge_paths(&package_method_edges),
        BTreeSet::from([SAME.to_owned()]),
        "package-private member candidates are restricted to the declaring package: {package_method_edges:#?}"
    );

    let secret = target(
        &analyzer,
        &fixture,
        BASE,
        "secret",
        crate::analyzer::CodeUnitType::Field,
    );
    let secret_edges = inverse(&analyzer, &secret);
    assert_eq!(
        edge_paths(&secret_edges),
        BTreeSet::from([BASE.to_owned()]),
        "private candidates are restricted to their top-level compilation unit: {secret_edges:#?}"
    );
}

#[test]
fn java_native_selected_inverse_candidate_mount_reader_seeks_shared_indexes() {
    let (fixture, analyzer) = fixture();
    let class = target(
        &analyzer,
        &fixture,
        BASE,
        "Base",
        crate::analyzer::CodeUnitType::Class,
    );
    let answer = inverse(&analyzer, &class);
    assert!(!answer.edges.is_empty(), "{answer:#?}");
    let plan = crate::analyzer::store::resolution_operation::java_reverse_rows::
        last_java_reverse_candidate_plan_for_test();
    eprintln!("selected Java reverse candidate EXPLAIN QUERY PLAN: {plan:#?}");
    for required in [
        "resolution_reference_lookup_identities_identity",
        "resolution_qualified_routes_source_lookup",
        "resolution_paths_root_terminal",
    ] {
        assert!(
            plan.iter().any(|detail| detail.contains(required)),
            "candidate mount discovery must seek {required}: {plan:#?}"
        );
    }
    assert!(
        !plan
            .iter()
            .any(|detail| detail.contains("SCAN resolution_")),
        "candidate discovery must not scan analyzer resolution tables: {plan:#?}"
    );
}

#[test]
fn java_native_selected_inverse_provider_is_test_support_only_and_reports_peer_scope_conditionally()
{
    let (fixture, analyzer) = fixture();
    let method = target(
        &analyzer,
        &fixture,
        BASE,
        "method",
        crate::analyzer::CodeUnitType::Function,
    );
    let index =
        match JavaNativeSelectedInverseProvider.build_selected_inverse_index(&analyzer, None) {
            SelectedInverseIndexOutcome::Ready(index) => index,
            SelectedInverseIndexOutcome::Unavailable(reason) => {
                panic!("Java test-support inverse provider unavailable: {reason}")
            }
            SelectedInverseIndexOutcome::Stale(reason) => {
                panic!("Java test-support inverse provider stale: {reason}")
            }
            SelectedInverseIndexOutcome::Cancelled => {
                panic!("Java test-support inverse provider cancelled")
            }
            SelectedInverseIndexOutcome::StoreError(reason) => {
                panic!("Java test-support inverse provider failed: {reason}")
            }
        };
    assert_eq!(
        index.generation(),
        analyzer.inner.project().analysis_generation()
    );
    let answer = index.inverse_for(&method);
    assert!(
        answer
            .edges
            .iter()
            .any(|edge| edge.site.file == fixture.file(SAME)),
        "selected Java inverse index must return real-store edges: {answer:#?}"
    );

    let admitted = analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<crate::hash::HashSet<_>>();
    let outcome = JavaNativeUsageStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&method),
        &admitted,
        100,
    );
    match outcome {
        FuzzyResult::Success { .. } => {}
        FuzzyResult::Incomplete { diagnostics, .. } => assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.reason_kind != "native_java_peer_languages_omitted"),
            "a pure-Java workspace must not report omitted peer languages: {diagnostics:#?}"
        ),
        other => panic!("unexpected pure-Java usage result: {other:?}"),
    }
}

#[test]
fn java_native_usage_sites_match_the_incumbent_on_shared_real_store_families() {
    let (fixture, analyzer) = fixture();
    let candidates = analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<crate::hash::HashSet<_>>();
    for target in [
        target(
            &analyzer,
            &fixture,
            BASE,
            "Base",
            crate::analyzer::CodeUnitType::Class,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "field",
            crate::analyzer::CodeUnitType::Field,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "method",
            crate::analyzer::CodeUnitType::Function,
        ),
        analyzer
            .declarations(&fixture.file(BASE))
            .into_iter()
            .find(|unit| {
                unit.kind() == crate::analyzer::CodeUnitType::Function
                    && unit.owner_is_type_scope()
                    && unit.signature() == Some("(int)")
            })
            .expect("explicit Java constructor target"),
        target(
            &analyzer,
            &fixture,
            BASE,
            "staticMethod",
            crate::analyzer::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "staticField",
            crate::analyzer::CodeUnitType::Field,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "protectedMethod",
            crate::analyzer::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "packageMethod",
            crate::analyzer::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "secret",
            crate::analyzer::CodeUnitType::Field,
        ),
    ] {
        let legacy = JavaUsageGraphStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        );
        let native = JavaNativeUsageStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        );
        let legacy_sites = usage_sites(legacy);
        let native_sites = usage_sites(native);
        let legacy_only = legacy_sites
            .difference(&native_sites)
            .cloned()
            .collect::<BTreeSet<_>>();
        let import_sites = if analyzer
            .signature_metadata(&target)
            .iter()
            .any(|metadata| metadata.callable_is_constructor())
        {
            Vec::new()
        } else {
            match target.terminal_name() {
                "Base" => vec![
                    (IMPORTED, 23, 33, "model.Base"),
                    (STATIC, 30, 40, "model.Base"),
                    (STATIC, 69, 79, "model.Base"),
                ],
                "staticMethod" => vec![(STATIC, 41, 53, "staticMethod")],
                "staticField" => vec![(STATIC, 80, 91, "staticField")],
                _ => Vec::new(),
            }
        };
        let expected_import_only = import_sites
            .into_iter()
            .map(|(path, start, end, expected_text)| {
                let source = fixture
                    .file(path)
                    .read_to_string()
                    .expect("read import source for differential adjudication");
                assert_eq!(&source[start..end], expected_text, "{path}: {start}..{end}");
                (fixture.file(path).rel_path().to_path_buf(), start, end)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            legacy_only,
            expected_import_only,
            "source-adjudicate selected/legacy Java usage differences for {}",
            target.fq_name(),
        );
        assert!(
            native_sites.is_subset(&legacy_sites),
            "native Java references must be a subset of source-resolved incumbent locations for {}: native-only={:?}",
            target.fq_name(),
            native_sites.difference(&legacy_sites).collect::<Vec<_>>(),
        );
    }
}

fn call_site_positions(
    result: &crate::analyzer::usages::CallRelationResult,
) -> BTreeSet<(std::path::PathBuf, usize, usize, CodeUnit)> {
    result
        .sites
        .iter()
        .map(|site| {
            (
                site.file.rel_path().to_path_buf(),
                site.range.start_byte,
                site.range.end_byte,
                site.callee.clone(),
            )
        })
        .collect()
}

#[test]
fn java_native_incoming_calls_equal_selected_call_rows_and_incumbent() {
    let (fixture, analyzer) = fixture();
    let method = target(
        &analyzer,
        &fixture,
        BASE,
        "method",
        crate::analyzer::CodeUnitType::Function,
    );
    let limits = crate::analyzer::usages::CallRelationLimits {
        max_files: 100,
        max_source_bytes: usize::MAX,
        max_candidates: 100,
    };
    let native = super::super::native_call_relations::java_native_incoming_calls(
        &analyzer, &method, limits, None,
    );
    let inverse = inverse(&analyzer, &method);
    let expected = inverse
        .edges
        .iter()
        .filter_map(|edge| {
            let facts = analyzer
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&edge.site.file))?;
            let syntax = crate::analyzer::usages::get_definition::call_site_syntax_for_reference(
                &facts,
                edge.site.range.start_byte,
                edge.site.range.end_byte,
            )?;
            Some((
                edge.site.file.rel_path().to_path_buf(),
                syntax.range.start_byte,
                syntax.range.end_byte,
                method.clone(),
            ))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        call_site_positions(&native),
        expected,
        "selected call-row projection"
    );
    assert!(native.sites.iter().all(|site| site.callee == method));

    let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent = crate::analyzer::usages::CallRelationService::incoming_bounded(
        &analyzer,
        scope.token(),
        &method,
        limits,
        None,
    );
    let native_positions = call_site_positions(&native);
    let incumbent_positions = call_site_positions(&incumbent);
    assert!(
        incumbent_positions.is_subset(&native_positions),
        "native incoming projection omitted an incumbent call: native={native_positions:?}, incumbent={incumbent_positions:?}"
    );
    let native_only = native_positions
        .difference(&incumbent_positions)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(native_only.len(), 1, "{native_only:?}");
    let inherited_call = native
        .sites
        .iter()
        .find(|site| site.file == fixture.file(INHERITED))
        .expect("inherited member call must be present in native inverse projection");
    let inherited_source = fixture
        .project()
        .read_source(&fixture.file(INHERITED))
        .expect("read inherited call for source adjudication");
    assert_eq!(
        &inherited_source[inherited_call.range.start_byte..inherited_call.range.end_byte],
        "c.method()",
        "the native-only site resolves through Child to Base.method"
    );
    assert!(
        fixture
            .project()
            .read_source(&fixture.file(CHILD))
            .expect("read child declaration")
            .contains("extends model.Base"),
        "source hierarchy confirms the inherited target"
    );

    let static_method = target(
        &analyzer,
        &fixture,
        BASE,
        "staticMethod",
        crate::analyzer::CodeUnitType::Function,
    );
    let native_static = super::super::native_call_relations::java_native_incoming_calls(
        &analyzer,
        &static_method,
        limits,
        None,
    );
    assert!(
        native_static
            .sites
            .iter()
            .any(|site| site.file == fixture.file(STATIC)),
        "the selected static import call must project: {native_static:#?}"
    );
    let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent_static = crate::analyzer::usages::CallRelationService::incoming_bounded(
        &analyzer,
        scope.token(),
        &static_method,
        limits,
        None,
    );
    assert_eq!(
        call_site_positions(&native_static),
        call_site_positions(&incumbent_static),
        "static-import Java call sites should match the incumbent incoming-call service"
    );

    let constructor = analyzer
        .declarations(&fixture.file(BASE))
        .into_iter()
        .find(|unit| {
            unit.kind() == crate::analyzer::CodeUnitType::Function
                && unit.owner_is_type_scope()
                && unit.signature() == Some("(int)")
                && analyzer
                    .signature_metadata(unit)
                    .iter()
                    .any(|metadata| metadata.callable_is_constructor())
        })
        .expect("explicit Base(int) constructor");
    let native_constructor = super::super::native_call_relations::java_native_incoming_calls(
        &analyzer,
        &constructor,
        limits,
        None,
    );
    assert!(native_constructor.sites.iter().all(|site| {
        site.kind == crate::analyzer::usages::get_definition::CallSyntaxKind::Constructor
    }));
    assert!(
        native_constructor
            .sites
            .iter()
            .any(|site| site.file == fixture.file(SAME)),
        "new Base(1) must project as a constructor invocation: {native_constructor:#?}"
    );
    let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent_constructor = crate::analyzer::usages::CallRelationService::incoming_bounded(
        &analyzer,
        scope.token(),
        &constructor,
        limits,
        None,
    );
    assert!(
        incumbent_constructor.sites.is_empty(),
        "the incumbent omits constructor invocations; source adjudication below validates native sites"
    );
    let constructor_sources = native_constructor
        .sites
        .iter()
        .map(|site| {
            let source = fixture
                .project()
                .read_source(&site.file)
                .expect("read constructor invocation for source adjudication");
            (
                site.file.rel_path().to_path_buf(),
                source[site.range.start_byte..site.range.end_byte].to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        constructor_sources,
        BTreeSet::from([
            (std::path::PathBuf::from(IMPORTED), "new Base(2)".to_owned()),
            (std::path::PathBuf::from(SAME), "new Base(1)".to_owned()),
            (
                std::path::PathBuf::from(QUALIFIED),
                "new model.Base(3)".to_owned(),
            ),
        ]),
        "native constructor sites are the three source-confirmed invocations omitted by the incumbent"
    );
}

#[test]
fn java_native_incoming_calls_preserve_overload_identity() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/model/Overloads.java",
            "package model; class Overloads { int pick(int value) { return value; } int pick(String value) { return value.length(); } int use() { return pick(1) + pick(\"x\"); } }",
        )
        .build();
    let analyzer = JavaAnalyzer::new(fixture.project_dyn());
    for file in analyzer.get_analyzed_files() {
        assert!(
            analyzer
                .inner
                .write_live_file_to_store_for_test(&file)
                .is_some()
        );
    }
    let declarations = analyzer.declarations(&fixture.file("src/main/java/model/Overloads.java"));
    let overloads = declarations
        .iter()
        .filter(|unit| {
            unit.kind() == crate::analyzer::CodeUnitType::Function && unit.terminal_name() == "pick"
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        overloads.len(),
        2,
        "fixture must retain both overloads: {declarations:#?}"
    );
    let limits = crate::analyzer::usages::CallRelationLimits {
        max_files: 20,
        max_source_bytes: usize::MAX,
        max_candidates: 20,
    };
    let answers = overloads
        .iter()
        .map(|overload| {
            super::super::native_call_relations::java_native_incoming_calls(
                &analyzer, overload, limits, None,
            )
        })
        .collect::<Vec<_>>();
    assert!(
        answers.iter().all(|answer| answer.sites.is_empty()),
        "{answers:#?}"
    );
    assert!(
        answers
            .iter()
            .all(|answer| answer.diagnostics.iter().any(|diagnostic| {
                diagnostic.reason_kind.as_deref() == Some("native_call_target_ambiguous")
            })),
        "multi-target rows must be withheld instead of attached to both overloads: {answers:#?}"
    );
    for (answer, overload) in answers.iter().zip(&overloads) {
        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let incumbent = crate::analyzer::usages::CallRelationService::incoming_bounded(
            &analyzer,
            scope.token(),
            overload,
            limits,
            None,
        );
        let expected = if overload.signature() == Some("(int)") {
            "pick(1)"
        } else {
            "pick(\"x\")"
        };
        let source = fixture
            .project()
            .read_source(&fixture.file("src/main/java/model/Overloads.java"))
            .expect("read overload fixture for source adjudication");
        let start = source.find(expected).expect("expected overload call");
        for site in &incumbent.sites {
            let legacy_source = fixture
                .project()
                .read_source(&site.file)
                .expect("read incumbent overloaded call for source adjudication");
            let text = &legacy_source[site.range.start_byte..site.range.end_byte];
            assert!(
                matches!(text, "pick(1)" | "pick(\"x\")"),
                "incumbent site must map to an exact overloaded call in source: {site:?}, {text:?}"
            );
        }
        assert_eq!(
            &source[start..start + expected.len()],
            expected,
            "the source-level argument selects this overload for {overload:?}"
        );
        assert!(
            answer
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.reason_kind.as_deref()
                    == Some("native_call_target_ambiguous"))
        );
    }
}

#[test]
fn java_native_rename_succeeds_for_pure_java_and_refuses_selected_peer_references() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public int value; }",
        ),
        (
            SAME,
            "package model; class SamePackage { int read(Base base) { return base.value; } }",
        ),
    ]);
    let base_field = target(
        &analyzer,
        &fixture,
        BASE,
        "value",
        crate::analyzer::CodeUnitType::Field,
    );
    let pure_listing_count = fixture.project().workspace_file_listing_count();
    let native = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &base_field,
        "renamed",
        &CancellationToken::new(),
    )
    .expect("a selected pure-Java source inventory can authorize rename");
    assert_eq!(
        fixture.project().workspace_file_listing_count(),
        pure_listing_count,
        "native rename reads the selected inventory without walking project files"
    );

    let source = fixture
        .project()
        .read_source(&fixture.file(BASE))
        .expect("read source for incumbent adjudication");
    let declaration = source.find("value;").expect("field declaration");
    let incumbent = crate::symbol_rename::rename_symbol(
        &analyzer,
        fixture.project(),
        fixture.file(BASE),
        crate::symbol_rename::RenameSelection::ByteOffset(declaration),
        "renamed",
    )
    .unwrap_or_else(|error| {
        panic!("incumbent Java rename should resolve this source fixture: {error:?}")
    });
    assert_eq!(
        normalized_rename_edits(&native.files),
        normalized_rename_edits(&incumbent.files)
    );
    for file_edits in &incumbent.files {
        let file_source = fixture
            .project()
            .read_source(&file_edits.file)
            .expect("read incumbent edit source");
        for edit in &file_edits.edits {
            assert_eq!(&file_source[edit.start_byte..edit.end_byte], "value");
            assert_eq!(edit.new_text, "renamed");
        }
    }

    let mixed = InlineTestProject::new()
        .file(
            "src/main/java/model/Visible.java",
            "package model; public class Visible {}",
        )
        .file(
            "src/main/java/model/Other.java",
            "package model; public class Other {}",
        )
        .file(
            "src/main/java/model/Hidden.java",
            "package model; class Hidden {}",
        )
        .file(
            "src/main/kotlin/client/Use.kt",
            "package client\nimport model.Visible\nclass Use { val value: Visible? = null }\n",
        )
        .build();
    let mixed_workspace = mixed.workspace_analyzer(crate::AnalyzerConfig::default());
    let mixed_analyzer =
        crate::analyzer::resolve_analyzer::<JavaAnalyzer>(mixed_workspace.analyzer())
            .expect("mixed workspace has a Java analyzer")
            .clone();
    assert!(
        mixed
            .project()
            .analyzer_languages()
            .contains(&Language::Kotlin)
    );
    let mixed_listing_count = mixed.project().workspace_file_listing_count();
    let visible = target(
        &mixed_analyzer,
        &mixed,
        "src/main/java/model/Visible.java",
        "Visible",
        crate::analyzer::CodeUnitType::Class,
    );
    let peer_error = super::super::native_rename::java_native_rename(
        &mixed_analyzer,
        mixed.project(),
        &visible,
        "Renamed",
        &CancellationToken::new(),
    )
    .expect_err("a Java target visible from Kotlin must refuse native rename");
    assert_eq!(peer_error.kind, "incomplete_analysis", "{peer_error:?}");
    assert!(
        peer_error
            .message
            .contains("InverseIndexReferenceEnumerationIncomplete")
    );
    let mixed_admitted = mixed_analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<crate::hash::HashSet<_>>();
    let mixed_usage = JavaNativeUsageStrategy::new().find_usages(
        &mixed_analyzer,
        std::slice::from_ref(&visible),
        &mixed_admitted,
        100,
    );
    let FuzzyResult::Incomplete { diagnostics, .. } = mixed_usage else {
        panic!(
            "selected Kotlin inventory must keep Java usages explicitly incomplete: {mixed_usage:?}"
        );
    };
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason_kind == "native_java_peer_languages_omitted"),
        "mixed-language diagnostics must name the omitted peer scope: {diagnostics:#?}"
    );
    let unrelated_public = target(
        &mixed_analyzer,
        &mixed,
        "src/main/java/model/Other.java",
        "Other",
        crate::analyzer::CodeUnitType::Class,
    );
    let public_error = super::super::native_rename::java_native_rename(
        &mixed_analyzer,
        mixed.project(),
        &unrelated_public,
        "RenamedOther",
        &CancellationToken::new(),
    )
    .expect_err("a selected Kotlin source can name any public Java type by qualified name");
    assert_eq!(public_error.kind, "incomplete_analysis", "{public_error:?}");
    assert!(
        public_error
            .message
            .contains("InverseIndexReferenceEnumerationIncomplete")
    );

    let package_private = target(
        &mixed_analyzer,
        &mixed,
        "src/main/java/model/Hidden.java",
        "Hidden",
        crate::analyzer::CodeUnitType::Class,
    );
    super::super::native_rename::java_native_rename(
        &mixed_analyzer,
        mixed.project(),
        &package_private,
        "RenamedHidden",
        &CancellationToken::new(),
    )
    .expect("a Kotlin source in another package cannot name a package-private Java type");
    assert_eq!(
        mixed.project().workspace_file_listing_count(),
        mixed_listing_count,
        "peer completeness is derived from selected rows, without a project file scan"
    );
}

#[test]
fn java_native_rename_rejects_local_variable_capture() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public int value; }",
        ),
        (
            "src/main/java/model/Local.java",
            "package model; class Local extends Base { int read() { int renamed = 0; return value; } }",
        ),
    ]);
    let field = target(
        &analyzer,
        &fixture,
        BASE,
        "value",
        crate::analyzer::CodeUnitType::Field,
    );
    let error = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &field,
        "renamed",
        &CancellationToken::new(),
    )
    .expect_err("a local variable must not capture an inherited field rename");
    assert_eq!(error.kind, "capture_or_rebinding", "{error:?}");
    assert!(
        error
            .message
            .contains("Java rename changes selected binding sites")
    );
}

#[test]
fn java_native_rename_rejects_field_hiding_in_the_counterfactual_world() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public int value; }",
        ),
        (
            "src/main/java/model/Child.java",
            "package model; class Child extends Base { int renamed; int read() { return value; } }",
        ),
    ]);
    let field = target(
        &analyzer,
        &fixture,
        BASE,
        "value",
        crate::analyzer::CodeUnitType::Field,
    );
    let error = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &field,
        "renamed",
        &CancellationToken::new(),
    )
    .expect_err("the child's field must not take over the base field's selected use");
    assert_eq!(error.kind, "capture_or_rebinding", "{error:?}");
    assert!(
        error
            .message
            .contains("Java rename changes selected binding sites")
    );
}

#[test]
fn java_native_rename_updates_confirmed_inherited_member_sites() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public int value; }",
        ),
        (
            "src/main/java/model/Child.java",
            "package model; class Child extends Base { int read(Child child) { return child.value; } }",
        ),
    ]);
    let field = target(
        &analyzer,
        &fixture,
        BASE,
        "value",
        crate::analyzer::CodeUnitType::Field,
    );
    let original = inverse(&analyzer, &field);
    assert_eq!(
        original.completeness,
        EdgeCompleteness::Complete,
        "{original:#?}"
    );
    assert!(edge_paths(&original).contains("src/main/java/model/Child.java"));

    let native = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &field,
        "renamed",
        &CancellationToken::new(),
    )
    .expect("a confirmed inherited field reference remains bound after a safe rename");
    let source = fixture
        .project()
        .read_source(&fixture.file(BASE))
        .expect("read field declaration for incumbent rename");
    let incumbent = crate::symbol_rename::rename_symbol(
        &analyzer,
        fixture.project(),
        fixture.file(BASE),
        crate::symbol_rename::RenameSelection::ByteOffset(
            source.find("value;").expect("field declaration"),
        ),
        "renamed",
    )
    .expect("incumbent inherited-field rename");
    assert_eq!(
        normalized_rename_edits(&native.files),
        normalized_rename_edits(&incumbent.files)
    );
    assert!(native.files.iter().any(|file| {
        file.file.rel_path() == std::path::Path::new("src/main/java/model/Child.java")
    }));
}

#[test]
fn java_native_rename_refuses_unproven_method_call_before_counterfactual() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public void oldName() {} }",
        ),
        (
            "src/main/java/model/Child.java",
            "package model; class Child extends Base { public void newName() {} void use(Child child) { child.oldName(); } }",
        ),
    ]);
    let method = target(
        &analyzer,
        &fixture,
        BASE,
        "oldName",
        crate::analyzer::CodeUnitType::Function,
    );
    let error = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &method,
        "newName",
        &CancellationToken::new(),
    )
    .expect_err("the replacement method would capture the child call site");
    assert_eq!(error.kind, "incomplete_analysis", "{error:?}");
    assert!(error.message.contains("original Java inverse evidence"));
    assert!(
        error.message.contains("InverseIndexResolutionIncomplete"),
        "method-call applicability remains explicitly incomplete: {error:?}"
    );
}

#[test]
fn java_native_rename_refuses_an_unproven_existing_override_family() {
    let (fixture, analyzer) = fixture_with_java_sources(&[
        (
            BASE,
            "package model; public class Base { public void action() {} }",
        ),
        (
            "src/main/java/model/Child.java",
            "package model; class Child extends Base { @Override public void action() {} }",
        ),
    ]);
    let method = target(
        &analyzer,
        &fixture,
        BASE,
        "action",
        crate::analyzer::CodeUnitType::Function,
    );
    let error = super::super::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &method,
        "renamed",
        &CancellationToken::new(),
    )
    .expect_err("an override family without inverse relation proof must be refused");
    assert_eq!(error.kind, "incomplete_analysis", "{error:?}");
    assert!(
        error
            .message
            .contains("cannot establish the override relation")
    );
}
