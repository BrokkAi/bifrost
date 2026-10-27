use crate::analyzer::java::selected_reverse::*;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use crate::analyzer::usages::java_graph::JavaUsageGraphStrategy;

use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_analysis::analyzer::usages::traits::UsageAnalyzer;

use brokk_bifrost_core::analyzer::project::Project;

use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::query_token::QueryScope;

use crate::native_resolution_test_support::JavaNativeUsageStrategy;
use std::collections::BTreeSet;

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
    kind: brokk_bifrost_core::analyzer::model::CodeUnitType,
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
        JavaSelectedReverseOutcome::Ready(answer) => {
            if std::env::var_os("BIFROST_REVERSE_EVIDENCE").is_some() {
                eprintln!("REVERSE-ROWS {answer:?}");
            }
            answer
        }
        outcome => panic!("selected Java inverse query failed: {outcome:?}"),
    }
}

#[test]
fn java_native_selected_inverse_candidate_mount_reader_seeks_shared_indexes() {
    let (fixture, analyzer) = fixture();
    let class = target(
        &analyzer,
        &fixture,
        BASE,
        "Base",
        brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
    );
    let answer = inverse(&analyzer, &class);
    assert!(!answer.edges.is_empty(), "{answer:#?}");
    let plan = brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_reverse_rows::last_jvm_reverse_candidate_plan_for_test();
    eprintln!("selected Java reverse candidate EXPLAIN QUERY PLAN: {plan:#?}");
    for required in [
        "resolution_reference_lookup_identities_identity",
        "resolution_qualified_routes_source_lookup",
        "resolution_paths_root_terminal",
        "resolution_paths_end_lookup_identity",
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

fn call_site_positions(
    result: &brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationResult,
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
    );
    let limits = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
        max_files: 100,
        max_source_bytes: usize::MAX,
        max_candidates: 100,
    };
    let native = crate::analyzer::java::native_call_relations::java_native_incoming_calls(
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
            let syntax = brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_site_syntax_for_reference(
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

    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService::incoming_bounded(
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
    );
    let native_static = crate::analyzer::java::native_call_relations::java_native_incoming_calls(
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
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent_static = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService::incoming_bounded(
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
            unit.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Function
                && unit.owner_is_type_scope()
                && unit.signature() == Some("(int)")
                && analyzer
                    .signature_metadata(unit)
                    .iter()
                    .any(|metadata| metadata.callable_is_constructor())
        })
        .expect("explicit Base(int) constructor");
    let native_constructor =
        crate::analyzer::java::native_call_relations::java_native_incoming_calls(
            &analyzer,
            &constructor,
            limits,
            None,
        );
    assert!(native_constructor.sites.iter().all(|site| {
        site.kind == brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind::Constructor
    }));
    assert!(
        native_constructor
            .sites
            .iter()
            .any(|site| site.file == fixture.file(SAME)),
        "new Base(1) must project as a constructor invocation: {native_constructor:#?}"
    );
    let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
    let incumbent_constructor = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService::incoming_bounded(
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
            unit.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Function
                && unit.terminal_name() == "pick"
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        overloads.len(),
        2,
        "fixture must retain both overloads: {declarations:#?}"
    );
    let limits = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits {
        max_files: 20,
        max_source_bytes: usize::MAX,
        max_candidates: 20,
    };
    let answers = overloads
        .iter()
        .map(|overload| {
            crate::analyzer::java::native_call_relations::java_native_incoming_calls(
                &analyzer, overload, limits, None,
            )
        })
        .collect::<Vec<_>>();
    for (answer, overload) in answers.iter().zip(&overloads) {
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let incumbent = brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService::incoming_bounded(
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
        assert_eq!(answer.sites.len(), 1, "{answer:#?}");
        let site = &answer.sites[0];
        assert_eq!(site.callee, *overload, "the call keeps its exact overload");
        assert_eq!(
            &source[site.range.start_byte..site.range.end_byte],
            expected,
            "intrinsic argument mismatch excludes the other overload"
        );
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
            answer.diagnostics.is_empty(),
            "the intrinsic overload pair is fully decidable: {answer:#?}"
        );
    }
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
    );
    let error = crate::analyzer::java::native_rename::java_native_rename(
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
    );
    let error = crate::analyzer::java::native_rename::java_native_rename(
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
    );
    let error = crate::analyzer::java::native_rename::java_native_rename(
        &analyzer,
        fixture.project(),
        &method,
        "newName",
        &CancellationToken::new(),
    )
    .expect_err("the replacement method would capture the child call site");
    // The call's evidence is complete: the unindexed Object superclass of
    // `Base` cannot declare `oldName`. The rename is still refused, by the
    // counterfactual capture check instead of before it.
    assert_eq!(error.kind, "capture_or_rebinding", "{error:?}");
    assert!(
        error
            .message
            .contains("Java rename changes selected binding sites"),
        "{error:?}"
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
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
    );
    let error = crate::analyzer::java::native_rename::java_native_rename(
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

#[test]
fn java_native_usage_sites_match_the_incumbent_on_shared_real_store_families() {
    let (fixture, analyzer) = fixture();
    let candidates = analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<brokk_bifrost_core::hash::HashSet<_>>();
    for target in [
        target(
            &analyzer,
            &fixture,
            BASE,
            "Base",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "field",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "method",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        ),
        analyzer
            .declarations(&fixture.file(BASE))
            .into_iter()
            .find(|unit| {
                unit.kind() == brokk_bifrost_core::analyzer::model::CodeUnitType::Function
                    && unit.owner_is_type_scope()
                    && unit.signature() == Some("(int)")
            })
            .expect("explicit Java constructor target"),
        target(
            &analyzer,
            &fixture,
            BASE,
            "staticMethod",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "staticField",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "protectedMethod",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "packageMethod",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        ),
        target(
            &analyzer,
            &fixture,
            BASE,
            "secret",
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
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
