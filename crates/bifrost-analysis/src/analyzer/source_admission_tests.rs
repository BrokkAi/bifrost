//! Hard-won grammar/preparation/store regressions for generated C admission.
use super::*;
use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::cpp::CppAdapter;
use crate::analyzer::javascript::JavascriptAdapter;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_test_macros::hardwon;

fn table() -> String {
    table_with_items(1400)
}

fn table_with_items(items: usize) -> String {
    format!(
        "static const unsigned long long words[] = {{{}}}, sibling = 7;\nint target(int n) {{ while (n > 0) {{ n = n - 1; }} return n; }}\n",
        "0x0123456789abcdef,".repeat(items)
    )
}

fn parse<A: LanguageAdapter>(adapter: &A, source: &str, setting: Option<&str>) -> BoundedParse {
    let mut parser = Parser::new();
    parser.set_language(&adapter.parser_language()).unwrap();
    parse_admitted_source_with_policy(
        &mut parser,
        adapter,
        source,
        None,
        Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
        SourceAdmissionPolicy::from_setting(setting),
    )
}

#[test]
#[hardwon("#5408: generated numeric data was rejected together with overlong executable syntax")]
fn numeric_data_admission_preserves_structure_and_explicit_limits() {
    let source = table();
    assert!(
        source
            .lines()
            .any(|line| line.len() > brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH)
    );
    let BoundedParse::Complete(tree) = parse(&CppAdapter, &source, None) else {
        panic!("default numeric table must be admitted");
    };
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
    assert_eq!(tree.root_node().end_byte(), source.len());
    for setting in [Some("invalid"), Some("0"), Some("32768")] {
        assert!(matches!(
            parse(&CppAdapter, &source, setting),
            BoundedParse::Complete(_)
        ));
    }
    assert!(matches!(
        parse(&CppAdapter, &source, Some("16000")),
        BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { limit: 16000, .. })
    ));
    assert!(matches!(
        parse(&CppAdapter, "int binary;\0", Some("0")),
        BoundedParse::Refused(SourceAdmissionRefusal::Binary)
    ));
    assert!(matches!(
        parse(
            &JavascriptAdapter,
            &format!("const words = [{}];", "1,".repeat(9000)),
            None
        ),
        BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
    ));

    let signed = format!(
        "long long values[][900] = {{{{{}}},{{1,2}}}};\n",
        "+0x0123456789abcdef,-0x0123456789abcdef,".repeat(450)
    );
    assert!(matches!(
        parse(&CppAdapter, &signed, None),
        BoundedParse::Complete(_)
    ));

    // Short-line tables must not spend the exception's excluded-node allowance.
    let ordinary_tables = "static int ordinary[] = {1,2,3,4,5,6,7,8};\n".repeat(600);
    assert!(matches!(
        parse(&CppAdapter, &(ordinary_tables + &source), None),
        BoundedParse::Complete(_)
    ));
}

#[test]
#[hardwon(
    "#5408: AST data exemption must not hide executable, recovered or structurally overlong source"
)]
fn numeric_data_admission_refuses_nonliteral_and_over_budget_trees() {
    for operand in [
        "f()",
        "identifier",
        "-f()",
        "+x",
        "!1",
        "1_tag",
        ".x=1",
        "[f()]=1",
        "[](){return 1;}()",
    ] {
        let source = format!(
            "int data[] = {{{}{operand}}};\n",
            "0x0123456789abcdef,".repeat(1000)
        );
        assert!(
            matches!(
                parse(&CppAdapter, &source, None),
                BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
            ),
            "nonliteral control {operand} was admitted"
        );
    }
    let source = format!(
        "int data[] = {{{}}}; {}\n",
        "0x0123456789abcdef,".repeat(1000),
        "int code;".repeat(2000)
    );
    assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
    ));
    let source = format!("int data[] = {{{}}};\n", "0x0123456789abcdef,".repeat(4200));
    assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: super::super::source_admission::AdmissionDimension::ExcludedNodes,
            limit: 8192,
            ..
        })
    ));
    let many_nodes = format!("int data[] = {{{}}};\n", "1,".repeat(33_000));
    assert!(matches!(
        parse(&CppAdapter, &many_nodes, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: super::super::source_admission::AdmissionDimension::Nodes,
            limit: 65_536,
            ..
        })
    ));
    let overlapping = format!(
        "int data[] = {{{}}};\n",
        "{".repeat(110) + &"0x0123456789abcdef,".repeat(4200) + &"}".repeat(110)
    );
    assert!(matches!(
        parse(&CppAdapter, &overlapping, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: super::super::source_admission::AdmissionDimension::SpanBytes,
            limit: 8_388_608,
            ..
        })
    ));
    let source = format!("int data[] = {{{}}};\n", "1,".repeat(600_000));
    assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: super::super::source_admission::AdmissionDimension::SourceBytes,
            limit: 1_048_576,
            ..
        })
    ));
    let source = format!(
        "int data[] = {{{}}};\n",
        "{".repeat(130) + "1" + &"}".repeat(130) + &",0x0123456789abcdef".repeat(1000)
    );
    assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: super::super::source_admission::AdmissionDimension::Depth,
            ..
        })
    ));
}

#[test]
#[hardwon(
    "#5408: successful generated-header admission must survive canonical reads, warm reuse and reopen"
)]
fn numeric_data_admission_cold_warm_reopen_retains_exact_source_and_siblings() {
    let source = table();
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("data.h", &source)
        .build();
    let file = fixture.file("data.h");
    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
    let project = fixture.project_dyn();
    let db = fixture.root().join("admission.db");
    let build = |context| {
        TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            CppAdapter,
            AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap()
    };
    let context = store_context_from_store(
        project.as_ref(),
        AnalyzerStore::open_persistent(&db).unwrap(),
        false,
    );
    let cold = build(context.clone());
    let warm = build(context);
    let analyzers: [&TreeSitterAnalyzer<CppAdapter>; 2] = [&cold, &warm];
    for analyzer in analyzers {
        let scope = AnalyzerQueryScope::new(analyzer);
        let facts = analyzer
            .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
            .expect("published canonical table facts");
        assert!(
            facts
                .declaration_units
                .values()
                .flatten()
                .any(|unit| unit.short_name() == "sibling")
        );
        assert!(
            facts
                .declaration_units
                .values()
                .flatten()
                .any(|unit| unit.short_name() == "target")
        );
        assert!(
            analyzer
                .store_context
                .store
                .contains_parsed_blob(oid, "cpp")
                .unwrap()
        );
        assert_eq!(analyzer.fetch_file_state(&file).unwrap().source, source);
        assert!(
            scope.read_completion().is_ok(),
            "{:?}",
            scope.read_completion()
        );
    }
    drop(warm);
    drop(cold);
    let reopened = build(store_context_from_store(
        project.as_ref(),
        AnalyzerStore::open_persistent(&db).unwrap(),
        false,
    ));
    let scope = AnalyzerQueryScope::new(&reopened);
    assert!(
        reopened
            .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
            .is_some()
    );
    assert!(scope.read_completion().is_ok());
    assert_eq!(reopened.fetch_file_state(&file).unwrap().source, source);
}

#[test]
#[hardwon("#5408: admission budget refusal was indistinguishable from a missing store publication")]
fn numeric_data_admission_refusal_is_incomplete_and_not_a_store_error() {
    let source = format!("int data[] = {{{}}};\n", "0x0123456789abcdef,".repeat(4200));
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("data.h", &source)
        .build();
    let file = fixture.file("data.h");
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
    for _ in 0..2 {
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            analyzer
                .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                .is_none()
        );
        assert!(
            matches!(scope.read_completion(), Err(QueryReadIncomplete::SemanticEvidenceUnavailable(reason)) if reason.contains("ExcludedNodes") && reason.contains("8192"))
        );
        assert!(scope.store_error().is_none());
    }
    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
    assert!(
        !analyzer
            .store_context
            .store
            .contains_parsed_blob(oid, "cpp")
            .unwrap()
    );
}

#[test]
#[hardwon("#5408: interrupted bounded data proofs must not poison exact syntax reuse")]
fn numeric_data_admission_interruption_is_transient() {
    let source = table();
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("data.h", &source)
        .build();
    let file = fixture.file("data.h");
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
    let scope = AnalyzerQueryScope::new(&analyzer);
    let cancellation = CancellationToken::cancel_after_checks_for_test(12);
    assert!(matches!(
        analyzer.prepared_syntax_limited_cancellable(
            scope.token(),
            &file,
            source.len(),
            Some(&cancellation)
        ),
        PreparedSyntaxLimitedOutcome::Cancelled
    ));
    let PreparedSyntaxLimitedOutcome::Available(_, syntax) =
        analyzer.prepared_syntax_limited_cancellable(scope.token(), &file, source.len(), None)
    else {
        panic!("an interrupted proof must be retried");
    };
    assert_eq!(syntax.source(), source);
    let mut parser = Parser::new();
    parser.set_language(&CppAdapter.parser_language()).unwrap();
    assert!(matches!(
        parse_admitted_source_with_policy(
            &mut parser,
            &CppAdapter,
            &source,
            None,
            Instant::now(),
            SourceAdmissionPolicy::from_setting(None)
        ),
        BoundedParse::TimedOut
    ));
    assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Complete(_)
    ));
}

#[test]
#[hardwon("#5408: cached data admission must not authorize a changed source blob")]
fn numeric_data_admission_cache_follows_the_exact_blob() {
    let source = table();
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("data.h", &source)
        .build();
    let file = fixture.file("data.h");
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
    let cache = moka::sync::Cache::new(4);
    assert!(
        analyzer
            .canonical_cpp_source_facts(&file, "cpp", &cache)
            .is_some()
    );
    file.write(format!(
        "int data[] = {{{}unknown}};\n",
        "0x0123456789abcdef,".repeat(1400)
    ))
    .unwrap();
    let changed: TreeSitterAnalyzer<CppAdapter> =
        IAnalyzer::update(&analyzer, &BTreeSet::from([file.clone()]));
    {
        let scope = AnalyzerQueryScope::new(&changed);
        assert!(
            changed
                .canonical_cpp_source_facts(&file, "cpp", &cache)
                .is_none()
        );
        assert!(
            matches!(scope.read_completion(), Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file)
        );
        assert!(scope.store_error().is_none());
    }
    file.write(&source).unwrap();
    let repaired: TreeSitterAnalyzer<CppAdapter> =
        IAnalyzer::update(&changed, &BTreeSet::from([file.clone()]));
    let scope = AnalyzerQueryScope::new(&repaired);
    assert!(
        repaired
            .canonical_cpp_source_facts(&file, "cpp", &cache)
            .is_some()
    );
    assert!(scope.read_completion().is_ok());
}

// Separate processes freeze configuration before any analyzer worker exists.
// Every stage uses the same workspace and store; no unsafe environment mutation.
const TRANSITION_CHILD_ROOT: &str = "BIFROST_5408_TRANSITION_CHILD_ROOT";
const TRANSITION_CHILD_DB: &str = "BIFROST_5408_TRANSITION_CHILD_DB";
const TRANSITION_CHILD_OUTPUT: &str = "BIFROST_5408_TRANSITION_CHILD_OUTPUT";

fn persisted_policy_stage(
    root: &std::path::Path,
    database: &std::path::Path,
    stage: &str,
    setting: Option<&str>,
) -> serde_json::Value {
    let output_path = root.join(format!("{stage}.json"));
    let qualified = concat!(
        module_path!(),
        "::numeric_data_admission_persisted_policy_transitions"
    );
    let test_name = qualified
        .split_once("::")
        .expect("test module has crate prefix")
        .1;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(TRANSITION_CHILD_ROOT, root)
        .env(TRANSITION_CHILD_DB, database)
        .env(TRANSITION_CHILD_OUTPUT, &output_path)
        .env_remove("BIFROST_MAX_LINE_LENGTH");
    if let Some(setting) = setting {
        command.env("BIFROST_MAX_LINE_LENGTH", setting);
    }
    let output = command.output().expect("run isolated admission stage");
    assert!(
        output.status.success(),
        "stage {stage}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // An incorrectly filtered child must fail here rather than pass with zero tests.
    serde_json::from_slice(&std::fs::read(output_path).expect("selected child wrote observation"))
        .unwrap()
}

fn observe_persisted_policy_child(root: std::path::PathBuf) {
    use serde_json::json;
    use std::collections::BTreeMap;
    let database = std::env::var_os(TRANSITION_CHILD_DB).expect("child database");
    let output = std::env::var_os(TRANSITION_CHILD_OUTPUT).expect("child output");
    let project: Arc<dyn Project> =
        Arc::new(crate::analyzer::TestProject::new(&root, Language::Cpp));
    let store = AnalyzerStore::open_persistent(std::path::Path::new(&database)).unwrap();
    let context = store_context_from_store(project.as_ref(), store, false);
    let parses = Arc::new(AtomicUsize::new(0));
    let progress_parses = Arc::clone(&parses);
    let analyzer: TreeSitterAnalyzer<CppAdapter> =
        TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            CppAdapter,
            AnalyzerConfig::default(),
            context,
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    progress_parses.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .unwrap();
    let unit_names = |units: Vec<CodeUnit>| {
        let mut names: Vec<_> = units
            .into_iter()
            .map(|unit| {
                (
                    crate::path_utils::rel_path_string(unit.source()),
                    unit.short_name().to_owned(),
                )
            })
            .collect();
        names.sort();
        names
    };
    let mut summary = BTreeMap::new();
    let mut canonical = BTreeMap::new();
    let mut incomplete = BTreeMap::new();
    let mut published = BTreeMap::new();
    for (path, language) in [("data.h", "cpp"), ("data.c", "cpp:c")] {
        let file = ProjectFile::new(root.clone(), path);
        // Summary first: this was the unguarded persisted reuse reported in review.
        summary.insert(
            path,
            analyzer
                .summary_file_projection(&file)
                .map(|projection| unit_names(projection.declarations.clone())),
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let facts =
            analyzer.canonical_cpp_source_facts(&file, language, &moka::sync::Cache::new(1));
        canonical.insert(path, facts.is_some());
        let reason = match scope.read_completion() {
            Ok(()) => {
                assert!(facts.is_some());
                None
            }
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) => {
                assert_eq!(unavailable, file);
                assert!(facts.is_none());
                Some("StructureUnavailable".to_owned())
            }
            Err(QueryReadIncomplete::SemanticEvidenceUnavailable(reason)) => {
                assert!(facts.is_none());
                Some(reason.into_string())
            }
            Err(other) => panic!("unexpected admission read failure: {other:?}"),
        };
        assert!(scope.store_error().is_none());
        incomplete.insert(path, reason);
        let source = project.read_source(&file).unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        published.insert(
            path,
            analyzer
                .store_context
                .store
                .contains_parsed_blob(oid, language)
                .unwrap(),
        );
    }
    // Exercise ordinary SQL-backed consumers, without a new per-reader guard.
    let all = unit_names(analyzer.all_declarations().collect());
    let primary_ranges = unit_names(
        analyzer
            .all_declarations_with_primary_ranges()
            .into_iter()
            .map(|(unit, _)| unit)
            .collect(),
    );
    let mounted = analyzer
        .workspace_declarations_with_primary_ranges(&CancellationToken::new())
        .map(|units| unit_names(units.into_iter().map(|(unit, _)| unit).collect()));
    let generations: BTreeMap<_, _> = analyzer
        .store_context
        .generations
        .iter()
        .map(|(language, generation)| (language.clone(), generation.get()))
        .collect();
    let observation = json!({
        "consumers": {"summary": summary, "canonical": canonical, "incomplete": incomplete,
            "published": published, "all": all, "primary_ranges": primary_ranges, "mounted": mounted},
        "generations": generations,
        "producer_parse_events": parses.load(Ordering::Relaxed),
        "content_identity": analyzer.language_content_identity().as_bytes().to_vec(),
        "read_epoch": crate::analyzer::read_verification::analysis_epoch_digest().as_bytes().to_vec(),
    });
    std::fs::write(
        std::path::Path::new(&output),
        serde_json::to_vec_pretty(&observation).unwrap(),
    )
    .unwrap();
}

#[test]
#[hardwon(
    "#5408: persisted summaries and bulk declarations reused a blob admitted under another policy"
)]
fn numeric_data_admission_persisted_policy_transitions() {
    if let Some(root) = std::env::var_os(TRANSITION_CHILD_ROOT) {
        observe_persisted_policy_child(root.into());
        return;
    }
    for oversized in [false, true] {
        let source = table_with_items(if oversized { 4200 } else { 1400 });
        let fixture = InlineTestProject::with_language(Language::Cpp)
            .file("data.h", &source)
            .file("data.c", &source)
            .file("healthy.cpp", "int retained() { return 1; }\n")
            .build();
        let database = fixture.root().join("same-store.db");
        let initial_setting = if oversized { Some("0") } else { None };
        let strict_setting = if oversized { None } else { Some("16000") };
        let admitted =
            persisted_policy_stage(fixture.root(), &database, "admitted", initial_setting);
        let warm = persisted_policy_stage(fixture.root(), &database, "warm", initial_setting);
        assert_eq!(admitted["consumers"], warm["consumers"]);
        assert_eq!(admitted["generations"], warm["generations"]);
        assert_eq!(warm["producer_parse_events"], 0);
        for path in ["data.h", "data.c"] {
            assert_eq!(admitted["consumers"]["canonical"][path], true);
            assert_eq!(admitted["consumers"]["published"][path], true);
            assert!(
                admitted["consumers"]["summary"][path]
                    .as_array()
                    .is_some_and(|units| units.iter().any(|unit| unit[1] == "sibling"))
            );
        }
        let strict = persisted_policy_stage(fixture.root(), &database, "strict", strict_setting);
        let fresh = persisted_policy_stage(
            fixture.root(),
            &fixture.root().join("fresh-strict.db"),
            "fresh-strict",
            strict_setting,
        );
        assert_eq!(
            strict["consumers"], fresh["consumers"],
            "reopened strict store must agree with fresh strict control"
        );
        assert_eq!(strict["read_epoch"], fresh["read_epoch"]);
        assert_ne!(admitted["content_identity"], strict["content_identity"]);
        assert_ne!(admitted["read_epoch"], strict["read_epoch"]);
        for language in ["cpp", "cpp:c"] {
            assert_ne!(
                admitted["generations"][language],
                strict["generations"][language]
            );
        }
        for path in ["data.h", "data.c"] {
            assert!(strict["consumers"]["summary"][path].is_null());
            assert_eq!(strict["consumers"]["canonical"][path], false);
            assert_eq!(strict["consumers"]["published"][path], false);
            if oversized {
                assert!(
                    strict["consumers"]["incomplete"][path]
                        .as_str()
                        .is_some_and(
                            |reason| reason.contains("ExcludedNodes") && reason.contains("8192")
                        )
                );
            } else {
                assert_eq!(
                    strict["consumers"]["incomplete"][path],
                    "StructureUnavailable"
                );
            }
        }
        assert!(
            strict["consumers"]["all"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unit| unit[0] == "healthy.cpp" && unit[1] == "retained")
        );
        // Restore valid default input. For the zero->default case the policy
        // stays default and only the blob changes; a refusal must not poison it.
        if oversized {
            for path in ["data.h", "data.c"] {
                fixture.file(path).write(table()).unwrap();
            }
        }
        let restored = persisted_policy_stage(fixture.root(), &database, "restored-default", None);
        let restored_warm =
            persisted_policy_stage(fixture.root(), &database, "restored-warm", None);
        if oversized {
            assert_eq!(
                strict["generations"], restored["generations"],
                "source repair under the same default policy must not rotate the epoch"
            );
        } else {
            for language in ["cpp", "cpp:c"] {
                assert_ne!(
                    strict["generations"][language],
                    restored["generations"][language]
                );
            }
        }
        assert_eq!(restored["consumers"], restored_warm["consumers"]);
        assert_eq!(restored["generations"], restored_warm["generations"]);
        assert_eq!(restored_warm["producer_parse_events"], 0);
        for path in ["data.h", "data.c"] {
            assert_eq!(restored["consumers"]["canonical"][path], true);
            assert_eq!(restored["consumers"]["published"][path], true);
            assert!(restored["consumers"]["summary"][path].is_array());
        }
    }
}

#[test]
#[hardwon("#5596: generated Python bytes descriptors were rejected by exact syntax admission")]
fn python_literal_admission_grammar_boundary() {
    let adapter = crate::analyzer::python::PythonAdapter;
    let payload = "x".repeat(17_000);
    for literal in [format!("b'{payload}'"), format!("'{payload}' 'suffix'")] {
        let source = format!("DESCRIPTOR = consume({literal})\n");
        let BoundedParse::Complete(tree) = parse(&adapter, &source, None) else {
            panic!("Python literal data must be admitted");
        };
        assert!(!tree.root_node().has_error());
        assert_eq!(tree.root_node().end_byte(), source.len());
        assert!(matches!(
            parse(&adapter, &source, Some("16000")),
            BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
        ));
    }
    let source = format!("value = f'{payload}{{replacement}}'\n");
    assert!(matches!(
        parse(&adapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
    ));
}
