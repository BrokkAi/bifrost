use super::*;
use crate::analyzer::RustAnalyzer;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::rust::native_points::resolve_rust_definition_bounded;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

fn project(source: &str) -> (BuiltInlineTestProject, RustAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_navigation\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

fn native_definition(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    source: &str,
    spelling: &str,
) -> DefinitionLookupOutcome {
    let start = source.rfind(spelling).expect("fixture reference");
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    let tree = context.tree(file, Language::Rust, source);
    let site = focused_reference_site(
        &mut context,
        &DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + spelling.len()),
        },
        Language::Rust,
        source,
        tree.as_ref(),
    )
    .expect("focused native reference");
    match resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: tree.as_ref(),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    }) {
        BoundedResolution::Complete { value, .. } => value,
        terminal => panic!("native fixture did not complete: {terminal:?}"),
    }
}

fn navigation(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    definition: DefinitionLookupOutcome,
    operation: NavigationOperation,
) -> NavigationLookupOutcome {
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    navigation_lookup_outcome(
        analyzer,
        scope.token(),
        &mut context,
        file,
        definition.into(),
        language_for_file(file),
        operation,
    )
}

fn reference_identity(site: &ResolvedReferenceSite) -> (&str, &str, &Range, usize, usize) {
    (
        &site.path,
        &site.text,
        &site.range,
        site.focus_start_byte,
        site.focus_end_byte,
    )
}

#[test]
fn native_navigation_preserves_lexical_and_import_target_cardinality() {
    let source = concat!(
        "pub mod provider { pub struct Target {} pub const Target: usize = 1; }\n",
        "use crate::provider::Target;\n",
        "pub fn caller(parameter: usize) -> usize { let local = parameter; local }\n",
    );
    let (fixture, analyzer) = project(source);
    let file = fixture.file("src/lib.rs");
    for (spelling, status, target_count) in [
        ("parameter", DefinitionLookupStatus::Resolved, 0),
        ("local", DefinitionLookupStatus::Resolved, 0),
        ("Target", DefinitionLookupStatus::Ambiguous, 2),
    ] {
        let definition = native_definition(&analyzer, &file, source, spelling);
        assert_eq!(definition.status, status, "{definition:#?}");
        for operation in [
            NavigationOperation::Definition,
            NavigationOperation::Declaration,
        ] {
            let finalized = finalize_navigation_outcome(definition.clone(), operation);
            let result = navigation(&analyzer, &file, finalized, operation);
            assert_eq!(result.status, status, "{result:#?}");
            assert_eq!(result.targets.len(), target_count);
            assert_eq!(result.lexical_definition, definition.lexical_definition);
            assert_eq!(
                result.reference.as_ref().map(reference_identity),
                definition.reference.as_ref().map(reference_identity)
            );
            assert_eq!(
                result
                    .targets
                    .iter()
                    .map(|target| target.code_unit.declaration_id())
                    .collect::<std::collections::HashSet<_>>(),
                definition
                    .definitions
                    .iter()
                    .map(CodeUnit::declaration_id)
                    .collect::<std::collections::HashSet<_>>()
            );
        }
    }
}

#[test]
fn native_navigation_keeps_canonical_ambiguity_after_display_deduplication() {
    let source = "pub mod provider { pub struct Target {} pub const Target: usize = 1; }\nuse crate::provider::Target;\n";
    let (fixture, analyzer) = project(source);
    let file = fixture.file("src/lib.rs");
    let mut definition = native_definition(&analyzer, &file, source, "Target");
    assert_eq!(definition.status, DefinitionLookupStatus::Ambiguous);
    assert_eq!(definition.definitions.len(), 2);
    assert_ne!(
        definition.definitions[0].declaration_id(),
        definition.definitions[1].declaration_id()
    );

    // Model the lossy presentation boundary independently of source identity:
    // the native answer retains two canonical bindings even if their display
    // projections coincide. Neither navigation conversion may create proof.
    definition.definitions[1] = definition.definitions[0].clone();
    for operation in [
        NavigationOperation::Definition,
        NavigationOperation::Declaration,
    ] {
        let finalized = finalize_navigation_outcome(definition.clone(), operation);
        assert_eq!(finalized.definitions.len(), 1);
        assert_eq!(finalized.status, DefinitionLookupStatus::Ambiguous);
        for input in [definition.clone(), finalized] {
            let result = navigation(&analyzer, &file, input, operation);
            assert_eq!(result.targets.len(), 1);
            assert_eq!(
                result.status,
                DefinitionLookupStatus::Ambiguous,
                "{result:#?}"
            );
        }
    }
}

#[test]
fn native_navigation_keeps_semantic_uncertainty_distinct_from_source_authority_failure() {
    // A missing root is a complete negative; use an actual activation gap to
    // exercise semantic uncertainty independently of source authority failure.
    let source = "#[cfg(unknown_configuration)] mod missing {}\nuse crate::missing::Target;\n";
    let (fixture, analyzer) = project(source);
    let file = fixture.file("src/lib.rs");
    let uncertain = native_definition(&analyzer, &file, source, "Target");
    assert_eq!(uncertain.status, DefinitionLookupStatus::Incomplete);
    let unavailable =
        native_definition(&analyzer, &file, "use crate::missing::Absent;\n", "Absent");
    assert_eq!(unavailable.status, DefinitionLookupStatus::Unavailable);
    assert!(
        unavailable
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_source_mismatch")
    );
    for definition in [uncertain, unavailable] {
        for operation in [
            NavigationOperation::Definition,
            NavigationOperation::Declaration,
        ] {
            let finalized = finalize_navigation_outcome(definition.clone(), operation);
            let result = navigation(&analyzer, &file, finalized, operation);
            assert_eq!(result.status, definition.status, "{result:#?}");
            assert!(result.targets.is_empty());
            assert!(result.lexical_definition.is_none());
            assert_eq!(
                result.reference.as_ref().map(reference_identity),
                definition.reference.as_ref().map(reference_identity)
            );
            assert_eq!(
                result
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.kind.as_str())
                    .collect::<Vec<_>>(),
                definition
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.kind.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn unavailable_navigation_discards_definition_and_lexical_leftovers() {
    let source = "pub struct Target {}\nfn caller(parameter: Target) -> Target { parameter }\n";
    let (fixture, analyzer) = project(source);
    let file = fixture.file("src/lib.rs");
    let mut unavailable = native_definition(&analyzer, &file, source, "parameter");
    assert!(unavailable.lexical_definition.is_some());
    unavailable.definitions = native_definition(&analyzer, &file, source, "Target").definitions;
    assert!(!unavailable.definitions.is_empty());
    // A language adapter can discover positive targets before source authority
    // fails. Neither conversion may publish those now-unauthorized leftovers.
    unavailable.status = DefinitionLookupStatus::Unavailable;
    unavailable.diagnostics.push(DefinitionLookupDiagnostic {
        claim: None,
        kind: "native_source_mismatch".to_string(),
        message: "source authority changed after candidate projection".to_string(),
    });
    for operation in [
        NavigationOperation::Definition,
        NavigationOperation::Declaration,
    ] {
        let finalized = finalize_navigation_outcome(unavailable.clone(), operation);
        assert_eq!(finalized.status, DefinitionLookupStatus::Unavailable);
        assert!(finalized.definitions.is_empty());
        assert!(finalized.lexical_definition.is_none());
        for input in [unavailable.clone(), finalized] {
            let result = navigation(&analyzer, &file, input, operation);
            assert_eq!(result.status, DefinitionLookupStatus::Unavailable);
            assert!(result.targets.is_empty());
            assert!(result.lexical_definition.is_none());
            assert_eq!(
                result.reference.as_ref().map(reference_identity),
                unavailable.reference.as_ref().map(reference_identity)
            );
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.kind == "native_source_mismatch" })
            );
        }
    }
}

#[test]
fn cpp_navigation_selects_own_body_from_one_logical_symbol() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("api.h", "int compute(int value);\n")
        .file(
            "api.cpp",
            "#include \"api.h\"\nint compute(int value) { return value; }\n",
        )
        .build();
    let analyzer = CppAnalyzer::new(fixture.project_dyn());
    let declarations = [fixture.file("api.h"), fixture.file("api.cpp")]
        .iter()
        .flat_map(|file| analyzer.get_declarations(file))
        .filter(|unit| unit.identifier() == "compute")
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 2, "{declarations:#?}");
    let definition = candidates_outcome(declarations);
    // The C++ producer groups physical declarations before navigation. A
    // semantic ambiguity is therefore unnecessary to select the body's site.
    assert_eq!(definition.status, DefinitionLookupStatus::Resolved);
    for (operation, expected_file) in [
        (NavigationOperation::Definition, fixture.file("api.cpp")),
        (NavigationOperation::Declaration, fixture.file("api.h")),
    ] {
        let result = navigation(
            &analyzer,
            &fixture.file("api.cpp"),
            definition.clone(),
            operation,
        );
        assert_eq!(
            result.status,
            DefinitionLookupStatus::Resolved,
            "{result:#?}"
        );
        assert_eq!(result.targets.len(), 1, "{result:#?}");
        assert_eq!(result.targets[0].code_unit.source(), &expected_file);
    }
}

#[test]
fn cpp_navigation_keeps_bodiless_overload_beside_another_overloads_body() {
    let source = concat!(
        "#include MISSING_HEADER\n#include \"api.h\"\n",
        "static int compute(int a) { return a; }\n",
        "int caller(int value) { return compute(value, value); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("api.h", "int compute(int a, int b);\n")
        .file("api.cpp", source)
        .build();
    let analyzer = CppAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("api.cpp");
    let start = source.rfind("compute").expect("overloaded call");
    let result = resolve_navigation_batch_with_source(
        &analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "compute".len()),
        }],
        file.clone(),
        Arc::from(source),
        NavigationOperation::Definition,
    )
    .remove(0);
    assert_eq!(
        result.status,
        DefinitionLookupStatus::Ambiguous,
        "{result:#?}"
    );
    assert_eq!(result.targets.len(), 2, "{result:#?}");
    assert!(
        result
            .targets
            .iter()
            .any(|target| target.code_unit.source() == &file)
    );
    assert!(
        result
            .targets
            .iter()
            .any(|target| target.code_unit.source() == &fixture.file("api.h"))
    );
}

#[test]
fn cpp_navigation_selects_one_exhaustive_conditional_family_occurrence() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file(
            "api.cpp",
            "#if FEATURE\nint compute() { return 1; }\n#else\nint compute() { return 2; }\n#endif\n",
        )
        .build();
    let analyzer = CppAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("api.cpp");
    let definition = candidates_outcome(
        analyzer
            .get_declarations(&file)
            .into_iter()
            .filter(|unit| unit.identifier() == "compute")
            .collect(),
    );
    assert_eq!(definition.status, DefinitionLookupStatus::Resolved);
    let scope = AnalyzerQueryScope::new(&analyzer);
    let occurrences = definition
        .definitions
        .iter()
        .flat_map(|unit| {
            brokk_bifrost_cpp::graph_support::CppSource::declaration_navigation_occurrences(
                &analyzer,
                scope.token(),
                unit,
            )
            .expect("indexed conditional occurrences")
        })
        .collect::<Vec<_>>();
    assert!(occurrences.len() >= 2, "{occurrences:#?}");
    assert!(
        occurrences
            .iter()
            .all(|occurrence| occurrence.conditional_family.is_some())
    );
    for operation in [
        NavigationOperation::Definition,
        NavigationOperation::Declaration,
    ] {
        let result = navigation(&analyzer, &file, definition.clone(), operation);
        assert_eq!(
            result.status,
            DefinitionLookupStatus::Resolved,
            "{result:#?}"
        );
        assert_eq!(result.targets.len(), 1, "{result:#?}");
    }
}

#[test]
fn cpp_navigation_preserves_same_declaration_nonvirtual_base_ambiguity() {
    let source = concat!(
        "struct Base { void run() {} };\n",
        "struct Left : Base {};\n",
        "struct Right : Base {};\n",
        "struct Diamond : Left, Right {};\n",
        "void caller(Diamond& receiver) { receiver.run(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("diamond.cpp", source)
        .build();
    let analyzer = CppAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("diamond.cpp");
    let start = source.rfind("run").expect("member call");
    let scope = AnalyzerQueryScope::new(&analyzer);
    let mut context = DefinitionBatchContext::new(&analyzer, scope.token());
    let tree = context.tree(&file, Language::Cpp, source);
    let site = focused_reference_site(
        &mut context,
        &DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "run".len()),
        },
        Language::Cpp,
        source,
        tree.as_ref(),
    )
    .expect("focused member reference");
    let definition = match cpp::resolve_cpp_bounded(
        &analyzer,
        &file,
        source,
        tree.as_ref(),
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ) {
        BoundedResolution::Complete { value, .. } => value,
        terminal => panic!("bounded C++ lookup did not complete: {terminal:?}"),
    };
    assert_eq!(definition.status, DefinitionLookupStatus::Ambiguous);
    assert_eq!(definition.definitions.len(), 1);
    assert!(
        definition
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.kind == "cpp_ambiguous_base_subobject" })
    );
    for operation in [
        NavigationOperation::Definition,
        NavigationOperation::Declaration,
    ] {
        let result = navigation(&analyzer, &file, definition.clone(), operation);
        assert_eq!(
            result.status,
            DefinitionLookupStatus::Ambiguous,
            "{result:#?}"
        );
        assert_eq!(result.targets.len(), 1, "{result:#?}");
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.kind == "cpp_ambiguous_base_subobject" })
        );
    }
}
