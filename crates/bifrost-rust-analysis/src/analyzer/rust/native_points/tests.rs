use crate::analyzer::rust::native_points::*;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::analyzer::project::OverlayProject;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::model::DeclarationKind;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::RustAnalyzer;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverBudgetLimit,
};
use brokk_bifrost_test_macros::hardwon;
use std::path::Path;
use std::sync::Arc;

#[test]
#[hardwon("#5231: prefetched calls changed operation ordinals in public binding diagnostics")]
fn incomplete_binding_diagnostics_do_not_depend_on_operation_ordinals() {
    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason as Reason;

    let render = |left, right, unknown, context| {
        let left = SemanticId::operation_local(left);
        let right = SemanticId::operation_local(right);
        let names = BTreeMap::from([(left, "left".to_owned()), (right, "right".to_owned())]);
        let completion = ResolutionCompletion::incomplete([
            Reason::UnsupportedSemantic(SemanticId::local(1, 181)),
            Reason::UnsupportedSemantic(left),
            Reason::UnsupportedSemantic(right),
            Reason::ReceiverBudgetExhausted(SemanticId::operation_local(unknown)),
            Reason::UnsupportedSemantic(SemanticId::context_local(context)),
        ]);
        describe_incomplete_binding(&completion, &names, &BTreeMap::new())
    };

    // Earlier demands change both the ordinals and their relative ordering.
    let before = render(202, 209, 300, 5);
    let after = render(46, 41, 100, 900);
    assert_eq!(before, after);
    assert_eq!(
        after,
        concat!(
            "receiver_budget_exhausted(runtime semantic), ",
            "unsupported_semantic(runtime semantic), ",
            "unsupported_semantic(runtime semantic, left), ",
            "unsupported_semantic(runtime semantic, right), ",
            "unsupported_semantic(semantic)"
        )
    );
}

fn rust_source_project(source: &str) -> (BuiltInlineTestProject, RustAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_points\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

fn rust_tree(source: &str) -> tree_sitter::Tree {
    brokk_bifrost_analysis::test_support::parse_fixture_tree(
        source,
        tree_sitter_rust::LANGUAGE.into(),
    )
}

fn reference_site_from_range(
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> ResolvedReferenceSite {
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    brokk_bifrost_analysis::test_support::resolved_reference_site(
        "src/lib.rs".to_owned(),
        source[start_byte..end_byte].to_owned(),
        Range {
            start_byte,
            end_byte,
            start_line,
            end_line: start_line,
        },
    )
}

fn reference_site(source: &str, spelling: &str) -> ResolvedReferenceSite {
    let start_byte = source
        .rfind(spelling)
        .unwrap_or_else(|| panic!("{spelling:?} reference is absent from fixture"));
    reference_site_from_range(source, start_byte, start_byte + spelling.len())
}

fn rust_2018_macro_reexport_project() -> (BuiltInlineTestProject, &'static str) {
    let other = "pub fn a() -> u32 { crate::macros::m!() }\n\
use crate::macros::m;\n\
pub fn b() -> u32 { m!() }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"macro_reexport\"\nversion = \"0.1.0\"\nedition = \"2018\"\n",
        )
        .file("src/lib.rs", "mod macros;\nmod other;\n")
        .file(
            "src/macros.rs",
            "macro_rules! m { () => { 1u32 }; }\npub(crate) use m;\n",
        )
        .file("src/other.rs", other)
        .build();
    (fixture, other)
}

fn rust_2018_reexport_site(source: &str, start: usize) -> ResolvedReferenceSite {
    let start_line = source[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    brokk_bifrost_analysis::test_support::resolved_reference_site(
        "src/other.rs".to_owned(),
        "m".to_owned(),
        Range {
            start_byte: start,
            end_byte: start + 1,
            start_line,
            end_line: start_line,
        },
    )
}

fn run_definition(
    source: &str,
    spelling: &str,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let site = reference_site(source, spelling);
    run_definition_at_site(source, &site, budget, cancellation)
}

fn run_definition_at_site(
    source: &str,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let (fixture, analyzer) = rust_source_project(source);
    let file = fixture.file("src/lib.rs");
    let tree = rust_tree(source);
    resolve_rust_definition_bounded(crate::analyzer::rust::test_support::bounded_receiver_query(
        &analyzer,
        &file,
        source,
        Some(&tree),
        site,
        budget,
        cancellation,
    ))
}

fn run_type(
    source: &str,
    spelling: &str,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let (fixture, analyzer) = rust_source_project(source);
    let file = fixture.file("src/lib.rs");
    let site = reference_site(source, spelling);
    let tree = rust_tree(source);
    resolve_rust_type_bounded(crate::analyzer::rust::test_support::bounded_receiver_query(
        &analyzer,
        &file,
        source,
        Some(&tree),
        &site,
        budget,
        cancellation,
    ))
}

fn complete_definition(
    result: BoundedResolution<DefinitionLookupOutcome>,
) -> DefinitionLookupOutcome {
    complete_native_result(result, "definition")
}

fn complete_type(result: BoundedResolution<TypeLookupOutcome>) -> TypeLookupOutcome {
    complete_native_result(result, "type")
}

fn complete_native_result<T>(result: BoundedResolution<T>, kind: &str) -> T {
    match result {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { limit, .. } => {
            panic!("expected complete native {kind}, exceeded {limit:?}")
        }
        BoundedResolution::Cancelled { .. } => panic!("expected complete native {kind}"),
    }
}

#[test]
fn native_self_member_excludes_unrelated_open_owner() {
    let source = r#"
mod first {
    struct Context;
    impl Context {
        fn edge(&self) {}
        fn caller(&self) { self.edge(); }
    }
}
mod second {
    unknown_items!();
    struct OtherContext;
    impl OtherContext {
        fn edge(&self) {}
    }
}
"#;
    for (source, expected) in [
        (source.to_owned(), DefinitionLookupStatus::Resolved),
        (
            source.replacen("mod first {", "mod first { unknown_items!();", 1),
            DefinitionLookupStatus::Incomplete,
        ),
    ] {
        let start = source.find("self.edge").unwrap() + "self.".len();
        let site = reference_site_from_range(&source, start, start + "edge".len());
        let outcome = complete_definition(run_definition_at_site(
            &source,
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ));
        assert_eq!(outcome.status, expected, "{source}\n{outcome:#?}");
        assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
        assert!(
            outcome.definitions[0]
                .fq_name()
                .contains("first.Context.edge")
        );
    }
}

#[test]
#[hardwon("77a06ad02155: function-local imports lost their lexical scope in native resolution")]
fn native_function_local_import_keeps_its_lexical_scope() {
    let source = "pub mod model { pub struct Item; } fn local() { use crate::model as alias; let _: alias::Item; } fn outside() { let _: alias::Item; }";
    let local = source.find("alias::Item").unwrap();
    let site = reference_site_from_range(source, local, local + 5);
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1);
    let outside = source.rfind("alias::Item").unwrap();
    let site = reference_site_from_range(source, outside, outside + 5);
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert!(outcome.definitions.is_empty(), "{outcome:#?}");
}

/// rustc resolves a single-segment macro name in textual scope first, so a
/// visible `macro_rules!` wins over every import of the scope. A glob from the
/// unindexed std is open in every namespace, and it must not reopen the
/// textual answer.
#[test]
#[hardwon("#3746: a macro_rules binder lost precedence to a same-scope import")]
fn native_textual_macro_is_not_reopened_by_an_unindexed_glob() {
    let source = "macro_rules! textual_macro { () => {} }\nuse std::sync::atomic::Ordering::*;\npub fn caller() {\n    textual_macro!();\n}\n";
    let outcome = complete_definition(run_definition(
        source,
        "textual_macro",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert_eq!(
        outcome.definitions[0].short_name(),
        "textual_macro",
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4925: macro head binding ignored textual scope without an expansion frontier")]
fn native_macro_heads_follow_textual_scope_and_import_authority() {
    let lib = "mod before;\n\
macro_rules! shadowed { () => { 1 }; }\n\
fn between() { shadowed!(); }\n\
macro_rules! shadowed { () => { 2 }; }\n\
mod after;\n\
mod inline { pub fn use_parent() { shadowed!(); } }\n\
#[macro_export]\nmacro_rules! exported { () => {}; }\n\
#[macro_use]\nmod imported;\n\
pub mod local_shadow {\n\
    use crate::exported as selected;\n\
    macro_rules! selected { () => {}; }\n\
    pub fn call() { selected!(); imported!(); }\n\
}\n\
pub mod external { pub fn call() { exported!(); } }\n";
    let lib = format!("{lib}\npub fn use_imported() {{ imported!(); }}\n");
    let before = "pub fn call() { shadowed!(); }\n";
    let after = "pub fn call() { shadowed!(); }\n";
    let imported = "pub fn call() { imported!(); }\nmacro_rules! imported { () => {}; }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"macro_scope\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", &lib)
        .file("src/before.rs", before)
        .file("src/after.rs", after)
        .file("src/imported.rs", imported)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());

    let answer = |path: &str, source: &str, spelling: &str| {
        let start = source
            .rfind(spelling)
            .unwrap_or_else(|| panic!("{spelling:?} is absent in {path}"));
        let site = reference_site_from_range(source, start, start + spelling.len());
        resolve_point_answers(&analyzer, &fixture.file(path), &site)
            .into_iter()
            .next()
            .expect("macro reference has one selected answer")
    };
    let before_answer = answer("src/before.rs", before, "shadowed");
    assert!(
        before_answer.definitions.is_empty(),
        "{:?}",
        before_answer.definitions
    );
    assert_eq!(
        before_answer.resolution.completion(),
        &ResolutionCompletion::Complete
    );
    let between_start = lib.find("fn between() { ").unwrap() + "fn between() { ".len();
    let between_site = reference_site_from_range(&lib, between_start, between_start + 8);
    let between_answer =
        resolve_point_answers(&analyzer, &fixture.file("src/lib.rs"), &between_site)
            .into_iter()
            .next()
            .expect("between macro reference has one selected answer");
    let after_answer = answer("src/after.rs", after, "shadowed");
    let inline_source_start = lib.find("mod inline").unwrap();
    let inline_source = &lib[inline_source_start..];
    let inline_start = inline_source.find("shadowed!").unwrap();
    let inline_site = reference_site_from_range(
        &lib,
        lib.find("mod inline").unwrap() + inline_start,
        lib.find("mod inline").unwrap() + inline_start + "shadowed".len(),
    );
    let inline_answer = resolve_point_answers(&analyzer, &fixture.file("src/lib.rs"), &inline_site)
        .into_iter()
        .next()
        .expect("inline macro reference has one selected answer");
    assert_eq!(between_answer.resolution.binding().targets().len(), 1);
    assert_eq!(after_answer.resolution.binding().targets().len(), 1);
    assert_eq!(inline_answer.resolution.binding().targets().len(), 1);
    assert_ne!(
        between_answer.resolution.binding().targets(),
        after_answer.resolution.binding().targets(),
        "later textual definition has a distinct canonical site"
    );
    assert_eq!(
        after_answer.resolution.binding().targets(),
        inline_answer.resolution.binding().targets(),
        "inline module inherits the latest visible textual macro"
    );

    let imported_answer = answer("src/lib.rs", &lib, "imported");
    assert_eq!(imported_answer.resolution.binding().targets().len(), 1);
    let exported_answer = answer("src/lib.rs", &lib, "exported");
    assert_eq!(exported_answer.resolution.binding().targets().len(), 1);
    let shadowed_import_answer = answer("src/lib.rs", &lib, "selected");
    assert_eq!(
        shadowed_import_answer.resolution.binding().targets().len(),
        1
    );
}

#[test]
fn rust_2018_macro_reexport_import_binds_exact_declaration() {
    let (fixture, other) = rust_2018_macro_reexport_project();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let imported_start = other.rfind("m!()").unwrap();
    let site = rust_2018_reexport_site(other, imported_start);
    let answer = resolve_point_answers(&analyzer, &fixture.file("src/other.rs"), &site)
        .into_iter()
        .next()
        .expect("imported macro reference has one selected answer");
    assert_eq!(
        answer.resolution.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert_eq!(answer.resolution.binding().targets().len(), 1);
    assert_eq!(answer.definition_names.len(), 1);
    assert_eq!(
        answer.resolution.binding().targets()[0],
        answer.definition_names[0].0,
        "the canonical binding and displayed definition name the same declaration site"
    );
    assert_eq!(answer.definition_names[0].1, "macro_reexport.macros.m");
}

#[test]
#[ignore = "finds real bug (#4938): path-qualified macro through a pub(crate) use re-export is unresolved"]
fn rust_2018_macro_reexport_qualified_path_resolves_exact_declaration() {
    let (fixture, other) = rust_2018_macro_reexport_project();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let imported_start = other.rfind("m!()").unwrap();
    let imported_site = rust_2018_reexport_site(other, imported_start);
    let imported_answer =
        resolve_point_answers(&analyzer, &fixture.file("src/other.rs"), &imported_site)
            .into_iter()
            .next()
            .expect("imported macro reference has one selected answer");

    let qualified_start = other.find("crate::macros::m!()").unwrap() + "crate::macros::".len();
    let qualified_site = rust_2018_reexport_site(other, qualified_start);
    let qualified_answer =
        resolve_point_answers(&analyzer, &fixture.file("src/other.rs"), &qualified_site)
            .into_iter()
            .next()
            .expect("qualified macro reference has one selected answer");
    assert_eq!(
        qualified_answer.resolution.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert_eq!(
        qualified_answer.resolution.binding().targets(),
        imported_answer.resolution.binding().targets(),
        "qualified path must bind to the imported macro's exact declaration site"
    );
    assert_eq!(
        qualified_answer.definition_names,
        imported_answer.definition_names
    );
}

#[test]
fn native_definition_retains_canonical_ambiguity_when_display_units_coincide() {
    let source = "pub fn left() {}\npub fn right() {}\npub fn caller() { left(); right(); }\n";
    let (fixture, analyzer) = rust_source_project(source);
    let file = fixture.file("src/lib.rs");
    let left_site = reference_site(source, "left");
    let right_site = reference_site(source, "right");
    let mut left = resolve_point_answers(&analyzer, &file, &left_site);
    let mut right = resolve_point_answers(&analyzer, &file, &right_site);
    assert_eq!(left.len(), 1);
    assert_eq!(right.len(), 1);
    let left = left.pop().unwrap();
    let mut right = right.pop().unwrap();
    assert_eq!(left.resolution.binding().targets().len(), 1);
    assert_eq!(right.resolution.binding().targets().len(), 1);
    assert_ne!(
        left.resolution.binding().targets(),
        right.resolution.binding().targets()
    );

    // Exercise the adapter's lossy-presentation boundary on hand-built
    // answers, so this case stays pinned whatever the producer crosswalk
    // projects. Both answers keep their real, distinct canonical binding
    // evidence.
    assert_eq!(left.definitions.len(), 1);
    right.definitions = left.definitions.clone();
    let repeated_left = || {
        SelectedRustReferenceAnswer::new(
            left.boundary_import_names.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            left.enumeration.clone(),
            Vec::new(),
            Vec::new(),
            left.resolution.clone(),
            left.definitions.clone(),
            left.lexical_definitions.clone(),
            left.definition_names.clone(),
            Vec::new(),
            (),
        )
    };
    assert_eq!(
        left.resolution.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert_eq!(
        right.resolution.binding().completion(),
        &ResolutionCompletion::Complete
    );
    let single = adapt_definition_answer(
        &left_site,
        vec![repeated_left(), repeated_left()],
        ResolutionCompletion::Complete,
        false,
    );
    assert_eq!(single.status, DefinitionLookupStatus::Resolved);
    assert_eq!(single.definitions.len(), 1);
    let outcome = adapt_definition_answer(
        &left_site,
        vec![left, right],
        ResolutionCompletion::Complete,
        false,
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:#?}"
    );
}

#[test]
fn native_definition_withdraws_only_the_alternative_that_has_no_unit() {
    // `WithoutUnit` is one alternative's own answer: the parser recorded the
    // source declaration but published no `CodeUnit` and no lexical binder for
    // it, so that alternative is out of both vocabularies. The point used to
    // refuse the whole answer for it and publish nothing, throwing away the
    // alternatives that did project. It withdraws itself instead, exactly as
    // the reverse batch does, and only a point where every alternative
    // withdrew is unavailable.
    let source = "pub fn target() {}\npub fn caller() { target(); }\n";
    let (fixture, analyzer) = rust_source_project(source);
    let file = fixture.file("src/lib.rs");
    let unit = analyzer
        .get_definitions("native_points.target")
        .into_iter()
        .next()
        .expect("target declares a unit");
    let site = reference_site(source, "target");
    let without_unit = || {
        (
            SemanticId::for_test("native-points-without-unit"),
            SelectedRustSourceDefinition::WithoutUnit {
                source_file: file.clone(),
                declaration_range: None,
            },
        )
    };

    let answered = adapt_declaration_value(
        &site,
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Complete(vec![
                without_unit(),
                (
                    SemanticId::for_test("native-points-unit"),
                    SelectedRustSourceDefinition::Unit(unit.clone()),
                ),
            ]),
        ),
    );
    assert_eq!(
        answered.definitions,
        vec![unit],
        "the projecting alternative is the answer: {answered:#?}"
    );
    assert_eq!(
        answered.status,
        DefinitionLookupStatus::Resolved,
        "{answered:#?}"
    );

    let withdrawn = adapt_declaration_value(
        &site,
        SelectedResolutionOperationOutcome::Native(
            SelectedRustSourceDefinitionProjection::Complete(vec![without_unit()]),
        ),
    );
    assert!(withdrawn.definitions.is_empty(), "{withdrawn:#?}");
    assert_eq!(
        withdrawn.status,
        DefinitionLookupStatus::Unavailable,
        "{withdrawn:#?}"
    );
}

fn resolve_point_answers(
    analyzer: &RustAnalyzer,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    site: &ResolvedReferenceSite,
) -> Vec<SelectedRustReferenceAnswer> {
    let cancellation = CancellationToken::default();
    let snapshots = analyzer.inner.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let SelectedResolutionOverlayInputsOutcome::Ready {
        masks,
        content_mounts,
    } = analyzer
        .inner
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
        .unwrap()
    else {
        panic!("point overlay publication must be ready");
    };
    let input = SelectedResolutionOperationInput::new(
        analyzer.inner.project(),
        analyzer.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let SelectedResolutionOperationOpenOutcome::Ready(mut operation) = analyzer
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("native point operation must open")
    };
    let outcome = operation
        .resolve_rust_reference_for_caller_bounded(
            file.rel_path(),
            &SelectedSemanticLocator::for_reference_range(
                "rust",
                rel_path_string(file),
                site.focus_start_byte,
                site.focus_end_byte,
            ),
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut ResolutionBatchMetrics::default(),
        )
        .unwrap();
    let BoundedResolution::Complete {
        value:
            SelectedRustCallerReferenceOutcome::Operation(SelectedResolutionOperationOutcome::Native(
                SelectedResolutionLocated::Found(answers),
            )),
        ..
    } = outcome
    else {
        panic!("native point alternatives must publish together")
    };
    answers
}

#[test]
fn native_import_alternatives_share_one_terminal_budget_and_cancellation() {
    let source = "pub mod provider { pub struct Target {} pub const Target: usize = 1; }\nuse crate::provider::Target;\n";
    let (fixture, analyzer) = rust_source_project(source);
    let file = fixture.file("src/lib.rs");
    let site = reference_site(source, "Target");
    let tree = rust_tree(source);
    let run = |budget, cancellation: Option<CancellationToken>| {
        resolve_rust_definition_bounded(BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget,
            cancellation: cancellation.as_ref(),
        })
    };
    // An analyzer's first selected operation charges more receiver-analysis
    // work than its later ones. Measured on this tree at HEAD: cold
    // (setup_nodes 0, resolution_rounds 17, scope_nodes 696), warm
    // (0, 15, 673) and identical on every operation after the first. The
    // difference is the R3 typed-frontier reads that the first operation
    // populates. The exact-budget property below is about one steady-state
    // operation, so discard the cold operation before measuring.
    let BoundedResolution::Complete { .. } = run(ReceiverAnalysisBudget::default(), None) else {
        panic!("default import-alternative budget must complete")
    };
    let BoundedResolution::Complete { value, work } = run(ReceiverAnalysisBudget::default(), None)
    else {
        panic!("default import-alternative budget must complete")
    };
    assert_eq!(
        value.status,
        DefinitionLookupStatus::Ambiguous,
        "{value:#?}"
    );
    assert_eq!(value.definitions.len(), 2);
    let exact = ReceiverAnalysisBudget {
        max_scope_nodes: work.scope_nodes,
        max_summary_expansions: work.summary_expansions,
        max_resolution_rounds: work.resolution_rounds,
        ..ReceiverAnalysisBudget::default()
    };
    assert_eq!(complete_definition(run(exact, None)).definitions.len(), 2);
    assert!(work.scope_nodes > 0);
    assert!(matches!(
        run(
            ReceiverAnalysisBudget {
                max_scope_nodes: work.scope_nodes - 1,
                ..exact
            },
            None
        ),
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            ..
        }
    ));

    // Sweep into resolution, including cancellation after earlier alternatives
    // have produced provisional definitions. Every terminal reply drops them.
    let mut cancelled_with_resolution_work = false;
    for checks in [1, 32, 128, 512, 2048, 8192] {
        let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
        match run(exact, Some(cancellation)) {
            BoundedResolution::Cancelled { work } => {
                cancelled_with_resolution_work |= work.resolution_rounds > 0;
            }
            BoundedResolution::Complete { value, .. } => assert_eq!(value.definitions.len(), 2),
            BoundedResolution::Exceeded { limit, .. } => panic!("cancellation exceeded {limit:?}"),
        }
    }
    assert!(cancelled_with_resolution_work);
}

#[test]
#[hardwon("93470ac55fe9: stale supplied source text resolved offsets against selected content")]
fn native_points_reject_text_from_a_different_selected_source() {
    let disk_source = "pub fn old_target() -> bool { true }\npub fn new_target() -> usize { 1 }\nfn caller() { new_target(); }\n";
    let supplied_source = "pub fn old_target() -> bool { true }\npub fn new_target() -> usize { 1 }\nfn caller() { old_target(); }\n";
    let (fixture, analyzer) = rust_source_project(disk_source);
    let file = fixture.file("src/lib.rs");
    let site = reference_site(supplied_source, "old_target");
    assert_eq!(
        site.focus_start_byte,
        disk_source.rfind("new_target").unwrap()
    );
    let tree = rust_tree(supplied_source);
    let query = BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: supplied_source,
        tree: Some(&tree),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    };
    let definition = complete_definition(resolve_rust_definition_bounded(query));
    assert_eq!(
        definition.status,
        DefinitionLookupStatus::Unavailable,
        "{definition:#?}"
    );
    assert!(
        definition
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_source_mismatch")
    );
    assert!(definition.definitions.is_empty());
    assert!(definition.lexical_definition.is_none());
    let ty = complete_type(resolve_rust_type_bounded(query));
    assert_eq!(ty.status, TypeLookupStatus::Unavailable, "{ty:#?}");
    assert!(
        ty.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "native_source_mismatch")
    );
    assert!(ty.types.is_empty());
}

#[test]
fn native_receiver_self_keeps_receiver_metadata_and_reference_type() {
    let source = concat!(
        "pub struct Service;\n",
        "impl Service {\n",
        "    fn method(&self) -> &Service { self }\n",
        "}\n",
    );
    let definition = complete_definition(run_definition(
        source,
        "self",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(definition.status, DefinitionLookupStatus::Resolved);
    assert!(definition.definitions.is_empty());
    let lexical = definition
        .lexical_definition
        .expect("&self definition retains lexical receiver metadata");
    assert_eq!(lexical.identifier, "self");
    assert_eq!(lexical.kind, DeclarationKind::ReceiverParameter);

    let type_outcome = complete_type(run_type(
        source,
        "self",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(type_outcome.status, TypeLookupStatus::Resolved);
    assert_eq!(type_outcome.types.len(), 1);
    assert_eq!(type_outcome.types[0].definitions.len(), 1);
    assert_eq!(
        type_outcome.types[0].fqn,
        format!("&{}", type_outcome.types[0].definitions[0].fq_name())
    );
}

#[test]
fn native_type_does_not_lie_about_async_callable_results() {
    let source = concat!(
        "pub async fn unit() {}\n",
        "pub fn caller() {\n",
        "    unit();\n",
        "}\n",
    );
    let definition = complete_definition(run_definition(
        source,
        "unit",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(definition.status, DefinitionLookupStatus::Resolved);
    assert_eq!(definition.definitions.len(), 1);
    assert_eq!(definition.definitions[0].short_name(), "unit");

    let outcome = complete_type(run_type(
        source,
        "unit",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(outcome.status, TypeLookupStatus::Incomplete);
    assert!(outcome.types.is_empty());
}

#[test]
fn native_type_observes_self_type_identity_across_impls() {
    let source = concat!(
        "pub struct Service;\n",
        "impl Service { fn first(&self) -> Self { Service } }\n",
        "impl Service { fn second(&self) -> Self { self.first() } }\n",
    );
    let outcome = complete_type(run_type(
        source,
        "Self",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    // The transfer remains the sole producer; its occurrence observation exposes the type.
    assert_eq!(outcome.status, TypeLookupStatus::Resolved, "{outcome:#?}");
    assert_eq!(outcome.types.len(), 1, "{outcome:#?}");
    assert_eq!(outcome.types[0].definitions.len(), 1, "{outcome:#?}");
    assert_eq!(outcome.types[0].definitions[0].identifier(), "Service");
    assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
}

#[test]
#[hardwon("450bbbd3ebdf: definition selections were omitted from native traces")]
fn native_definition_trace_projects_units_without_claiming_rejection_coverage() {
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCandidateRef;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::TraceCompleteness;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;

    let source = "pub struct Item; fn run(_: Item) {}";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace =
        project.workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
    let file = project.file("src/lib.rs");
    let start = source.rfind("Item").expect("fixture reference");
    let (outcome, trace) = resolve_definition_batch_with_trace(
        workspace.analyzer(),
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + 4),
        }],
        file,
        Arc::from(source),
        &CancellationToken::new(),
    )
    .pop()
    .expect("one request");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
    assert_eq!(trace.completeness, TraceCompleteness::SelectionOnly);
    let selected = trace
        .selected()
        .map(|row| match &row.candidate {
            TraceCandidateRef::Unit(unit) => unit.clone(),
            other => panic!("expected workspace definition, got {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(selected, outcome.definitions);
    assert_eq!(selected.len(), 1);
}

#[test]
fn native_cfg_activation_filters_declarations_and_body_references_on_disk_and_overlay() {
    for manifest in [false, true] {
        for (predicate, expected) in [
            ("test", DefinitionLookupStatus::Resolved),
            ("not(test)", DefinitionLookupStatus::NoDefinition),
            (
                "feature = \"not_configured\"",
                DefinitionLookupStatus::NoDefinition,
            ),
            ("custom_cfg", DefinitionLookupStatus::Incomplete),
        ] {
            let source = format!(
                "#[cfg({predicate})]\npub fn gated() {{ target(); }}\npub fn target() {{}}\npub fn caller() {{ gated(); }}\n"
            );
            let mut project =
                InlineTestProject::with_language(Language::Rust).file("src/lib.rs", &source);
            if manifest {
                project = project.file(
                    "Cargo.toml",
                    "[package]\nname = \"cfg_case\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                );
            }
            let fixture = project.build();
            let disk = RustAnalyzer::new(fixture.project_dyn());
            let file = fixture.file("src/lib.rs");
            for overlay in [false, true] {
                let selected_source = if overlay {
                    format!("// overlay\n{source}")
                } else {
                    source.clone()
                };
                let analyzer = if overlay {
                    let project = Arc::new(OverlayProject::new(fixture.project_dyn()));
                    assert!(project.set(file.abs_path(), selected_source.clone()));
                    disk.clone_with_project(Arc::new(project.snapshot()) as Arc<dyn Project>)
                } else {
                    disk.clone_with_project(fixture.project_dyn())
                };
                let _declarations = analyzer.declarations(&file);
                let tree = rust_tree(&selected_source);
                for spelling in ["gated();", "target();"] {
                    let start = selected_source.find(spelling).unwrap();
                    let length = if spelling == "gated();" { 5 } else { 6 };
                    let site = reference_site_from_range(&selected_source, start, start + length);
                    let outcome = complete_definition(resolve_rust_definition_bounded(
                        BoundedReceiverQuery {
                            analyzer: &analyzer,
                            file: &file,
                            source: &selected_source,
                            tree: Some(&tree),
                            site: &site,
                            budget: ReceiverAnalysisBudget::default(),
                            cancellation: None,
                        },
                    ));
                    let expected = if predicate == "custom_cfg" && spelling == "target();" {
                        DefinitionLookupStatus::Resolved
                    } else {
                        expected
                    };
                    assert_eq!(
                        outcome.status, expected,
                        "manifest={manifest}, overlay={overlay}, predicate={predicate}, spelling={spelling}: {outcome:#?}"
                    );
                    assert_eq!(
                        outcome.definitions.len(),
                        usize::from(expected == DefinitionLookupStatus::Resolved),
                        "{outcome:#?}"
                    );
                    if predicate == "custom_cfg" && spelling == "target();" {
                        assert!(
                            outcome
                                .diagnostics
                                .iter()
                                .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
                            "{outcome:#?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
#[hardwon("#4481: an undecidable site cfg does not block a resolved Rust reference")]
fn native_unknown_site_cfg_resolves_with_condition_diagnostic() {
    let source = "#[cfg(miri)]\nfn caller() { target(); }\nfn target() {}\n";
    let start = source.find("target();").expect("call site");
    let site = reference_site_from_range(source, start, start + "target".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    let conditional = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "conditional_cfg")
        .expect("conditional answer diagnostic");
    assert!(conditional.message.contains("miri"), "{conditional:#?}");
}

#[test]
#[hardwon("#4481: a declaration with the same undecidable cfg as its reference is active")]
fn native_unknown_site_cfg_activates_same_cfg_candidate() {
    for condition in ["miri", "not(miri)"] {
        let source = format!(
            "#[cfg({condition})]\nfn target() {{}}\n#[cfg({condition})]\nfn caller() {{ target(); }}\n"
        );
        let start = source.find("target();").expect("call site");
        let site = reference_site_from_range(&source, start, start + "target".len());
        let outcome = complete_definition(run_definition_at_site(
            &source,
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ));

        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "condition={condition}: {outcome:#?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
        assert_eq!(outcome.definitions[0].identifier(), "target");
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
            "condition={condition}: {outcome:#?}"
        );
    }
}

#[test]
#[hardwon("#4481: unrelated candidate cfg alternatives remain incomplete")]
fn native_unknown_site_cfg_keeps_conflicting_candidate_cfgs_incomplete() {
    let source = "#[cfg(compiler_a)] pub fn selected() {}\n#[cfg(not(compiler_a))] pub fn selected() {}\n#[cfg(miri)]\nfn caller() { selected(); }\n";
    let start = source.find("selected();").expect("call site");
    let site = reference_site_from_range(source, start, start + "selected".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:#?}");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4481: a refuted site cfg remains inactive")]
fn native_refuted_site_cfg_stays_inactive() {
    let source =
        "#[cfg(target_pointer_width = \"0\")]\nfn caller() { target(); }\nfn target() {}\n";
    let start = source.find("target();").expect("call site");
    let site = reference_site_from_range(source, start, start + "target".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::NoDefinition,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "inactive_cfg"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4481: a known-false conjunct refutes a site cfg despite an unknown atom")]
fn native_compound_site_cfg_with_known_false_is_inactive() {
    let source = "#[cfg(all(target_pointer_width = \"0\", miri))]\nfn caller() { target(); }\nfn target() {}\n";
    let start = source.find("target();").expect("call site");
    let site = reference_site_from_range(source, start, start + "target".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::NoDefinition,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "inactive_cfg"),
        "{outcome:#?}"
    );
    assert!(
        !outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4481: a satisfying unknown disjunct makes the site answer conditional")]
fn native_compound_site_cfg_with_unknown_disjunct_is_conditional() {
    let source = "#[cfg(any(target_pointer_width = \"0\", miri))]\nfn caller() { target(); }\nfn target() {}\n";
    let start = source.find("target();").expect("call site");
    let site = reference_site_from_range(source, start, start + "target".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "conditional_cfg")
        .expect("conditional answer diagnostic");
    assert!(diagnostic.message.contains("miri"), "{diagnostic:#?}");
}

#[test]
#[hardwon("#4481: type lookup honors an undecidable reference-site cfg")]
fn native_type_at_unknown_site_cfg_is_conditional() {
    let source = "fn target() -> u8 { 1 }\n#[cfg(miri)]\nfn caller() { let _value = target(); }\n";
    let outcome = complete_type(run_type(
        source,
        "target",
        ReceiverAnalysisBudget::default(),
        None,
    ));

    assert_eq!(outcome.status, TypeLookupStatus::Resolved, "{outcome:#?}");
    assert_eq!(outcome.types.len(), 1, "{outcome:#?}");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("038671fb2434: a root import borrowed inventory from an inline module")]
fn native_root_import_does_not_borrow_an_inline_modules_inventory() {
    for suffix in [
        "fn use_type(_: Target) {}",
        "macro_rules! take { ($t:ty) => { fn use_type(_: $t) {} }; } take!(Target);",
    ] {
        let source =
            format!("mod inner {{ pub struct Target {{}} }} pub use inner::Target; {suffix}");
        let outcome = complete_definition(run_definition_at_site(
            &source,
            &reference_site(&source, "Target"),
            ReceiverAnalysisBudget::default(),
            None,
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{source}: {outcome:#?}"
        );
        assert_eq!(outcome.definitions.len(), 1);
    }
}

/// A root absent from the selected crate inventory stays an unindexed boundary:
/// Cargo target selection does not prove that an arbitrary external crate is absent.
#[test]
#[hardwon(
    "038671fb2434: a missing crate import was reported as a closed miss without index evidence"
)]
fn native_missing_import_keeps_an_unindexed_boundary() {
    let source = "mod sibling { pub struct Item; } use external::Item; fn use_type(_: Item) {}";
    let outcome = complete_definition(run_definition_at_site(
        source,
        &reference_site(source, "Item"),
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(outcome.definitions.is_empty());
}

/// `use inner::Err` binds the enum in the type namespace only, so the
/// workspace declares no bare callable value `Err`. rustc resolves the call
/// through the std prelude's `Result::Err`, which Bifrost does not index: an
/// unindexed boundary, not a proved absence.
#[test]
#[hardwon("038671fb2434: an imported enum variant was misclassified as a bare callable value")]
fn native_imported_enum_has_no_bare_callable_value() {
    let source =
        "mod inner { pub enum Err<E> { Error(E) } } use inner::Err; fn call() { Err(()); }";
    let outcome = complete_definition(run_definition_at_site(
        source,
        &reference_site(source, "Err"),
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(outcome.definitions.is_empty());
}

#[test]
#[hardwon("28289e10b43a: macro evidence was lost from an open export inventory")]
fn native_open_export_inventory_carries_macro_evidence() {
    let source = "mod provider { generate!(); } use crate::provider::Missing;";
    let outcome = complete_definition(run_definition_at_site(
        source,
        &reference_site(source, "Missing"),
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == "UnsupportedMacroGeneratedModule")
        .unwrap_or_else(|| {
            panic!("open inventory must retain its invocation evidence: {outcome:#?}")
        });
    let detail: serde_json::Value = serde_json::from_str(&diagnostic.message).unwrap();
    let evidence = &detail["evidence"][0];
    assert!(evidence["member_blob"].is_i64(), "{detail}");
    assert!(evidence["invocation_occurrence"].is_u64(), "{detail}");
    assert_eq!(evidence["replay_covered"], false, "{detail}");
}

/// A broken local glob keeps lexical resolution incomplete, while the exact
/// Cargo dependency still places the crate root route.
#[hardwon("#4460: incomplete local import facts hid an exact workspace dependency route")]
#[test]
fn an_incomplete_local_import_keeps_exact_workspace_dependency_routes() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\", \"helper\"]\nresolver = \"2\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../helper\" }\n",
            ),
            (
                "helper/Cargo.toml",
                "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "helper/src/lib.rs",
                "pub struct Thing;\nimpl Thing { pub fn make() -> Self { Self } }\n",
            ),
            ("app/src/lib.rs", "pub mod orphan;\n"),
            (
                "app/src/orphan.rs",
                "use crate::missing::*;\npub fn caller() { let _ = helper::Thing::make(); }\n",
            ),
        ],
        "app/src/orphan.rs",
        "helper::Thing::make()",
        "make",
    );
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "make"),
        "the selected Cargo dependency route supplies the target: {outcome:#?}"
    );
}

#[test]
#[hardwon("#4460: a local module alias hid a declared external HMAC route")]
fn a_local_module_alias_keeps_an_external_import_boundary() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nring = \"0.17\"\n",
            ),
            (
                "src/lib.rs",
                "pub(crate) mod dnssec { pub(crate) use ring_impl as ring_like; mod ring_impl { pub(crate) use ring::hmac; } }\npub fn caller() { let _ = dnssec::ring_like::hmac::HMAC_SHA256; }\n",
            ),
        ],
        "src/lib.rs",
        "HMAC_SHA256",
        "HMAC_SHA256",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "unindexed_import_boundary"),
        "the local alias must reach the declared but unindexed external crate: {outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "the external terminal must not be called an unplaced workspace route: {outcome:#?}"
    );
}

/// Workspace crate re-exports, inherited Cargo aliases, and a selected module
/// import all use the same persisted route rows as direct crate names.
#[hardwon("#4460: workspace re-export and imported module roots were not placed")]
#[test]
fn workspace_reexports_and_imported_modules_keep_their_selected_routes() {
    let files = [
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"facade\", \"helper\"]\nresolver = \"2\"\n[workspace.dependencies]\nbackend = { package = \"helper\", path = \"helper\" }\n",
        ),
        (
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbackend.workspace = true\nfacade = { path = \"../facade\" }\n",
        ),
        (
            "facade/Cargo.toml",
            "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../helper\" }\n",
        ),
        (
            "helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "helper/src/lib.rs",
            "pub mod registry { pub struct SpanRef; }\npub struct Thing;\nimpl Thing { pub fn make() -> Self { Self } }\n",
        ),
        ("facade/src/lib.rs", "pub use helper as milli;\n"),
        (
            "app/src/lib.rs",
            "use backend::registry::{self};\npub fn caller(_: registry::SpanRef) { let _: Option<backend::registry::SpanRef>; let _ = backend::Thing::make(); let _ = facade::milli::Thing::make(); }\n",
        ),
    ];
    for (marker, name, expected_terminal) in [
        ("backend::Thing::make()", "make", "make"),
        ("backend::registry::SpanRef", "SpanRef", "SpanRef"),
        ("facade::milli::Thing::make()", "make", "make"),
        ("registry::SpanRef", "SpanRef", "SpanRef"),
    ] {
        let outcome = definition_in_workspace(&files, "app/src/lib.rs", marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{marker}: {outcome:#?}"
        );
        assert!(
            outcome
                .definitions
                .iter()
                .any(|definition| definition.terminal_name() == expected_terminal),
            "{marker}: {outcome:#?}"
        );
    }
}

#[test]
#[hardwon("#4460: an excluded manifest disabled inherited workspace backend type routes")]
fn inherited_renamed_workspace_crate_routes_nested_backend_types() {
    const FILES: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"candle-nn\", \"candle-core\"]\nexclude = [\"candle-book\"]\nresolver = \"2\"\n[workspace.package]\nedition = \"2021\"\n[workspace.dependencies]\ncandle = { package = \"candle-core\", path = \"candle-core\" }\n",
        ),
        (
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncandle-nn = { path = \"../candle-nn\" }\n",
        ),
        (
            "candle-nn/Cargo.toml",
            "[package]\nname = \"candle-nn\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncandle = { workspace = true }\n",
        ),
        (
            "candle-core/Cargo.toml",
            "[package]\nname = \"candle-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "candle-nn/src/lib.rs",
            "pub use candle::npy::NpzTensors;\npub trait SimpleBackend {}\nimpl SimpleBackend for candle::npy::NpzTensors {}\npub fn load_backend() -> candle::npy::NpzTensors { candle::npy::NpzTensors }\n",
        ),
        (
            "app/src/lib.rs",
            "pub fn use_backend(_: candle_nn::NpzTensors) { let _ = candle_nn::load_backend(); }\n",
        ),
        ("candle-core/src/lib.rs", "pub mod npy;\n"),
        ("candle-core/src/npy.rs", "pub struct NpzTensors;\n"),
        (
            "candle-book/Cargo.toml",
            "[package]\nname = \"candle-book\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
        ),
        ("candle-book/src/lib.rs", "pub fn excluded() {}\n"),
    ];
    let outcome = definition_in_workspace(
        FILES,
        "app/src/lib.rs",
        "candle_nn::NpzTensors",
        "NpzTensors",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "NpzTensors"),
        "{outcome:#?}"
    );
    let dependency_surface = definition_in_workspace(
        FILES,
        "app/src/lib.rs",
        "candle_nn::load_backend()",
        "load_backend",
    );
    assert_eq!(
        dependency_surface.status,
        DefinitionLookupStatus::Resolved,
        "{dependency_surface:#?}"
    );
    assert!(
        dependency_surface
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "dependency source routes stay inside the selected Cargo graph: {dependency_surface:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );

    let inherited_import = definition_in_workspace(
        FILES,
        "candle-nn/src/lib.rs",
        "impl SimpleBackend for candle::npy::NpzTensors",
        "NpzTensors",
    );
    assert_eq!(
        inherited_import.status,
        DefinitionLookupStatus::Resolved,
        "{inherited_import:#?}"
    );
    assert!(
        inherited_import
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "NpzTensors"),
        "{inherited_import:#?}"
    );
}

fn definition_at_name(source: &str, marker: &str, name: &str) -> DefinitionLookupOutcome {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("{marker:?} is absent from fixture"))
        + marker.find(name).expect("marker contains the name");
    let site = reference_site_from_range(source, start, start + name.len());
    complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ))
}

#[test]
fn rust_supertrait_callable_members_preserve_ambiguity_and_open_bounds() {
    let source = "pub trait Base { fn base() -> Self; } pub trait Mid: Base {} pub trait Other { fn base() -> Self; } pub trait Sub: Mid + Other {} pub fn made<T: Sub>() -> T { T::base() }";
    let outcome = definition_at_name(source, "T::base()", "base");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:#?}"
    );
    let mut names = outcome
        .definitions
        .iter()
        .map(CodeUnit::fq_name)
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["native_points.Base.base", "native_points.Other.base"]
    );
    let source = "pub trait Base { fn base() -> Self; } pub trait Sub: Base + external::Unknown {} pub fn made<T: Sub>() -> T { T::base() }";
    let outcome = definition_at_name(source, "T::base()", "base");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(CodeUnit::fq_name)
            .collect::<Vec<_>>(),
        ["native_points.Base.base"],
        "{outcome:#?}"
    );
}

#[test]
fn rust_supertrait_callable_cycle_stays_incomplete() {
    let source = "pub trait Left: Right {} pub trait Right: Left {} pub fn caller<T: Left>() { T::missing(); }";
    let outcome = definition_at_name(source, "T::missing()", "missing");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:#?}");
}

#[test]
#[hardwon(
    "68a733004b58: alias enum variant origins collided and lost their distinct projection outputs"
)]
fn native_aliased_enum_variant_field_preserves_projection_origins() {
    let source = "enum Error { Entry { value: u32 } }\ntype Alias = Error;\nfn make(value: u32) -> Alias { Alias::Entry { value } }\n";
    let outcome = complete_definition(run_definition_at_site(
        source,
        &reference_site(source, "value"),
        brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.fq_name().contains("Error.Entry.value")),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .lexical_definition
            .as_ref()
            .is_some_and(|definition| definition.kind == DeclarationKind::Parameter),
        "{outcome:#?}"
    );
}

#[hardwon("5a808be07866: a standalone qualified type path lacked a complete definition binding")]
#[test]
fn native_standalone_qualified_type_has_complete_binding() {
    let source = "pub mod model { pub struct Item; } fn local() { use crate::model as alias; let _: alias::Item; }";
    let start = source.rfind("Item").unwrap();
    let site = reference_site_from_range(source, start, start + 4);
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("6c1755ea3ccb: a second declaration sharing one parser unit lost its definition result")]
fn native_definition_projects_duplicate_source_declarations_to_their_shared_unit() {
    // `resolution_definition_unit_crosswalks` is injective on `unit_key`, so
    // the second of two declarations that share one `CodeUnit` holds no
    // crosswalk row. The projection reads the parser's own declaration-to-unit
    // relation for it instead, so both targets project and the point publishes
    // the one unit they name, with the canonical ambiguity the two distinct
    // target semantics carry. This used to refuse the whole point with
    // `MissingDefinitionUnit` and publish no definition at all.
    let source = concat!(
        "pub fn target() {}\n",
        "pub fn target() {}\n",
        "pub fn caller() { target(); }\n",
    );
    let outcome = complete_definition(run_definition(
        source,
        "target",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(CodeUnit::fq_name)
            .collect::<Vec<_>>(),
        ["native_points.target"],
        "{outcome:#?}"
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:#?}"
    );
}

#[test]
#[hardwon(
    "e6c2d7c92da5: a parent declaration failed to shadow a glob re-export in qualified lookup"
)]
fn native_definition_parent_module_shadows_a_glob_reexport() {
    let source = concat!(
        "pub mod outer {\n",
        "    mod execution { pub mod plan { pub struct Marker; } }\n",
        "    pub mod search {\n",
        "        use super::execution::plan::Marker;\n",
        "        mod execution {}\n",
        "        pub fn marker() -> Marker { Marker }\n",
        "    }\n",
        "    pub use execution::*;\n",
        "    pub use search::*;\n",
        "}\n",
    );
    let start = source.find("super::execution").unwrap() + "super::".len();
    let site = reference_site_from_range(source, start, start + "execution".len());
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(CodeUnit::fq_name)
            .collect::<Vec<_>>(),
        ["native_points.outer.execution"],
        "{outcome:#?}"
    );
}

#[test]
#[hardwon(
    "e6c2d7c92da5: a Rust glob incorrectly competed with a nearer binder in the module that wrote it"
)]
fn native_definition_ranks_a_glob_below_a_nearer_binder_in_its_own_scope() {
    // A glob import is the weakest binder Rust has, and the shadow belongs to
    // the module that wrote the glob. `host` globs `other` and also declares
    // its own `shared`, so `shared` in `host` is the declared one and the
    // glob offers nothing; `Far`, which `host` does not declare, still comes
    // through the glob. `child` reads both through `use super::*;`.
    //
    // `host::local` writes `use crate::other::Far;` inside a function. That
    // binding is scoped to the function, so it must not switch the module's
    // glob off for `child::far`. A shadow test keyed by module alone would do
    // exactly that: `rust_crate_imports` records the row under `host`, and
    // only its binder scope separates it from a module-level `use`. This is
    // `data/src/dim/tree.rs`, which globs `sym::*` and holds a function-local
    // `use super::super::sym::SymbolValues;`.
    let source = concat!(
        "pub mod other {\n",
        "    pub fn shared() -> u8 { 0 }\n",
        "    pub struct Far;\n",
        "}\n",
        "pub mod host {\n",
        "    use crate::other::*;\n",
        "\n",
        "    fn shared() -> u8 { 1 }\n",
        "\n",
        "    pub fn local() -> u8 {\n",
        "        use crate::other::Far;\n",
        "        let local_value = Far;\n",
        "        let _ = local_value;\n",
        "        0\n",
        "    }\n",
        "\n",
        "    pub mod child {\n",
        "        use super::*;\n",
        "\n",
        "        pub fn near() -> u8 { let near_call = shared(); near_call }\n",
        "\n",
        "        pub fn far() -> Far { let far_value = Far; far_value }\n",
        "    }\n",
        "}\n",
    );
    let site_after = |marker: &str, name: &str| {
        let at = source
            .find(marker)
            .unwrap_or_else(|| panic!("{marker:?} is absent from the fixture"));
        let start = at
            + source[at..]
                .find(name)
                .unwrap_or_else(|| panic!("{name:?} is absent after {marker:?}"));
        reference_site_from_range(source, start, start + name.len())
    };
    let answer = |site| {
        let outcome = complete_definition(run_definition_at_site(
            source,
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ));
        (
            outcome
                .definitions
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>(),
            outcome.status,
        )
    };

    // The globbing module declares `shared` itself, so the glob offers no
    // second answer and this is resolved, not ambiguous.
    assert_eq!(
        answer(site_after("let near_call = ", "shared")),
        (
            vec!["native_points.host.shared".to_owned()],
            DefinitionLookupStatus::Resolved
        )
    );
    // The glob still binds every name the module does not declare, and the
    // function-local `use Far` in `host::local` does not reach this far.
    assert_eq!(
        answer(site_after("let far_value = ", "Far")),
        (
            vec!["native_points.other.Far".to_owned()],
            DefinitionLookupStatus::Resolved
        )
    );
    // The function-local binding itself resolves where it is written.
    assert_eq!(
        answer(site_after("let local_value = ", "Far")),
        (
            vec!["native_points.other.Far".to_owned()],
            DefinitionLookupStatus::Resolved
        )
    );
}

#[test]
fn native_import_points_union_namespace_alternatives_on_disk_and_prepared_overlays() {
    for (source, expected_count) in [
        ("pub mod provider {}\nuse crate::provider::Target;\n", 0),
        (
            "pub mod provider { pub mod model {} pub use model::*; }\nuse crate::provider::Target;\n",
            0,
        ),
        (
            "pub mod provider { pub mod model { pub fn Target() {} } pub use model::Target; }\nuse crate::provider::Target as Alias;\n",
            1,
        ),
        (
            "pub mod provider { pub mod model { pub fn Target() {} } pub use model::*; }\nuse crate::provider::Target;\n",
            1,
        ),
        (
            "pub mod provider { pub mod model { pub fn Target() {} } pub mod left { pub use super::model::*; } pub mod right { pub use super::model::*; } pub use left::*; pub use right::*; }\nuse crate::provider::Target;\n",
            1,
        ),
        (
            "pub mod provider { pub struct Target {} }\nuse crate::provider::Target;\n",
            1,
        ),
        (
            "pub mod provider { pub struct Target {} }\nuse crate::provider::Target as Alias;\n",
            1,
        ),
        (
            "pub mod provider { pub struct Target {} pub const Target: usize = 1; }\nuse crate::provider::Target as Alias;\n",
            2,
        ),
    ] {
        let (fixture, disk) = rust_source_project(source);
        let file = fixture.file("src/lib.rs");
        let site = reference_site(source, "Target");
        let tree = rust_tree(source);
        assert_import_alternatives(&disk, &file, &site);
        let disk_result =
            complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
                analyzer: &disk,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            }));
        assert_eq!(
            disk_result.definitions.len(),
            expected_count,
            "{disk_result:#?}"
        );
        assert_eq!(
            disk_result.status,
            match expected_count {
                0 => DefinitionLookupStatus::NoDefinition,
                1 => DefinitionLookupStatus::Resolved,
                _ => DefinitionLookupStatus::Ambiguous,
            },
            "{disk_result:#?}"
        );
        assert_eq!(
            disk_result
                .definitions
                .iter()
                .map(|unit| unit.declaration_id())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            expected_count
        );

        // A content change forces the same source occurrence through transient
        // lowering rather than reusing the persisted lookup's range rows.
        let overlay_source = format!("// prepared overlay\n{source}");
        let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), overlay_source.clone()));
        let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
        assert!(!analyzer.declarations(&file).is_empty());
        let overlay_site = reference_site(&overlay_source, "Target");
        let overlay_tree = rust_tree(&overlay_source);
        assert_import_alternatives(&analyzer, &file, &overlay_site);
        let overlay_result =
            complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source: &overlay_source,
                tree: Some(&overlay_tree),
                site: &overlay_site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            }));
        assert_eq!(
            overlay_result.status, disk_result.status,
            "{overlay_result:#?}"
        );
        assert_eq!(
            overlay_result.definitions.len(),
            expected_count,
            "{overlay_result:#?}"
        );
        assert!(
            overlay_result
                .definitions
                .iter()
                .all(|unit| unit.terminal_name() == "Target")
        );
    }
}

#[hardwon("be76515b1bc3: unknown route evidence was mistaken for a closed empty namespace")]
#[test]
fn native_empty_namespace_keeps_unknown_routes_and_open_inventories_incomplete() {
    // An undeclared root is now a proved negative. Unknown activation keeps
    // these routes uncertain without relying on that former completeness gap.
    for source in [
        "#[cfg(unknown_configuration)] mod missing {}\nuse crate::missing::Target;\n",
        "#[cfg(unknown_configuration)] mod missing {}\npub mod provider { pub use crate::missing::*; }\nuse crate::provider::Target;\n",
        "#[cfg(unknown_configuration)] mod missing {}\npub mod provider { pub use crate::missing::Target; }\nuse crate::provider::Target;\n",
        "pub mod provider { include!(\"generated.rs\"); }\nuse crate::provider::Target;\n",
        "pub mod provider { generate!(); }\nuse crate::provider::Target;\n",
        "pub mod provider { #[cfg(unknown_configuration)] pub struct Target {} }\nuse crate::provider::Target;\n",
        "pub mod provider { pub mod model { include!(\"generated.rs\"); } pub use model::*; }\nuse crate::provider::Target;\n",
    ] {
        let (fixture, disk) = rust_source_project(source);
        let file = fixture.file("src/lib.rs");
        for overlay in [false, true] {
            let selected_source = if overlay {
                format!("// prepared overlay\n{source}")
            } else {
                source.to_owned()
            };
            let analyzer = if overlay {
                let project = Arc::new(OverlayProject::new(fixture.project_dyn()));
                assert!(project.set(file.abs_path(), selected_source.clone()));
                disk.clone_with_project(Arc::new(project.snapshot()) as Arc<dyn Project>)
            } else {
                disk.clone_with_project(fixture.project_dyn())
            };
            // Hydrate overlay facts even when this module has no declarations.
            let _declarations = analyzer.declarations(&file);
            let site = reference_site(&selected_source, "Target");
            let tree = rust_tree(&selected_source);
            let result =
                complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source: &selected_source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                }));
            assert_eq!(
                result.status,
                DefinitionLookupStatus::Incomplete,
                "open route published as closed: overlay={overlay}, source={selected_source:?}, result={result:#?}"
            );
        }
    }
}

#[test]
#[hardwon("4bb46b89d2b1: an unrelated open module inventory made a selected Rust route incomplete")]
fn native_closed_namespace_uses_only_route_dependency_inventory_on_disk_and_overlay() {
    let source = "pub mod provider; pub mod hidden; use crate::provider::Target;\n";
    for (provider, expected_status) in [
        ("", DefinitionLookupStatus::NoDefinition),
        (
            "pub mod left { pub use super::right::*; } pub mod right { pub use super::left::*; } pub use left::*;",
            DefinitionLookupStatus::NoDefinition,
        ),
        ("pub struct Target {}", DefinitionLookupStatus::Resolved),
        (
            "include!(\"generated.rs\");",
            DefinitionLookupStatus::Incomplete,
        ),
    ] {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"route_inventory\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .file("src/provider.rs", provider)
            .file("src/hidden.rs", "unknown_macro!();")
            .build();
        let disk = RustAnalyzer::new(fixture.project_dyn());
        let file = fixture.file("src/lib.rs");
        for overlay in [false, true] {
            let selected_source = if overlay {
                format!("// overlay\n{source}")
            } else {
                source.to_owned()
            };
            let analyzer = if overlay {
                let project = Arc::new(OverlayProject::new(fixture.project_dyn()));
                assert!(project.set(file.abs_path(), selected_source.clone()));
                disk.clone_with_project(Arc::new(project.snapshot()) as Arc<dyn Project>)
            } else {
                disk.clone_with_project(fixture.project_dyn())
            };
            let _declarations = analyzer.declarations(&file);
            let site = reference_site(&selected_source, "Target");
            let tree = rust_tree(&selected_source);
            let result =
                complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source: &selected_source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                }));
            assert_eq!(
                result.status, expected_status,
                "provider={provider:?}, overlay={overlay}, result={result:#?}"
            );
        }
    }
}

#[test]
fn native_definition_uses_dirty_overlay_source_and_exact_reference_range() {
    let disk_source = concat!(
        "pub fn disk_target() -> usize { 1 }\n",
        "pub fn caller() -> usize { disk_target() }\n",
    );
    let overlay_source = concat!(
        "pub fn overlay_target() -> usize { 2 }\n",
        "pub fn caller() -> usize { overlay_target() }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"native_overlay\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", disk_source)
        .build();
    let disk = RustAnalyzer::new(fixture.project_dyn());
    let file = fixture.file("src/lib.rs");
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
    let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    let site = reference_site(overlay_source, "overlay_target");
    let tree = rust_tree(overlay_source);
    // The first call answers. A dirty buffer's facts exist once its file state
    // is fetched, and the selected overlay inputs fetch it, so nothing has to
    // hydrate the overlay by another route first.
    let unprepared = complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: overlay_source,
        tree: Some(&tree),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    }));
    assert_eq!(
        unprepared.status,
        DefinitionLookupStatus::Resolved,
        "{unprepared:#?}"
    );
    assert_eq!(unprepared.definitions.len(), 1, "{unprepared:#?}");
    assert_eq!(unprepared.definitions[0].short_name(), "overlay_target");
    assert!(
        analyzer
            .declarations(&file)
            .iter()
            .any(|unit| unit.short_name() == "overlay_target")
    );
    let result = resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: overlay_source,
        tree: Some(&tree),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    });
    let outcome = complete_definition(result);
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1);
    assert_eq!(outcome.definitions[0].short_name(), "overlay_target");
    assert_eq!(
        outcome.definitions[0].source().rel_path(),
        Path::new("src/lib.rs")
    );
    let reference = outcome.reference.expect("native overlay retains reference");
    assert_eq!(reference.path, "src/lib.rs");
    assert_eq!(reference.focus_start_byte, site.focus_start_byte);
    assert_eq!(reference.focus_end_byte, site.focus_end_byte);
}

/// An explicit type argument decides a generic return (`generic::<usize>()`
/// is a `usize`), and so does the type a `let` annotation expects of its call
/// initializer (`let value: usize = generic();`). A call with neither stays
/// incomplete.
#[test]
fn native_type_follows_a_type_argument_or_expected_type_into_a_generic_return() {
    for (call, expected) in [
        ("    generic::<usize>();\n", Some("usize")),
        ("    let value: usize = generic();\n", Some("usize")),
        ("    let value = generic();\n", None),
    ] {
        let source =
            format!("pub fn generic<T>() -> T {{ panic!() }}\npub fn caller() {{\n{call}}}\n");
        let outcome = complete_type(run_type(
            &source,
            "generic",
            ReceiverAnalysisBudget::default(),
            None,
        ));
        match expected {
            Some(fqn) => {
                assert_eq!(
                    outcome.status,
                    TypeLookupStatus::Resolved,
                    "{call}: {outcome:#?}"
                );
                assert_eq!(outcome.types.len(), 1, "{call}: {outcome:#?}");
                assert_eq!(outcome.types[0].fqn, fqn, "{call}: {outcome:#?}");
            }
            None => {
                assert_eq!(
                    outcome.status,
                    TypeLookupStatus::Incomplete,
                    "{call}: {outcome:#?}"
                );
                assert!(outcome.types.is_empty(), "{call}: {outcome:#?}");
            }
        }
    }
}

#[test]
#[hardwon(
    "e55decb2727b: unresolved private import gaps hid navigable Rust super and self module anchors"
)]
fn native_definition_import_anchor_names_its_module() {
    for import in [
        "use super::ITEM;",
        "use super::{ITEM};",
        "use super::ITEM as ALIAS;",
        "use super::*;",
    ] {
        let source =
            format!("mod parent {{ pub const ITEM: u32 = 1; mod child {{ {import} }} }}\n");
        let site = reference_site(&source, "super");
        let outcome = complete_definition(run_definition_at_site(
            &source,
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{import}: {outcome:#?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
        assert_eq!(
            outcome.definitions[0].identifier(),
            "parent",
            "{outcome:#?}"
        );
    }
    let source = "mod parent { pub const ITEM: u32 = 1; use self::ITEM as ALIAS; }\n";
    let site = reference_site(source, "self");
    let outcome = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert_eq!(
        outcome.definitions[0].identifier(),
        "parent",
        "{outcome:#?}"
    );
}

#[test]
#[hardwon(
    "ff03d3df8d2a: a child glob reported false absence through an uncertain private parent import"
)]
fn native_definition_glob_preserves_authored_names_and_fields() {
    // Attributes preserve imported authored names and written fields through
    // both private parent imports and child globs.
    for attributes in ["", "#[cfg(test)]"] {
        for import in ["use super::*;", "use crate::cli::CliArgs;"] {
            let source = format!(
                "pub mod cli {{ #[unknown_attribute] pub struct CliArgs {{ pub command: u32 }} }}\n\
                 use crate::cli::CliArgs;\n\
                 {attributes} mod tests {{ {import} fn caller() {{ let _ = CliArgs {{ command: 1 }}; }} }}\n"
            );
            for spelling in ["CliArgs", "command"] {
                let site = reference_site(&source, spelling);
                let outcome = complete_definition(run_definition_at_site(
                    &source,
                    &site,
                    ReceiverAnalysisBudget::default(),
                    None,
                ));
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{attributes} {import} {spelling}: {outcome:#?}"
                );
                assert!(
                    outcome
                        .definitions
                        .iter()
                        .any(|definition| definition.identifier() == spelling),
                    "{attributes} {import} {spelling}: the uncertain binding retains its authored source candidate: {outcome:#?}"
                );
                assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
            }
        }
    }
}

#[test]
#[hardwon("51f82df1a892: a nominal alias Self route selected the wrapped payload as its owner")]
fn native_definition_self_alias_does_not_select_wrapper_payload() {
    for (target, expected) in [
        ("Option<Item>", None),
        ("Box<Item>", None),
        ("std::sync::Arc<Item>", None),
        ("Item", Some("Item")),
        ("Wrapper<Item>", Some("Wrapper")),
    ] {
        for alias_path in ["Alias", "owners::Alias"] {
            let source = format!(
                "pub struct Item;\npub struct Wrapper<T> {{ inner: T }}\n\
             mod owners {{ use super::*; pub type Alias = {target}; }}\n\
             use owners::Alias;\npub type Chained = {alias_path};\n\
             pub trait Make {{ fn make() -> Self; }}\n\
             impl Make for Chained {{ fn make() -> Self {{ loop {{}} }} }}\n"
            );
            let tree = rust_tree(&source);
            let site = return_type_self_site(&source, &tree, "make");
            let definition = complete_definition(run_definition_at_site(
                &source,
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            ));
            if let Some(expected) = expected {
                assert_eq!(definition.definitions.len(), 1, "{definition:#?}");
                assert_eq!(
                    definition.definitions[0].identifier(),
                    expected,
                    "{definition:#?}"
                );
            } else {
                assert!(
                    definition.definitions.is_empty(),
                    "Self denotes {target}, not its payload: {definition:#?}"
                );
                assert!(
                    matches!(
                        definition.status,
                        DefinitionLookupStatus::Incomplete
                            | DefinitionLookupStatus::UnresolvableImportBoundary
                    ),
                    "unindexed nominal owner must preserve its boundary: {definition:#?}"
                );
            }
        }
    }
}

#[test]
#[hardwon("51f82df1a892: an aliased impl member leaked onto the wrapped payload type")]
fn native_definition_alias_impl_does_not_attach_members_to_payload() {
    let source = concat!(
        "pub struct Item;\n",
        "pub type Alias = Box<Item>;\n",
        "pub trait Make { fn make() -> Self; }\n",
        "impl Make for Alias { fn make() -> Self { loop {} } }\n",
        "fn caller() { let _ = Item::make(); }\n",
    );
    let site = reference_site(source, "make");
    let definition = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert!(definition.definitions.is_empty(), "{definition:#?}");
}

#[test]
#[hardwon(
    "04e5b1753605: alias receiver lookup confused nominal Self ownership with dereferenced fields"
)]
fn native_definition_alias_self_receiver_keeps_deref_payload() {
    let source = concat!(
        "pub struct Item { pub field: u32 }\n",
        "pub type Alias = Box<Item>;\n",
        "pub trait Read { fn read(&self) -> u32; }\n",
        "impl Read for Alias { fn read(&self) -> u32 { self.field } }\n",
    );
    let site = reference_site(source, "field");
    let definition = complete_definition(run_definition_at_site(
        source,
        &site,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(definition.definitions.len(), 1, "{definition:#?}");
    assert_eq!(definition.definitions[0].identifier(), "field");
}

#[test]
#[hardwon(
    "4a6e672b7308: transfer-owned Self occurrences lost their nominal type reference observation"
)]
fn native_definition_observes_transferred_self_type_frontier() {
    let source = concat!(
        "pub struct Service;\n",
        "impl Service {\n",
        "    fn new() -> Self { Service }\n",
        "    fn make() -> Self { Self::new() }\n",
        "}\n",
    );
    let tree = rust_tree(source);
    let bare_self = return_type_self_site(source, &tree, "make");
    let definition = complete_definition(run_definition_at_site(
        source,
        &bare_self,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        definition.status,
        DefinitionLookupStatus::Resolved,
        "{definition:#?}"
    );
    assert_eq!(definition.definitions.len(), 1, "{definition:#?}");
    assert_eq!(definition.definitions[0].identifier(), "Service");
    assert!(definition.diagnostics.is_empty(), "{definition:#?}");
    assert!(definition.lexical_definition.is_none(), "{definition:#?}");

    // The nominal route through the same occurrence still answers: `Self::new()`
    // resolves the associated item through the enclosing owner, whose declared
    // type identity the impl header carries. A locator names one reference by
    // its exact range, and `Self::new` spans two of them, so name the terminal.
    let terminal_start = source
        .rfind("Self::new")
        .expect("the fixture calls Self::new")
        + "Self::".len();
    let terminal = reference_site_from_range(source, terminal_start, terminal_start + "new".len());
    let call = complete_definition(run_definition_at_site(
        source,
        &terminal,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(call.status, DefinitionLookupStatus::Resolved, "{call:#?}");
    assert_eq!(call.definitions.len(), 1, "{call:#?}");
    assert_eq!(call.definitions[0].terminal_name(), "new", "{call:#?}");
    assert_eq!(call.definitions[0].short_name(), "Service.new", "{call:#?}");
}

#[test]
#[hardwon(
    "43d634c88f4e: clicking a Rust parameter binder returned a missing reference instead of itself"
)]
fn native_definition_click_on_rust_parameter_declaration_answers_itself() {
    const SOURCE: &str = concat!(
        "pub fn render(width: usize) -> usize {\n",
        "    width\n",
        "}\n",
    );
    let (fixture, mut disk) = rust_source_project(SOURCE);
    let file = fixture.file("src/lib.rs");
    assert!(!disk.declarations(&file).is_empty());
    disk.inner.clear_retained_file_states_for_test();
    assert!(
        disk.inner
            .fetch_file_state(&file)
            .unwrap()
            .resolution_facts
            .is_empty()
    );
    let overlay_source = SOURCE.replace("usize", "u32");
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(file.abs_path(), overlay_source.clone()));
    let dirty = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    assert!(!dirty.declarations(&file).is_empty());

    for (analyzer, source) in [(&disk, SOURCE), (&dirty, overlay_source.as_str())] {
        let declaration_start = source.find("width").expect("parameter declaration");
        let declaration_end = declaration_start + "width".len();
        let site = reference_site_from_range(source, declaration_start, declaration_end);
        let tree = rust_tree(source);
        let outcome = complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        }));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:#?}"
        );
        assert!(
            outcome.reference.is_none(),
            "a declaration click answers the declaration itself: {outcome:#?}"
        );
        let definition = outcome.lexical_definition.as_ref().unwrap_or_else(|| {
            panic!("clicking a parameter declaration answers the declaration: {outcome:#?}")
        });
        assert_eq!(definition.identifier, "width");
        assert_eq!(definition.kind, DeclarationKind::Parameter);
        assert_eq!(definition.name_range.start_byte, declaration_start);
        assert_eq!(definition.name_range.end_byte, declaration_end);
        assert!(
            definition.declaration_range.start_byte <= declaration_start
                && definition.declaration_range.end_byte >= declaration_end,
            "the declaration occurrence covers its identifier token: {definition:#?}"
        );
    }
}

#[hardwon("1917dc0a0854: selected cfg activation was lost across macro fragments")]
#[test]
fn native_cfg_macro_fragments_keep_selected_activation() {
    for (predicate, expected) in [
        ("test", DefinitionLookupStatus::Resolved),
        ("not(test)", DefinitionLookupStatus::NoDefinition),
        ("custom_cfg", DefinitionLookupStatus::Incomplete),
    ] {
        for source in [
            format!(
                "struct Item; macro_rules! take {{ ($t:ty) => {{}}; }} #[cfg({predicate})] fn caller() {{ take!(Item); }}"
            ),
            format!(
                "fn target() {{}} #[cfg({predicate})] macro_rules! take {{ () => {{ crate::target(); }}; }}"
            ),
        ] {
            let (fixture, analyzer) = rust_source_project(&source);
            let file = fixture.file("src/lib.rs");
            let _declarations = analyzer.declarations(&file);
            let tree = rust_tree(&source);
            let spelling = if source.starts_with("struct") {
                "Item"
            } else {
                "target"
            };
            let site = reference_site(&source, spelling);
            let outcome =
                complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source: &source,
                    tree: Some(&tree),
                    site: &site,
                    budget: ReceiverAnalysisBudget::default(),
                    cancellation: None,
                }));
            let expected = if predicate == "custom_cfg" {
                DefinitionLookupStatus::Resolved
            } else {
                expected
            };
            assert_eq!(outcome.status, expected, "{source}: {outcome:#?}");
            assert_eq!(
                outcome.definitions.len(),
                usize::from(expected == DefinitionLookupStatus::Resolved),
                "{source}: {outcome:#?}"
            );
            if predicate == "custom_cfg" {
                assert!(
                    outcome
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
                    "{source}: {outcome:#?}"
                );
            }
        }
    }
}

#[hardwon("754457cd8054: a refuted local binder hid the active outer Rust item")]
#[test]
fn native_cfg_refuted_shadow_does_not_hide_an_active_outer_binding() {
    let source = "pub fn selected() {}\npub fn caller() { #[cfg(not(test))] fn selected() {} selected(); }\n";
    let outcome = complete_definition(run_definition(
        source,
        "selected",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert!(
        outcome.lexical_definition.is_none(),
        "the refuted local binder cannot shadow the module item: {outcome:#?}"
    );
}

#[test]
#[hardwon("#3773: an unknown local activation remains incomplete")]
fn native_cfg_unknown_local_activation_keeps_answer_incomplete() {
    let source = "pub fn selected() {}\npub fn caller() { #[cfg(custom_cfg)] fn selected() {} selected(); }\n";
    let outcome = complete_definition(run_definition(
        source,
        "selected",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "unknown activation is not discharged: {outcome:#?}"
    );
}

#[test]
fn native_cfg_complementary_declarations_select_only_the_active_item() {
    let source = "#[cfg(test)] pub fn selected() {}\n#[cfg(not(test))] pub fn selected() {}\npub fn caller() { selected(); }\n";
    let outcome = complete_definition(run_definition(
        source,
        "selected",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
}

#[test]
fn native_cfg_type_queries_withhold_refuted_and_resolve_conditional_bodies() {
    for (predicate, expected) in [
        ("not(test)", TypeLookupStatus::NoType),
        ("custom_cfg", TypeLookupStatus::Resolved),
    ] {
        let source = format!("#[cfg({predicate})] fn caller() {{ let value: u32 = 1; value; }}");
        let outcome = complete_type(run_type(
            &source,
            "value",
            ReceiverAnalysisBudget::default(),
            None,
        ));
        assert_eq!(outcome.status, expected, "{outcome:#?}");
        if predicate == "custom_cfg" {
            assert_eq!(outcome.types.len(), 1, "{outcome:#?}");
            assert!(
                outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.kind == "conditional_cfg"),
                "{outcome:#?}"
            );
        } else {
            assert!(outcome.types.is_empty(), "{outcome:#?}");
        }
    }
}

#[hardwon("695a400f1854: tuple-variant constructor ranges failed exact receiver type lookup")]
#[test]
#[ignore = "finds real bug: nonempty tuple constructor call retains UnsupportedCallApplicability because argument slots are omitted. Owner: RustResolutionBuilder::lower_call_reference_result"]
fn native_enum_tuple_receiver_expression_range_has_exact_type() {
    assert_enum_receiver_expression_type("State::Tuple(1)");
}

/// A module whose item inventory is open does not prove a missing name
/// absent, in either path form: an invocation of a macro the workspace does
/// not define may declare `missing`, so the module route reports the
/// structured macro evidence instead of an actionable route dead end.
#[hardwon("1daf8988132d: an undecided item macro made a missing module name look absent")]
#[test]
fn a_module_with_an_undecided_item_macro_does_not_prove_a_missing_name_absent() {
    let source = "pub mod m {\n    unknown_items! { pub fn generated() {} }\n    pub fn present() {}\n}\npub fn caller() {\n    m::present();\n    m::missing();\n    crate::m::missing();\n}\n";
    // The declared item still answers, with the inventory's uncertainty.
    let present = definition_at_name(source, "m::present()", "present");
    assert_eq!(present.definitions.len(), 1, "{present:#?}");
    for marker in ["    m::missing()", "crate::m::missing()"] {
        let outcome = definition_at_name(source, marker, "missing");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "{marker}: {outcome:#?}"
        );
        assert!(outcome.definitions.is_empty(), "{marker}: {outcome:#?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "UnsupportedMacroGeneratedModule"),
            "{marker}: the open inventory names its reason: {outcome:#?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
            "{marker}: the structured boundary replaces the generic route gap: {outcome:#?}"
        );
    }
}

/// Source authority for a macro does not decide its expansion. Both a
/// generated inline module and an open module inventory keep binding partial.
#[hardwon(
    "#4676: a selected source macro's undecided expansion is an open local binding, not an import boundary"
)]
#[test]
fn a_source_defined_item_macro_keeps_its_local_binding_incomplete() {
    for (source, marker, name) in [
        (
            "macro_rules! helpers { ($t:ty) => { pub fn helper(_: $t) {} }; }\npub mod m { helpers!(u8); }\npub fn caller() { m::missing(); }\n",
            "m::missing()",
            "missing",
        ),
        (
            "macro_rules! allowed { ($($item:item)*) => { $( #[allow(dead_code)] $item )* }; }\nallowed! { pub mod w { pub fn h() {} } }\npub fn caller() { crate::w::h(); }\n",
            "crate::w::h()",
            "h",
        ),
    ] {
        let outcome = definition_at_name(source, marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "{marker}: {outcome:#?}"
        );
        assert!(outcome.definitions.is_empty(), "{marker}: {outcome:#?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.kind == "UnsupportedMacroGeneratedModule" }),
            "{marker}: the undecided inventory keeps its evidence: {outcome:#?}"
        );
        assert!(
            outcome.diagnostics.iter().all(|diagnostic| {
                diagnostic.kind != brokk_bifrost_analysis::analyzer::usages::get_definition::RUST_UNSUPPORTED_GENERATED_SURFACE_BOUNDARY_DIAGNOSTIC_KIND
            }),
            "{marker}: local uncertainty must not claim an import boundary: {outcome:#?}"
        );
    }
}

/// An import into a module whose route is gated by an undecided item macro
/// keeps the invocation boundary and does not invent an engine route gap.
#[hardwon("#4460: a macro-gated workspace module was reported as an unplaced crate route")]
#[test]
fn a_macro_gated_import_route_is_an_explicit_boundary() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("app/src/lib.rs", "pub mod client;\n"),
            (
                "app/src/client/mod.rs",
                "cfg_feature! { pub mod dispatch; }\npub mod conn { pub mod http1; }\n",
            ),
            (
                "app/src/client/conn/http1.rs",
                "use super::super::dispatch;\npub fn caller() { let _ = dispatch::Sender::new(); }\n",
            ),
        ],
        "app/src/client/conn/http1.rs",
        "dispatch::Sender::new()",
        "new",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.kind == "UnsupportedMacroGeneratedModule" }),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

/// A file inside a module selected by an unexpanded item macro keeps the
/// structured macro boundary when its enclosing route is not mounted.
#[hardwon("#4460: an unmounted descendant of a macro-gated module got a generic route gap")]
#[test]
fn an_unmounted_macro_gated_module_file_is_an_explicit_boundary() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("app/src/lib.rs", "pub mod client;\n"),
            (
                "app/src/client/mod.rs",
                "cfg_feature! { #![any(feature = \"http1\")] pub mod conn; pub(super) mod dispatch; }\n",
            ),
            ("app/src/client/conn/mod.rs", "pub mod http1;\n"),
            (
                "app/src/client/conn/http1.rs",
                "pub fn caller() { let _ = super::super::dispatch::Sender::new(); }\n",
            ),
        ],
        "app/src/client/conn/http1.rs",
        "dispatch::Sender::new()",
        "new",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "UnsupportedMacroGeneratedModule"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon(
    "#4460: a module excluded by the selected Cargo feature was reported as an unplaced crate route"
)]
fn an_inactive_cfg_module_file_is_an_explicit_boundary() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = []\nenterprise = []\n",
            ),
            (
                "app/src/lib.rs",
                "#[cfg(feature = \"enterprise\")] mod enterprise;\npub mod network { pub enum ImportState { Finished } }\n",
            ),
            (
                "app/src/enterprise.rs",
                "use crate::network::ImportState;\npub fn caller() { let _ = ImportState::Finished; }\n",
            ),
        ],
        "app/src/enterprise.rs",
        "ImportState::Finished",
        "Finished",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "InactiveCfgPlacement"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4460: an inactive cfg kept a cxx bridge source candidate incomplete")]
fn a_generated_surface_in_an_inactive_module_preserves_its_authored_binding() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = []\nenabled = []\n",
            ),
            (
                "app/src/lib.rs",
                "#[cfg(feature = \"enabled\")] mod bridge_module;\n",
            ),
            (
                "app/src/bridge_module.rs",
                "#[cxx::bridge(namespace = \"example\")] mod ffi { pub struct OperatorPtr { raw: *const u8 } }\npub fn use_it() { let _: Option<ffi::OperatorPtr> = None; }\n",
            ),
        ],
        "app/src/bridge_module.rs",
        "ffi::OperatorPtr",
        "ffi",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "ffi"),
        "the authored module stays available as source evidence: {outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "incomplete_binding"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

/// The census's unnamed Incomplete reason on tract and Bifrost (10,254 and
/// 26,120 sites): a qualified path whose prefix resolved, but to nothing the
/// selected crates place a continuation under (`Box`, `Arc`, a primitive, an
/// item declared inside a function body), and not to a dependency outside the
/// workspace. The route stops at its prefix, and the reply names that dead end
/// with its evidence instead of a bare `unsupported_semantic` number.
#[test]
fn a_route_through_an_unplaced_prefix_names_its_dead_end() {
    let source = "pub fn made() {\n    struct L;\n    L::y();\n}\n";
    let result = definition_at_name(source, "L::y()", "y");
    let named = result
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "UnplacedRoutePrefix")
        .map(|diagnostic| serde_json::from_str::<serde_json::Value>(&diagnostic.message).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        result.status,
        DefinitionLookupStatus::Incomplete,
        "{result:#?}"
    );
    assert_eq!(named.len(), 1, "{result:#?}");
    let evidence = &named[0]["evidence"][0];
    assert_eq!(evidence["reason"], "UnplacedRoutePrefix");
    assert_eq!(evidence["rel_path"], "src/lib.rs");
    assert_eq!(evidence["prefix"], "L");
    assert_eq!(evidence["demand"], "y");
    assert_eq!(evidence["namespace"], "value");
}

/// The classes of an unplaced route prefix that one file can reach. In one
/// file a primitive, the standard library and an undeclared crate never reach
/// the dead end: the route-head guard already answers them as the
/// unindexed-import boundary, which is pinned beside them. `Self` and a
/// generic parameter no longer reach it either; see
/// `a_self_path_resolves_through_the_enclosing_impl_or_trait` and
/// `a_type_parameter_member_resolves_through_its_bounds`.
#[test]
fn an_unplaced_route_prefix_reports_its_class() {
    for (source, spelling, class) in [
        (
            "pub fn made() {\n    struct L;\n    L::y();\n}\n",
            "y",
            Some("other"),
        ),
        ("pub fn low() -> i64 { i64::MIN }\n", "MIN", None),
        (
            "pub fn swap(a: &mut u8, b: &mut u8) { std::mem::swap(a, b) }\n",
            "swap",
            None,
        ),
        (
            "pub fn matches() { let _ = clap::ArgMatches::default(); }\n",
            "ArgMatches",
            None,
        ),
    ] {
        let result = complete_definition(run_definition(
            source,
            spelling,
            ReceiverAnalysisBudget::default(),
            None,
        ));
        let classes = result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.kind == "UnplacedRoutePrefix")
            .map(|diagnostic| {
                serde_json::from_str::<serde_json::Value>(&diagnostic.message).unwrap()["evidence"]
                    [0]["prefix_class"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        match class {
            Some(class) => {
                assert_eq!(
                    result.status,
                    DefinitionLookupStatus::Incomplete,
                    "{source}"
                );
                assert_eq!(classes, [class], "{source}: {result:#?}");
            }
            None => {
                assert_eq!(
                    result.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "{source}: {result:#?}"
                );
                assert!(classes.is_empty(), "{source}: {result:#?}");
            }
        }
    }
}

/// A qualified path whose prefix a glob binds resolves through the glob, in
/// another file of the crate and through a dependency's prelude, and a crate
/// re-exported under another name is the external boundary. A glob that
/// reaches `pub use std::sync::Arc;` is the std boundary even when another
/// glob of the same module targets a module whose inventory is open: the name
/// was found, the way a found declaration is. tract's `core/src/model/fact.rs`
/// writes `Arc::new` under `use crate::internal::*;`, whose `internal` globs
/// both `crate::prelude` (with the `Arc` import) and modules with undecided
/// item macros. A name only the open module could supply stays incomplete,
/// and the route's dead end says the prefix sits behind an open inventory.
#[test]
fn a_glob_bound_route_prefix_resolves_through_the_glob() {
    let app = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    let app_with_data = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\ndata = { path = \"../data\" }\nndarray = \"0.15\"\n";
    let data = "[package]\nname = \"data\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    let data_prelude = "pub mod prelude { pub use crate::datum::DatumType; }\npub mod datum { pub enum DatumType { F32, F16 } }\n";
    let data_open = "macro_rules! mk { () => { pub struct Made; } }\npub mod internal { mk!(); pub struct Tensor; }\n";
    let app_open_glob = "pub mod prelude { pub use std::sync::Arc; }\npub mod internal { pub use crate::prelude::*; pub use data::internal::*; }\npub mod user;\n";
    let resolved = |outcome: DefinitionLookupOutcome| {
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:#?}"
        );
        outcome
            .definitions
            .iter()
            .map(CodeUnit::fq_name)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        resolved(definition_in_workspace(
            &[
                ("Cargo.toml", app),
                ("src/lib.rs", "pub mod semantic;\npub mod user;\n"),
                (
                    "src/semantic.rs",
                    "pub enum Cap { A, B }\nimpl Cap { pub fn make() -> Cap { Cap::A } }\n"
                ),
                (
                    "src/user.rs",
                    "use crate::semantic::*;\npub fn f() -> Cap { let v = Cap::make(); v }\n"
                ),
            ],
            "src/user.rs",
            "let v = Cap::make",
            "make",
        )),
        ["app.semantic.Cap.make"]
    );
    for root in [
        "use data::prelude::*;\npub mod arm;\n",
        "pub mod internal { pub use data::prelude::*; }\nuse internal::*;\npub mod arm;\n",
    ] {
        assert_eq!(
            resolved(definition_in_workspace(
                &[
                    ("app/Cargo.toml", app_with_data),
                    ("data/Cargo.toml", data),
                    ("data/src/lib.rs", data_prelude),
                    ("app/src/lib.rs", root),
                    (
                        "app/src/arm.rs",
                        "use crate::DatumType;\npub fn f() -> DatumType { let v = DatumType::F32; v }\n"
                    ),
                ],
                "app/src/arm.rs",
                "let v = DatumType::F32",
                "F32",
            )),
            ["data.datum.DatumType.F32"],
            "{root}"
        );
    }
    for (lib, user, marker, name) in [
        (
            "pub mod internal { pub use ndarray as tract_ndarray; }\npub mod user;\n",
            "use crate::internal::*;\npub fn f() { let v = tract_ndarray::arr1(&[1]); }\n",
            "let v = tract_ndarray::arr1",
            "arr1",
        ),
        (
            app_open_glob,
            "use crate::internal::*;\npub fn f(a: Arc<u8>) -> Arc<u8> { let v = Arc::clone(&a); v }\n",
            "let v = Arc::clone",
            "clone",
        ),
        (
            app_open_glob,
            "use crate::internal::*;\npub fn f(a: Arc<u8>) { let v: Arc<u8> = a; }\n",
            "let v: Arc",
            "Arc",
        ),
    ] {
        let outcome = definition_in_workspace(
            &[
                ("app/Cargo.toml", app_with_data),
                ("data/Cargo.toml", data),
                ("data/src/lib.rs", data_open),
                ("app/src/lib.rs", lib),
                ("app/src/user.rs", user),
            ],
            "app/src/user.rs",
            marker,
            name,
        );
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "{marker}: {outcome:#?}"
        );
    }
    let outcome = definition_in_workspace(
        &[
            ("app/Cargo.toml", app_with_data),
            ("data/Cargo.toml", data),
            ("data/src/lib.rs", data_open),
            ("app/src/lib.rs", app_open_glob),
            (
                "app/src/user.rs",
                "use crate::internal::*;\npub fn f() { let v = Made::default(); }\n",
            ),
        ],
        "app/src/user.rs",
        "let v = Made::default",
        "default",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    let kinds = outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.kind.as_str())
        .collect::<Vec<_>>();
    assert!(
        kinds.contains(&"UnsupportedMacroGeneratedModule"),
        "{outcome:#?}"
    );
    let route_gaps = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "UnplacedRoutePrefix")
        .collect::<Vec<_>>();
    assert!(route_gaps.is_empty(), "{outcome:#?}");
}

/// `#[serde(..)]` is an inert helper of serde's derives, and the producer
/// proves that only from the item's own file (`rust_item_has_serde_derive`:
/// `#[derive(serde::Serialize)]` or a `use serde::Serialize` in the item's
/// scope). bifrost-rql's `search/results.rs` derives `Serialize` imported
/// through `use super::*;`, so the producer treats the helper as a possibly
/// item-transforming attribute macro, withholds the enum's binders, and
/// `CodeQueryResultValue::FlowEndpoint` in the same file cannot place its
/// prefix. Whether the bare `serde` name is an attribute macro is a crate-row
/// question; the persisted helper-name list leaves only this item's binder
/// open until the stage proves macro absence.
#[test]
#[hardwon("3bfcb9e3d4a4: a serde helper through a parent glob left its same-file enum unplaced")]
fn a_serde_helper_on_a_glob_imported_derive_is_inert() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nserde = \"1\"\n",
            ),
            ("src/lib.rs", "mod results;\nuse serde::Serialize;\n"),
            (
                "src/results.rs",
                "use super::*;\npub struct Item { value: Value }\npub fn f(item: &mut Item) {\n    if let Value::Flow { value } = &mut item.value {\n        let _ = value;\n    }\n}\n#[derive(Debug, Serialize)]\n#[serde(tag = \"result_type\")]\npub enum Value {\n    Flow { value: u8 },\n}\n",
            ),
        ],
        "src/results.rs",
        "if let Value::Flow",
        "Flow",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
}

/// A route prefix bound through an import rooted at `crate`, `self` or
/// `super` names a module of this crate, so it never leaves the workspace.
/// When the route finds nothing, the answer is the route's dead end; it used
/// to read the complete absence as a route that left the workspace and claim
/// an unindexed boundary. It is not a decided absence: on the census the
/// crate rows still miss declarations such a walk should find. An open module
/// inventory still answers its reason, and a prefix bound through an external
/// crate is still the boundary.
#[test]
#[hardwon(
    "bfd8542e01ae: crate-rooted missing paths were misreported as external import boundaries"
)]
fn a_crate_anchored_prefix_never_leaves_the_workspace() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nanyhow = \"1\"\n";
    let answer = |lib: &str, user: &str| {
        let outcome = definition_in_workspace(
            &[
                ("Cargo.toml", manifest),
                ("src/lib.rs", lib),
                ("src/user.rs", user),
            ],
            "src/user.rs",
            "let v = Local::new",
            "new",
        );
        (
            outcome.status,
            outcome
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.kind.clone())
                .collect::<Vec<_>>(),
        )
    };
    for (lib, user) in [
        (
            "pub mod user;\n",
            "use crate::missing::Local;\npub fn f() { let v = Local::new(); }\n",
        ),
        (
            "pub mod m {}\npub mod user;\n",
            "use crate::m::Local;\npub fn f() { let v = Local::new(); }\n",
        ),
        (
            "pub mod m {}\npub mod user;\n",
            "use super::m::Local;\npub fn f() { let v = Local::new(); }\n",
        ),
    ] {
        let (status, kinds) = answer(lib, user);
        assert_eq!(
            status,
            DefinitionLookupStatus::Incomplete,
            "{user}: {kinds:?}"
        );
        assert!(
            kinds.iter().any(|kind| kind == "UnplacedRoutePrefix"),
            "{user}: {kinds:?}"
        );
        assert!(
            !kinds.iter().any(|kind| kind == "unindexed_import_boundary"),
            "{user}: {kinds:?}"
        );
    }
    // A transforming attribute retains the authored enum as an uncertain
    // source candidate. It must not turn the crate-rooted lookup into an
    // unindexed external boundary; a tool attribute is inert and resolves.
    let (status, kinds) = answer(
        "pub mod m { #[my_attr] pub enum Local { A } }\npub mod user;\n",
        "use crate::m::Local;\npub fn f() { let v = Local::new(); }\n",
    );
    assert_eq!(status, DefinitionLookupStatus::Incomplete, "{kinds:?}");
    assert!(
        kinds.iter().any(|kind| kind == "incomplete_binding"),
        "{kinds:?}"
    );
    assert!(
        !kinds.iter().any(|kind| kind == "unindexed_import_boundary"),
        "{kinds:?}"
    );
    let outcome = definition_in_workspace(
        &[
            ("Cargo.toml", manifest),
            (
                "src/lib.rs",
                "pub mod m { #[rustfmt::skip]\n#[derive(Debug)]\npub enum Local { A }\n}\npub mod user;\n",
            ),
            (
                "src/user.rs",
                "use crate::m::Local;\npub fn f() { let v = Local::A; }\n",
            ),
        ],
        "src/user.rs",
        "let v = Local::A",
        "A",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    let (status, kinds) = answer(
        "pub mod user;\n",
        "use anyhow::Local;\npub fn f() { let v = Local::new(); }\n",
    );
    assert_eq!(
        status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{kinds:?}"
    );
}

#[test]
#[hardwon(
    "#4460: an attribute-withheld item retained incomplete evidence without a false route gap"
)]
fn attribute_generated_declaration_route_preserves_incomplete_source_evidence() {
    let outcome = definition_in_workspace(
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nanyhow = \"1\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod m { #[my_attr] pub enum Local { A } }\npub mod user;\n",
            ),
            (
                "src/user.rs",
                "use crate::m::Local;\npub fn f() { let v = Local::new(); }\n",
            ),
        ],
        "src/user.rs",
        "let v = Local::new",
        "new",
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "unindexed_import_boundary"),
        "{outcome:#?}"
    );
}

/// A generated-surface fact on a same-module type must take precedence over
/// the generic workspace-root classification when an associated path cannot
/// bind that source declaration.
#[hardwon(
    "#4460: an attribute-generated type kept its authored implementation candidate incomplete"
)]
#[test]
fn same_module_attribute_generated_type_route_preserves_its_incomplete_candidate() {
    let source = "#[my_attr]\npub enum Local { A }\nimpl From<u8> for Local { fn from(_: u8) -> Self { Self::A } }\npub fn caller() { let _ = Local::from(1); }\n";
    let outcome = definition_at_name(source, "Local::from(1)", "from");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "from"),
        "the authored implementation remains a candidate: {outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "GeneratedItemSurface"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "incomplete_binding"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon("#4460: an inline cxx bridge kept its authored type candidate incomplete")]
fn attribute_generated_inline_module_route_preserves_its_authored_binding() {
    let source = "#[cxx::bridge]\nmod ffi { pub struct OperatorPtr { value: u64 } }\npub fn caller(value: ffi::OperatorPtr) { let _ = value; }\n";
    let outcome = definition_at_name(source, "ffi::OperatorPtr", "OperatorPtr");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .definitions
            .iter()
            .any(|definition| definition.terminal_name() == "OperatorPtr"),
        "the authored type remains a candidate: {outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "incomplete_binding"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

#[test]
#[hardwon(
    "#4460: a pin_project-generated projection field remained an actionable incomplete binding"
)]
fn pin_project_generated_projection_field_is_an_explicit_boundary() {
    let source = "pub mod m {\n    pin_project! {\n        #[project = StateProj]\n        pub enum State<F> { Service { #[pin] fut: F } }\n    }\n}\npub fn caller(state: m::State<()>) {\n    match state.project() { m::StateProj::Service { fut: _ } => {} }\n}\n";
    let outcome = definition_at_name(source, "StateProj::Service { fut", "fut");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "UnsupportedMacroGeneratedSurface"),
        "{outcome:#?}"
    );
    assert!(
        outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
        "{outcome:#?}"
    );
}

/// A helper-looking attribute only stays open while macro lookup can answer
/// its name. The derive's identity is not a macro binding for the helper.
#[test]
#[hardwon("3bfcb9e3d4a4: serde helper names stayed open after macro lookup proved absence")]
fn a_serde_helper_closes_when_its_macro_name_is_absent() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nserde = \"1\"\nother = \"1\"\n";
    let results = "pub struct Item { value: Value }\npub fn f(item: &mut Item) {\n    if let Value::Flow { value } = &mut item.value {\n        let _ = value;\n    }\n}\n#[derive(Debug, Serialize)]\n#[serde(tag = \"result_type\")]\npub enum Value {\n    Flow { value: u8 },\n}\n";
    let answer = |lib: &str, header: &str| {
        let results = format!("{header}{results}");
        let outcome = definition_in_workspace(
            &[
                ("Cargo.toml", manifest),
                ("src/lib.rs", lib),
                ("src/results.rs", &results),
            ],
            "src/results.rs",
            "if let Value::Flow",
            "Flow",
        );
        (
            outcome.status,
            outcome
                .definitions
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>(),
        )
    };
    let resolved = (
        DefinitionLookupStatus::Resolved,
        vec!["app.results.Value.Flow".to_owned()],
    );
    assert_eq!(
        answer(
            "mod results;\nuse serde::Serialize;\n",
            "use crate::Serialize;\n"
        ),
        resolved
    );
    for (lib, header) in [
        ("mod results;\n", "use super::*;\n"),
        ("mod results;\nuse other::Serialize;\n", "use super::*;\n"),
    ] {
        assert_eq!(answer(lib, header), resolved, "{lib}{header}");
    }
}

/// A path to a member of a type parameter resolves through the parameter's
/// bounds, written inline or in a `where` clause, and inside a macro's
/// arguments as well. The crate route used to claim a dead end at the
/// parameter (census class `generic_parameter`, 379 tract and 494 Bifrost
/// sites), which made the answer incomplete even where the bound named the
/// member: the typed member route owns this question, and the crate route has
/// no module to continue through.
#[test]
#[hardwon("60c37e4f565a: Rust type-parameter member lookup dead-ended despite a declaring bound")]
fn a_type_parameter_member_resolves_through_its_bounds() {
    for (source, marker) in [
        (
            "pub trait Zero { fn zero() -> Self; }\npub fn made<T: Zero>() -> T { T::zero() }\n",
            "T::zero()",
        ),
        (
            "pub trait Zero { fn zero() -> Self; }\npub fn made<T>() -> T where T: Zero { T::zero() }\n",
            "T::zero()",
        ),
        (
            "pub trait Zero { fn zero() -> Self; fn ok(&self) -> bool; }\npub fn made<T: Zero>() { assert!(T::zero().ok()); }\n",
            "T::zero()",
        ),
    ] {
        let outcome = definition_at_name(source, marker, "zero");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{source}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|definition| definition.fq_name())
                .collect::<Vec<_>>(),
            ["native_points.Zero.zero"],
            "{source}: {outcome:#?}"
        );
    }
    // An associated type of the parameter's bound is a member too.
    let source = "pub trait Items { type Item; }\npub fn take<T: Items>(item: T::Item) {}\n";
    let outcome = definition_at_name(source, "T::Item)", "Item");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    // A supertrait's associated type or const is reached through the bound
    // trait's supertype rows, inline or in a `where` clause, through more
    // than one supertrait step, and beside a supertrait the index does not
    // hold.
    for (source, marker, name, fq_name) in [
        (
            "pub trait Items { type Item; }\npub trait Sub: Items {}\npub fn take<T: Sub>(item: T::Item) {}\n",
            "T::Item)",
            "Item",
            "native_points.Items.Item",
        ),
        (
            "pub trait Base { const N: u8; }\npub trait Mid: Base {}\npub trait Sub: Mid {}\npub fn n<T>() -> u8 where T: Sub { T::N }\n",
            "T::N",
            "N",
            "native_points.Base.N",
        ),
        (
            "pub trait Base<U> { const N: u8; }\npub trait Sub: Base<u8> + 'static {}\npub fn n<T: Sub>() -> u8 { T::N }\n",
            "T::N",
            "N",
            "native_points.Base.N",
        ),
    ] {
        let outcome = definition_at_name(source, marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{source}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|definition| definition.fq_name())
                .collect::<Vec<_>>(),
            [fq_name],
            "{source}: {outcome:#?}"
        );
    }
    // A supertrait the index does not hold (`Clone`) could declare the same
    // name, so the find stays incomplete.
    let source = "pub trait Base { const N: u8; }\npub trait Sub: Clone + Base {}\npub fn n<T: Sub>() -> u8 { T::N }\n";
    let outcome = definition_at_name(source, "T::N", "N");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:#?}"
    );
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(|definition| definition.fq_name())
            .collect::<Vec<_>>(),
        ["native_points.Base.N"],
        "{outcome:#?}"
    );
}

/// When the parameter's bounds do not declare the member, the answer is
/// incomplete and names the parameter, the bounds the index resolved, and the
/// member, never a route dead end: a blanket impl over a bound can still give
/// the parameter the member, so the miss is not an absence.
///
/// A bound the index does not hold (`Default`) is reported as an
/// unresolved bound rather than as a parameter with no bounds.
#[test]
#[hardwon(
    "60c37e4f565a: a missing type-parameter member lacked structured bound evidence and stayed a bare dead end"
)]
fn a_type_parameter_member_no_bound_declares_names_the_parameter_and_its_bounds() {
    for (source, marker, name, bounds, unresolved) in [
        (
            "pub trait Zero { fn zero() -> Self; }\npub fn made<T: Zero>() { T::one(); }\n",
            "T::one()",
            "one",
            vec!["native_points.Zero"],
            false,
        ),
        (
            "pub fn made<T>() { T::zero(); }\n",
            "T::zero()",
            "zero",
            vec![],
            false,
        ),
        (
            "pub fn made<T: Default>() -> T { T::default() }\n",
            "T::default()",
            "default",
            vec![],
            true,
        ),
    ] {
        let outcome = definition_at_name(source, marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "{source}: {outcome:#?}"
        );
        assert!(outcome.definitions.is_empty(), "{source}: {outcome:#?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
            "{source}: {outcome:#?}"
        );
        let evidence = generic_parameter_member_evidence(&outcome);
        assert_eq!(evidence.len(), 1, "{source}: {outcome:#?}");
        assert_eq!(evidence[0]["reason"], "GenericParameterMember");
        assert_eq!(evidence[0]["rel_path"], "src/lib.rs");
        assert_eq!(evidence[0]["parameter"], "T");
        assert_eq!(evidence[0]["demand"], name);
        assert_eq!(evidence[0]["namespace"], "value");
        assert_eq!(evidence[0]["bounds"], serde_json::json!(bounds), "{source}");
        assert_eq!(evidence[0]["unresolved_bounds"], unresolved, "{source}");
    }
}

/// A `Self::` path resolves through the enclosing impl or trait, written
/// directly or inside a macro's arguments: an inherent impl's own item, a
/// trait impl's item, a trait body's own item, and an impl's associated type.
/// Inside a macro the path used to have no owner at all -- a macro fragment is
/// parsed as a tree of its own, with no impl or trait ancestor -- so it took a
/// scope gap and the crate route claimed a dead end at `Self` (census class
/// `self_qualifier`, 97 tract and 719 Bifrost sites).
#[test]
#[hardwon(
    "804a845324ba: Self paths inside macro fragments lost their enclosing impl or trait owner"
)]
fn a_self_path_resolves_through_the_enclosing_impl_or_trait() {
    for (source, marker, name, fq_name) in [
        (
            "pub struct S;\nimpl S {\n    pub fn ok() -> bool { true }\n    pub fn check() -> bool { Self::ok() }\n}\n",
            "Self::ok()",
            "ok",
            "native_points.S.ok",
        ),
        (
            "pub struct S;\nimpl S {\n    pub fn ok() -> bool { true }\n    pub fn check() { assert!(Self::ok()); }\n}\n",
            "Self::ok()",
            "ok",
            "native_points.S.ok",
        ),
        (
            "pub trait Check { fn ok() -> bool; fn run(); }\npub struct S;\nimpl Check for S {\n    fn ok() -> bool { true }\n    fn run() { assert!(Self::ok()); }\n}\n",
            "Self::ok()",
            "ok",
            "native_points.S.ok",
        ),
        (
            "pub trait Check {\n    fn ok() -> bool;\n    fn run() -> bool { Self::ok() }\n}\n",
            "Self::ok()",
            "ok",
            "native_points.Check.ok",
        ),
        (
            "pub trait Check {\n    fn ok() -> bool;\n    fn run() { assert!(Self::ok()); }\n}\n",
            "Self::ok()",
            "ok",
            "native_points.Check.ok",
        ),
        (
            "pub trait Make { type Out; fn make() -> Self::Out; }\npub struct S;\nimpl Make for S {\n    type Out = u8;\n    fn make() -> Self::Out { 0 }\n}\n",
            "Self::Out {",
            "Out",
            "native_points.S.Out",
        ),
    ] {
        let outcome = definition_at_name(source, marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{source}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|definition| definition.fq_name())
                .collect::<Vec<_>>(),
            [fq_name],
            "{source}: {outcome:#?}"
        );
    }
    // A blanket impl whose Self is a parameter, and an impl on an
    // unindexed type, still report the structured missing support.
    for (source, marker, name) in [
        (
            "pub trait Dt { fn dt() -> u8; }\npub trait Packing { fn packing() -> u8; }\nimpl<D: Dt> Packing for D {\n    fn packing() -> u8 { Self::dt() }\n}\n",
            "Self::dt()",
            "dt",
        ),
        (
            "pub struct Scaler;\nimpl std::ops::Mul<Scaler> for f32 {\n    type Output = f32;\n    fn mul(self, rhs: Scaler) -> Self::Output { self }\n}\n",
            "Self::Output {",
            "Output",
        ),
    ] {
        let outcome = definition_at_name(source, marker, name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "{source}: {outcome:#?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind != "UnplacedRoutePrefix"),
            "{source}: {outcome:#?}"
        );
    }
}

/// A workspace crate re-exported under a name (`pub use dep::{self as rql}`,
/// `pub use dep as rql;`, `pub use dep;`) is a module a path can walk into:
/// `use crate::rql::Kind`, `crate::rql::Kind::A`, and `rql::Kind::A` in the
/// module that re-exports it all reach the dependency's items. bifrost-lsp's
/// `use crate::rql::{.., CodeQueryResultValue}` over `pub use
/// brokk_bifrost_rql::{self as rql}` is this shape.
#[test]
#[hardwon(
    "f41467a572d7: a workspace crate re-exported under a name was not traversable as a module"
)]
fn a_crate_re_exported_under_a_name_is_walked_into() {
    let app = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\ndata = { path = \"../data\" }\n";
    let data = "[package]\nname = \"data\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    for (lib, user, path, marker) in [
        (
            "pub use data::{self as rql};\npub mod user;\n",
            "use crate::rql::{Kind};\npub fn f() { let v = Kind::A; }\n",
            "app/src/user.rs",
            "let v = Kind::A",
        ),
        (
            "pub use data::{self as rql};\npub mod user;\n",
            "pub fn f() { let v = crate::rql::Kind::A; }\n",
            "app/src/user.rs",
            "let v = crate::rql::Kind::A",
        ),
        (
            "pub use data as rql;\npub mod user;\n",
            "use crate::rql::Kind;\npub fn f() { let v = Kind::A; }\n",
            "app/src/user.rs",
            "let v = Kind::A",
        ),
        (
            "pub use data;\npub mod user;\n",
            "use crate::data::Kind;\npub fn f() { let v = Kind::A; }\n",
            "app/src/user.rs",
            "let v = Kind::A",
        ),
        (
            "pub use data::{self as rql};\npub mod user;\npub fn g() { let w = rql::Kind::A; }\n",
            "pub fn f() {}\n",
            "app/src/lib.rs",
            "let w = rql::Kind::A",
        ),
    ] {
        let outcome = definition_in_workspace(
            &[
                ("app/Cargo.toml", app),
                ("data/Cargo.toml", data),
                ("data/src/lib.rs", "pub enum Kind { A }\n"),
                ("app/src/lib.rs", lib),
                ("app/src/user.rs", user),
            ],
            path,
            marker,
            "A",
        );
        assert_eq!(
            (
                outcome.status,
                outcome
                    .definitions
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<Vec<_>>()
            ),
            (
                DefinitionLookupStatus::Resolved,
                vec!["data.Kind.A".to_owned()]
            ),
            "{lib}{user}: {outcome:#?}"
        );
    }
}

/// A `crate::` path can name a private import of the crate root from any
/// module of the crate: rustc resolves `use crate::{LibraryName}` in a child
/// module through the root's private `use crate::kernels::LibraryName;`
/// (tract_metal's shape). `super::` reaches a parent's private import the same
/// way. The derivation used to bind an import only to the target module's
/// exports, so these were unresolved imports, and a `use super::*;` in the
/// importing module's inline `tests` module then saw nothing for the name.
#[test]
#[hardwon(
    "7707bfa5be04: descendants could not resolve a crate path through an ancestor private import"
)]
fn a_crate_path_reaches_a_private_import_of_an_ancestor() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    for (lib, child_path, child) in [
        (
            "pub mod kernels { pub enum LibraryName { Ggml } }\nuse crate::kernels::LibraryName;\npub mod ops;\n",
            "src/ops.rs",
            "use crate::{LibraryName};\npub fn f() { let v = LibraryName::Ggml; }\n",
        ),
        (
            "pub mod kernels { pub enum LibraryName { Ggml } }\nuse crate::kernels::LibraryName;\npub mod ops;\n",
            "src/ops.rs",
            "use crate::{LibraryName};\n#[cfg(test)]\nmod tests {\n    use super::*;\n    pub fn f() { let v = LibraryName::Ggml; }\n}\n",
        ),
        (
            "pub mod kernels { pub enum LibraryName { Ggml } }\nuse crate::kernels::LibraryName;\npub mod ops { pub mod deep; }\n",
            "src/ops/deep.rs",
            "use crate::LibraryName;\npub fn f() { let v = LibraryName::Ggml; }\n",
        ),
        (
            "pub mod kernels { pub enum LibraryName { Ggml } }\npub mod ops;\n",
            "src/ops.rs",
            "use crate::kernels::LibraryName as Name;\npub mod deep { use super::Name; pub fn f() { let v = Name::Ggml; } }\n",
        ),
    ] {
        let outcome = definition_in_workspace(
            &[
                ("Cargo.toml", manifest),
                ("src/lib.rs", lib),
                (child_path, child),
            ],
            child_path,
            "::Ggml",
            "Ggml",
        );
        assert_eq!(
            (
                outcome.status,
                outcome
                    .definitions
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<Vec<_>>()
            ),
            (
                DefinitionLookupStatus::Resolved,
                vec!["app.kernels.LibraryName.Ggml".to_owned()]
            ),
            "{lib}{child}: {outcome:#?}"
        );
    }
}

/// An item-position invocation of a macro no visible definition declares
/// (`thread_local! { static CONTEXT: .. }`, bifrost-lsp's server.rs) expands to
/// items the index cannot see. Those items cannot rebind a name the module
/// imports by name or declares. Under #5375 this also applies to an existing
/// glob-imported binding: generated items cannot shadow a found binding.
#[test]
#[hardwon("1a78838913f3: an undecided item macro made unrelated named imports incomplete")]
fn an_unknown_item_macro_leaves_named_imports_exact() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    let lib = "pub mod m { pub enum Kind { A } pub enum Other { B } }\npub mod user;\n";
    let answer = |user: &str, marker: &str, name: &str| {
        let outcome = definition_in_workspace(
            &[
                ("Cargo.toml", manifest),
                ("src/lib.rs", lib),
                ("src/user.rs", user),
            ],
            "src/user.rs",
            marker,
            name,
        );
        (
            outcome.status,
            outcome
                .definitions
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>(),
        )
    };
    let prelude = "use crate::m::Kind;\nuse crate::m::*;\nthread_local! {\n    static CONTEXT: u8 = const { 0 };\n}\n";
    assert_eq!(
        answer(
            &format!("{prelude}pub fn f() {{ let v = Kind::A; }}\n"),
            "let v = Kind::A",
            "A"
        ),
        (
            DefinitionLookupStatus::Resolved,
            vec!["app.m.Kind.A".to_owned()]
        )
    );
    let (status, definitions) = answer(
        &format!("{prelude}pub fn f() {{ let v = Other::B; }}\n"),
        "let v = Other::B",
        "B",
    );
    // #5375: a found glob binding is exact even beside an unknown item macro.
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions, ["app.m.Other.B"]);
}

/// Resolving the arguments says nothing about declarations the transcriber adds.
#[test]
#[hardwon(
    "305824c68bde: a reference-free macro input incorrectly closed the generated-item inventory"
)]
fn reference_free_macro_input_keeps_its_generated_items_open() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    for invocation in ["helpers!(u8);", "helpers!(Local);"] {
        let source = format!(
            "pub struct Local;\nmacro_rules! helpers {{ ($t:ty) => {{ pub fn generated(_: $t) {{}} }}; }}\n{invocation}\npub fn caller() {{ missing(); }}\n"
        );
        let outcome = definition_in_workspace(
            &[("Cargo.toml", manifest), ("src/lib.rs", &source)],
            "src/lib.rs",
            "missing()",
            "missing",
        );
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "{invocation}: {outcome:#?}"
        );
    }
}

#[hardwon("158831caa9ff: callable traversal attribution skipped supertrait owner hops")]
#[test]
fn rust_supertrait_callable_trace_records_each_owner_hop() {
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;
    let source = "pub trait Base { fn base(&self) -> bool; } pub trait Mid: Base {} pub trait Sub: Mid {} pub fn made<T: Sub>(value: T) -> bool { value.base() }";
    let (project, _) = rust_source_project(source);
    let workspace =
        project.workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
    let file = project.file("src/lib.rs");
    let start = source.rfind("base").unwrap();
    let (outcome, trace) = resolve_definition_batch_with_trace(
        workspace.analyzer(),
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + 4),
        }],
        file,
        Arc::from(source),
        &CancellationToken::new(),
    )
    .pop()
    .unwrap();
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    let selected = trace.selected().collect::<Vec<_>>();
    assert_eq!(selected.len(), 1, "{trace:#?}");
    let member = selected[0]
        .member
        .as_ref()
        .expect("selected member attribution");
    assert_eq!(member.hierarchy_depth, 2);
    assert_eq!(
        member
            .route
            .iter()
            .map(|hop| (hop.from.fq_name(), hop.to.fq_name()))
            .collect::<Vec<_>>(),
        [
            (
                "native_points.Sub".to_owned(),
                "native_points.Mid".to_owned()
            ),
            (
                "native_points.Mid".to_owned(),
                "native_points.Base".to_owned()
            )
        ]
    );
}

#[test]
#[hardwon("#5205: unexpanded attribute macros made existing bindings incomplete")]
fn generated_surfaces_preserve_existing_names_and_keep_absence_and_members_open() {
    // An enum variant is an authored binding even though its owner row calls
    // it a constructor. A derive on an unrelated item must not open it.
    let enumeration = "#[derive(Default)]\npub struct Marker;\npub enum Choice { No, Yes }\npub struct Other;\npub trait Action { fn action(&self); }\nimpl Action for Marker { fn action(&self) {} }\nimpl Action for Other { fn action(&self) {} }\npub fn caller(derived: Marker, other: Other) { let _ = Choice::Yes; derived.action(); other.action(); }\n";
    let variant = definition_in_workspace(
        &[("src/lib.rs", enumeration)],
        "src/lib.rs",
        "Choice::Yes;",
        "Yes",
    );
    assert_eq!(
        variant.status,
        DefinitionLookupStatus::Resolved,
        "{variant:#?}"
    );
    assert_eq!(variant.definitions.len(), 1, "{variant:#?}");
    for receiver in ["derived", "other"] {
        let marker = format!("{receiver}.action");
        let member = definition_in_workspace(
            &[("src/lib.rs", enumeration)],
            "src/lib.rs",
            &marker,
            "action",
        );
        assert_eq!(
            member.status,
            DefinitionLookupStatus::Resolved,
            "{member:#?}"
        );
        assert_eq!(member.definitions.len(), 1, "{member:#?}");
    }
    // Reduced from the two-module #4964 Vector diagnosis. The macro is an
    // imported, declared external attribute, with no expansion available.
    let manifest = "[package]\nname = \"generated_surface\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmacro-lib = \"1\"\nderivative = \"1\"\n";
    let batch = "use macro_lib::configurable_component;\nuse derivative::Derivative;\n#[derive(Derivative)]\n#[derivative(Clone)]\npub struct Auxiliary;\n#[configurable_component]\npub struct BatchConfig<D, S = Unmerged> { pub settings: D, state: S }\npub struct Unmerged;\npub struct Settings;\nimpl<D, S> BatchConfig<D, S> { pub fn validate(&self) {} }\npub trait Marker { fn trait_only(&self); }\nimpl<D, S> Marker for BatchConfig<D, S> { fn trait_only(&self) {} }\npub fn absent() { MissingName; }\n";
    let app = "mod batch;\nuse batch::{BatchConfig, Settings, Marker};\nstruct HoneycombConfig { batch: BatchConfig<Settings> }\nfn caller(batch: BatchConfig<Settings>) { batch.validate(); batch.trait_only(); let _ = &batch.settings; let _ = &batch.generated_field; batch.generated_member(); }\n";
    let files = [
        ("Cargo.toml", manifest),
        ("src/lib.rs", app),
        ("src/batch.rs", batch),
    ];
    for name in ["BatchConfig", "Settings"] {
        let outcome =
            definition_in_workspace(&files, "src/lib.rs", "batch: BatchConfig<Settings> }", name);
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{name}: {outcome:#?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "{name}: {outcome:#?}");
    }
    let absent = definition_in_workspace(&files, "src/batch.rs", "MissingName;", "MissingName");
    assert_eq!(
        absent.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{absent:#?}"
    );
    assert!(absent.definitions.is_empty(), "{absent:#?}");
    assert!(
        absent
            .diagnostics
            .iter()
            .any(|item| item.kind == "GeneratedItemSurface"),
        "{absent:#?}"
    );
    for name in ["validate", "settings"] {
        let marker = format!("batch.{name}");
        let member = definition_in_workspace(&files, "src/lib.rs", &marker, name);
        assert_eq!(
            member.status,
            DefinitionLookupStatus::Resolved,
            "{name}: {member:#?}"
        );
        assert_eq!(member.definitions.len(), 1, "{name}: {member:#?}");
    }
    let trait_member =
        definition_in_workspace(&files, "src/lib.rs", "batch.trait_only", "trait_only");
    assert_eq!(trait_member.definitions.len(), 1, "{trait_member:#?}");
    assert!(
        trait_member
            .diagnostics
            .iter()
            .all(|item| item.kind != "GeneratedItemSurface"),
        "found trait members gain no generated obligation: {trait_member:#?}"
    );
    for name in ["generated_member", "generated_field"] {
        let marker = format!("batch.{name}");
        let member = definition_in_workspace(&files, "src/lib.rs", &marker, name);
        assert!(
            matches!(
                member.status,
                DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ),
            "{name}: {member:#?}"
        );
        assert_eq!(member.definitions.len(), 0, "{name}: {member:#?}");
        assert!(
            member
                .diagnostics
                .iter()
                .any(|item| item.kind == "GeneratedItemSurface"),
            "{name} retains its member surface: {member:#?}"
        );
    }
}

#[test]
#[hardwon("#5172: inactive cfg_if arm macros leaked name and member frontiers")]
fn cfg_if_unsupported_macro_frontiers_follow_cfg_placement() {
    let manifest = "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2024\"\n";
    for (condition, active) in [
        ("all()", true),
        ("unknown_build_flag", true),
        ("any()", false),
    ] {
        let source = format!(
            r#"
pub struct Local;
impl Local {{ pub fn existing(&self) {{}} }}
mod helpers {{ pub fn imported_item() {{}} }}
use helpers::imported_item as imported;
pub fn ordinary() {{}}
cfg_if::cfg_if! {{ if #[cfg({condition})] {{ unsupported_items! {{}} }} }}
pub fn caller(value: Local) {{ ordinary(); imported(); missing_name(); value.existing(); }}
"#
        );
        for (marker, name, expected) in [
            ("ordinary();", "ordinary", DefinitionLookupStatus::Resolved),
            ("imported();", "imported", DefinitionLookupStatus::Resolved),
            (
                "missing_name();",
                "missing_name",
                if active {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::NoDefinition
                },
            ),
            (
                "value.existing();",
                "existing",
                if active {
                    DefinitionLookupStatus::Incomplete
                } else {
                    DefinitionLookupStatus::Resolved
                },
            ),
        ] {
            let outcome = definition_in_workspace(
                &[("Cargo.toml", manifest), ("src/lib.rs", &source)],
                "src/lib.rs",
                marker,
                name,
            );
            assert_eq!(
                outcome.status, expected,
                "{condition} {marker}: {outcome:#?}"
            );
            if expected == DefinitionLookupStatus::Incomplete {
                assert!(!outcome.diagnostics.is_empty(), "{outcome:#?}");
            }
            if name != "missing_name" {
                assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
                let expected_name = match name {
                    "imported" => "app.helpers.imported_item",
                    "existing" => "app.Local.existing",
                    _ => "app.ordinary",
                };
                assert_eq!(
                    outcome.definitions[0].fq_name(),
                    expected_name,
                    "{outcome:#?}"
                );
            }
        }
    }
}

#[test]
#[hardwon("#5172: cfg_if ordinary items and ordered alternatives remained generated surfaces")]
fn cfg_if_first_match_else_if_else_and_unknown_context() {
    let source = r#"pub mod platform {
cfg_if::cfg_if! {
    if #[cfg(feature = "first")] {
        pub fn first() {}
        pub use crate::helpers::first_target as selected;
        pub mod selected_mod { pub use crate::helpers::first_target as run; }
    } else if #[cfg(feature = "second")] {
        pub fn second() {}
        pub use crate::helpers::second_target as selected;
        pub mod selected_mod { pub use crate::helpers::second_target as run; }
    } else {
        pub fn last() {}
        pub use crate::helpers::last_target as selected;
        pub mod selected_mod { pub use crate::helpers::last_target as run; }
    }
}
pub fn caller() { first(); second(); last(); selected(); selected_mod::run(); }
}
pub mod helpers {
    pub fn first_target() {}
    pub fn second_target() {}
    pub fn last_target() {}
}
"#;
    for (features, selected) in [
        ("[\"first\", \"second\"]", "first"),
        ("[\"second\"]", "second"),
        ("[]", "last"),
    ] {
        let manifest = format!(
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = {features}\nfirst = []\nsecond = []\n"
        );
        for name in ["first", "second", "last"] {
            let outcome = definition_in_workspace(
                &[("Cargo.toml", &manifest), ("src/lib.rs", source)],
                "src/lib.rs",
                &format!("{name}();"),
                name,
            );
            if name == selected {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Resolved,
                    "{features} {name}: {outcome:#?}"
                );
                assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
            } else {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::NoDefinition,
                    "{features} {name}: {outcome:#?}"
                );
                assert!(outcome.definitions.is_empty(), "{outcome:#?}");
            }
        }
        for (marker, name) in [("selected();", "selected"), ("selected_mod::run();", "run")] {
            let outcome = definition_in_workspace(
                &[("Cargo.toml", &manifest), ("src/lib.rs", source)],
                "src/lib.rs",
                marker,
                name,
            );
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{features} {marker}: {outcome:#?}"
            );
            assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
            assert_eq!(
                outcome.definitions[0].terminal_name(),
                format!("{selected}_target")
            );
        }
    }
    let source = source.replace("feature = \"first\"", "unknown_build_flag");
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = [\"second\"]\nsecond = []\n";
    for name in ["first", "second", "selected"] {
        let outcome = definition_in_workspace(
            &[("Cargo.toml", manifest), ("src/lib.rs", &source)],
            "src/lib.rs",
            &format!("{name}();"),
            name,
        );
        assert!(
            matches!(
                outcome.status,
                DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ),
            "{name}: {outcome:#?}"
        );
    }
}

fn definition_in_workspace(
    files: &[(&str, &str)],
    path: &str,
    marker: &str,
    name: &str,
) -> DefinitionLookupOutcome {
    let mut project = InlineTestProject::with_language(Language::Rust);
    for (file, text) in files {
        project = project.file(*file, *text);
    }
    let fixture = project.build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let source = files
        .iter()
        .find(|(file, _)| *file == path)
        .expect("the reference file is a fixture file")
        .1;
    let start = source.find(marker).expect("marker is in the fixture")
        + marker.find(name).expect("marker contains the name");
    let mut site = reference_site_from_range(source, start, start + name.len());
    site.path = path.to_owned();
    let file = fixture.file(path);
    let tree = rust_tree(source);
    complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source,
        tree: Some(&tree),
        site: &site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    }))
}

fn generic_parameter_member_evidence(outcome: &DefinitionLookupOutcome) -> Vec<serde_json::Value> {
    outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "GenericParameterMember")
        .map(|diagnostic| {
            serde_json::from_str::<serde_json::Value>(&diagnostic.message).unwrap()["evidence"][0]
                .clone()
        })
        .collect()
}

fn return_type_self_site(
    source: &str,
    tree: &tree_sitter::Tree,
    function_name: &str,
) -> ResolvedReferenceSite {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_item" {
            let name = node
                .child_by_field_name("name")
                .expect("a function item names its declaration");
            if name
                .utf8_text(source.as_bytes())
                .expect("fixture names are utf8")
                == function_name
            {
                // `function_item` points its `return_type` field straight at
                // the `_type` node, so `-> Self` has no wrapper to descend
                // through and the bare type is that node.
                let self_type = node
                    .child_by_field_name("return_type")
                    .expect("the fixture function declares a return type");
                assert_eq!(
                    self_type.kind(),
                    "type_identifier",
                    "the fixture return type is a bare type name",
                );
                assert_eq!(
                    self_type
                        .utf8_text(source.as_bytes())
                        .expect("fixture types are utf8"),
                    "Self",
                    "the fixture return type is the bare Self type",
                );
                let range = self_type.byte_range();
                return reference_site_from_range(source, range.start, range.end);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    panic!("fixture has no function named {function_name:?}");
}

fn assert_import_alternatives(
    analyzer: &RustAnalyzer,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    site: &ResolvedReferenceSite,
) {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    let answers = resolve_point_answers(analyzer, file, site);
    assert_eq!(
        answers.len(),
        3,
        "the range includes every namespace, including complete-empty alternatives"
    );
    let metadata = answers
        .iter()
        .map(|answer| answer.resolution.site_metadata().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        metadata
            .iter()
            .map(|site| site.namespace())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Macro
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        metadata
            .iter()
            .map(|site| site.site())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    assert!(answers.iter().all(|answer| matches!(
        answer.resolution.binding().completion(),
        ResolutionCompletion::Complete
    )));
}

fn assert_enum_receiver_expression_type(expression: &str) {
    let source = "enum State { Unit, Tuple(u8), Struct { value: u8 } } impl State { fn run(&self) {} } fn call() { State::Unit.run(); State::Tuple(1).run(); (State::Struct { value: 1 }).run(); }";
    let outcome = complete_type(run_type(
        source,
        expression,
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        TypeLookupStatus::Resolved,
        "{expression}: {outcome:#?}"
    );
    assert_eq!(
        outcome
            .types
            .iter()
            .map(|ty| ty.fqn.as_str())
            .collect::<Vec<_>>(),
        ["native_points.State"],
        "{expression}: {outcome:#?}"
    );
}

#[test]
fn rust_definition_batch_reuses_one_selected_operation_per_file() {
    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source;

    let source = "pub struct Item; pub fn run() { let first = Item; let second = Item; }";
    let (project, _) = rust_source_project(source);
    let workspace =
        project.workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
    let file = project.file("src/lib.rs");
    let requests = source
        .match_indices("Item")
        .skip(1)
        .map(|(start, name)| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + name.len()),
        })
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);

    reset_rust_definition_operation_open_count_for_test();
    let batched = resolve_definition_batch_with_source(
        workspace.analyzer(),
        requests.clone(),
        file.clone(),
        Arc::from(source),
    );
    assert_eq!(rust_definition_operation_open_count_for_test(), 1);

    reset_rust_definition_operation_open_count_for_test();
    let separate = requests
        .iter()
        .cloned()
        .map(|request| {
            resolve_definition_batch_with_source(
                workspace.analyzer(),
                vec![request],
                file.clone(),
                Arc::from(source),
            )
            .pop()
            .expect("one separate request has one outcome")
        })
        .collect::<Vec<_>>();
    assert_eq!(rust_definition_operation_open_count_for_test(), 2);

    for (batched, separate) in batched.iter().zip(separate) {
        assert_eq!(batched.status, DefinitionLookupStatus::Resolved);
        assert_eq!(batched.status, separate.status);
        assert_eq!(batched.definitions.len(), 1);
        assert_eq!(
            batched.definitions[0].declaration_id(),
            separate.definitions[0].declaration_id(),
        );
    }
}
