use super::*;
use crate::CancellationToken;
use crate::OverlayProject;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, DefinitionLookupStatus, ResolvedReferenceSite,
};
use crate::analyzer::usages::get_type::{TypeLookupOutcome, TypeLookupStatus};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{CodeUnitIndex, DeclarationKind, Language, Project, Range, RustAnalyzer};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverBudgetLimit,
};
use std::path::Path;
use std::sync::Arc;

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
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    parser
        .parse(source, None)
        .expect("parse Rust native point fixture")
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
    ResolvedReferenceSite {
        path: "src/lib.rs".to_owned(),
        text: source[start_byte..end_byte].to_owned(),
        range: Range {
            start_byte,
            end_byte,
            start_line,
            end_line: start_line,
        },
        focus_start_byte: start_byte,
        focus_end_byte: end_byte,
    }
}

fn reference_site(source: &str, spelling: &str) -> ResolvedReferenceSite {
    let start_byte = source
        .rfind(spelling)
        .unwrap_or_else(|| panic!("{spelling:?} reference is absent from fixture"));
    reference_site_from_range(source, start_byte, start_byte + spelling.len())
}

/// The bare `Self` type in the return type of `function_name`.
///
/// `reference_site` answers from the last textual occurrence, so it cannot
/// separate `-> Self` from the `Self` path segment of a later `Self::new()`. The
/// AST carries the occurrence, so read the node.
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
    resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source,
        tree: Some(&tree),
        site,
        budget,
        cancellation,
    })
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
    resolve_rust_type_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source,
        tree: Some(&tree),
        site: &site,
        budget,
        cancellation,
    })
}

fn complete_definition(
    result: BoundedResolution<DefinitionLookupOutcome>,
) -> DefinitionLookupOutcome {
    match result {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { limit, .. } => {
            panic!("expected complete native definition, exceeded {limit:?}")
        }
        BoundedResolution::Cancelled { .. } => panic!("expected complete native definition"),
    }
}

fn complete_type(result: BoundedResolution<TypeLookupOutcome>) -> TypeLookupOutcome {
    match result {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { limit, .. } => {
            panic!("expected complete native type, exceeded {limit:?}")
        }
        BoundedResolution::Cancelled { .. } => panic!("expected complete native type"),
    }
}

#[test]
fn native_aliased_enum_variant_field_preserves_projection_origins() {
    let source = "enum Error { Entry { value: u32 } }\ntype Alias = Error;\nfn make(value: u32) -> Alias { Alias::Entry { value } }\n";
    let outcome = complete_definition(run_definition_at_site(
        source,
        &reference_site(source, "value"),
        crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
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

/// rustc resolves a single-segment macro name in textual scope first, so a
/// visible `macro_rules!` wins over every import of the scope. A glob from the
/// unindexed std is open in every namespace, and it must not reopen the
/// textual answer.
#[test]
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
    let repeated_left = || SelectedRustReferenceAnswer {
        boundary_import_names: left.boundary_import_names.clone(),
        macro_expansion_gaps: Vec::new(),
        enumeration: left.enumeration.clone(),
        inventory_details: Vec::new(),
        named_reasons: Vec::new(),
        resolution: left.resolution.clone(),
        definitions: left.definitions.clone(),
        lexical_definitions: left.lexical_definitions.clone(),
        definition_names: left.definition_names.clone(),
        member_attributions: Vec::new(),
        projection: (),
    };
    let single = adapt_definition_answer(&left_site, vec![repeated_left(), repeated_left()]);
    assert_eq!(single.status, DefinitionLookupStatus::Resolved);
    assert_eq!(single.definitions.len(), 1);
    let outcome = adapt_definition_answer(&left_site, vec![left, right]);
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Ambiguous,
        "{outcome:#?}"
    );
}

#[test]
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

fn resolve_point_answers(
    analyzer: &RustAnalyzer,
    file: &crate::analyzer::ProjectFile,
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
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
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

fn assert_import_alternatives(
    analyzer: &RustAnalyzer,
    file: &crate::analyzer::ProjectFile,
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
    // (setup_nodes 0, summary_expansions 17, scope_nodes 696), warm
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
                cancelled_with_resolution_work |= work.summary_expansions > 0;
            }
            BoundedResolution::Complete { value, .. } => assert_eq!(value.definitions.len(), 2),
            BoundedResolution::Exceeded { limit, .. } => panic!("cancellation exceeded {limit:?}"),
        }
    }
    assert!(cancelled_with_resolution_work);
}

#[test]
fn native_definition_projects_local_and_parameter_bindings_as_lexical_metadata() {
    let source = concat!(
        "pub fn caller(parameter: usize) -> usize {\n",
        "    let local: usize = parameter;\n",
        "    local\n",
        "}\n",
    );
    let parameter = complete_definition(run_definition(
        source,
        "parameter",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(parameter.status, DefinitionLookupStatus::Resolved);
    assert!(parameter.definitions.is_empty());
    assert_eq!(
        parameter
            .lexical_definition
            .as_ref()
            .map(|d| d.identifier.as_str()),
        Some("parameter")
    );
    assert_eq!(
        parameter.reference.as_ref().map(|site| site.path.as_str()),
        Some("src/lib.rs")
    );

    let local = complete_definition(run_definition(
        source,
        "local",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(local.status, DefinitionLookupStatus::Resolved);
    assert!(local.definitions.is_empty());
    assert_eq!(
        local
            .lexical_definition
            .as_ref()
            .map(|d| d.identifier.as_str()),
        Some("local")
    );
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

#[test]
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
fn native_type_projects_declared_primitive_value_with_exact_site() {
    let source = concat!(
        "pub fn caller() -> usize {\n",
        "    let value: usize = 1;\n",
        "    value\n",
        "}\n",
    );
    let outcome = complete_type(run_type(
        source,
        "value",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(outcome.status, TypeLookupStatus::Resolved);
    assert_eq!(outcome.types.len(), 1);
    assert_eq!(outcome.types[0].fqn, "usize");
    assert!(outcome.types[0].definitions.is_empty());
    assert_eq!(
        outcome.reference.as_ref().map(|site| site.path.as_str()),
        Some("src/lib.rs")
    );
    assert_eq!(outcome.target_kind, TypeLookupTargetKind::ValueExpression);
}

#[test]
fn native_type_projects_intrinsic_unit_call_without_a_definition() {
    let source = concat!(
        "pub fn unit() {}\n",
        "pub fn caller() {\n",
        "    unit();\n",
        "}\n",
    );
    let outcome = complete_type(run_type(
        source,
        "unit",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(outcome.status, TypeLookupStatus::Resolved);
    assert_eq!(outcome.types.len(), 1);
    assert_eq!(outcome.types[0].fqn, "()");
    assert!(outcome.types[0].definitions.is_empty());
}

#[test]
fn native_type_projects_nominal_call_return_to_its_code_unit() {
    let source = concat!(
        "pub struct Item;\n",
        "pub fn make() -> Item { Item }\n",
        "pub fn caller() {\n",
        "    make();\n",
        "}\n",
    );
    let outcome = complete_type(run_type(
        source,
        "make",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(outcome.status, TypeLookupStatus::Resolved);
    assert_eq!(outcome.types.len(), 1);
    assert_eq!(outcome.types[0].definitions.len(), 1);
    assert_eq!(
        outcome.types[0].fqn,
        outcome.types[0].definitions[0].fq_name()
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
fn native_definition_preserves_cancellation_and_budget_boundaries() {
    let source = "pub fn caller(value: usize) -> usize { value }\n";
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        run_definition(
            source,
            "value",
            ReceiverAnalysisBudget::default(),
            Some(&cancellation)
        ),
        BoundedResolution::Cancelled { .. }
    ));
    assert!(matches!(
        run_type(
            source,
            "value",
            ReceiverAnalysisBudget::default(),
            Some(&cancellation)
        ),
        BoundedResolution::Cancelled { .. }
    ));

    assert!(matches!(
        run_definition(
            source,
            "value",
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        ),
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            ..
        }
    ));
    assert!(matches!(
        run_type(
            source,
            "value",
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        ),
        BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes,
            ..
        }
    ));
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
fn native_definition_glob_preserves_private_import_incompleteness() {
    // The private parent import reaches a declaration an unknown attribute may
    // replace. A child glob must preserve that uncertainty for both the type
    // and its field, just as the direct import does.
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
                    DefinitionLookupStatus::Incomplete,
                    "{attributes} {import} {spelling}: {outcome:#?}"
                );
                assert!(outcome.definitions.is_empty(), "{outcome:#?}");
                assert!(!outcome.diagnostics.is_empty(), "{outcome:#?}");
            }
        }
    }
}

#[test]
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

/// Native resolution projects Rust parameters and locals itself.
///
/// The flag day switched the generic lexical shortcut off for Rust
/// (`get_definition/mod.rs`, `language != Language::Rust`), so nothing upstream
/// answers a parameter or a `let` binding any more. Both come back as lexical
/// definitions from the selected operation, with the declaration range the
/// binder occupies.
#[test]
fn native_definitions_answer_rust_parameters_and_locals() {
    const SOURCE: &str = concat!(
        "pub fn render(width: usize) -> usize {\n",
        "    let height = width;\n",
        "    height\n",
        "}\n",
    );
    let (fixture, analyzer) = rust_source_project(SOURCE);
    let file = fixture.file("src/lib.rs");
    let tree = rust_tree(SOURCE);

    // `width` in `let height = width;` reads the parameter.
    let parameter_read = SOURCE.find("= width;").expect("parameter read") + 2;
    let mut parameter_site = reference_site(SOURCE, "width");
    parameter_site.range.start_byte = parameter_read;
    parameter_site.range.end_byte = parameter_read + "width".len();
    parameter_site.focus_start_byte = parameter_read;
    parameter_site.focus_end_byte = parameter_read + "width".len();
    let parameter = complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: SOURCE,
        tree: Some(&tree),
        site: &parameter_site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    }));
    assert_eq!(
        parameter.status,
        DefinitionLookupStatus::Resolved,
        "{parameter:#?}"
    );
    let parameter_definition = parameter
        .lexical_definition
        .as_ref()
        .unwrap_or_else(|| panic!("a Rust parameter is a lexical definition: {parameter:#?}"));
    assert_eq!(parameter_definition.identifier, "width");
    assert_eq!(
        &SOURCE
            [parameter_definition.name_range.start_byte..parameter_definition.name_range.end_byte],
        "width"
    );
    assert!(
        parameter_definition.name_range.start_byte < parameter_read,
        "the parameter binder precedes its read: {parameter_definition:#?}"
    );

    // `height` in the tail expression reads the local.
    let local_site = reference_site(SOURCE, "height");
    let local = complete_definition(resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer: &analyzer,
        file: &file,
        source: SOURCE,
        tree: Some(&tree),
        site: &local_site,
        budget: ReceiverAnalysisBudget::default(),
        cancellation: None,
    }));
    assert_eq!(local.status, DefinitionLookupStatus::Resolved, "{local:#?}");
    let local_definition = local
        .lexical_definition
        .as_ref()
        .unwrap_or_else(|| panic!("a Rust local is a lexical definition: {local:#?}"));
    assert_eq!(local_definition.identifier, "height");
    assert_eq!(
        local_definition.name_range.start_byte,
        SOURCE.find("let height").expect("local binder") + "let ".len()
    );
}

#[test]
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

#[test]
fn native_definition_trace_projects_units_without_claiming_rejection_coverage() {
    use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
    use crate::analyzer::usages::get_definition::trace::{
        TraceCandidateRef, TraceCompleteness, resolve_definition_batch_with_trace,
    };

    let source = "pub struct Item; fn run(_: Item) {}";
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let workspace = project.workspace_analyzer(crate::AnalyzerConfig::default());
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
fn native_qualified_enum_value_has_a_complete_definition_answer() {
    let source = "pub enum State { Ready } fn run() { let _ = State::Ready; }";
    let outcome = complete_definition(run_definition(
        source,
        "Ready",
        ReceiverAnalysisBudget::default(),
        None,
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:#?}");
    assert_eq!(outcome.definitions[0].terminal_name(), "Ready");
    assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
}

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
            assert_eq!(outcome.status, expected, "{source}: {outcome:#?}");
            assert_eq!(
                outcome.definitions.len(),
                usize::from(expected == DefinitionLookupStatus::Resolved),
                "{source}: {outcome:#?}"
            );
        }
    }
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
                    assert_eq!(
                        outcome.status, expected,
                        "manifest={manifest}, overlay={overlay}, predicate={predicate}, spelling={spelling}: {outcome:#?}"
                    );
                    assert_eq!(
                        outcome.definitions.len(),
                        usize::from(expected == DefinitionLookupStatus::Resolved),
                        "{outcome:#?}"
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "finds real bug: block-local item UnsupportedScopeOrBinder and lexical shadow selection precede selected activation; the refuted target is withheld but the active outer target remains incomplete. Owner: DW/RI selected lexical activation before shadow selection."]
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
fn native_cfg_type_queries_withhold_refuted_and_unknown_bodies() {
    for (predicate, expected) in [
        ("not(test)", TypeLookupStatus::NoType),
        ("custom_cfg", TypeLookupStatus::Incomplete),
    ] {
        let source = format!("#[cfg({predicate})] fn caller() {{ let value: u32 = 1; value; }}");
        let outcome = complete_type(run_type(
            &source,
            "value",
            ReceiverAnalysisBudget::default(),
            None,
        ));
        assert_eq!(outcome.status, expected, "{outcome:#?}");
        assert!(outcome.types.is_empty(), "{outcome:#?}");
    }
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
fn native_enum_unit_receiver_expression_range_has_exact_type() {
    assert_enum_receiver_expression_type("State::Unit");
}

#[test]
#[ignore = "finds real bug: nonempty tuple constructor call retains UnsupportedCallApplicability because argument slots are omitted. Owner: RustResolutionBuilder::lower_call_reference_result"]
fn native_enum_tuple_receiver_expression_range_has_exact_type() {
    assert_enum_receiver_expression_type("State::Tuple(1)");
}

#[test]
fn native_enum_struct_receiver_expression_range_has_exact_type() {
    assert_enum_receiver_expression_type("(State::Struct { value: 1 })");
}

#[test]
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

/// `Self::resolve_symbols(..)` inside `impl OpState for Cache` is the
/// type-relative path `<Cache>::resolve_symbols`, and rustc probes inherent
/// impls first: it names the inherent associated function (three arguments),
/// not the impl's own trait method (two). tract's
/// `transformers/src/ops/dyn_kv_cache.rs:130` has this shape. A `Self::` path
/// with no inherent item of the name still reaches the impl's trait item.
#[test]
fn a_self_path_in_a_trait_impl_names_the_inherent_associated_function() {
    let source = "pub trait OpState {\n    fn resolve_symbols(&mut self, state: &mut u8) -> u8 { *state }\n    fn load_from(&mut self, state: &mut u8) -> u8;\n}\npub struct Cache;\nimpl Cache {\n    pub fn resolve_symbols(state: &mut u8, fact: u8, shape: Option<&[usize]>) -> u8 { fact }\n}\nimpl OpState for Cache {\n    fn load_from(&mut self, state: &mut u8) -> u8 { Self::resolve_symbols(state, 1, None) }\n    fn resolve_symbols(&mut self, state: &mut u8) -> u8 { Self::resolve_symbols(state, 2, None) + Self::load_from(self, state) }\n}\n";
    let outcome = definition_at_name(source, "Self::resolve_symbols(state, 1", "resolve_symbols");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(|definition| definition.signature())
            .collect::<Vec<_>>(),
        [Some(
            "impl Cache::pub fn resolve_symbols(state: &mut u8, fact: u8, shape: Option<&[usize]>) -> u8 { ... }"
        )],
        "{outcome:#?}"
    );
    // With no inherent item of the name, the path reaches the impl's trait
    // item.
    let outcome = definition_at_name(source, "Self::load_from(self", "load_from");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:#?}"
    );
    assert_eq!(
        outcome
            .definitions
            .iter()
            .map(|definition| definition.signature())
            .collect::<Vec<_>>(),
        [Some(
            "impl OpState for Cache::fn load_from(&mut self, state: &mut u8) -> u8 { ... }"
        )],
        "{outcome:#?}"
    );
}

/// A `crate::`-rooted path to an associated function that the type gets from
/// a trait impl names that impl's function, as the same path without the
/// `crate::` prefix does.
#[test]
fn a_crate_rooted_path_to_a_trait_provided_function_resolves() {
    for path in ["generic::erf::Erf4", "crate::generic::erf::Erf4"] {
        let source = format!(
            "pub mod frame {{\n    pub trait Kernel<T> {{\n        fn run(values: &mut [T]);\n    }}\n}}\npub mod generic {{\n    pub mod erf {{\n        use crate::frame::Kernel;\n        pub struct Erf4;\n        impl Kernel<f32> for Erf4 {{\n            fn run(values: &mut [f32]) {{}}\n        }}\n    }}\n}}\nuse crate::frame::Kernel;\npub fn bench(values: &mut [f32]) {{ {path}::run(values); }}\n"
        );
        let outcome = definition_at_name(&source, "Erf4::run(values", "run");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{path}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|definition| definition.signature())
                .collect::<Vec<_>>(),
            [Some(
                "impl Kernel<f32> for Erf4::fn run(values: &mut [f32]) { ... }"
            )],
            "{path}: {outcome:#?}"
        );
    }
}

/// The explicit-module form of an inherent associated function and of a
/// member the type does not have: `crate::m::Type::inherent` names the
/// inherent function, as the relative path does, and `crate::m::Type::missing`
/// answers the open member boundary the relative path answers, not a proved
/// absence. A route through modules only keeps its exact negative.
#[test]
fn a_crate_rooted_member_path_follows_the_type_like_the_relative_path() {
    let source = "pub mod generic {\n    pub mod erf {\n        pub struct Erf4;\n        impl Erf4 {\n            pub fn inherent(values: &mut [f32]) {}\n        }\n    }\n}\npub fn bench(values: &mut [f32]) {\n    crate::generic::erf::Erf4::inherent(values);\n    generic::erf::Erf4::inherent(values);\n    crate::generic::erf::Erf4::missing(values);\n    generic::erf::Erf4::missing(values);\n    crate::generic::erf::missing(values);\n}\n";
    for marker in [
        "crate::generic::erf::Erf4::inherent(values",
        "    generic::erf::Erf4::inherent(values",
    ] {
        let outcome = definition_at_name(source, marker, "inherent");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{marker}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(|definition| definition.signature())
                .collect::<Vec<_>>(),
            [Some(
                "impl Erf4::pub fn inherent(values: &mut [f32]) { ... }"
            )],
            "{marker}: {outcome:#?}"
        );
    }
    // A member the rows cannot rule out is the open member boundary the
    // relative path answers too, never a proved absence.
    let anchored = definition_at_name(
        source,
        "crate::generic::erf::Erf4::missing(values",
        "missing",
    );
    let relative = definition_at_name(source, "    generic::erf::Erf4::missing(values", "missing");
    assert_eq!(
        anchored.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "{anchored:#?}"
    );
    assert_eq!(
        anchored.status, relative.status,
        "{anchored:#?} {relative:#?}"
    );
    assert!(anchored.definitions.is_empty(), "{anchored:#?}");
    let outcome = definition_at_name(source, "erf::missing(values", "missing");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::NoDefinition,
        "a route through modules only proves the absence: {outcome:#?}"
    );
}

/// A module whose item inventory is open does not prove a missing name
/// absent, in either path form: an invocation of a macro the workspace does
/// not define may declare `missing`, so the module route answers incomplete
/// with the open-inventory reason. The module-has-no-type rule removes only
/// the member lookup, never the inventory's own uncertainty.
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
    }
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
        DefinitionLookupStatus::Incomplete,
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
    let classes = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "UnplacedRoutePrefix")
        .map(|diagnostic| {
            serde_json::from_str::<serde_json::Value>(&diagnostic.message).unwrap()["evidence"][0]
                ["prefix_class"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(classes, ["open_inventory"], "{outcome:#?}");
}

/// `#[serde(..)]` is an inert helper of serde's derives, and the producer
/// proves that only from the item's own file (`rust_item_has_serde_derive`:
/// `#[derive(serde::Serialize)]` or a `use serde::Serialize` in the item's
/// scope). bifrost-rql's `search/results.rs` derives `Serialize` imported
/// through `use super::*;`, so the producer treats the helper as a possibly
/// item-transforming attribute macro, withholds the enum's binders, and
/// `CodeQueryResultValue::FlowEndpoint` in the same file cannot place its
/// prefix. The derive's binding is a crate-row question; answering it needs a
/// persisted derive-helper fact the crate route can discharge
/// (`source_rust_declaration_properties.serde_helper_derive`).
#[test]
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
    // A declaration the producer withholds (an attribute it treats as
    // possibly item-transforming) opens its module's inventory, so the walk is
    // not an absence; a tool attribute is inert and the item resolves.
    let (status, kinds) = answer(
        "pub mod m { #[my_attr] pub enum Local { A } }\npub mod user;\n",
        "use crate::m::Local;\npub fn f() { let v = Local::new(); }\n",
    );
    assert_eq!(status, DefinitionLookupStatus::Incomplete, "{kinds:?}");
    assert!(
        kinds.iter().any(|kind| kind == "UnloweredDeclaration"),
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
/// The serde helper stays open while the crate rows cannot show that the
/// derive is serde's: a derive name nothing binds, or one bound to another
/// crate's derive, leaves the item found but incomplete, because `#[serde]`
/// could then be an attribute macro that replaces it. A derive name bound in
/// the item's own scope through the crate root's serde import is proved.
#[test]
fn a_serde_helper_stays_open_until_the_rows_prove_the_derive() {
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
    assert_eq!(
        answer(
            "mod results;\nuse serde::Serialize;\n",
            "use crate::Serialize;\n"
        ),
        (
            DefinitionLookupStatus::Resolved,
            vec!["app.results.Value.Flow".to_owned()]
        )
    );
    for (lib, header) in [
        ("mod results;\n", "use super::*;\n"),
        ("mod results;\nuse other::Serialize;\n", "use super::*;\n"),
    ] {
        let (status, _) = answer(lib, header);
        assert_eq!(status, DefinitionLookupStatus::Incomplete, "{lib}{header}");
    }
}

/// The `GenericParameterMember` reasons of an answer, as evidence objects.
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

/// A path to a member of a type parameter resolves through the parameter's
/// bounds, written inline or in a `where` clause, and inside a macro's
/// arguments as well. The crate route used to claim a dead end at the
/// parameter (census class `generic_parameter`, 379 tract and 494 Bifrost
/// sites), which made the answer incomplete even where the bound named the
/// member: the typed member route owns this question, and the crate route has
/// no module to continue through.
#[test]
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
/// imports by name or declares, so such a name resolves exactly; a name only a
/// glob binds stays open, because an expanded item could shadow it.
#[test]
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
    let (status, _) = answer(
        &format!("{prelude}pub fn f() {{ let v = Other::B; }}\n"),
        "let v = Other::B",
        "B",
    );
    assert_eq!(status, DefinitionLookupStatus::Incomplete);
}

/// Resolving the arguments says nothing about declarations the transcriber adds.
#[test]
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

#[test]
fn rust_supertrait_callable_members_resolve_at_every_depth() {
    for (source, marker) in [
        (
            "pub trait Base { fn base() -> Self; } pub trait Sub: Base {} pub fn made<T: Sub>() -> T { T::base() }",
            "T::base()",
        ),
        (
            "pub trait Base { fn base() -> Self; } pub trait Mid: Base {} pub trait Sub: Mid {} pub fn made<T>() -> T where T: Sub { T::base() }",
            "T::base()",
        ),
        (
            "pub trait Base { fn base() -> bool; } pub trait Sub: Base { fn run() -> bool { Self::base() } }",
            "Self::base()",
        ),
        (
            "pub trait Base { fn base(&self) -> bool; } pub trait Mid: Base {} pub trait Sub: Mid {} pub fn made<T: Sub>(value: T) -> bool { value.base() }",
            "value.base()",
        ),
        (
            "pub trait Base { fn base() -> Self; } pub trait Left: Base {} pub trait Right: Base {} pub trait Sub: Left + Right {} pub fn made<T: Sub>() -> T { T::base() }",
            "T::base()",
        ),
    ] {
        let outcome = definition_at_name(source, marker, "base");
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{source}: {outcome:#?}"
        );
        assert_eq!(
            outcome
                .definitions
                .iter()
                .map(CodeUnit::fq_name)
                .collect::<Vec<_>>(),
            ["native_points.Base.base"],
            "{source}: {outcome:#?}"
        );
    }
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
fn rust_supertrait_callable_trace_records_each_owner_hop() {
    use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
    use crate::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;
    let source = "pub trait Base { fn base(&self) -> bool; } pub trait Mid: Base {} pub trait Sub: Mid {} pub fn made<T: Sub>(value: T) -> bool { value.base() }";
    let (project, _) = rust_source_project(source);
    let workspace = project.workspace_analyzer(crate::AnalyzerConfig::default());
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
