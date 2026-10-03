use super::*;
use crate::analyzer::structural::{NormalizedKind, OccurrenceRole, Role};
use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
use crate::analyzer::{Language, Range};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use std::path::Path;

fn rust_tree(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    parser
        .parse(source, None)
        .expect("parse Rust module-system fixture")
}

fn reference_site(path: &str, source: &str, spelling: &str) -> ResolvedReferenceSite {
    let start_byte = source
        .rfind(spelling)
        .unwrap_or_else(|| panic!("{spelling:?} reference in {path}"));
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    ResolvedReferenceSite {
        path: path.to_string(),
        text: spelling.to_string(),
        range: Range {
            start_byte,
            end_byte: start_byte + spelling.len(),
            start_line,
            end_line: start_line,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + spelling.len(),
    }
}

fn assert_complete_shadow(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    path: &str,
    source: &str,
    spelling: &str,
    expected_source: &str,
) {
    assert_complete_shadow_with_budget(
        fixture,
        analyzer,
        path,
        source,
        spelling,
        expected_source,
        ReceiverAnalysisBudget::default(),
    );
}

fn assert_complete_shadow_with_budget(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    path: &str,
    source: &str,
    spelling: &str,
    expected_source: &str,
    budget: ReceiverAnalysisBudget,
) {
    let native = shadow_results(fixture, analyzer, path, source, spelling, budget);
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("Rust module-system point must complete for {path}:{spelling}: {native:#?}")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].source().rel_path(),
        Path::new(expected_source),
        "unexpected definition for {path}:{spelling}: {definitions:#?}"
    );
}

fn assert_complete_native_at_range(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    path: &str,
    source: &str,
    spelling: &str,
    expected_source: &str,
    expected_range: Range,
) {
    let native = shadow_results(
        fixture,
        analyzer,
        path,
        source,
        spelling,
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("Rust module-system point must complete for {path}:{spelling}: {native:#?}")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].source().rel_path(),
        Path::new(expected_source)
    );
    assert_eq!(analyzer.ranges(&definitions[0]), vec![expected_range]);
}

fn assert_complete_shadow_at_range(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    path: &str,
    source: &str,
    reference_start: usize,
    expected_source: &str,
    expected_range: Range,
) {
    let start_line = source[..reference_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let site = ResolvedReferenceSite {
        path: path.to_string(),
        text: "target".to_string(),
        range: Range {
            start_byte: reference_start,
            end_byte: reference_start + "target".len(),
            start_line,
            end_line: start_line,
        },
        focus_start_byte: reference_start,
        focus_end_byte: reference_start + "target".len(),
    };
    let native = shadow_results_at_site(
        fixture,
        analyzer,
        source,
        site,
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("chained-let target reference must complete")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].source().rel_path(),
        Path::new(expected_source)
    );
    assert_eq!(analyzer.ranges(&definitions[0]), vec![expected_range]);
}

fn shadow_results(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    path: &str,
    source: &str,
    spelling: &str,
    budget: ReceiverAnalysisBudget,
) -> RustDefinitionShadowResult {
    let site = reference_site(path, source, spelling);
    shadow_results_at_site(fixture, analyzer, source, site, budget)
}

fn shadow_results_at_site(
    fixture: &BuiltInlineTestProject,
    analyzer: &RustAnalyzer,
    source: &str,
    site: ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
) -> RustDefinitionShadowResult {
    let file = fixture.file(&site.path);
    let tree = rust_tree(source);
    let query = BoundedReceiverQuery {
        analyzer,
        file: &file,
        source,
        tree: Some(&tree),
        site: &site,
        budget,
        cancellation: None,
    };
    selected_rust_definition_shadow_result(analyzer, query)
}

#[test]
fn production_rust_module_gate_matches_structure_imports_reexports_and_visibility() {
    let lib_source = concat!(
        "pub mod outer;\n",
        "mod consumer;\n",
        "mod inline_host {\n",
        "    pub mod nested {\n",
        "        pub fn inline_direct_target() {}\n",
        "        pub fn inline_direct_caller() { inline_direct_target(); }\n",
        "    }\n",
        "}\n",
        "pub use outer::named_target as root_named_reexport;\n",
        "pub use outer::*;\n",
    );
    let outer_source = concat!(
        "pub mod nested;\n",
        "pub use nested::public_target as named_target;\n",
        "pub use nested::*;\n",
        "pub mod child;\n",
        "pub(crate) mod crate_scope;\n",
        "pub(super) mod super_scope;\n",
        "pub(in crate::outer) mod outer_scope;\n",
        "pub(self) mod self_scope;\n",
        "mod private_scope;\n",
    );
    let nested_source = concat!(
        "pub fn public_target() {}\n",
        "pub fn wildcard_target() {}\n",
        "pub fn crate_visible() {}\n",
        "pub fn parent_visible() {}\n",
        "pub fn outer_only() {}\n",
        "pub fn self_only() {}\n",
        "pub fn private_only() {}\n",
        "pub fn local_visibility_caller() { self_only(); private_only(); }\n",
    );
    let consumer_source = concat!(
        "use crate::outer::named_target as named_import;\n",
        "use crate::outer::*;\n",
        "use crate::outer::nested::{crate_visible, parent_visible};\n",
        "use crate::outer::crate_scope::crate_scope_target;\n",
        "use crate::outer::super_scope::super_scope_target;\n",
        "use crate::root_named_reexport as named_reexport_import;\n",
        "use crate::wildcard_target as wildcard_reexport_import;\n",
        "fn wildcard_target() {}\n",
        "pub fn named_import_caller() { named_import(); }\n",
        "pub fn wildcard_import_caller() { public_target(); }\n",
        "pub fn local_precedence_caller() { wildcard_target(); }\n",
        "pub fn crate_visibility_caller() { crate_visible(); }\n",
        "pub fn parent_visibility_caller() { parent_visible(); }\n",
        "pub fn crate_scope_caller() { crate_scope_target(); }\n",
        "pub fn super_scope_caller() { super_scope_target(); }\n",
        "pub fn named_reexport_caller() { named_reexport_import(); }\n",
        "pub fn wildcard_reexport_caller() { wildcard_reexport_import(); }\n",
    );
    let child_source = concat!(
        "use super::nested::outer_only as restricted_alias;\n",
        "use super::outer_scope::outer_scope_target;\n",
        "use super::self_scope::self_scope_target;\n",
        "use super::private_scope::private_scope_target;\n",
        "pub fn restricted_caller() { restricted_alias(); }\n",
        "pub fn outer_scope_caller() { outer_scope_target(); }\n",
        "pub fn self_scope_caller() { self_scope_target(); }\n",
        "pub fn private_scope_caller() { private_scope_target(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"module_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/outer.rs", outer_source)
        .file("src/outer/nested.rs", nested_source)
        .file("src/outer/child.rs", child_source)
        .file(
            "src/outer/crate_scope.rs",
            "pub fn crate_scope_target() {}\n",
        )
        .file(
            "src/outer/super_scope.rs",
            "pub fn super_scope_target() {}\n",
        )
        .file(
            "src/outer/outer_scope.rs",
            "pub fn outer_scope_target() {}\n",
        )
        .file("src/outer/self_scope.rs", "pub fn self_scope_target() {}\n")
        .file(
            "src/outer/private_scope.rs",
            "pub fn private_scope_target() {}\n",
        )
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());

    for (path, source, spelling, expected_source) in [
        (
            "src/lib.rs",
            lib_source,
            "inline_direct_target",
            "src/lib.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "named_import",
            "src/outer/nested.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "public_target",
            "src/outer/nested.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "wildcard_target",
            "src/consumer.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "crate_visible",
            "src/outer/nested.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "parent_visible",
            "src/outer/nested.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "crate_scope_target",
            "src/outer/crate_scope.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "super_scope_target",
            "src/outer/super_scope.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "named_reexport_import",
            "src/outer/nested.rs",
        ),
        (
            "src/consumer.rs",
            consumer_source,
            "wildcard_reexport_import",
            "src/outer/nested.rs",
        ),
        (
            "src/outer/child.rs",
            child_source,
            "restricted_alias",
            "src/outer/nested.rs",
        ),
        (
            "src/outer/nested.rs",
            nested_source,
            "self_only",
            "src/outer/nested.rs",
        ),
        (
            "src/outer/nested.rs",
            nested_source,
            "private_only",
            "src/outer/nested.rs",
        ),
        (
            "src/outer/child.rs",
            child_source,
            "outer_scope_target",
            "src/outer/outer_scope.rs",
        ),
        (
            "src/outer/child.rs",
            child_source,
            "self_scope_target",
            "src/outer/self_scope.rs",
        ),
        (
            "src/outer/child.rs",
            child_source,
            "private_scope_target",
            "src/outer/private_scope.rs",
        ),
    ] {
        assert_complete_shadow(&fixture, &analyzer, path, source, spelling, expected_source);
    }
}

#[test]
fn production_rust_module_gate_matches_mutually_dependent_modules() {
    let lib_source = "mod cycle_a;\nmod cycle_b;\n";
    let cycle_a_source = concat!(
        "use crate::cycle_b::right_target as right_from_cycle;\n",
        "pub fn left_target() {}\n",
        "pub fn call_right() { right_from_cycle(); }\n",
    );
    let cycle_b_source = concat!(
        "use crate::cycle_a::left_target as left_from_cycle;\n",
        "pub fn right_target() {}\n",
        "pub fn call_left() { left_from_cycle(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"cycle_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/cycle_a.rs", cycle_a_source)
        .file("src/cycle_b.rs", cycle_b_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/cycle_a.rs",
        cycle_a_source,
        "right_from_cycle",
        "src/cycle_b.rs",
    );
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/cycle_b.rs",
        cycle_b_source,
        "left_from_cycle",
        "src/cycle_a.rs",
    );
}

#[test]
fn production_rust_module_gate_matches_external_file_nested_in_inline_module() {
    let lib_source = concat!(
        "mod inline { pub mod leaf; }\n",
        "use crate::inline::leaf::target as imported;\n",
        "pub fn caller() { imported(); }\n",
    );
    let leaf_source = "pub fn target() {}\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_external_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/inline/leaf.rs", leaf_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/lib.rs",
        lib_source,
        "imported",
        "src/inline/leaf.rs",
    );
}

#[test]
fn production_rust_module_gate_bridges_public_items_in_inline_modules() {
    let lib_source = "pub mod inline { pub fn target() {} }\nmod consumer;\n";
    let consumer_source =
        "use crate::inline::target as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_item_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        "src/lib.rs",
    );
}

#[test]
fn production_rust_module_gate_does_not_leak_exports_between_inline_siblings() {
    let lib_source = concat!(
        "pub mod left { pub fn only_left() {} }\n",
        "pub mod right {}\n",
        "mod consumer;\n",
    );
    let consumer_source =
        "use crate::right::only_left as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_sibling_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("the missing sibling export must complete without a definition")
    };
    assert_eq!(status, DefinitionLookupStatus::NoDefinition);
    assert!(definitions.is_empty());
}

#[test]
fn production_rust_trait_impl_body_reference_resolves_lexically() {
    let source = concat!(
        "fn target() {}\n",
        "struct Service;\n",
        "trait Contract { fn method(&self); }\n",
        "impl Contract for Service {\n",
        "    fn method(&self) { target(); }\n",
        "}\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"skipped_impl_reference\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "target",
        ReceiverAnalysisBudget::default(),
    );

    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("enumerated trait impl call must resolve: {native:#?}")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(analyzer.ranges(&definitions[0])[0].start_line, 1);
}

#[test]
fn production_rust_inherent_impl_body_references_resolve_lexically() {
    let source = concat!(
        "fn target() {}\n",
        "struct Service;\n",
        "impl Service { fn first(&self) { target(); } }\n",
        "impl Service { fn second() { target(); } }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inherent_lexical\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let target = analyzer
        .all_declarations()
        .find(|unit| unit.identifier() == "target")
        .expect("free target declaration");
    for (start_byte, _) in source.match_indices("target();") {
        let mut site = reference_site("src/lib.rs", source, "target");
        site.range.start_byte = start_byte;
        site.range.end_byte = start_byte + "target".len();
        site.range.start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        site.range.end_line = site.range.start_line;
        site.focus_start_byte = site.range.start_byte;
        site.focus_end_byte = site.range.end_byte;
        let native = shadow_results_at_site(
            &fixture,
            &analyzer,
            source,
            site,
            ReceiverAnalysisBudget::default(),
        );
        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = native
        else {
            panic!("retained inherent body must resolve its local free call: {native:?}")
        };
        assert_eq!(status, DefinitionLookupStatus::Resolved);
        assert_eq!(definitions, vec![target.clone()]);
    }
}

#[test]
fn production_rust_inherent_self_type_observation_resolves_nominal_definition() {
    let source = concat!(
        "fn target() {}\n",
        "struct Service;\n",
        "impl Service { fn typed(self: Box<Self>) -> Self { target(); *self } }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inherent_self_type\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    for (start_byte, _) in source.match_indices("Self") {
        let mut site = reference_site("src/lib.rs", source, "Self");
        site.range.start_byte = start_byte;
        site.range.end_byte = start_byte + "Self".len();
        site.focus_start_byte = site.range.start_byte;
        site.focus_end_byte = site.range.end_byte;
        let self_type = shadow_results_at_site(
            &fixture,
            &analyzer,
            source,
            site,
            ReceiverAnalysisBudget::default(),
        );
        // The transfer-owned occurrence exposes the implementing nominal definition.
        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = self_type
        else {
            panic!("an impl-scope Self occurrence resolves without uncertainty: {self_type:?}")
        };
        assert_eq!(status, DefinitionLookupStatus::Resolved);
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].identifier(), "Service");
    }
    let local_call = shadow_results(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "target",
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = local_call
    else {
        panic!("the Self alias must not poison the free call: {local_call:?}")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[0].identifier(), "target");
}

#[test]
fn production_rust_nested_inherent_impl_does_not_invent_a_callable_crosswalk() {
    let source = concat!(
        "fn target() {}\n",
        "struct Service;\n",
        "fn outer() { impl Service { fn nested(&self) { target(); } } }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"nested_impl_boundary\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert!(
        !analyzer
            .all_declarations()
            .any(|unit| unit.identifier() == "nested"),
        "this fixture deliberately crosses the production parser-unit boundary"
    );
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "target",
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("the enumerated nested body resolves its free call: {native:?}");
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[0].identifier(), "target");
}

#[test]
fn production_rust_inherent_calls_do_not_bind_a_free_function_decoy() {
    let source = concat!(
        "fn method() {}\n",
        "struct Service;\n",
        "impl Service {\n",
        "    fn method(&self) {}\n",
        "}\n",
        "fn caller(service: Service) {\n",
        "    Service::method(&service);\n",
        "    service.method();\n",
        "}\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"skipped_impl_calls\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let inherent_method = analyzer
        .all_declarations()
        .find(|unit| unit.identifier() == "method" && unit.owner_identifier() == Some("Service"))
        .expect("the inherent method declaration is projectable");
    let method_site = |start_byte| {
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        ResolvedReferenceSite {
            path: "src/lib.rs".to_string(),
            text: "method".to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + "method".len(),
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "method".len(),
        }
    };
    let static_start = source
        .find("Service::method")
        .expect("associated-call terminal")
        + "Service::".len();
    let receiver_start = source
        .find("service.method")
        .expect("receiver-call terminal")
        + "service.".len();

    for (label, site) in [
        ("type-qualified", method_site(static_start)),
        ("receiver-qualified", method_site(receiver_start)),
    ] {
        let native = shadow_results_at_site(
            &fixture,
            &analyzer,
            source,
            site,
            ReceiverAnalysisBudget::default(),
        );
        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = native
        else {
            panic!("{label} inherent call must resolve its exact method: {native:#?}");
        };
        assert_eq!(status, DefinitionLookupStatus::Resolved);
        assert_eq!(
            definitions,
            vec![inherent_method.clone()],
            "{label} call must not bind the same-named free function"
        );
    }
}

#[test]
fn production_rust_module_gate_expands_modules_declared_by_included_content() {
    let lib_source = "include!(\"shared.rs\");\nmod consumer;\n";
    let shared_source = "pub mod nested { pub fn target() {} }\n";
    let consumer_source =
        "use crate::nested::target as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"included_inline_module\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/shared.rs", shared_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        ReceiverAnalysisBudget::default(),
    );
    let definitions = match native {
        RustDefinitionShadowResult::Complete { definitions, .. }
        | RustDefinitionShadowResult::Incomplete { definitions, .. } => definitions,
        other => panic!("included inline target must be recovered: {other:#?}"),
    };
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].source().rel_path(),
        Path::new("src/shared.rs")
    );
    let declaration = "pub fn target() {}";
    let start_byte = shared_source
        .find(declaration)
        .expect("included target declaration");
    assert_eq!(
        analyzer.ranges(&definitions[0]),
        vec![Range {
            start_byte,
            end_byte: start_byte + declaration.len(),
            start_line: 1,
            end_line: 1,
        }]
    );
}

#[test]
fn production_rust_module_gate_selects_exact_same_named_inline_sibling() {
    let lib_source = concat!(
        "pub mod left {\n",
        "    pub fn target() {}\n",
        "}\n",
        "pub mod right {\n",
        "    pub fn target() {}\n",
        "}\n",
        "mod consumer;\n",
    );
    let consumer_source = concat!(
        "use crate::left::target as left_target;\n",
        "use crate::right::target as right_target;\n",
        "pub fn caller() { left_target(); right_target(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_sibling_exact\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let declaration = "pub fn target() {}";
    let left_start = lib_source
        .find(declaration)
        .expect("left target declaration");
    let right_start = lib_source
        .rfind(declaration)
        .expect("right target declaration");

    for (spelling, start_byte, line) in [
        ("left_target", left_start, 2),
        ("right_target", right_start, 5),
    ] {
        assert_complete_native_at_range(
            &fixture,
            &analyzer,
            "src/consumer.rs",
            consumer_source,
            spelling,
            "src/lib.rs",
            Range {
                start_byte,
                end_byte: start_byte + declaration.len(),
                start_line: line,
                end_line: line,
            },
        );
    }
}

#[test]
fn production_rust_module_gate_attaches_inline_imports_and_reexports_exactly() {
    let lib_source = concat!(
        "pub fn target() {}\n",
        "pub fn decoy() {}\n",
        "pub mod left {\n",
        "    use super::target as local;\n",
        "    pub use super::target as exposed;\n",
        "    pub fn left_caller() { local(); }\n",
        "}\n",
        "pub mod right {\n",
        "    use super::decoy as local;\n",
        "    pub fn right_caller() { local(); }\n",
        "}\n",
        "mod consumer;\n",
    );
    let consumer_source =
        "use crate::left::exposed as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_import_exact\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let target_declaration = "pub fn target() {}";
    let decoy_declaration = "pub fn decoy() {}";
    let target_start = lib_source
        .find(target_declaration)
        .expect("root target declaration");
    let decoy_start = lib_source
        .find(decoy_declaration)
        .expect("root decoy declaration");
    let left_call = lib_source
        .find("local();")
        .expect("left local import reference");
    let right_call = lib_source
        .rfind("local();")
        .expect("right local import reference");

    for (reference_start, expected_start, expected_text, expected_line) in [
        (left_call, target_start, target_declaration, 1),
        (right_call, decoy_start, decoy_declaration, 2),
    ] {
        let reference_line = lib_source[..reference_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let native = shadow_results_at_site(
            &fixture,
            &analyzer,
            lib_source,
            ResolvedReferenceSite {
                path: "src/lib.rs".to_string(),
                text: "local".to_string(),
                range: Range {
                    start_byte: reference_start,
                    end_byte: reference_start + "local".len(),
                    start_line: reference_line,
                    end_line: reference_line,
                },
                focus_start_byte: reference_start,
                focus_end_byte: reference_start + "local".len(),
            },
            ReceiverAnalysisBudget::default(),
        );
        let RustDefinitionShadowResult::Complete {
            status,
            definitions,
            ..
        } = native
        else {
            panic!("inline import reference must complete")
        };
        assert_eq!(status, DefinitionLookupStatus::Resolved);
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].source().rel_path(), Path::new("src/lib.rs"));
        assert_eq!(
            analyzer.ranges(&definitions[0]),
            vec![Range {
                start_byte: expected_start,
                end_byte: expected_start + expected_text.len(),
                start_line: expected_line,
                end_line: expected_line,
            }]
        );
    }

    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        "src/lib.rs",
        Range {
            start_byte: target_start,
            end_byte: target_start + target_declaration.len(),
            start_line: 1,
            end_line: 1,
        },
    );
}

#[test]
fn production_rust_module_gate_matches_chained_let_operands_and_bodies() {
    let source = concat!(
        "pub fn target() -> bool { true }\n",
        "pub fn if_chain(value: Option<u8>) {\n",
        "    if let Some(value) = value && target() {\n",
        "        target();\n",
        "    }\n",
        "}\n",
        "pub fn while_chain(mut value: Option<u8>) {\n",
        "    while let Some(value) = value && target() {\n",
        "        target();\n",
        "        value = None;\n",
        "    }\n",
        "}\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"chained_let_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let declaration = "pub fn target() -> bool { true }";
    let declaration_start = source.find(declaration).expect("target declaration");
    let expected_range = Range {
        start_byte: declaration_start,
        end_byte: declaration_start + declaration.len(),
        start_line: 1,
        end_line: 1,
    };

    for (reference_start, _) in source.match_indices("target()").skip(1) {
        assert_complete_shadow_at_range(
            &fixture,
            &analyzer,
            "src/lib.rs",
            source,
            reference_start,
            "src/lib.rs",
            expected_range,
        );
    }
}

#[test]
fn production_rust_module_gate_attaches_inline_glob_reexports_exactly() {
    let lib_source = concat!(
        "pub mod source { pub fn target() {} }\n",
        "pub mod inline {\n",
        "    pub use super::source::*;\n",
        "    pub fn inline_caller() { target(); }\n",
        "}\n",
        "mod consumer;\n",
    );
    let consumer_source =
        "use crate::inline::target as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"inline_glob_exact\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let declaration = "pub fn target() {}";
    let target_start = lib_source
        .find(declaration)
        .expect("glob source declaration");
    let target_range = Range {
        start_byte: target_start,
        end_byte: target_start + declaration.len(),
        start_line: 1,
        end_line: 1,
    };

    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/lib.rs",
        lib_source,
        "target",
        "src/lib.rs",
        target_range,
    );
    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        "src/lib.rs",
        target_range,
    );
}

#[test]
fn production_rust_module_gate_matches_public_external_file_nested_in_inline_module() {
    let app_source = concat!(
        "use engine::inline::leaf::target as imported;\n",
        "pub fn caller() { imported(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "app/Cargo.toml",
            concat!(
                "[package]\n",
                "name = \"inline_app\"\n",
                "version = \"0.1.0\"\n",
                "edition = \"2024\"\n",
                "[dependencies]\n",
                "engine = { path = \"../engine\" }\n",
            ),
        )
        .file(
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("app/src/lib.rs", app_source)
        .file("engine/src/lib.rs", "pub mod inline { pub mod leaf; }\n")
        .file("engine/src/inline/leaf.rs", "pub fn target() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "app/src/lib.rs",
        app_source,
        "imported",
        "engine/src/inline/leaf.rs",
    );
}

#[test]
fn production_rust_module_gate_anchors_modern_leading_absolute_imports_to_dependencies() {
    let app_source = concat!(
        "mod engine;\n",
        "use ::engine::{target as imported};\n",
        "pub fn caller() { imported(); }\n",
    );
    let dependency_source = "pub fn target() {}\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "app/Cargo.toml",
            concat!(
                "[package]\n",
                "name = \"absolute_app\"\n",
                "version = \"0.1.0\"\n",
                "edition = \"2024\"\n",
                "[dependencies]\n",
                "engine = { path = \"../engine\" }\n",
            ),
        )
        .file(
            "engine/Cargo.toml",
            "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("app/src/lib.rs", app_source)
        .file("app/src/engine.rs", "pub fn target() {}\n")
        .file("engine/src/lib.rs", dependency_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "app/src/lib.rs",
        app_source,
        "imported",
        "engine/src/lib.rs",
        Range {
            start_byte: 0,
            end_byte: dependency_source.trim_end().len(),
            start_line: 1,
            end_line: 1,
        },
    );
}

#[test]
fn production_rust_module_gate_matches_restricted_inline_module_within_crate() {
    let lib_source = "pub(super) mod inline { pub mod leaf; }\nmod consumer;\n";
    let consumer_source =
        "use crate::inline::leaf::target as imported;\npub fn caller() { imported(); }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"restricted_inline\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .file("src/inline/leaf.rs", "pub fn target() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "imported",
        "src/inline/leaf.rs",
    );
}

#[test]
fn production_rust_module_gate_matches_large_wildcard_fan_in() {
    let mut lib_source = String::from("mod consumer;\n");
    let consumer_source = "use crate::*;\npub fn fan_in_caller() { fan_target_31(); }\n";
    let mut project = InlineTestProject::with_language(Language::Rust).file(
        "Cargo.toml",
        "[package]\nname = \"fan_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    for index in 0..32 {
        lib_source.push_str(&format!(
            "mod leaf_{index:02};\npub use leaf_{index:02}::*;\n"
        ));
        project = project.file(
            format!("src/leaf_{index:02}.rs"),
            format!("pub fn fan_target_{index:02}() {{}}\n"),
        );
    }
    let fixture = project
        .file("src/lib.rs", lib_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow_with_budget(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        "fan_target_31",
        "src/leaf_31.rs",
        ReceiverAnalysisBudget {
            max_scope_nodes: 200_000,
            ..Default::default()
        },
    );
}

#[test]
fn production_rust_module_gate_matches_rust_2015_crate_root_imports() {
    let source = concat!(
        "mod model;\n",
        "use model::edition_target as imported_2015_target;\n",
        "pub fn caller() { imported_2015_target(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            concat!(
                "[package]\n",
                "name = \"edition_gate\"\n",
                "version = \"0.1.0\"\n",
                "edition = \"2015\"\n",
            ),
        )
        .file("src/lib.rs", source)
        .file("src/model.rs", "pub fn edition_target() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "imported_2015_target",
        "src/model.rs",
    );
}

#[test]
fn production_rust_module_gate_anchors_rust_2015_leading_absolute_imports_to_crate_root() {
    let source = concat!(
        "mod root_model;\n",
        "use ::root_model::{target as imported_2015_absolute};\n",
        "pub fn caller() { imported_2015_absolute(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            concat!(
                "[package]\n",
                "name = \"absolute_edition_gate\"\n",
                "version = \"0.1.0\"\n",
                "edition = \"2015\"\n",
            ),
        )
        .file("src/lib.rs", source)
        .file("src/root_model.rs", "pub fn target() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "imported_2015_absolute",
        "src/root_model.rs",
    );
}

#[test]
fn production_rust_module_gate_anchors_nested_rust_2015_imports_exactly() {
    let lib_source = concat!(
        "mod root_model;\n",
        "mod outer {\n",
        "    mod child { pub fn target() {} }\n",
        "    use root_model::target as root_imported;\n",
        "    use self::child::target as child_imported;\n",
        "    pub fn caller() { root_imported(); child_imported(); }\n",
        "}\n",
    );
    let root_model_source = "pub fn target() {}\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            concat!(
                "[package]\n",
                "name = \"nested_edition_gate\"\n",
                "version = \"0.1.0\"\n",
                "edition = \"2015\"\n",
            ),
        )
        .file("src/lib.rs", lib_source)
        .file("src/root_model.rs", root_model_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let declaration = "pub fn target() {}";
    let child_start = lib_source
        .find(declaration)
        .expect("nested child declaration");

    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/lib.rs",
        lib_source,
        "root_imported",
        "src/root_model.rs",
        Range {
            start_byte: 0,
            end_byte: declaration.len(),
            start_line: 1,
            end_line: 1,
        },
    );
    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/lib.rs",
        lib_source,
        "child_imported",
        "src/lib.rs",
        Range {
            start_byte: child_start,
            end_byte: child_start + declaration.len(),
            start_line: 3,
            end_line: 3,
        },
    );
}

#[test]
fn production_rust_qualified_module_calls_use_the_selected_route() {
    for route in ["crate::left", "self::left"] {
        let source = format!(
            "pub mod left;\npub mod right;\nfn target() {{}}\nfn caller() {{ target(); {route}::target(); }}\n"
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"qualified_route\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", &source)
            .file("src/left.rs", "pub fn target() {}\n")
            .file("src/right.rs", "pub fn target() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_complete_shadow(
            &fixture,
            &analyzer,
            "src/lib.rs",
            &source,
            "target",
            "src/left.rs",
        );
        let local_end = source.find("target();").unwrap() + "target".len();
        let site = reference_site("src/lib.rs", &source[..local_end], "target");
        let native = shadow_results_at_site(
            &fixture,
            &analyzer,
            &source,
            site,
            ReceiverAnalysisBudget::default(),
        );
        let RustDefinitionShadowResult::Complete { definitions, .. } = native else {
            panic!("an explicit module route must not contaminate the unqualified call");
        };
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].source().rel_path(), Path::new("src/lib.rs"));
    }
}

#[test]
fn production_rust_root_reference_absence_and_unknown_routes_stay_local() {
    for (qualified, spelling, closed) in [
        ("crate::left::missing", "missing", true),
        ("crate::left::hidden", "hidden", true),
        ("crate::unknown::missing", "missing", true),
        ("crate::conditional::missing", "missing", false),
    ] {
        let source = format!(
            "pub mod left;\n#[cfg(unknown_configuration)] mod conditional {{}}\nfn target() {{}}\nfn caller() {{ {qualified}(); target(); }}\n"
        );
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"qualified_gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", &source)
            .file("src/left.rs", "fn hidden() {}\n")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        assert_complete_shadow(
            &fixture,
            &analyzer,
            "src/lib.rs",
            &source,
            "target",
            "src/lib.rs",
        );
        let native = shadow_results(
            &fixture,
            &analyzer,
            "src/lib.rs",
            &source,
            spelling,
            ReceiverAnalysisBudget::default(),
        );
        if closed {
            assert!(
                matches!(native, RustDefinitionShadowResult::Complete {
                status: DefinitionLookupStatus::NoDefinition, ref definitions, ..
            } if definitions.is_empty()),
                "a closed module proves absence without leaking a private declaration: {native:#?}"
            );
        } else {
            assert!(
                matches!(native, RustDefinitionShadowResult::Incomplete { ref definitions, .. } if definitions.is_empty()),
                "an unknown module route cannot certify absence: {native:#?}"
            );
        }
    }
}

#[test]
fn production_rust_root_references_preserve_nested_module_anchors() {
    let source = "pub mod left { pub fn target() {} }\nmod nested { fn caller() { super::left::target(); } }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", "[package]\nname = \"nested_root_reference\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_shadow(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "target",
        "src/lib.rs",
    );
}

#[test]
fn production_rust_root_reference_absolute_terminal_uses_2015_crate_root() {
    let source = "pub fn target() {}\nmod nested { fn caller() { ::target(); } }\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"absolute_terminal\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
        )
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    // Rust 2015 resolves this from the crate root.
    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "target",
        "src/lib.rs",
        Range {
            start_byte: 0,
            end_byte: "pub fn target() {}".len(),
            start_line: 1,
            end_line: 1,
        },
    );
}

#[test]
fn production_rust_root_references_preserve_absolute_dependency_anchor() {
    let source = "mod engine;\nfn caller() { ::engine::target(); }\n";
    let dependency = "pub fn target() {}\n";
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("app/Cargo.toml", "[package]\nname = \"absolute_reference\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nengine = { path = \"../engine\" }\n")
        .file("engine/Cargo.toml", "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")
        .file("app/src/lib.rs", source)
        .file("app/src/engine.rs", "pub fn target() {}\n")
        .file("engine/src/lib.rs", dependency)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    assert_complete_native_at_range(
        &fixture,
        &analyzer,
        "app/src/lib.rs",
        source,
        "target",
        "engine/src/lib.rs",
        Range {
            start_byte: 0,
            end_byte: dependency.trim_end().len(),
            start_line: 1,
            end_line: 1,
        },
    );
}

#[test]
fn production_rust_module_qualified_paths_prove_absence() {
    let source = concat!(
        "mod model;\n",
        "pub fn callable_caller() { model::missing_qualified_target(); }\n",
        "pub fn type_caller(_: model::MissingQualifiedType) {}\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"qualified_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .file("src/model.rs", "pub fn unrelated() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());

    for spelling in ["missing_qualified_target", "MissingQualifiedType"] {
        let native = shadow_results(
            &fixture,
            &analyzer,
            "src/lib.rs",
            source,
            spelling,
            ReceiverAnalysisBudget::default(),
        );
        // A module is not a type, so its prefix adds no member lookup, and
        // the module route, which enumerates `model`'s items, proves the
        // absence.
        assert!(
            matches!(native, RustDefinitionShadowResult::Complete {
                status: DefinitionLookupStatus::NoDefinition, ref definitions, ..
            } if definitions.is_empty()),
            "qualified {spelling} names nothing the module declares: {native:#?}"
        );
    }
}

#[test]
fn production_rust_cfg_boundaries_distinguish_disabled_and_unknown_modules() {
    let source = concat!(
        "#[cfg(test)] mod disabled;\n",
        "mod enabled;\n",
        "use enabled::enabled_target as enabled_call;\n",
        "pub fn enabled_caller() { enabled_call(); }\n",
        "pub fn disabled_surface_caller() { disabled_surface_target(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"cfg_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", source)
        .file("src/enabled.rs", "pub fn enabled_target() {}\n")
        .file("src/disabled.rs", "pub fn disabled_target() {}\n")
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "enabled_call",
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Incomplete { definitions, .. } = native else {
        panic!("the inactive module route remains an explicit lexical boundary")
    };
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        definitions[0].source().rel_path(),
        Path::new("src/enabled.rs")
    );
    let native = shadow_results(
        &fixture,
        &analyzer,
        "src/lib.rs",
        source,
        "disabled_surface_target",
        ReceiverAnalysisBudget::default(),
    );
    assert!(
        matches!(
            &native,
            RustDefinitionShadowResult::Incomplete { definitions, .. } if definitions.is_empty()
        ),
        "unexpected native cfg-disabled result: {native:#?}"
    );
    let unknown_source = concat!(
        "#[cfg(test)]\n",
        "#[cfg(feature = \"left\")]\n",
        "mod uncertain;\n",
        "use uncertain::unknown_target as unknown_call;\n",
        "pub fn caller() { unknown_call(); }\n",
    );
    let unknown_fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"unknown_cfg_gate\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", unknown_source)
        .build();
    let unknown_analyzer = RustAnalyzer::new(unknown_fixture.project_dyn());
    let native = shadow_results(
        &unknown_fixture,
        &unknown_analyzer,
        "src/lib.rs",
        unknown_source,
        "unknown_call",
        ReceiverAnalysisBudget::default(),
    );
    assert!(
        matches!(
            &native,
            RustDefinitionShadowResult::Incomplete { definitions, .. } if definitions.is_empty()
        ),
        "unexpected native unknown-cfg result: {native:#?}"
    );
}

#[test]
fn production_rust_macro_and_include_surfaces_remain_explicit_boundaries() {
    let cases = [
        (
            // The macro has no `macro_rules!` anywhere, so its expansion is
            // undecidable and the module's export inventory stays open. A
            // visible definition would decide it: a proven item passthrough
            // expands to the arguments declaration replay already indexed, and
            // a visible definition that is not one contributes no items, so
            // neither is a boundary. `rust_crate_item_macro_decisions.sql`
            // states that rule.
            "item_macro_gate",
            concat!(
                "opaque_items!(pub fn generated() {});\n",
                "pub fn caller() { item_macro_surface_target(); }\n",
            ),
            "item_macro_surface_target",
            None,
        ),
        (
            "procedural_attribute_gate",
            concat!(
                "#[runtime::entry]\n",
                "pub fn transformed_source() {}\n",
                "pub fn caller() { attribute_surface_target(); }\n",
            ),
            "attribute_surface_target",
            None,
        ),
        (
            "missing_include_gate",
            concat!(
                "include!(\"missing.rs\");\n",
                "pub fn caller() { include_surface_target(); }\n",
            ),
            "include_surface_target",
            Some(("src/included.rs", "pub fn unrelated_included_item() {}\n")),
        ),
    ];
    for (package, source, spelling, included) in cases {
        let manifest =
            format!("[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n");
        let mut project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest)
            .file("src/lib.rs", source);
        if let Some((path, included_source)) = included {
            project = project.file(path, included_source);
        }
        let fixture = project.build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let native = shadow_results(
            &fixture,
            &analyzer,
            "src/lib.rs",
            source,
            spelling,
            ReceiverAnalysisBudget::default(),
        );
        assert!(
            matches!(
                &native,
                RustDefinitionShadowResult::Incomplete { definitions, .. } if definitions.is_empty()
            ),
            "unexpected native {package}:{spelling} result: {native:#?}"
        );
    }
}

#[test]
fn canonical_rust_occurrences_are_shared_by_native_structural_and_declaration_projections() {
    let source = concat!(
        "pub struct Service;\nimpl Service { fn method(&self) {} }\n",
        "pub fn target() {}\npub fn caller(target: usize) { crate::target(); }\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("src/first.rs", source)
        .file("src/second.rs", source)
        .build();
    let parse = |path| {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        brokk_bifrost_rust::declarations::parse_rust_file(&fixture.file(path), source, &tree)
    };
    let first = parse("src/first.rs");
    let second = parse("src/second.rs");
    let first_source = first
        .source_facts
        .as_ref()
        .expect("canonical Rust source facts");
    let second_source = second
        .source_facts
        .as_ref()
        .expect("canonical Rust source facts");
    assert_eq!(first_source.occurrences, second_source.occurrences);
    assert_eq!(
        first_source.native_site_occurrences,
        second_source.native_site_occurrences
    );
    assert_eq!(
        first
            .source_declaration_units
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        second
            .source_declaration_units
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
    );
    for ((_, first_unit), (_, second_unit)) in first
        .source_declaration_units
        .iter()
        .zip(&second.source_declaration_units)
    {
        assert_ne!(
            first_unit, second_unit,
            "mount identity must remain distinct"
        );
    }

    let (caller_source, caller_unit) = first
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit.identifier() == "caller")
        .unwrap();
    let caller_native = first
        .resolution_facts
        .definition_units
        .iter()
        .find(|definition| &definition.unit == caller_unit)
        .unwrap()
        .declaration;
    assert_eq!(
        first_source
            .native_declaration_sources
            .iter()
            .find(|(site, _)| *site == caller_native)
            .unwrap()
            .1,
        *caller_source,
        "native and mounted declaration projections share one declaration handle",
    );
    let parameter = first
        .resolution_facts
        .binders
        .iter()
        .find(|binder| {
            binder.kind
                == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBinderKind::Parameter
                && first.resolution_facts.identifiers.iter().any(|identifier| {
                    identifier.site == binder.declaration
                        && first.resolution_facts.names[identifier.name.index()].spelling
                            == "target"
                })
        })
        .unwrap()
        .declaration;
    let parameter_source = first_source
        .native_declaration_sources
        .iter()
        .find(|(site, _)| *site == parameter)
        .unwrap()
        .1;
    let parameter_declaration = first_source.occurrences.declaration(parameter_source);
    assert_eq!(
        parameter_declaration.name,
        Some(first_source.native_site_occurrences[parameter.index()])
    );
    let parameter_range = first_source
        .occurrences
        .occurrence(parameter_declaration.occurrence)
        .range;
    assert_eq!(
        &source[parameter_range.start_byte..parameter_range.end_byte],
        "target: usize"
    );

    let call_name_start = source.rfind("target").unwrap();
    let native_site = first
        .resolution_facts
        .sites
        .iter()
        .find(|site| {
            site.start_byte == call_name_start && site.kind == ResolutionSiteKind::CallableReference
        })
        .expect("native call reference");
    let native_occurrence = first_source.native_site_occurrences[native_site.id.index()];
    let structural_occurrence = first_source
        .structural
        .nodes()
        .iter()
        .find(|node| {
            node.kind == NormalizedKind::Identifier
                && first_source
                    .occurrences
                    .occurrence(node.occurrence)
                    .range
                    .start_byte
                    == call_name_start
        })
        .expect("structural callee identifier")
        .occurrence;
    assert_eq!(native_occurrence, structural_occurrence);
    let range = first_source.occurrences.occurrence(native_occurrence).range;
    assert_eq!(
        (range.start_byte, range.end_byte),
        (native_site.start_byte, native_site.end_byte)
    );
}

#[test]
fn directive_3_milestone_1_rust_fact_baseline_records_declarations_shadowing_and_gaps() {
    let provider_source = "pub fn target() {}\n";
    let consumer_source = concat!(
        "pub fn caller(target: usize) {\n",
        "    let target = target;\n",
        "    let _ = target;\n",
        "    crate::provider::target();\n",
        "}\n",
        "trait Contract {\n",
        "    fn method(&self);\n",
        "}\n",
        "struct Service;\n",
        "impl Contract for Service {\n",
        "    fn method(&self) {\n",
        "        crate::provider::target();\n",
        "    }\n",
        "}\n",
    );
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"directive_3_baseline\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", "pub mod provider;\nmod consumer;\n")
        .file("src/provider.rs", provider_source)
        .file("src/consumer.rs", consumer_source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    let provider_file = fixture.file("src/provider.rs");
    let consumer_file = fixture.file("src/consumer.rs");

    let target = analyzer
        .declarations(&provider_file)
        .into_iter()
        .find(|unit| unit.identifier() == "target")
        .expect("provider target declaration");
    let caller = analyzer
        .declarations(&consumer_file)
        .into_iter()
        .find(|unit| unit.identifier() == "caller")
        .expect("consumer caller declaration");
    let provider_target_range = Range {
        start_byte: 0,
        end_byte: provider_source.trim_end().len(),
        start_line: 1,
        end_line: 1,
    };
    let caller_end = consumer_source
        .find("}\ntrait Contract")
        .expect("caller closing brace")
        + 1;
    let caller_range = Range {
        start_byte: 0,
        end_byte: caller_end,
        start_line: 1,
        end_line: 5,
    };
    assert_eq!(analyzer.ranges(&target), vec![provider_target_range]);
    assert_eq!(analyzer.ranges(&caller), vec![caller_range]);

    let structural_provider = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .expect("Rust structural provider");
    let facts = structural_provider
        .structural_facts(&consumer_file)
        .expect("consumer structural facts");
    assert_eq!(facts.source(), consumer_source);
    let provider_facts = structural_provider
        .structural_facts(&provider_file)
        .expect("provider structural facts");
    assert_eq!(provider_facts.source(), provider_source);
    assert!(provider_facts.nodes().iter().any(|node| {
        node.kind == NormalizedKind::Function
            && node.range == provider_target_range
            && node
                .name
                .is_some_and(|name| name.text(provider_facts.source()) == "target")
    }));

    let caller_fact = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == NormalizedKind::Function && node.range == caller_range)
        .map(|(id, _)| u32::try_from(id).expect("caller fact id fits in u32"))
        .expect("caller function fact");
    let parameter_start = consumer_source
        .find("caller(target")
        .expect("caller parameter")
        + "caller(".len();
    let parameter_range = Range {
        start_byte: parameter_start,
        end_byte: parameter_start + "target".len(),
        start_line: 1,
        end_line: 1,
    };
    let parameter_fact = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == NormalizedKind::Identifier && node.range == parameter_range)
        .map(|(id, _)| u32::try_from(id).expect("parameter fact id fits in u32"))
        .expect("parameter identifier fact");
    assert_eq!(facts.node(parameter_fact).parent, Some(caller_fact));
    assert_eq!(
        facts.occurrence_roles(parameter_fact),
        &[OccurrenceRole::Binder]
    );

    let local_start = consumer_source
        .find("let target = target;")
        .expect("local shadowing declaration")
        + "let ".len();
    let local_range = Range {
        start_byte: local_start,
        end_byte: local_start + "target".len(),
        start_line: 2,
        end_line: 2,
    };
    let local_statement_start = local_start - "let ".len();
    let local_statement_range = Range {
        start_byte: local_statement_start,
        end_byte: local_statement_start + "let target = target;".len(),
        start_line: 2,
        end_line: 2,
    };
    let local_assignment = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| {
            node.kind == NormalizedKind::Assignment && node.range == local_statement_range
        })
        .map(|(id, _)| u32::try_from(id).expect("local assignment fact id fits in u32"))
        .expect("local assignment fact");
    let local_fact = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == NormalizedKind::Identifier && node.range == local_range)
        .map(|(id, _)| u32::try_from(id).expect("local fact id fits in u32"))
        .expect("local binder fact");
    assert_eq!(facts.node(local_fact).parent, Some(local_assignment));
    assert_eq!(
        facts.occurrence_roles(local_fact),
        &[OccurrenceRole::Binder]
    );
    assert_eq!(
        facts
            .role_targets(local_assignment, Role::Left)
            .map(|target| target.span.text(facts.source()))
            .collect::<Vec<_>>(),
        vec!["target"]
    );

    let qualified_call = "crate::provider::target()";
    let qualified_call_start = consumer_source
        .find(qualified_call)
        .expect("caller crate-anchored call");
    let qualified_target_start = qualified_call_start + "crate::provider::".len();
    let qualified_call_range = Range {
        start_byte: qualified_call_start,
        end_byte: qualified_call_start + qualified_call.len(),
        start_line: 4,
        end_line: 4,
    };
    let call_fact = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == NormalizedKind::Call && node.range == qualified_call_range)
        .map(|(id, _)| u32::try_from(id).expect("call fact id fits in u32"))
        .expect("crate-anchored call fact");
    let caller_body = facts
        .node(call_fact)
        .parent
        .expect("crate-anchored call lexical block");
    assert_eq!(facts.node(caller_body).kind, NormalizedKind::Block);
    assert_eq!(facts.node(caller_body).parent, Some(caller_fact));
    let callee = facts
        .role_targets(call_fact, Role::Callee)
        .next()
        .expect("crate-anchored call callee role");
    assert_eq!(callee.span.start_byte, qualified_target_start);
    assert_eq!(callee.span.text(facts.source()), "target");

    // The parameter and local share the provider declaration's spelling, but the
    // explicit crate anchor still selects the declaration in the other file.
    assert_complete_shadow_at_range(
        &fixture,
        &analyzer,
        "src/consumer.rs",
        consumer_source,
        qualified_target_start,
        "src/provider.rs",
        provider_target_range,
    );

    // Trait implementation bodies retain the same lexical calls as free bodies.
    let unsupported_call_start = consumer_source
        .rfind(qualified_call)
        .expect("skipped trait implementation call");
    let unsupported_target_start = unsupported_call_start + "crate::provider::".len();
    let unsupported_call_range = Range {
        start_byte: unsupported_call_start,
        end_byte: unsupported_call_start + qualified_call.len(),
        start_line: 12,
        end_line: 12,
    };
    let unsupported_call_fact = facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| node.kind == NormalizedKind::Call && node.range == unsupported_call_range)
        .map(|(id, _)| u32::try_from(id).expect("unsupported call fact id fits in u32"))
        .expect("skipped trait call fact");
    let unsupported_owner = facts
        .node(unsupported_call_fact)
        .parent
        .expect("skipped trait call lexical block");
    assert_eq!(facts.node(unsupported_owner).kind, NormalizedKind::Block);
    let unsupported_method = facts
        .node(unsupported_owner)
        .parent
        .expect("skipped trait call lexical method");
    assert_eq!(facts.node(unsupported_method).kind, NormalizedKind::Method);
    let unsupported_site = ResolvedReferenceSite {
        path: "src/consumer.rs".to_string(),
        text: "target".to_string(),
        range: Range {
            start_byte: unsupported_target_start,
            end_byte: unsupported_target_start + "target".len(),
            start_line: 12,
            end_line: 12,
        },
        focus_start_byte: unsupported_target_start,
        focus_end_byte: unsupported_target_start + "target".len(),
    };
    let native = shadow_results_at_site(
        &fixture,
        &analyzer,
        consumer_source,
        unsupported_site,
        ReceiverAnalysisBudget::default(),
    );
    let RustDefinitionShadowResult::Complete {
        status,
        definitions,
        ..
    } = native
    else {
        panic!("enumerated trait impl call must resolve: {native:#?}")
    };
    assert_eq!(status, DefinitionLookupStatus::Resolved);
    assert_eq!(definitions.len(), 1);
    assert_eq!(
        analyzer.ranges(&definitions[0]),
        vec![provider_target_range]
    );
}
