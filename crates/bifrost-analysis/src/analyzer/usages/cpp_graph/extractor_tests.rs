//! The analyzer-bound half of [`brokk_bifrost_cpp::graph::extractor`]'s tests.
//!
//! See [`super::resolver_tests`] for why they stayed on this side of the seam.

use crate::analyzer::usages::cpp_graph::CppDispatch;
use crate::analyzer::{CppAnalyzer, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_cpp::graph::extractor::*;
use brokk_bifrost_cpp::graph::resolver::*;
use std::cell::Cell;

#[cfg(test)]
mod effective_using_scale_tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, CodeUnitType, Language, TestProject, WorkspaceAnalyzer,
        resolve_analyzer,
    };
    use std::sync::Arc;

    fn reset_lexical_scope_reconstructions_for_test() {
        LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST.with(|count| count.set(0));
    }

    fn lexical_scope_reconstructions_for_test() -> usize {
        LEXICAL_SCOPE_RECONSTRUCTIONS_FOR_TEST.with(Cell::get)
    }

    #[test]
    fn effective_using_projection_and_callable_metadata_are_cached_at_scale() {
        const HEADER_COUNT: usize = 24;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let mut includes = String::new();
        for index in 0..HEADER_COUNT {
            let header = ProjectFile::new(root.clone(), format!("api_{index}.h"));
            let mut header_source = format!(
                "#pragma once\nnamespace api_{index} {{\nint Call_{index}(int value = 0);\n"
            );
            for unrelated in 0..64 {
                header_source.push_str(&format!("struct Noise_{index}_{unrelated} {{}};\n"));
            }
            header_source.push_str(&format!("}}\nusing namespace api_{index};\n"));
            header.write(header_source).expect("write scale header");
            includes.push_str(&format!("#include \"api_{index}.h\"\n"));
        }
        let left = ProjectFile::new(root.clone(), "left.cc");
        let right = ProjectFile::new(root.clone(), "right.cc");
        left.write(format!("{includes}int left() {{ return Call_0(); }}\n"))
            .expect("write left consumer");
        right
            .write(format!("{includes}int right() {{ return Call_0(); }}\n"))
            .expect("write right consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let _scope = AnalyzerQueryScope::new(analyzer);
        let roots = HashSet::from_iter([left.clone(), right]);
        let visibility = VisibilityIndex::build(cpp, &CppDispatch::new(analyzer).source(), &roots);
        let prepared = cpp.prepared_syntax(&left).expect("prepared left consumer");
        let root_node = prepared.tree().root_node();
        let imports = initialized_ordinary_type_imports(
            root_node,
            &CppDispatch::new(analyzer).source(),
            &visibility,
            &left,
            prepared.source(),
        );

        for _ in 0..1_000 {
            assert!(
                effective_using_bindings_for_name(
                    &visibility,
                    &imports,
                    &left,
                    root_node,
                    prepared.source(),
                    "Absent",
                )
                .is_empty()
            );
        }
        let after_absent = visibility.using_work_counts_for_test();
        assert_eq!(
            after_absent.0,
            visibility.all_visible_source_files().len(),
            "the union source index must walk each physical source once"
        );
        assert_eq!(
            (
                after_absent.1,
                after_absent.2,
                after_absent.3,
                after_absent.4
            ),
            (0, 0, 0, 0),
            "an absent name must not activate donors, expand namespaces, hydrate callables, or inspect unrelated declarations"
        );
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let imports = Arc::clone(&imports);
                let left = left.clone();
                let visibility = &visibility;
                scope.spawn(move || {
                    let prepared = visibility
                        .cpp()
                        .prepared_syntax(&left)
                        .expect("prepared concurrent consumer");
                    for _ in 0..100 {
                        let _ = effective_using_bindings_for_name(
                            visibility,
                            &imports,
                            &left,
                            prepared.tree().root_node(),
                            prepared.source(),
                            "Call_0",
                        );
                    }
                });
            }
        });
        let after_projection = visibility.using_work_counts_for_test();
        assert!(
            after_projection.4 <= HEADER_COUNT,
            "namespace validation must inspect only requested-name candidates, not the unrelated declaration population: {after_projection:?}"
        );
        let _ = effective_using_bindings_for_name(
            &visibility,
            &imports,
            &left,
            root_node,
            prepared.source(),
            "Call_0",
        );
        assert_eq!(
            visibility.using_work_counts_for_test(),
            after_projection,
            "repeated name lookup must reuse donor projection and namespace expansion"
        );

        let callable = cpp
            .get_all_declarations()
            .into_iter()
            .find(|candidate| candidate.fq_name() == "api_0.Call_0" && candidate.is_function())
            .expect("scale callable");
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let callable = callable.clone();
                let left = left.clone();
                let visibility = &visibility;
                scope.spawn(move || {
                    for _ in 0..100 {
                        assert!(
                            visibility
                                .callable_arity_at_reference(
                                    &CppDispatch::new(analyzer).source(),
                                    &left,
                                    &callable,
                                    usize::MAX,
                                )
                                .is_some()
                        );
                    }
                });
            }
        });
        assert_eq!(
            visibility.using_work_counts_for_test().3,
            1,
            "repeated logical callable lookup must hydrate default metadata once"
        );
    }

    #[test]
    fn structured_prefilter_skips_unrelated_unqualified_type_before_scope_or_alias_work() {
        const NOISE_COUNT: usize = 96;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let header = ProjectFile::new(root.clone(), "types.h");
        let alias_header = ProjectFile::new(root.clone(), "aliases.h");
        alias_header
            .write("namespace aliasing { using SeenAlias = int; }\n")
            .expect("write alias header");
        let mut header_source =
            String::from("#include \"aliases.h\"\nnamespace target { struct Wanted {}; }\n");
        for index in 0..NOISE_COUNT {
            header_source.push_str(&format!(
                "namespace noise_{index} {{ struct Value {{}}; }}\n"
            ));
        }
        header.write(header_source).expect("write header");
        let consumer = ProjectFile::new(root.clone(), "consumer.cc");
        consumer
            .write(
                "#include \"types.h\"\nvoid consume() { Missing value; Missing<int> templated; }\n",
            )
            .expect("write consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let _scope = AnalyzerQueryScope::new(analyzer);
        let roots = HashSet::from_iter([consumer.clone()]);
        let visibility = VisibilityIndex::build(cpp, &CppDispatch::new(analyzer).source(), &roots);
        let prepared = cpp.prepared_syntax(&consumer).expect("prepared consumer");
        let source = prepared.source();
        let start = source.find("Missing").expect("unqualified type reference");
        let end = start + "Missing".len();
        let mut stack = vec![prepared.tree().root_node()];
        let mut type_node = None;
        while let Some(node) = stack.pop() {
            if node.start_byte() == start
                && node.end_byte() == end
                && matches!(node.kind(), "type_identifier" | "identifier")
            {
                type_node = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let type_node = type_node.expect("qualified type node");
        let template_start = source.rfind("Missing<int>").expect("template reference");
        let template_end = template_start + "Missing<int>".len();
        let mut stack = vec![prepared.tree().root_node()];
        let mut template_node = None;
        while let Some(node) = stack.pop() {
            if node.start_byte() == template_start
                && node.end_byte() == template_end
                && node.kind() == "template_type"
            {
                template_node = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        let template_node = template_node.expect("template type node");
        let imports = initialized_ordinary_type_imports(
            prepared.tree().root_node(),
            &CppDispatch::new(analyzer).source(),
            &visibility,
            &consumer,
            source,
        );
        let target = cpp
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.kind() == CodeUnitType::Class && unit.fq_name() == "target.Wanted")
            .expect("target declaration");
        let first_alias_names = visibility.visible_type_reference_component_names_for_target(
            &CppDispatch::new(analyzer).source(),
            &consumer,
            &target,
        );
        let second_alias_names = visibility.visible_type_reference_component_names_for_target(
            &CppDispatch::new(analyzer).source(),
            &consumer,
            &target,
        );
        assert_eq!(
            first_alias_names, second_alias_names,
            "repeated target component-name lookups must reuse the root alias index"
        );

        reset_lexical_scope_reconstructions_for_test();
        visibility.reset_target_preserving_type_resolution_count();
        for node in [type_node, template_node] {
            for _ in 0..2 {
                let resolution = resolve_type_node_lexically_for_target(
                    node,
                    &CppDispatch::new(analyzer).source(),
                    &visibility,
                    &imports,
                    &consumer,
                    source,
                    &target,
                    None,
                    None,
                );
                assert!(
                    matches!(resolution, LexicalTypeResolution::Missing),
                    "an unrelated bare or template type must fail closed before scope reconstruction"
                );
            }
        }
        assert_eq!(
            lexical_scope_reconstructions_for_test(),
            0,
            "the coarse unqualified prefilter must bypass lexical-scope reconstruction"
        );
        assert_eq!(
            visibility.target_preserving_type_resolution_count(),
            0,
            "the coarse unqualified prefilter must bypass target-preserving lexical resolution"
        );
        assert_eq!(
            visibility.visible_parser_alias_name_set_build_count(),
            1,
            "the visible parser-alias-name set must build lazily once and then be reused"
        );
        assert_eq!(
            visibility.visible_parser_alias_target_names_build_count(),
            1,
            "the visible parser-alias target index must build once per root and serve repeated target scans"
        );
        assert_eq!(
            visibility.alias_source_parse_count_for_test(&alias_header),
            1,
            "the shared visible parser-alias-name set must parse each visible alias source at most once"
        );
    }
}
