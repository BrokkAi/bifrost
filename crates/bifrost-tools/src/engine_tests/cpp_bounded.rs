#[cfg(test)]
mod bounded_tests {
    use brokk_bifrost_analysis::analyzer::QueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallEvidence;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::CppReferenceNode;

    use brokk_bifrost_core::analyzer::cpp_facts::CppStructuredAliasTarget;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

    use tree_sitter::Tree;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::collapse_same_fqn_alias_spellings_with_targets;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_declarator_qualified_name_node;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_enclosing_local_scope;

    use brokk_bifrost_cpp::declarations::node_text as cpp_node_text;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_nodes_share_preprocessor_branch;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_recovered_function_declaration_scope;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_reference_node;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_type_alias_declaration_contains_node;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_written_reference_is_type_shaped;

    use brokk_bifrost_cpp::graph::resolver::is_c_source_file;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::parse_cpp_tree;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::resolve_cpp;

    use brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::resolve_cpp_bounded;

    use brokk_bifrost_cpp::graph::resolver::same_logical_symbol;

    use crate::searchtools::{DefinitionReferenceQuery, GetDefinitionParams};

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#4271: visible same-FQN aliases with different structured targets were collapsed")]
    fn cpp_visible_same_fqn_aliases_with_different_targets_stay_distinct() {
        let root = std::env::temp_dir();
        let first_file = ProjectFile::new(&root, "first.hpp");
        let second_file = ProjectFile::new(&root, "second.hpp");
        let first = CodeUnit::with_signature(
            first_file.clone(),
            CodeUnitType::Class,
            "pkg",
            "Choice",
            Some("using Choice = Target;".to_string()),
            false,
        );
        let second = CodeUnit::with_signature(
            second_file.clone(),
            CodeUnitType::Class,
            "pkg",
            "Choice",
            Some("using Choice = Target;".to_string()),
            false,
        );
        assert!(same_logical_symbol(&first, &second));
        let first_target = CppStructuredAliasTarget::Named {
            components: vec!["FirstTarget".to_string()],
            global: false,
            arguments: None,
        };
        let second_target = CppStructuredAliasTarget::Named {
            components: vec!["SecondTarget".to_string()],
            global: false,
            arguments: None,
        };
        let mut aliases = vec![first, second];

        collapse_same_fqn_alias_spellings_with_targets(
            &mut aliases,
            |_| true,
            |_| true,
            |unit| {
                if unit.source() == &first_file {
                    Some(first_target.clone())
                } else {
                    Some(second_target.clone())
                }
            },
        );

        assert_eq!(aliases.len(), 2, "distinct targets must stay ambiguous");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4407: ABI 15 template type references must retain type identity"
    )]
    fn cpp_template_type_classifier_rejects_expression_shapes() {
        let source = r#"
namespace app {
namespace matchers {
    template <typename T> class MatcherBase {};
    namespace detail {
        template <typename... Ts> class MatchAllOfGeneric {};
    }
    using Positive = detail::MatchAllOfGeneric<int, MatcherBase<long>>;
}
}
template <typename T> constexpr int make_value();
void valid_function_body() {
    int value = make_value<int>();
    auto address = &make_value<int>;
    using CallType = decltype(make_value<int>());
    (void)value;
    (void)address;
}
namespace public_api {
template <typename T> struct Gate {};
namespace detail {
    template <typename... Ts> struct Pair {};
    template <typename T, typename U> struct Box {};
}
template <typename L, typename R>
detail::Box<L, detail::Pair<L, Gate<R>>> ready(L lhs, R rhs) { return {}; }
}
"#;
        let tree = parse_cpp_tree(source).expect("C++ tree");
        let node_for = |needle: &str, occurrence: usize| {
            let start = source
                .match_indices(needle)
                .nth(occurrence)
                .map(|(start, _)| start)
                .expect("needle occurrence");
            tree.root_node()
                .named_descendant_for_byte_range(start, start + needle.len())
                .expect("named node at needle")
        };

        let positive = node_for("MatcherBase<long>", 0);
        assert_eq!(positive.kind(), "template_type");
        let positive_name = positive.child_by_field_name("name").expect("positive name");
        assert!(matches!(
            cpp_reference_node(positive_name),
            Some(CppReferenceNode::Type(_))
        ));

        let public_positive = node_for("Gate<R>", 0);
        assert_eq!(public_positive.kind(), "template_function");
        let public_arguments = public_positive
            .parent()
            .expect("public positive template arguments");
        assert_eq!(public_arguments.kind(), "template_argument_list");
        let public_template = public_arguments
            .parent()
            .expect("public positive template type");
        assert_eq!(public_template.kind(), "template_type");
        assert_eq!(
            public_template.child_by_field_name("arguments"),
            Some(public_arguments)
        );
        let public_qualified = public_template
            .parent()
            .expect("public positive qualified identifier");
        assert_eq!(public_qualified.kind(), "qualified_identifier");
        assert_eq!(
            public_qualified.child_by_field_name("name"),
            Some(public_template)
        );
        let public_descriptor = public_qualified
            .parent()
            .expect("public positive type descriptor");
        assert_eq!(public_descriptor.kind(), "type_descriptor");
        assert_eq!(
            public_descriptor.child_by_field_name("type"),
            Some(public_qualified)
        );
        let public_name = public_positive
            .child_by_field_name("name")
            .expect("public positive name");
        assert!(matches!(
            cpp_reference_node(public_name),
            Some(CppReferenceNode::Type(_))
        ));

        let call = node_for("make_value<int>", 0);
        assert_eq!(call.kind(), "template_function");
        let call_name = call.child_by_field_name("name").expect("call name");
        assert!(matches!(
            cpp_reference_node(call_name),
            Some(CppReferenceNode::Call(_))
        ));

        let address = node_for("make_value<int>", 1);
        assert_eq!(address.kind(), "template_function");
        let address_name = address.child_by_field_name("name").expect("address name");
        assert!(cpp_reference_node(address_name).is_none());

        let decltype_call = node_for("make_value<int>", 2);
        assert_eq!(decltype_call.kind(), "template_function");
        let decltype_name = decltype_call
            .child_by_field_name("name")
            .expect("decltype call name");
        assert!(matches!(
            cpp_reference_node(decltype_name),
            Some(CppReferenceNode::Call(_))
        ));
    }

    #[test]
    #[hardwon(
        "cd472d9c1eff: Checks a focused C++ namespace qualifier does not navigate to a neighboring type with similar range context"
    )]
    fn focused_namespace_qualifier_does_not_return_the_adjacent_type() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[(
                "main.cpp",
                "namespace helpers { struct Pool {}; }\nvoid owner() { helpers::Pool p; }\n",
            )],
        );
        let result = crate::searchtools::get_definitions_by_reference(
            fixture.analyzer.analyzer(),
            crate::searchtools::GetDefinitionByReferenceParams {
                references: vec![crate::searchtools::DefinitionContextReferenceQuery {
                    symbol: "owner".to_string(),
                    context: "void owner() { helpers::Pool p; }".to_string(),
                    target: "helpers".to_string(),
                }],
            },
        );

        assert!(
            result.results[0]
                .definitions
                .iter()
                .all(|definition| definition.name != "Pool"),
            "{result:#?}"
        );
    }

    #[test]
    #[hardwon(
        "1c570a35813e: Parser-recovery case verifies a recovered C++ function declaration still defines a local scope boundary"
    )]
    fn recovered_function_declaration_is_a_local_scope() {
        let source =
            "namespace n {\nprivate:\nvoid flatten(const T& value) BROKEN {\n{ value.type(); }\n";
        let tree = parse_cpp_tree(source).expect("C++ recovery tree");
        let focus = source.find("value.type").expect("parameter receiver");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(focus, focus + "value".len())
            .expect("focused receiver node");
        let scope = cpp_enclosing_local_scope(node).expect("recovered function scope");

        assert_eq!(scope.kind(), "declaration");
        assert!(cpp_recovered_function_declaration_scope(scope));
        assert_eq!(
            scope
                .child_by_field_name("declarator")
                .map(|node| node.kind()),
            Some("function_declarator")
        );
    }

    #[test]
    #[hardwon(
        "31982bd4d78a: Preprocessor fixture ensures recovered local declarations bind only within the same conditional branch"
    )]
    fn local_binding_recovery_matches_only_the_same_preprocessor_branch() {
        let source = r#"void use(int value);
void run(void) {
#if OUTER
    int same = 1;
#if INNER
    int nested = 2;
#else
    int sibling = 3;
#endif
    use(same);
#else
    int other = 4;
#endif
}
"#;
        let tree = parse_cpp_tree(source).expect("C++ tree");
        let node_at = |needle: &str, token: &str| {
            let start = source.find(needle).expect("fixture needle")
                + needle.find(token).expect("token in fixture needle");
            tree.root_node()
                .named_descendant_for_byte_range(start, start + token.len())
                .expect("fixture token node")
        };
        let reference = node_at("use(same)", "same");
        let same = node_at("int same", "same");
        let nested = node_at("int nested", "nested");
        let sibling = node_at("int sibling", "sibling");
        let other = node_at("int other", "other");

        assert!(cpp_nodes_share_preprocessor_branch(same, reference));
        assert!(!cpp_nodes_share_preprocessor_branch(nested, reference));
        assert!(!cpp_nodes_share_preprocessor_branch(sibling, reference));
        assert!(!cpp_nodes_share_preprocessor_branch(other, reference));
    }

    #[test]
    #[hardwon(
        "0e6df36dfa5d: C++ template fixture prevents a class alias from resolving recursively inside its own declaration argument"
    )]
    fn class_alias_is_not_visible_in_its_own_template_argument() {
        let source = r#"
namespace lib {
template<typename T> struct wrapper {};
struct value_type {};
struct holder {
    using value_type = wrapper<value_type>;
};
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("alias.hpp", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let alias = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name().ends_with("holder$value_type"))
            .expect("member alias");
        let tree = parse_cpp_tree(source).expect("C++ tree");
        let start = source
            .find("wrapper<value_type>")
            .expect("alias right-hand type")
            + "wrapper<".len();
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + "value_type".len())
            .expect("alias right-hand type node");

        assert_eq!(node.kind(), "type_identifier");
        assert!(cpp_type_alias_declaration_contains_node(
            analyzer, &alias, node
        ));
    }

    #[test]
    fn capitalized_c_api_names_keep_the_c_cpp_shape_split() {
        let root = std::env::temp_dir();
        let c_file = ProjectFile::new(root.clone(), "main.c");
        let cpp_file = ProjectFile::new(root, "main.cpp");

        assert!(is_c_source_file(&c_file));
        assert!(!is_c_source_file(&cpp_file));
        assert!(cpp_written_reference_is_type_shaped("PQexec"));
        assert!(!cpp_written_reference_is_type_shaped("getenv"));
        assert!(is_c_source_file(&c_file) || !cpp_written_reference_is_type_shaped("PQexec"));
        assert!(!(is_c_source_file(&cpp_file) || !cpp_written_reference_is_type_shaped("PQexec")));
        assert!(is_c_source_file(&cpp_file) || !cpp_written_reference_is_type_shaped("getenv"));
    }

    #[test]
    #[hardwon(
        "0029e7d9886a: an unknown-arity C macro suppressed unanimous call-result receiver inference"
    )]
    fn unknown_macro_arity_uses_unanimous_c_call_return_type_for_receiver() {
        let source = r#"#include UNKNOWN_BUILD_HEADER
struct pending { struct pending *next; };
typedef struct pending pending_t;
struct ring { pending_t items[4]; int count; };
typedef struct ring ring_t;
pending_t *get(ring_t *ring, int index) { return &ring->items[index]; }
void advance(ring_t *ring) { get(ring, ring->count - 2)->next = 0; }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("issue.c", source)]);
        let start = source.find("->next").expect("member use") + "->".len();
        let prefix = &source[..start];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix, |(_, current)| current)
            .chars()
            .count()
            + 1;

        let result = crate::searchtools::get_definitions_by_location(
            fixture.analyzer.analyzer(),
            GetDefinitionParams {
                references: vec![DefinitionReferenceQuery {
                    path: "issue.c".to_string(),
                    line: Some(line),
                    column: Some(column),
                }],
            },
        );

        assert_eq!(result.results[0].status, "resolved", "{result:#?}");
        assert_eq!(
            result.results[0].definitions[0].fqn.as_deref(),
            Some("pending.next")
        );
    }

    #[test]
    #[hardwon("8ff0108f8253: definition navigation entered a non-callable prototype declaration")]
    fn definition_navigation_enters_only_callable_prototype_declarations() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[(
                "main.cpp",
                "struct Owner { int value; };\nvoid run();\nvoid run() {}\n",
            )],
        );
        let result = crate::searchtools::get_definitions_by_location(
            fixture.analyzer.analyzer(),
            GetDefinitionParams {
                references: vec![
                    DefinitionReferenceQuery {
                        path: "main.cpp".to_string(),
                        line: Some(1),
                        column: Some(20),
                    },
                    DefinitionReferenceQuery {
                        path: "main.cpp".to_string(),
                        line: Some(2),
                        column: Some(6),
                    },
                ],
            },
        );

        assert_ne!(result.results[0].status, "resolved", "{result:#?}");
        assert_eq!(result.results[1].status, "resolved", "{result:#?}");
        assert_eq!(
            result.results[1].definitions[0].start_line, 3,
            "{result:#?}"
        );
    }

    #[test]
    #[hardwon(
        "a787c7778210: canonical navigation lost a tagged struct body behind an identical typedef"
    )]
    fn reachable_identical_typedef_navigates_to_its_reachable_copy() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Cpp,
            &[
                (
                    "visible.hpp",
                    "typedef struct internal_tag public_name;\nstruct internal_tag { static void member(); };\n",
                ),
                (
                    "hidden.hpp",
                    "typedef struct internal_tag public_name;\nstruct internal_tag { static void member(); };\n",
                ),
                (
                    "use.cpp",
                    "#include \"visible.hpp\"\nvoid use() { public_name::member(); }\n",
                ),
            ],
        );

        let result = crate::searchtools::get_definitions_by_location(
            fixture.analyzer.analyzer(),
            GetDefinitionParams {
                references: vec![DefinitionReferenceQuery {
                    path: "use.cpp".to_string(),
                    line: Some(2),
                    column: Some(14),
                }],
            },
        );

        assert_eq!(result.results[0].status, "resolved", "{result:#?}");
        // Navigation answers with the alias the reference spells (#2430), and
        // of the two identical copies only the included one is reachable.
        let definitions = &result.results[0].definitions;
        assert!(
            definitions.iter().all(|definition| {
                definition.fqn.as_deref() == Some("public_name") && definition.path == "visible.hpp"
            }) && !definitions.is_empty(),
            "the typedef must navigate to its reachable copy: {result:#?}"
        );
    }

    #[test]
    #[hardwon("2cdd8b65c095: owner lookup failed through a reference declarator")]
    fn qualified_name_descends_through_reference_declarator() {
        let source = "C& C::operator<<(bool) { return helper(); }";
        let tree = parse_cpp_tree(source).expect("C++ tree");
        let function = tree
            .root_node()
            .named_child(0)
            .expect("function definition");
        let declarator = function
            .child_by_field_name("declarator")
            .expect("outer declarator");
        let qualified = cpp_declarator_qualified_name_node(declarator)
            .expect("qualified operator name through reference declarator");

        assert_eq!(qualified.kind(), "qualified_identifier");
        assert_eq!(cpp_node_text(qualified, source), "C::operator<<");
    }

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    int value{index} = {index};\n"))
            .collect::<String>();
        let expression = format!("{}service{}->run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "struct Service {{ void run() {{}} }};\n\n\
             void use(Service* service) {{\n{statements}    {expression};\n}}\n"
        );
        brokk_bifrost_analysis::analyzer::usages::test_support::wide_deep_member_fixture(
            Language::Cpp,
            "receiver.cpp",
            source,
            &expression,
            "run",
            parse_cpp_tree,
        )
    }

    #[test]
    #[hardwon(
        "eff59cd0d2a2: initializer inference rebuilt C++ bindings instead of reusing the seeded binding"
    )]
    fn initializer_inference_reuses_seeded_bindings() {
        let declarations = (1..=16)
            .map(|index| format!("    auto& value{index} = value{}.next();\n", index - 1))
            .collect::<String>();
        let source = format!(
            "class Node {{\npublic:\n    static Node& GetInstance();\n    Node& next();\n    int value();\n}};\n\n\
             int read(Node& value0) {{\n{declarations}    return value16.value();\n}}\n"
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("chain.cpp", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "chain.cpp");
        let tree = parse_cpp_tree(&source).expect("C++ tree");
        let start_byte = source.rfind("value()").expect("final member");
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "value".to_string(),
            range: Range {
                start_byte,
                end_byte: start_byte + "value".len(),
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + "value".len(),
        };

        brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::reset_cpp_bindings_build_count_for_test();
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        context.bounded_support.set_language(Language::Cpp);
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcome = resolve_cpp(
            analyzer,
            token,
            &mut context,
            &file,
            &source,
            Some(&tree),
            &site,
            false,
            None,
            &mut CallEvidence::default(),
        );
        let builds = brokk_bifrost_cpp_analysis::analyzer::usages::get_definition::cpp::cpp_bindings_build_count_for_test();

        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "unexpected lookup outcome: {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1);
        assert_eq!(outcome.definitions[0].fq_name(), "Node.value");
        assert_eq!(
            builds, 1,
            "initializer inference must reuse the source-ordered binding engine"
        );
    }

    #[test]
    fn bounded_cpp_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let outcome = resolve_cpp_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[test]
    fn bounded_cpp_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_cpp_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }
}
