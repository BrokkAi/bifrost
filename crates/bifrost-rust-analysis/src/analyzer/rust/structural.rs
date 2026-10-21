//! Rust's structural-spec coverage, kept beside the engine it exercises.
//!
//! The spec itself is [`brokk_bifrost_rust::structural::RUST_STRUCTURAL_SPEC`].
//! These assertions run through `structural::extract`, the analysis-owned fact
//! engine, so the tests stay on this side of the crate line (the Go pilot's
//! structural test tail did the same, in the other direction: it dropped the
//! engine dependency so it could ride along).

#[cfg(test)]
mod structural_spec_tests {

    use brokk_bifrost_core::analyzer::structural::adapter_helpers::assert_kind_table_matches_grammar;

    use brokk_bifrost_analysis::analyzer::structural::adapter_helpers::assert_occurrence_role;

    use brokk_bifrost_analysis::analyzer::structural::adapter_helpers::block_facts_of;

    use brokk_bifrost_analysis::analyzer::structural::adapter_helpers::occurrence_roles_of;

    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;

    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

    use brokk_bifrost_core::analyzer::structural::kinds::Role;

    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use brokk_bifrost_rust::structural::{RUST_KIND_TABLE, RUST_STRUCTURAL_SPEC};

    /// Every Rust scope-forming statement list is a `block`, whether it is a
    /// function body, a conditional body, or a bare block in expression
    /// position.
    use brokk_bifrost_test_macros::hardwon;

    #[hardwon("#1569: rust blocks become scope facts wherever they appear")]
    #[test]
    fn rust_blocks_become_scope_facts_wherever_they_appear() {
        let source = concat!(
            "fn demo(flag: bool) {\n",
            "    if flag {\n",
            "        work();\n",
            "    }\n",
            "    let value = { 1 };\n",
            "}\n",
        );

        assert_eq!(
            block_facts_of(
                &RUST_STRUCTURAL_SPEC,
                &tree_sitter_rust::LANGUAGE.into(),
                source,
            ),
            vec![
                concat!(
                    "{\n",
                    "    if flag {\n",
                    "        work();\n",
                    "    }\n",
                    "    let value = { 1 };\n",
                    "}",
                ),
                concat!("{\n", "        work();\n", "    }"),
                "{ 1 }",
            ]
        );
    }

    /// Raw identifiers are the Rust-specific trap #1473 names: `r#type` is one
    /// `identifier` token in a pattern position, so it must classify as a
    /// binder exactly like any other local, without any prefix stripping.
    #[hardwon("#1568: rust classifies raw identifier binders declarations and use trees")]
    #[test]
    fn rust_classifies_raw_identifier_binders_declarations_and_use_trees() {
        let source = concat!(
            "use std::collections::HashMap as Map;\n",
            "\n",
            "struct Widget {\n",
            "    label: String,\n",
            "}\n",
            "\n",
            "impl Widget {\n",
            "    fn render(&self, r#type: Map) -> String {\n",
            "        self.label.clone()\n",
            "    }\n",
            "}\n",
        );
        let found = occurrence_roles_of(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        assert_occurrence_role(&found, at("std"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("collections"), OccurrenceRole::PathSegment);
        assert_occurrence_role(&found, at("HashMap"), OccurrenceRole::ImportTarget);
        assert_occurrence_role(&found, at("Map;"), OccurrenceRole::ImportAlias);
        assert_occurrence_role(&found, at("Widget {"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("label: String"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("String,"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("render"), OccurrenceRole::DeclarationName);
        assert_occurrence_role(&found, at("r#type"), OccurrenceRole::Binder);
        assert_occurrence_role(&found, at("Map)"), OccurrenceRole::TypeOperand);
        assert_occurrence_role(&found, at("label.clone"), OccurrenceRole::MemberPosition);
        assert_occurrence_role(&found, at("clone()"), OccurrenceRole::MemberPosition);
    }

    #[test]
    fn rust_retains_structured_derive_and_field_attribute_facts() {
        let source = concat!(
            "use getset::Getters;\n",
            "#[derive(Getters)]\n",
            "struct Record {\n",
            "    #[get = \"pub\"]\n",
            "    value: String,\n",
            "}\n",
        );
        let facts = brokk_bifrost_analysis::analyzer::structural::extract::extract_file_facts(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        )
        .unwrap();
        let derive = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Decorator
                    && node
                        .name
                        .is_some_and(|name| name.text(facts.source()) == "Getters")
            })
            .map(|(index, _)| u32::try_from(index).unwrap())
            .expect("derive path decorator");
        assert_eq!(
            facts
                .role_targets(derive, Role::Module)
                .filter_map(|target| target.name)
                .map(|name| name.text(facts.source()))
                .collect::<Vec<_>>(),
            Vec::<&str>::new()
        );
        assert!(facts.nodes().iter().any(|node| {
            node.kind == NormalizedKind::Decorator
                && node
                    .name
                    .is_some_and(|name| name.text(facts.source()) == "get")
        }));
        let getter = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Decorator
                    && node
                        .name
                        .is_some_and(|name| name.text(facts.source()) == "get")
            })
            .map(|(index, _)| u32::try_from(index).unwrap())
            .expect("get attribute");
        assert_eq!(
            facts
                .role_targets(getter, Role::Arg)
                .map(|target| target.span.text(facts.source()))
                .collect::<Vec<_>>(),
            vec!["\"pub\""]
        );
        assert!(facts.nodes().iter().any(|node| {
            node.kind == NormalizedKind::Declaration
                && node
                    .name
                    .is_some_and(|name| name.text(facts.source()) == "value")
        }));
    }

    #[test]
    fn rust_kind_table_matches_grammar() {
        assert_kind_table_matches_grammar(
            tree_sitter_rust::LANGUAGE.into(),
            "tree-sitter-rust",
            RUST_KIND_TABLE,
        );
    }

    #[test]
    fn rust_result_branches_use_native_failure_hook_seeds() {
        let source =
            "fn run(value: Result<i32, i32>) { match value { Err(_) => {}, Ok(_) => {} } }";
        let facts = brokk_bifrost_analysis::analyzer::structural::extract::extract_file_facts(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        )
        .expect("Rust result source extracts");
        let catches = facts
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::Catch)
            .map(|node| &source[node.range.start_byte..node.range.end_byte])
            .collect::<Vec<_>>();
        assert!(
            catches.is_empty(),
            "Rust native branches are not Catch facts"
        );
        assert!(
            facts
                .nodes()
                .iter()
                .any(|node| node.kind.satisfies(NormalizedKind::Callable))
        );
    }

    #[test]
    fn rust_marks_only_qualified_task_spawn_calls_as_concurrent_spawns() {
        let source = concat!(
            "fn candidates() {\n",
            "    std::thread::spawn(|| {});\n",
            "    tokio::spawn(async {});\n",
            "    ::tokio::spawn(async {});\n",
            "    tokio::task::spawn_blocking(|| {});\n",
            "    rayon::spawn(|| {});\n",
            "    spawn(|| {});\n",
            "    let spawn = || {};\n",
            "    spawn();\n",
            "    std::process::Command::new(\"child\").spawn();\n",
            "}\n",
        );
        let facts = brokk_bifrost_analysis::analyzer::structural::extract::extract_file_facts(
            &RUST_STRUCTURAL_SPEC,
            &tree_sitter_rust::LANGUAGE.into(),
            source,
        )
        .expect("Rust task-spawn source extracts");
        let spawns = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| node.kind == NormalizedKind::ConcurrentSpawn)
            .collect::<Vec<_>>();

        assert!(RUST_STRUCTURAL_SPEC.supports_kind(NormalizedKind::ConcurrentSpawn));
        assert_eq!(
            spawns
                .iter()
                .map(|(_, node)| node.span().text(source))
                .collect::<Vec<_>>(),
            vec![
                "std::thread::spawn(|| {})",
                "tokio::spawn(async {})",
                "::tokio::spawn(async {})",
                "tokio::task::spawn_blocking(|| {})",
                "rayon::spawn(|| {})",
            ]
        );
        for (id, node) in spawns {
            let callee = facts
                .role_targets(u32::try_from(id).expect("structural id fits"), Role::Callee)
                .next()
                .expect("concurrent spawn retains its callee role");
            assert!(callee.span.text(source).starts_with("spawn"));
            assert_eq!(
                facts
                    .role_targets(u32::try_from(id).expect("structural id fits"), Role::Arg)
                    .count(),
                1,
                "spawn call retains its callable argument: {}",
                node.span().text(source)
            );
        }
    }
}
