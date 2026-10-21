#[cfg(test)]
mod ruby_scope_hit_tests {
    use brokk_bifrost_analysis::EmptyAnalyzer;
    use brokk_bifrost_analysis::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::{CodeUnit, Language};
    use std::collections::BTreeSet;
    #[test]
    fn ruby_reference_without_enclosing_declaration_keeps_file_scope_hit() {
        let source = "target()\n";
        let project = InlineTestProject::with_language(Language::Ruby)
            .file("caller.rb", source)
            .build();
        let file = project.file("caller.rb");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let call = tree.root_node().named_child(0).unwrap();
        let node = call.child_by_field_name("method").unwrap();
        let attribution = EmptyAnalyzer::new(project.project_dyn());
        let mut hits = BTreeSet::new();
        brokk_bifrost_ruby::graph::hits::record_usage_hit(
            &attribution,
            &file,
            source,
            &[0],
            &mut hits,
            node,
        );
        assert_eq!(hits.len(), 1, "{hits:?}");
        let hit = hits.first().unwrap();
        assert_eq!(hit.enclosing, CodeUnit::file_scope(file));
        assert_eq!(&source[hit.start_offset..hit.end_offset], "target");
        let mut unproven = BTreeSet::new();
        brokk_bifrost_ruby::graph::hits::record_unproven_usage_hit(
            &attribution,
            &hit.file,
            source,
            &[0],
            &mut unproven,
            node,
        );
        assert_eq!(unproven.len(), 1, "{unproven:?}");
        assert_eq!(unproven.first().unwrap().enclosing, hit.enclosing);
    }
}
