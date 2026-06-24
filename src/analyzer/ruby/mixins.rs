use super::RubyAnalyzer;
use super::declarations::{
    is_descendable_container, parse_ruby_tree, qualified_internal_name, ruby_node_text,
};
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::{CodeUnit, IAnalyzer};
use tree_sitter::Node;

impl RubyAnalyzer {
    #[allow(dead_code)]
    pub(crate) fn mixin_relations(&self) -> Vec<TypeRelation> {
        let mut relations = Vec::new();
        for file in self.get_analyzed_files() {
            let Ok(source) = self.project().read_source(&file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                match node.kind() {
                    "class" | "module" => {
                        self.collect_mixin_relations_for_type(node, &source, &mut relations);
                        let mut cursor = node.walk();
                        for child in node.named_children(&mut cursor) {
                            stack.push(child);
                        }
                    }
                    _ => {
                        let mut cursor = node.walk();
                        for child in node.named_children(&mut cursor) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        relations
    }

    fn collect_mixin_relations_for_type(
        &self,
        node: Node<'_>,
        source: &str,
        relations: &mut Vec<TypeRelation>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let Some(owner_name) = qualified_internal_name(name_node, source) else {
            return;
        };
        let Some(owner) = self.resolve_ruby_type_by_name(&owner_name) else {
            return;
        };
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };

        let mut stack = vec![body];
        while let Some(current) = stack.pop() {
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                match child.kind() {
                    "call" => {
                        let Some(kind) = mixin_call_kind(child, source) else {
                            continue;
                        };
                        let Some(arguments) = child.child_by_field_name("arguments") else {
                            continue;
                        };
                        let mut arg_cursor = arguments.walk();
                        for arg in arguments.named_children(&mut arg_cursor) {
                            if matches!(arg.kind(), "constant" | "scope_resolution")
                                && let Some(name) = qualified_internal_name(arg, source)
                                && let Some(target) = self.resolve_supertype(&name)
                            {
                                relations.push(TypeRelation {
                                    from: owner.clone(),
                                    to: target,
                                    kind,
                                });
                            }
                        }
                    }
                    kind if is_descendable_container(kind) => stack.push(child),
                    _ => {}
                }
            }
        }
    }

    fn resolve_ruby_type_by_name(&self, name: &str) -> Option<CodeUnit> {
        self.definitions(name)
            .find(|unit| unit.is_class() || unit.is_module())
            .cloned()
            .or_else(|| {
                self.all_declarations()
                    .find(|unit| {
                        (unit.is_class() || unit.is_module())
                            && (unit.short_name() == name || unit.identifier() == name)
                    })
                    .cloned()
            })
    }
}

fn mixin_call_kind(node: Node<'_>, source: &str) -> Option<TypeRelationKind> {
    let method = node.child_by_field_name("method")?;
    match ruby_node_text(method, source).trim() {
        "include" => Some(TypeRelationKind::MixinInclude),
        "prepend" => Some(TypeRelationKind::MixinPrepend),
        "extend" => Some(TypeRelationKind::MixinExtend),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, TestProject};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn mixin_relations_distinguish_include_prepend_and_extend() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("mixins.rb"),
            r#"
module Auditable
  def audit; end
end

module Ordered
  def compare; end
end

module Findable
  def find; end
end

class User
  include Auditable
  prepend Ordered
  extend Findable
end
"#,
        )
        .unwrap();
        let analyzer =
            RubyAnalyzer::from_project(TestProject::new(temp.path().to_path_buf(), Language::Ruby));
        let relations = analyzer.mixin_relations();

        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "User"
                && relation.to.identifier() == "Auditable"
                && relation.kind == TypeRelationKind::MixinInclude
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "User"
                && relation.to.identifier() == "Ordered"
                && relation.kind == TypeRelationKind::MixinPrepend
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "User"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinExtend
        }));
    }
}
