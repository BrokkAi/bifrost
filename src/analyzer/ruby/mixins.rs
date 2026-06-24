#![allow(dead_code)]

use super::RubyAnalyzer;
use super::declarations::{
    extract_name_segments, is_descendable_container, parse_ruby_tree, qualified_internal_name,
    ruby_node_text,
};
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::{CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::HashSet;
use tree_sitter::Node;

impl RubyAnalyzer {
    pub(crate) fn mixin_relations(&self) -> &[TypeRelation] {
        self.mixin_relations
            .get_or_init(|| self.collect_mixin_relations())
            .as_slice()
    }

    fn collect_mixin_relations(&self) -> Vec<TypeRelation> {
        let mut relations = Vec::new();
        for file in self.get_analyzed_files() {
            let Ok(source) = self.project().read_source(&file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };

            let mut stack = Vec::new();
            push_children(tree.root_node(), &[], &mut stack);
            while let Some((node, segments)) = stack.pop() {
                self.collect_mixin_relation_statement(
                    &file,
                    &source,
                    node,
                    &segments,
                    &mut relations,
                    &mut stack,
                );
            }
        }
        relations
    }

    fn collect_mixin_relation_statement<'tree>(
        &self,
        file: &ProjectFile,
        source: &str,
        node: Node<'tree>,
        segments: &[String],
        relations: &mut Vec<TypeRelation>,
        stack: &mut Vec<(Node<'tree>, Vec<String>)>,
    ) {
        match node.kind() {
            "class" | "module" => {
                let Some(name_node) = node.child_by_field_name("name") else {
                    return;
                };
                let name_segments = extract_name_segments(name_node, source);
                if name_segments.is_empty() {
                    return;
                }

                let mut type_segments = segments.to_vec();
                type_segments.extend(name_segments);
                let owner = CodeUnit::new(
                    file.clone(),
                    if node.kind() == "module" {
                        CodeUnitType::Module
                    } else {
                        CodeUnitType::Class
                    },
                    String::new(),
                    type_segments.join("$"),
                );
                self.collect_mixin_relations_for_type(file, source, node, &owner, relations);

                if let Some(body) = node.child_by_field_name("body") {
                    push_children(body, &type_segments, stack);
                }
            }
            "singleton_class" => {
                if let Some(body) = node.child_by_field_name("body") {
                    push_children(body, segments, stack);
                }
            }
            "method" | "singleton_method" => {}
            kind if is_descendable_container(kind) => push_children(node, segments, stack),
            _ => {}
        }
    }

    fn collect_mixin_relations_for_type(
        &self,
        file: &ProjectFile,
        source: &str,
        node: Node<'_>,
        owner: &CodeUnit,
        relations: &mut Vec<TypeRelation>,
    ) {
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
                                && let Some(target) = self.resolve_mixin_target(file, &name)
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

    fn resolve_mixin_target(&self, file: &ProjectFile, raw: &str) -> Option<CodeUnit> {
        let visible_files = self.visible_mixin_files(file);
        self.declarations(file)
            .find(|unit| ruby_type_matches(unit, raw))
            .cloned()
            .or_else(|| {
                self.imported_code_units_of(file)
                    .into_iter()
                    .find(|unit| ruby_type_matches(unit, raw))
            })
            .or_else(|| {
                self.inner
                    .definitions(raw)
                    .find(|unit| {
                        (unit.is_class() || unit.is_module())
                            && visible_files.contains(unit.source())
                    })
                    .cloned()
            })
            .or_else(|| {
                self.all_declarations()
                    .filter(|unit| visible_files.contains(unit.source()))
                    .find(|unit| ruby_type_matches(unit, raw))
                    .cloned()
            })
    }

    fn visible_mixin_files(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut files = HashSet::default();
        files.insert(file.clone());
        files.extend(
            self.imported_code_units_of(file)
                .into_iter()
                .map(|unit| unit.source().clone()),
        );
        files
    }
}

fn push_children<'tree>(
    node: Node<'tree>,
    segments: &[String],
    stack: &mut Vec<(Node<'tree>, Vec<String>)>,
) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    for child in children.into_iter().rev() {
        stack.push((child, segments.to_vec()));
    }
}

fn ruby_type_matches(unit: &CodeUnit, raw: &str) -> bool {
    (unit.is_class() || unit.is_module())
        && (unit.fq_name() == raw || unit.short_name() == raw || unit.identifier() == raw)
}

fn mixin_call_kind(node: Node<'_>, source: &str) -> Option<TypeRelationKind> {
    if node.child_by_field_name("receiver").is_some() {
        return None;
    }
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
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, RubyAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Ruby, files);
        let analyzer = RubyAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    #[test]
    fn mixin_relations_distinguish_include_prepend_and_extend() {
        let (_project, analyzer) = analyzer_with_files(&[
            (
                "mixins/findable.rb",
                "module Findable\n  def find; end\nend\n",
            ),
            (
                "mixins/rankable.rb",
                "module Rankable\n  def rank; end\nend\n",
            ),
            (
                "mixins/outer/shared.rb",
                "module Outer\n  module Shared\n    def shared; end\n  end\nend\n",
            ),
            (
                "app/repository.rb",
                r#"
require_relative "../mixins/findable"
require_relative "../mixins/rankable"
require_relative "../mixins/outer/shared"

class Repository
  include Findable
  prepend Rankable
  extend Outer::Shared
end
"#,
            ),
        ]);
        let relations = analyzer.mixin_relations();
        let repository_file =
            ProjectFile::new(analyzer.project().root().to_path_buf(), "app/repository.rb");
        let imported: Vec<_> = analyzer
            .imported_code_units_of(&repository_file)
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect();
        assert!(
            imported.iter().any(|name| name == "Findable")
                && imported.iter().any(|name| name == "Rankable")
                && imported.iter().any(|name| name == "Outer"),
            "expected mixins to be visible through require_relative imports, got {imported:?}"
        );

        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinInclude
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.identifier() == "Rankable"
                && relation.kind == TypeRelationKind::MixinPrepend
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.short_name() == "Outer$Shared"
                && relation.kind == TypeRelationKind::MixinExtend
        }));
    }

    #[test]
    fn include_and_extend_are_distinct_lookup_inputs() {
        let (_project, analyzer) = analyzer_with_files(&[
            (
                "mixins/findable.rb",
                "module Findable\n  def find; end\nend\n",
            ),
            (
                "app/repositories.rb",
                r#"
require_relative "../mixins/findable"

class InstanceRepository
  include Findable
end

class SingletonRepository
  extend Findable
end
"#,
            ),
        ]);

        let relations = analyzer.mixin_relations();
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "InstanceRepository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinInclude
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "SingletonRepository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinExtend
        }));
        assert!(!relations.iter().any(|relation| {
            relation.from.identifier() == "InstanceRepository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinExtend
        }));
        assert!(!relations.iter().any(|relation| {
            relation.from.identifier() == "SingletonRepository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinInclude
        }));
    }

    #[test]
    fn receiver_calls_do_not_create_mixin_relations() {
        let (_project, analyzer) = analyzer_with_files(&[(
            "app.rb",
            r#"
module Auditable
end

class Other
end

class Repository
  Other.include Auditable
end
"#,
        )]);

        assert!(!analyzer.mixin_relations().iter().any(|relation| {
            relation.from.identifier() == "Repository" && relation.to.identifier() == "Auditable"
        }));
    }

    #[test]
    fn unqualified_mixin_uses_import_visibility_over_global_same_name() {
        let (_project, analyzer) = analyzer_with_files(&[
            ("unloaded/shared.rb", "module Shared\nend\n"),
            ("visible/shared.rb", "module Shared\nend\n"),
            (
                "app/repository.rb",
                r#"
require_relative "../visible/shared"

class Repository
  include Shared
end
"#,
            ),
            (
                "app/other.rb",
                r#"
class OtherRepository
  include Shared
end
"#,
            ),
        ]);

        let relations = analyzer.mixin_relations();
        let visible_shared = std::path::Path::new("visible").join("shared.rb");
        let unloaded_shared = std::path::Path::new("unloaded").join("shared.rb");
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.source().rel_path() == visible_shared.as_path()
                && relation.kind == TypeRelationKind::MixinInclude
        }));
        assert!(!relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.source().rel_path() == unloaded_shared.as_path()
        }));
        assert!(!relations.iter().any(|relation| {
            relation.from.identifier() == "OtherRepository" && relation.to.identifier() == "Shared"
        }));
    }
}
