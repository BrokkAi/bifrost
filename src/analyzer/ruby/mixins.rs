use super::RubyAnalyzer;
use super::declarations::{is_descendable_container, qualified_internal_name, ruby_node_text};
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::HashSet;
use tree_sitter::Node;

#[derive(Clone)]
pub(crate) struct RubyForwardMixinSpec {
    pub(crate) kind: TypeRelationKind,
    pub(crate) raw_target: String,
}

impl RubyAnalyzer {
    pub(crate) fn mixin_relations(&self) -> &[TypeRelation] {
        self.mixin_relations
            .get_or_init(|| self.collect_mixin_relations())
            .as_slice()
    }

    fn collect_mixin_relations(&self) -> Vec<TypeRelation> {
        let mut relations = Vec::new();
        for file in self.get_analyzed_files() {
            for owner in self
                .declarations(&file)
                .into_iter()
                .filter(|unit| unit.is_class() || unit.is_module())
            {
                for spec in self.forward_mixin_specs(&owner) {
                    if let Some(target) = self.resolve_mixin_target(&file, &spec.raw_target) {
                        relations.push(TypeRelation {
                            from: owner.clone(),
                            to: target,
                            kind: spec.kind,
                        });
                    }
                }
            }
        }
        relations
    }

    /// Reads parser-derived mixin facts for exactly one owner file. Forward
    /// definition lookup therefore never reparses Ruby source or constructs the
    /// global mixin graph.
    pub(crate) fn forward_mixin_specs(&self, owner: &CodeUnit) -> Vec<RubyForwardMixinSpec> {
        self.forward_owner_relation_facts(owner)
            .into_iter()
            .filter_map(|fact| {
                fact.kind.map(|kind| RubyForwardMixinSpec {
                    kind,
                    raw_target: fact.raw_target,
                })
            })
            .collect()
    }

    pub(crate) fn forward_superclass_targets(&self, owner: &CodeUnit) -> Vec<String> {
        self.forward_owner_relation_facts(owner)
            .into_iter()
            .filter(|fact| fact.kind.is_none())
            .map(|fact| fact.raw_target)
            .collect()
    }

    fn forward_owner_relation_facts(&self, owner: &CodeUnit) -> Vec<RubyOwnerRelationFact> {
        let Some(state) = self.inner.fetch_file_state(owner.source()) else {
            return Vec::new();
        };
        if !state.declarations.contains(owner) {
            return Vec::new();
        }
        state
            .raw_supertypes
            .get(owner)
            .into_iter()
            .flatten()
            .zip(
                state
                    .supertype_lookup_paths
                    .get(owner)
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|(raw, encoded)| decode_owner_relation(encoded, raw))
            .collect()
    }

    fn resolve_mixin_target(&self, file: &ProjectFile, raw: &str) -> Option<CodeUnit> {
        let visible_files = self.visible_mixin_files(file);
        self.declarations(file)
            .into_iter()
            .find(|unit| ruby_type_matches(unit, raw))
            .or_else(|| {
                self.imported_code_units_of(file)
                    .into_iter()
                    .find(|unit| ruby_type_matches(unit, raw))
            })
            .or_else(|| {
                self.inner.definitions(raw).find(|unit| {
                    (unit.is_class() || unit.is_module()) && visible_files.contains(unit.source())
                })
            })
            .or_else(|| {
                self.all_declarations()
                    .filter(|unit| visible_files.contains(unit.source()))
                    .find(|unit| ruby_type_matches(unit, raw))
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

pub(super) fn raw_mixin_specs_for_type(node: Node<'_>, source: &str) -> Vec<RubyForwardMixinSpec> {
    let Some(body) = node.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut specs = Vec::new();
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
                    let mut call_specs = Vec::new();
                    for argument in arguments.named_children(&mut arg_cursor) {
                        if matches!(argument.kind(), "constant" | "scope_resolution")
                            && let Some(raw_target) = qualified_internal_name(argument, source)
                        {
                            call_specs.push(RubyForwardMixinSpec { kind, raw_target });
                        }
                    }
                    specs.extend(call_specs.into_iter().rev());
                }
                kind if is_descendable_container(kind) => stack.push(child),
                _ => {}
            }
        }
    }
    specs
}

struct RubyOwnerRelationFact {
    kind: Option<TypeRelationKind>,
    raw_target: String,
}

pub(super) fn encode_superclass_relation(raw_target: &str) -> String {
    encode_owner_relation("superclass", raw_target)
}

pub(super) fn encode_mixin_relation(spec: &RubyForwardMixinSpec) -> String {
    let kind = match spec.kind {
        TypeRelationKind::MixinInclude => "include",
        TypeRelationKind::MixinPrepend => "prepend",
        TypeRelationKind::MixinExtend => "extend",
        _ => unreachable!("Ruby mixin extractor only emits mixin relations"),
    };
    encode_owner_relation(kind, &spec.raw_target)
}

fn encode_owner_relation(kind: &str, raw_target: &str) -> String {
    serde_json::json!({ "kind": kind, "target": raw_target }).to_string()
}

fn decode_owner_relation(encoded: &str, expected_target: &str) -> Option<RubyOwnerRelationFact> {
    let value: serde_json::Value = serde_json::from_str(encoded).ok()?;
    let raw_target = value.get("target")?.as_str()?.to_string();
    if raw_target != expected_target {
        return None;
    }
    let kind = match value.get("kind")?.as_str()? {
        "superclass" => None,
        "include" => Some(TypeRelationKind::MixinInclude),
        "prepend" => Some(TypeRelationKind::MixinPrepend),
        "extend" => Some(TypeRelationKind::MixinExtend),
        _ => return None,
    };
    Some(RubyOwnerRelationFact { kind, raw_target })
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
    fn update_all_rebuilds_mixin_relations_from_disk() {
        let (project, analyzer) = analyzer_with_files(&[
            (
                "mixins/findable.rb",
                "module Findable\n  def find; end\nend\n",
            ),
            (
                "app/repository.rb",
                r#"
require_relative "../mixins/findable"

class Repository
  include Findable
end
"#,
            ),
        ]);

        assert!(analyzer.mixin_relations().iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.identifier() == "Findable"
                && relation.kind == TypeRelationKind::MixinInclude
        }));

        let file = |rel| ProjectFile::new(project.test_project().root_path().to_path_buf(), rel);
        std::fs::remove_file(file("mixins/findable.rb").abs_path()).unwrap();
        file("mixins/searchable.rb")
            .write("module Searchable\n  def search; end\nend\n")
            .unwrap();
        file("app/repository.rb")
            .write(
                r#"
require_relative "../mixins/searchable"

class Repository
  include Searchable
end
"#,
            )
            .unwrap();

        let updated = analyzer.update_all();
        let relations = updated.mixin_relations();
        assert!(!relations.iter().any(|relation| {
            relation.from.identifier() == "Repository" && relation.to.identifier() == "Findable"
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.identifier() == "Repository"
                && relation.to.identifier() == "Searchable"
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
