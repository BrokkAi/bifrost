//! Ruby's mixin facts: the parser-side extraction of `include`/`prepend`/
//! `extend` arguments out of a class or module body, and the encode/decode pair
//! that round-trips them (together with the true superclass) through the
//! analyzer's persisted `supertype_lookup_paths` column.
//!
//! The *read* of that persisted state stays in `analyzer/ruby/mixins.rs`:
//! `RubyAnalyzer::forward_owner_relation_facts` calls
//! `TreeSitterAnalyzer::fetch_file_state`, whose `Arc<FileState>` is
//! crate-private to `brokk-bifrost-analysis`. It decodes with
//! [`decode_owner_relation`] and hands the resulting [`RubyOwnerRelationFact`]s
//! back across the crate line, which is why this module owns the fact type and
//! the decoder but not the accessor.

use crate::declarations::{is_descendable_container, qualified_internal_name, ruby_node_text};
use crate::graph_support::RubySource;
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

#[derive(Clone)]
pub struct RubyForwardMixinSpec {
    pub kind: TypeRelationKind,
    pub raw_target: String,
}

pub fn raw_mixin_specs_for_type(node: Node<'_>, source: &str) -> Vec<RubyForwardMixinSpec> {
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

pub fn encode_superclass_relation(raw_target: &str) -> String {
    encode_owner_relation("superclass", raw_target)
}

pub fn encode_mixin_relation(spec: &RubyForwardMixinSpec) -> String {
    let kind = match spec.kind {
        TypeRelationKind::MixinInclude => "include",
        TypeRelationKind::MixinPrepend => "prepend",
        TypeRelationKind::MixinExtend => "extend",
        _ => unreachable!("Ruby mixin extractor only emits mixin relations"),
    };
    encode_owner_relation(kind, &spec.raw_target)
}

pub struct RubyOwnerRelationFact {
    pub kind: Option<TypeRelationKind>,
    pub raw_target: String,
}

fn encode_owner_relation(kind: &str, raw_target: &str) -> String {
    serde_json::json!({ "kind": kind, "target": raw_target }).to_string()
}

pub fn decode_owner_relation(
    encoded: &str,
    expected_target: &str,
) -> Option<RubyOwnerRelationFact> {
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

pub fn ruby_collect_mixin_relations(ruby: &dyn RubySource) -> Vec<TypeRelation> {
    let mut relations = Vec::new();
    for file in ruby.get_analyzed_files() {
        for owner in ruby
            .declarations(&file)
            .into_iter()
            .filter(|unit| unit.is_class() || unit.is_module())
        {
            for spec in ruby_forward_mixin_specs(ruby, &owner) {
                if let Some(target) = ruby_resolve_mixin_target(ruby, &file, &spec.raw_target) {
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
pub fn ruby_forward_mixin_specs(
    ruby: &dyn RubySource,
    owner: &CodeUnit,
) -> Vec<RubyForwardMixinSpec> {
    ruby.forward_owner_relation_facts(owner)
        .into_iter()
        .filter_map(|fact| {
            fact.kind.map(|kind| RubyForwardMixinSpec {
                kind,
                raw_target: fact.raw_target,
            })
        })
        .collect()
}

pub fn ruby_forward_superclass_targets(ruby: &dyn RubySource, owner: &CodeUnit) -> Vec<String> {
    ruby.forward_owner_relation_facts(owner)
        .into_iter()
        .filter(|fact| fact.kind.is_none())
        .map(|fact| fact.raw_target)
        .collect()
}

fn ruby_resolve_mixin_target(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    raw: &str,
) -> Option<CodeUnit> {
    let visible_files = ruby_visible_mixin_files(ruby, file);
    ruby.declarations(file)
        .into_iter()
        .find(|unit| ruby_type_matches(unit, raw))
        .or_else(|| {
            ruby.imported_code_units_of(file)
                .into_iter()
                .find(|unit| ruby_type_matches(unit, raw))
        })
        .or_else(|| {
            ruby.definitions(raw).find(|unit| {
                (unit.is_class() || unit.is_module()) && visible_files.contains(unit.source())
            })
        })
        .or_else(|| {
            ruby.all_declarations()
                .filter(|unit| visible_files.contains(unit.source()))
                .find(|unit| ruby_type_matches(unit, raw))
        })
}

fn ruby_visible_mixin_files(ruby: &dyn RubySource, file: &ProjectFile) -> HashSet<ProjectFile> {
    let mut files = HashSet::default();
    files.insert(file.clone());
    files.extend(
        ruby.imported_code_units_of(file)
            .into_iter()
            .map(|unit| unit.source().clone()),
    );
    files
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
