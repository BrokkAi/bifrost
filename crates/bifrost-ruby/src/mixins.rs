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
use brokk_bifrost_core::analyzer::type_relations::TypeRelationKind;
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
