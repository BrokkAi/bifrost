//! Ruby mixin facts, modeled separately from superclass ancestry.
//!
//! `include`/`prepend` contribute a module's instance methods to a type's
//! instance-method lookup; `extend` contributes them to the class/singleton
//! lookup. These are deliberately NOT folded into `raw_supertypes` (which feeds
//! `TypeHierarchyProvider` ancestry) so consumers never see a module as a
//! superclass-style ancestor. Names are stored in the internal `$`-joined key
//! form and resolved on demand against declared types.

use super::declarations::{
    extract_name_segments, is_descendable_container, qualified_internal_name, ruby_node_text,
};
use crate::hash::HashMap;
use tree_sitter::Node;

#[derive(Clone, Copy)]
enum MixinKind {
    Include,
    Prepend,
    Extend,
}

/// The mixin modules a single type pulls in, by kind. Names are internal
/// `$`-joined references, resolved to declarations by the analyzer.
#[derive(Default, Clone)]
pub(super) struct RawMixins {
    pub(super) includes: Vec<String>,
    pub(super) prepends: Vec<String>,
    pub(super) extends: Vec<String>,
}

impl RawMixins {
    fn push(&mut self, kind: MixinKind, name: String) {
        match kind {
            MixinKind::Include => self.includes.push(name),
            MixinKind::Prepend => self.prepends.push(name),
            MixinKind::Extend => self.extends.push(name),
        }
    }

    fn is_empty(&self) -> bool {
        self.includes.is_empty() && self.prepends.is_empty() && self.extends.is_empty()
    }

    /// Folds another type fragment's mixins in (a class reopened across files
    /// contributes mixins from each fragment).
    pub(super) fn merge(&mut self, other: RawMixins) {
        self.includes.extend(other.includes);
        self.prepends.extend(other.prepends);
        self.extends.extend(other.extends);
    }
}

/// Extracts every type's direct mixin facts from a parsed Ruby file, keyed by
/// the type's internal `$`-joined fully-qualified name. Iterative, to stay
/// stack-safe on deeply nested input.
pub(super) fn extract_file_mixins(root: Node<'_>, source: &str) -> HashMap<String, RawMixins> {
    let mut out: HashMap<String, RawMixins> = HashMap::default();
    let mut stack = vec![(root, Vec::<String>::new())];

    while let Some((node, segments)) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "class" | "module" => {
                    let Some(name_node) = child.child_by_field_name("name") else {
                        continue;
                    };
                    let name_segments = extract_name_segments(name_node, source);
                    if name_segments.is_empty() {
                        continue;
                    }
                    let mut new_segments = segments.clone();
                    new_segments.extend(name_segments);

                    if let Some(body) = child.child_by_field_name("body") {
                        let mixins = collect_body_mixins(body, source);
                        if !mixins.is_empty() {
                            out.entry(new_segments.join("$")).or_default().merge(mixins);
                        }
                        stack.push((body, new_segments));
                    }
                }
                // `class << self` shares the enclosing type's namespace.
                "singleton_class" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        stack.push((body, segments.clone()));
                    }
                }
                kind if is_descendable_container(kind) => stack.push((child, segments.clone())),
                _ => {}
            }
        }
    }

    out
}

/// Collects `include`/`prepend`/`extend` calls in a type body, descending
/// control-flow containers but not nested types or methods (whose mixins belong
/// to those nested types).
fn collect_body_mixins(body: Node<'_>, source: &str) -> RawMixins {
    let mut mixins = RawMixins::default();
    let mut stack = vec![body];

    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "call" => {
                    let Some(method) = child.child_by_field_name("method") else {
                        continue;
                    };
                    let kind = match ruby_node_text(method, source).trim() {
                        "include" => MixinKind::Include,
                        "prepend" => MixinKind::Prepend,
                        "extend" => MixinKind::Extend,
                        _ => continue,
                    };
                    let Some(arguments) = child.child_by_field_name("arguments") else {
                        continue;
                    };
                    let mut arg_cursor = arguments.walk();
                    for arg in arguments.named_children(&mut arg_cursor) {
                        if matches!(arg.kind(), "constant" | "scope_resolution")
                            && let Some(name) = qualified_internal_name(arg, source)
                        {
                            mixins.push(kind, name);
                        }
                    }
                }
                kind if is_descendable_container(kind) => stack.push(child),
                _ => {}
            }
        }
    }

    mixins
}
