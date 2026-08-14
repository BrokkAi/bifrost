//! Kotlin supertype extraction (#1237).
//!
//! A Kotlin class header lists its superclass, its interfaces, and any
//! interface delegation in one comma-separated *delegation specifier* list:
//!
//! ```text
//! class Child : Base(seed), Contract, Logged by logger
//! ```
//!
//! What resolution needs from each entry is the dotted type path that names
//! the supertype — `Base`, `Contract`, `Logged` — with constructor arguments,
//! type arguments, and the delegate expression stripped. The full header text
//! is not lost: it is already the declaration's rendered signature.
//!
//! The paths are recorded in `ParsedFile::raw_supertypes`, the same
//! language-neutral slot Java and Go use, so Kotlin's hierarchy can reuse the
//! shared batched declaration-facts path instead of a bespoke one.

use tree_sitter::Node;

use brokk_bifrost_core::analyzer::tree_walk::named_children;

use crate::kotlin::declarations::kotlin_identifier_text;

/// The dotted paths of the supertypes a class-like declaration names directly,
/// in source order.
///
/// A function-type specifier (`class Handler : (Int) -> String`) names no
/// declaration, so it yields no path rather than one that can never resolve.
pub fn extract_kotlin_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
    named_children(declaration)
        .into_iter()
        .filter(|child| child.kind() == "delegation_specifier")
        .filter_map(|specifier| {
            let user_type = delegation_user_type(specifier)?;
            let segments = kotlin_user_type_segments(user_type, source);
            (!segments.is_empty()).then(|| segments.join("."))
        })
        .collect()
}

/// The `user_type` a delegation specifier names, unwrapping the constructor
/// call and `by`-delegation forms that carry one.
fn delegation_user_type(specifier: Node<'_>) -> Option<Node<'_>> {
    for child in named_children(specifier) {
        match child.kind() {
            "user_type" => return Some(child),
            // `Base(seed)` and `Contract by delegate` both wrap the type in
            // another node; the constructor arguments and the delegate
            // expression are not part of the supertype's name.
            "constructor_invocation" | "explicit_delegation" => {
                if let Some(user_type) = named_children(child)
                    .into_iter()
                    .find(|inner| inner.kind() == "user_type")
                {
                    return Some(user_type);
                }
            }
            _ => {}
        }
    }
    None
}

/// The dotted segments of a `user_type`, dropping type arguments.
///
/// The grammar builds `user_type` as dot-separated simple types, so its
/// `type_identifier` children are already exactly the path segments in source
/// order — `Outer.Base<Int>` yields `["Outer", "Base"]` with no text splitting.
pub fn kotlin_user_type_segments(user_type: Node<'_>, source: &str) -> Vec<String> {
    named_children(user_type)
        .into_iter()
        .filter(|child| child.kind() == "type_identifier")
        .map(|segment| kotlin_identifier_text(segment, source).to_string())
        .filter(|segment| !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn supertypes_of(source: &str, class_name: &str) -> Vec<String> {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse Kotlin source");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if crate::kotlin::declarations::KOTLIN_CLASS_LIKE_KINDS.contains(&node.kind())
                && named_children(node).into_iter().any(|child| {
                    child.kind() == "type_identifier"
                        && kotlin_identifier_text(child, source) == class_name
                })
            {
                return extract_kotlin_supertypes(node, source);
            }
            stack.extend(named_children(node));
        }
        Vec::new()
    }

    #[test]
    fn constructor_call_and_plain_interfaces_keep_source_order() {
        assert_eq!(
            supertypes_of(
                "class Child(seed: Int) : Base(seed), Contract, Outer.Nested",
                "Child"
            ),
            vec![
                "Base".to_string(),
                "Contract".to_string(),
                "Outer.Nested".to_string(),
            ]
        );
    }

    #[test]
    fn generic_supertype_drops_type_arguments_from_the_lookup_path() {
        assert_eq!(
            supertypes_of("class Child : lib.Base<Int, String>()", "Child"),
            vec!["lib.Base".to_string()]
        );
    }

    #[test]
    fn interface_delegation_names_the_interface_not_the_delegate() {
        assert_eq!(
            supertypes_of(
                "class Child(logger: Logged) : Contract, Logged by logger",
                "Child"
            ),
            vec!["Contract".to_string(), "Logged".to_string()]
        );
    }

    #[test]
    fn objects_and_companions_carry_their_own_supertypes() {
        assert_eq!(
            supertypes_of("object Catalog : Shelver", "Catalog"),
            vec!["Shelver".to_string()]
        );
        assert_eq!(
            supertypes_of("class Owner { companion object : Factory }", "Owner"),
            Vec::<String>::new(),
            "the companion's supertype belongs to the companion, not its owner"
        );
    }

    #[test]
    fn function_type_supertype_names_no_declaration() {
        assert_eq!(
            supertypes_of("class Handler : (Int) -> String", "Handler"),
            Vec::<String>::new()
        );
    }
}
