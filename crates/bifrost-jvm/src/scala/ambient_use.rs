//! Whether importing one Scala declaration can consume it without the
//! importing file spelling the imported name.
//!
//! Scala has exactly two such forms: a Scala 2 `implicit` definition and a
//! Scala 3 `given`. The compiler selects both by type out of the imported
//! scope, so `import scala.language.postfixOps` is used by writing `100 millis`
//! and `import concurrent.duration.DurationInt` by writing `42.seconds`.
//! Neither use spells the imported name, which is why the absence of that
//! spelling in the importing file proves nothing about those imports.
//!
//! This is the one place that answers the question, for two consumers that must
//! not answer it differently: the Scala structural spec, which the unused-import
//! derivation asks about a resolved workspace declaration's own syntax, and the
//! Scala source-JAR pack producer, which records the answer on every
//! declaration fact it emits so that a declaration outside the workspace can be
//! classified at all. A workspace declaration and the identical declaration
//! inside a dependency therefore get the same answer.

use brokk_bifrost_core::analyzer::model::AmbientUseRole;
use tree_sitter::Node;

/// The contextual role this declaration node carries, or `None` when the node
/// is not a declaration form whose role is established here.
///
/// `None` is unknown, never "ordinary": a consumer that turns it into
/// [`AmbientUseRole::NotAmbient`] would publish a proof this module did not
/// make. A type alias is deliberately absent for that reason -- the producer
/// emits one as a `TypeFact`, and what it aliases is not read here.
pub fn scala_declaration_ambient_use(node: Node<'_>) -> Option<AmbientUseRole> {
    match node.kind() {
        // A `given` is contextual by its declaration keyword; it carries no
        // `implicit` modifier to read.
        "given_definition" => Some(AmbientUseRole::Given),
        "function_definition"
        | "function_declaration"
        | "val_definition"
        | "val_declaration"
        | "var_definition"
        | "var_declaration"
        | "class_definition"
        | "object_definition"
        | "trait_definition"
        | "enum_definition" => Some(if scala_has_modifier(node, "implicit") {
            AmbientUseRole::Implicit
        } else {
            AmbientUseRole::NotAmbient
        }),
        _ => None,
    }
}

/// Whether this declaration writes `modifier` in its modifier list.
///
/// Scala's keyword modifiers are *anonymous* tokens of the `modifiers` node in
/// tree-sitter-scala -- only `access_modifier`, `open_modifier` and their
/// siblings are named -- and an anonymous token's `kind()` is the literal
/// itself, so matching on `kind()` reads the tree rather than scanning text.
/// A named-child walk would find none of them, which is why the inner walk
/// takes every child. A declaration can carry more than one `modifiers` node,
/// because an annotation splits the list, so the outer walk takes every one.
pub fn scala_has_modifier(node: Node<'_>, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        child.kind() == "modifiers" && {
            let mut tokens = child.walk();
            child
                .children(&mut tokens)
                .any(|token| token.kind() == modifier)
        }
    })
}
