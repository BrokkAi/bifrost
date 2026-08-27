//! Provable temporary-free classification of C++ call expressions.
//!
//! The C++ lowering marks a callable as having RAII boundaries when its body
//! contains any call expression, because a call can materialize a class-typed
//! temporary whose destructor runs at the end of the full expression. That
//! over-approximation is honest for unknown callees, but it is refutable for
//! an exact local free-function call whose signature proves that neither the
//! returned value nor any parameter conversion can materialize an automatic
//! object that needs destruction (#1984, under #1951).
//!
//! [`CppTemporaryFreeCallIndex`] holds the per-file proof. It stays strictly
//! conservative: any preprocessor content, any second declaration of the
//! name, any non-callee use of the name (function pointers, address-taking,
//! shadowing locals, member declarations), templates, overloads, virtual or
//! member call syntax, default arguments, variadic parameters, and non-trivial
//! argument expressions all keep the call unproven, so the RAII gap stays.

use tree_sitter::Node;

use crate::declarations::node_text;
use brokk_bifrost_core::hash::{HashMap, HashSet};

/// Base type specifiers that name provably trivially destructible types.
/// `type_identifier` names (class types, aliases) stay unproven.
const TRIVIAL_TYPE_KINDS: &[&str] = &["primitive_type", "sized_type_specifier"];

/// Per-name evidence collected from one translation unit.
#[derive(Default)]
struct NameFacts {
    /// Count of top-level free-function declarations of this name.
    declarations: usize,
    /// Whether the single recorded declaration has a provably temporary-free
    /// signature. Meaningful only while `declarations == 1`.
    trivial_signature: bool,
    /// A use of the name outside a callee or its own declarator name
    /// position: the name may denote something other than the recorded free
    /// function at some call site.
    poisoned: bool,
}

/// The per-file index answering whether a call expression provably
/// materializes no automatic object that needs destruction.
pub struct CppTemporaryFreeCallIndex<'a> {
    source: &'a str,
    /// `None` when the file itself is unprovable (any preprocessor content
    /// can introduce declarations this index cannot see).
    facts: Option<HashMap<&'a str, NameFacts>>,
    /// Names this file declares only as arrays of a provably trivially
    /// destructible element type. Subscripting one is the built-in subscript
    /// operator -- an array type has no user-declarable `operator[]` -- and it
    /// yields an lvalue of that element type, so such an argument materializes
    /// no more than a plain identifier does.
    trivial_arrays: HashSet<&'a str>,
    /// Named nodes visited while building, for work accounting.
    visited_nodes: usize,
}

impl<'a> CppTemporaryFreeCallIndex<'a> {
    /// Build the index from a parsed C++ translation unit.
    pub fn build(source: &'a str, root: Node<'a>) -> Self {
        let mut facts: HashMap<&'a str, NameFacts> = HashMap::default();
        let mut trivial_arrays: HashSet<&'a str> = HashSet::default();
        let mut rejected_arrays: HashSet<&'a str> = HashSet::default();
        let mut declaration_names: HashSet<usize> = HashSet::default();
        let mut provable_file = true;
        let mut visited_nodes = 0usize;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            visited_nodes += 1;
            let kind = node.kind();
            if kind.starts_with("preproc_") {
                // An include or macro can declare overloads and names this
                // index cannot see; nothing in the file stays provable.
                provable_file = false;
            }
            if matches!(
                kind,
                "declaration" | "parameter_declaration" | "field_declaration"
            ) {
                record_object_declarations(node, source, &mut trivial_arrays, &mut rejected_arrays);
            }
            if let Some(candidate) = free_function_candidate(node) {
                declaration_names.insert(candidate.name.id());
                let name = node_text(candidate.name, source);
                let entry = facts.entry(name).or_default();
                entry.declarations += 1;
                entry.trivial_signature = candidate.trivial_signature;
            }
            if matches!(
                kind,
                "identifier" | "field_identifier" | "type_identifier" | "namespace_identifier"
            ) && !declaration_names.contains(&node.id())
                && !(kind == "identifier" && is_callee_position(node))
            {
                facts.entry(node_text(node, source)).or_default().poisoned = true;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        for name in &rejected_arrays {
            trivial_arrays.remove(name);
        }
        Self {
            source,
            facts: provable_file.then_some(facts),
            trivial_arrays,
            visited_nodes,
        }
    }

    /// Named nodes visited while building, for lowering work accounting.
    pub fn visited_nodes(&self) -> usize {
        self.visited_nodes
    }

    /// Whether `call` provably materializes no automatic object that needs
    /// destruction: the callee is one exact, unshadowed, non-template local
    /// free function whose return and parameter types are provably trivially
    /// destructible, and every argument is a trivially shaped expression.
    /// Nested call arguments are accepted here because the caller's scan
    /// classifies each nested call expression on its own.
    pub fn call_is_provably_temporary_free(&self, call: Node<'_>) -> bool {
        debug_assert_eq!(call.kind(), "call_expression");
        let Some(facts) = &self.facts else {
            return false;
        };
        let Some(callee) = call.child_by_field_name("function") else {
            return false;
        };
        if callee.kind() != "identifier" {
            return false;
        }
        let Some(name) = facts.get(node_text(callee, self.source)) else {
            return false;
        };
        if name.declarations != 1 || !name.trivial_signature || name.poisoned {
            return false;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return false;
        };
        let mut cursor = arguments.walk();
        arguments
            .named_children(&mut cursor)
            .all(|argument| self.argument_is_trivially_shaped(argument))
    }

    /// Argument shapes that cannot materialize a class-typed temporary given a
    /// provably trivial parameter list: names, literals, member accesses
    /// through `.`, subscripts of a provably trivial array, and nested calls
    /// (which the caller's scan classifies independently).
    fn argument_is_trivially_shaped(&self, argument: Node<'_>) -> bool {
        let mut node = argument;
        loop {
            match node.kind() {
                // Naming a member of an existing object with `.` yields an
                // lvalue subobject and runs no user code -- `operator.` cannot
                // be declared in C++ -- so the argument is exactly as
                // temporary-free as the plain identifier below. `->` may
                // resolve to a user-defined `operator->`, which is a call
                // returning whatever it likes.
                "field_expression" => {
                    let Some(base) = node.child_by_field_name("argument") else {
                        return false;
                    };
                    let mut cursor = node.walk();
                    if node
                        .children(&mut cursor)
                        .any(|child| matches!(child.kind(), "->" | "->*"))
                    {
                        return false;
                    }
                    node = base;
                }
                "subscript_expression" => {
                    let Some(base) = node.child_by_field_name("argument") else {
                        return false;
                    };
                    if base.kind() != "identifier"
                        || !self.trivial_arrays.contains(node_text(base, self.source))
                    {
                        return false;
                    }
                    let mut cursor = node.walk();
                    let indices = node
                        .named_children(&mut cursor)
                        .filter(|child| child.id() != base.id())
                        .collect::<Vec<_>>();
                    if !indices
                        .iter()
                        .all(|index| self.subscript_is_trivially_shaped(*index))
                    {
                        return false;
                    }
                    node = base;
                }
                "parenthesized_expression" => {
                    let mut cursor = node.walk();
                    let mut children = node.named_children(&mut cursor);
                    let (Some(inner), None) = (children.next(), children.next()) else {
                        return false;
                    };
                    node = inner;
                }
                "identifier"
                | "number_literal"
                | "char_literal"
                | "string_literal"
                | "concatenated_string"
                | "true"
                | "false"
                | "null"
                | "nullptr" => return true,
                "call_expression" => return true,
                _ => return false,
            }
        }
    }

    /// A subscript operand, which the C++ grammar wraps in a
    /// `subscript_argument_list` and the C grammar leaves bare.
    fn subscript_is_trivially_shaped(&self, node: Node<'_>) -> bool {
        if node.kind() != "subscript_argument_list" {
            return self.argument_is_trivially_shaped(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        children
            .iter()
            .all(|child| self.argument_is_trivially_shaped(*child))
    }
}

/// Record whether `declaration` declares names as arrays of a provably
/// trivially destructible element type.
///
/// A name declared any other way anywhere in the file is rejected: this index
/// is name-based and has no scopes, so a second meaning for one name makes
/// every occurrence of it unprovable.
fn record_object_declarations<'a>(
    declaration: Node<'a>,
    source: &'a str,
    trivial_arrays: &mut HashSet<&'a str>,
    rejected: &mut HashSet<&'a str>,
) {
    let element_is_trivial = declaration
        .child_by_field_name("type")
        .is_some_and(|node| TRIVIAL_TYPE_KINDS.contains(&node.kind()));
    let mut cursor = declaration.walk();
    let declarators = declaration
        .children_by_field_name("declarator", &mut cursor)
        .collect::<Vec<_>>();
    for declarator in declarators {
        let mut current = declarator;
        let mut is_array = false;
        // A declarator this walk does not recognize -- a function, a pointer, a
        // reference -- names no array, and it must not stop the other
        // declarators of the same declaration from being recorded.
        let name = loop {
            match current.kind() {
                "array_declarator" | "init_declarator" => {
                    is_array |= current.kind() == "array_declarator";
                    match current.child_by_field_name("declarator") {
                        Some(inner) => current = inner,
                        None => break None,
                    }
                }
                "identifier" => break Some(current),
                _ => break None,
            }
        };
        let Some(name) = name else {
            continue;
        };
        let name = node_text(name, source);
        if is_array && element_is_trivial && !rejected.contains(name) {
            trivial_arrays.insert(name);
        } else {
            rejected.insert(name);
        }
    }
}

/// A top-level free-function declaration and whether its signature proves
/// temporary-free calls.
struct FreeFunctionCandidate<'a> {
    name: Node<'a>,
    trivial_signature: bool,
}

fn free_function_candidate(node: Node<'_>) -> Option<FreeFunctionCandidate<'_>> {
    if !matches!(node.kind(), "function_definition" | "declaration") {
        return None;
    }
    // Only translation-unit scope: a template_declaration, class, or
    // namespace parent leaves the name to the poisoning walk.
    if node.parent()?.kind() != "translation_unit" {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let mut declarator = node.child_by_field_name("declarator")?;
    let mut indirect_return = false;
    while matches!(
        declarator.kind(),
        "pointer_declarator" | "reference_declarator"
    ) {
        indirect_return = true;
        declarator = declarator.child_by_field_name("declarator")?;
    }
    if declarator.kind() != "function_declarator" {
        return None;
    }
    let name = declarator.child_by_field_name("declarator")?;
    if name.kind() != "identifier" {
        return None;
    }
    // A pointer or reference return is trivially destructible regardless of
    // the pointee; otherwise the written base type must prove it.
    let trivial_return = indirect_return || TRIVIAL_TYPE_KINDS.contains(&type_node.kind());
    let trivial_signature = trivial_return
        && declarator
            .child_by_field_name("parameters")
            .is_some_and(|parameters| {
                let mut cursor = parameters.walk();
                parameters
                    .named_children(&mut cursor)
                    .all(parameter_is_provably_trivial)
            });
    Some(FreeFunctionCandidate {
        name,
        trivial_signature,
    })
}

/// A parameter that provably cannot bind a class-typed temporary: a written
/// trivially destructible base type, or a pointer at some indirection level.
/// Default arguments and variadic parameters stay unproven.
fn parameter_is_provably_trivial(parameter: Node<'_>) -> bool {
    if parameter.kind() != "parameter_declaration" {
        return false;
    }
    let Some(type_node) = parameter.child_by_field_name("type") else {
        return false;
    };
    if TRIVIAL_TYPE_KINDS.contains(&type_node.kind()) {
        return true;
    }
    // A pointer parameter only ever binds a pointer value; any conversion
    // from a class argument yields a pointer prvalue, never a class
    // temporary. A plain reference to a class type can bind a converted
    // temporary, so it stays unproven.
    parameter
        .child_by_field_name("declarator")
        .is_some_and(declarator_contains_pointer)
}

fn declarator_contains_pointer(declarator: Node<'_>) -> bool {
    let mut stack = vec![declarator];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "pointer_declarator" | "abstract_pointer_declarator"
        ) {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn is_callee_position(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node.id())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse_cpp(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("cpp language");
        parser.parse(source, None).expect("cpp tree")
    }

    /// Every `call_expression` in `source`, paired with its provability.
    fn classified_calls(source: &str) -> Vec<(String, bool)> {
        let tree = parse_cpp(source);
        let index = CppTemporaryFreeCallIndex::build(source, tree.root_node());
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                calls.push((
                    node_text(node, source).to_string(),
                    index.call_is_provably_temporary_free(node),
                ));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        calls.sort();
        calls
    }

    fn assert_calls(source: &str, expected: &[(&str, bool)]) {
        let mut expected = expected
            .iter()
            .map(|(text, provable)| (text.to_string(), *provable))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(classified_calls(source), expected);
    }

    /// The #1951 balanced positive: exact local free-function calls with
    /// provably trivial signatures are temporary-free.
    #[test]
    fn exact_local_free_function_calls_are_provable() {
        assert_calls(
            r#"
const char *dfb_source() {
    return "tainted";
}

void dfb_sink(const char *value) {}

void run() {
    dfb_sink(dfb_source());
}
"#,
            &[("dfb_source()", true), ("dfb_sink(dfb_source())", true)],
        );
    }

    /// The #1951 balanced negative keeps both calls provable: a discarded
    /// trivial result and a literal argument.
    #[test]
    fn discarded_result_and_literal_argument_are_provable() {
        assert_calls(
            r#"
const char *dfb_source() {
    return "tainted";
}

void dfb_sink(const char *value) {}

void run() {
    dfb_source();
    dfb_sink("clean");
}
"#,
            &[("dfb_source()", true), ("dfb_sink(\"clean\")", true)],
        );
    }

    /// A prototype without a body still proves the signature.
    #[test]
    fn local_prototype_is_provable() {
        assert_calls(
            r#"
const char *dfb_source();

void run() {
    dfb_source();
}
"#,
            &[("dfb_source()", true)],
        );
    }

    /// Near miss: overloaded functions stay unproven even when every
    /// overload is trivially typed.
    #[test]
    fn overloaded_functions_stay_unproven() {
        assert_calls(
            r#"
const char *dfb_source() { return "a"; }
const char *dfb_source(int selector) { return "b"; }

void run() {
    dfb_source();
}
"#,
            &[("dfb_source()", false)],
        );
    }

    /// Near miss: a call through a function pointer stays unproven; the
    /// pointer declaration is a non-callee use of the name.
    #[test]
    fn function_pointer_calls_stay_unproven() {
        assert_calls(
            r#"
const char *real_source() { return "a"; }

void run() {
    const char *(*dfb_source)() = real_source;
    dfb_source();
}
"#,
            &[("dfb_source()", false)],
        );
    }

    /// Near miss: member call syntax stays unproven, so virtual dispatch
    /// keeps its RAII gap.
    #[test]
    fn virtual_member_calls_stay_unproven() {
        assert_calls(
            r#"
struct Producer {
    virtual const char *dfb_source() { return "a"; }
};

void run(Producer *producer) {
    producer->dfb_source();
}
"#,
            &[("producer->dfb_source()", false)],
        );
    }

    /// Near miss: an unqualified call that a same-named member could
    /// capture stays unproven; the member declaration poisons the name.
    #[test]
    fn member_declaration_poisons_unqualified_calls() {
        assert_calls(
            r#"
const char *dfb_source() { return "a"; }

struct Wrapper {
    const char *dfb_source() { return "b"; }
    const char *read() { return dfb_source(); }
};
"#,
            &[("dfb_source()", false)],
        );
    }

    /// Near miss: template functions stay unproven, with or without
    /// explicit template arguments.
    #[test]
    fn template_functions_stay_unproven() {
        assert_calls(
            r#"
template <typename T>
T dfb_source() { return T(); }

void run() {
    dfb_source<const char *>();
}
"#,
            &[("dfb_source<const char *>()", false), ("T()", false)],
        );
    }

    /// Near miss: a class return type may construct a destructible
    /// temporary; the written base type is not provably trivial.
    #[test]
    fn class_return_types_stay_unproven() {
        assert_calls(
            r#"
struct Token {};
Token dfb_source() { return Token{}; }

void run() {
    dfb_source();
}
"#,
            &[("dfb_source()", false)],
        );
    }

    /// Near miss: a const reference parameter of class type can bind a
    /// converted temporary.
    #[test]
    fn class_reference_parameters_stay_unproven() {
        assert_calls(
            r#"
struct Token {};
void dfb_sink(const Token &value) {}

void run() {
    dfb_sink(Token{});
}
"#,
            &[("dfb_sink(Token{})", false)],
        );
    }

    /// Near miss: default arguments can evaluate arbitrary expressions.
    #[test]
    fn default_arguments_stay_unproven() {
        assert_calls(
            r#"
void dfb_sink(const char *value = "d") {}

void run() {
    dfb_sink();
}
"#,
            &[("dfb_sink()", false)],
        );
    }

    /// Near miss: a non-trivial argument expression can materialize a
    /// class-typed temporary via overloaded operators, even when the
    /// callee's parameters are trivially typed.
    #[test]
    fn complex_argument_expressions_stay_unproven() {
        assert_calls(
            r#"
void dfb_sink(const char *value) {}

void run(const char *left) {
    dfb_sink(left + 1);
}
"#,
            &[("dfb_sink(left + 1)", false)],
        );
    }

    /// Near miss: any preprocessor content can introduce declarations this
    /// index cannot see, so nothing in the file is provable.
    #[test]
    fn preprocessor_content_makes_the_file_unprovable() {
        assert_calls(
            r#"
#include <string>

const char *dfb_source() { return "a"; }

void run() {
    dfb_source();
}
"#,
            &[("dfb_source()", false)],
        );
    }

    /// Near miss: taking the function's address is a non-callee use, so a
    /// pointer alias can no longer be told apart from the direct call.
    #[test]
    fn address_taken_names_stay_unproven() {
        assert_calls(
            r#"
const char *dfb_source() { return "a"; }

void keep(const char *(*pointer)()) {}

void run() {
    keep(&dfb_source);
    dfb_source();
}
"#,
            &[("dfb_source()", false), ("keep(&dfb_source)", false)],
        );
    }

    /// Pointer returns and pointer parameters are trivial regardless of the
    /// pointee type; nested parentheses stay transparent.
    #[test]
    fn pointer_indirection_over_class_types_is_provable() {
        assert_calls(
            r#"
struct Token;
Token *dfb_source() { return nullptr; }

void dfb_sink(Token *value) {}

void run() {
    dfb_sink((dfb_source()));
}
"#,
            &[("dfb_source()", true), ("dfb_sink((dfb_source()))", true)],
        );
    }

    /// #2666: an lvalue subobject named through `.`, and a subscript of a name
    /// this file declares only as an array of arithmetic element type, are the
    /// built-in operators. Both yield an lvalue and run no user code, so they
    /// are exactly as temporary-free as the identifier they are rooted at.
    #[test]
    fn member_access_and_trivial_array_subscript_arguments_are_provable() {
        assert_calls(
            r#"
struct Holder {
    int value;
};

void consume(int value) {}

void run() {
    Holder holder;
    int values[2];
    consume(holder.value);
    consume(values[0]);
}
"#,
            &[
                ("consume(holder.value)", true),
                ("consume(values[0])", true),
            ],
        );
    }

    /// Near miss: a subscript whose base this file does not declare as an
    /// array of arithmetic element type may resolve through a user-defined
    /// `operator[]`, which can materialize a class-typed temporary.
    #[test]
    fn subscript_of_an_unproven_base_stays_unproven() {
        assert_calls(
            r#"
struct Table {
    int &operator[](int index);
};

void consume(int value) {}

void run(Table table) {
    consume(table[0]);
}
"#,
            &[("consume(table[0])", false)],
        );
    }
}
