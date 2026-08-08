//! Where a BARE Scala name can bind to a declaration this file publishes.
//!
//! The reference census grades a forward-unresolvable occurrence by asking
//! whether the file declares the name, and a bare CALL of a name the file
//! declares somewhere is its highest-confidence gap signal (#1783). "Somewhere"
//! is too weak for Scala: `type Left = A1` is a member of the TYPE namespace,
//! which no application expression can reach, and `class Oneshot(var more: ...)`
//! owns `more` only inside `Oneshot`. This index answers the reachability
//! question structurally, from the parse tree, so the census stops treating an
//! unreachable same-name declaration as evidence (#1858).
//!
//! The model is deliberately about DECLARATIONS the analyzer publishes, not
//! about every lexical binder. A local `val`, a parameter and a `case` pattern
//! binder are not CodeUnits, so they are never what a same-file name match
//! found; when one of them shadows the name, the forward resolver answers
//! `local_variable_reference` and the census excludes that adjudicated answer
//! before it asks this question.
//!
//! Reach is over-approximated on purpose: a name is reported bindable when a
//! same-file declaration of it is visible through the site's own template, an
//! enclosing template, a same-file supertype, a self-type, or an import of a
//! same-file object. Missing evidence costs an actionable tier-1 finding, while
//! extra evidence only leaves a site in the triage queue.

use std::collections::HashMap;

use tree_sitter::Node;

use crate::scala::graph::syntax::node_text;

/// Template (class/object/trait/enum) declaration kinds that own members.
const TEMPLATE_KINDS: [&str; 4] = [
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
];

/// Member kinds that declare a name in the TYPE namespace only. A bare call is
/// an application expression, so it binds in the term namespace and can never
/// reach one of these -- the zio-http `type Left = A1` artifact.
const TYPE_ONLY_DECLARATION_KINDS: [&str; 3] =
    ["type_definition", "type_declaration", "trait_definition"];

/// Container kinds whose members the analyzer does not publish: a declaration
/// under one of them is a local binder (or an anonymous-class member), never
/// the same-file CodeUnit the census matched.
const LOCAL_CONTAINER_KINDS: [&str; 13] = [
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
    "function_definition",
    "function_declaration",
    "val_definition",
    "var_definition",
    "instance_expression",
    "arguments",
    "if_expression",
    "match_expression",
    "for_expression",
];

/// Per-file scopes in which a bare Scala name binds to a declaration this file
/// publishes, keyed by the declared name.
#[derive(Debug, Default)]
pub struct ScalaBareNameDeclarationScopes {
    scopes_by_name: HashMap<String, Vec<(usize, usize)>>,
}

#[derive(Debug)]
struct ScalaTemplate {
    name: String,
    start_byte: usize,
    end_byte: usize,
    /// Simple names of the templates whose members this template reaches bare:
    /// its supertypes, its self-types, and the objects it imports from.
    opens: Vec<String>,
}

/// Where a declaration's owner puts it: at file scope, or inside a template.
#[derive(Debug, Clone, Copy)]
enum ScalaDeclarationOwner {
    File,
    Template(usize),
}

impl ScalaBareNameDeclarationScopes {
    pub fn build(root: Node<'_>, source: &str) -> Self {
        let templates = collect_templates(root, source);
        let file_scope = (root.start_byte(), root.end_byte());
        let file_opens = collect_file_opens(root, source);
        let visible_ranges = template_visible_ranges(&templates, &file_opens, file_scope);

        let mut scopes_by_name: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for (name, owner) in collect_declarations(root, source, &templates) {
            let ranges = match owner {
                ScalaDeclarationOwner::File => std::slice::from_ref(&file_scope),
                ScalaDeclarationOwner::Template(index) => visible_ranges[index].as_slice(),
            };
            scopes_by_name
                .entry(name)
                .or_default()
                .extend_from_slice(ranges);
        }
        for scopes in scopes_by_name.values_mut() {
            scopes.sort_unstable();
            scopes.dedup();
        }
        Self { scopes_by_name }
    }

    /// Whether a bare occurrence of `name` at `byte` can bind to a declaration
    /// this file publishes.
    pub fn is_bound_at(&self, name: &str, byte: usize) -> bool {
        self.scopes_by_name.get(name).is_some_and(|scopes| {
            scopes
                .iter()
                .any(|(start, end)| *start <= byte && byte < *end)
        })
    }
}

/// Every template declaration in the file, with the simple names whose members
/// it opens into its own body.
fn collect_templates(root: Node<'_>, source: &str) -> Vec<ScalaTemplate> {
    let mut templates = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if TEMPLATE_KINDS.contains(&node.kind())
            && let Some(name) = node
                .child_by_field_name("name")
                .and_then(|name| identifier_text(name, source))
        {
            templates.push(ScalaTemplate {
                name,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                opens: template_opens(node, source),
            });
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    templates
}

/// Supertype, self-type and import names a template body reaches bare.
fn template_opens(declaration: Node<'_>, source: &str) -> Vec<String> {
    let mut opens = Vec::new();
    let mut cursor = declaration.walk();
    for child in declaration.named_children(&mut cursor) {
        match child.kind() {
            "extends_clause" => opens.extend(named_segments(child, source)),
            "template_body" | "enum_body" => {
                let mut body_cursor = child.walk();
                for member in child.named_children(&mut body_cursor) {
                    if matches!(
                        member.kind(),
                        "self_type" | "import_declaration" | "export_declaration"
                    ) {
                        opens.extend(named_segments(member, source));
                    }
                }
            }
            _ => {}
        }
    }
    opens
}

/// Import names at file scope: they open an object's members into the whole
/// compilation unit.
fn collect_file_opens(root: Node<'_>, source: &str) -> Vec<String> {
    let mut opens = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "import_declaration" | "export_declaration") {
            opens.extend(named_segments(node, source));
            continue;
        }
        if !matches!(node.kind(), "compilation_unit" | "package_clause") {
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    opens
}

/// The ranges in which each template's members are reachable by a bare name:
/// its own declaration, plus every template that opens it, transitively. An
/// inherited member of an inherited member is reachable the same way, so the
/// closure walks the opener edges rather than one level of them.
fn template_visible_ranges(
    templates: &[ScalaTemplate],
    file_opens: &[String],
    file_scope: (usize, usize),
) -> Vec<Vec<(usize, usize)>> {
    let mut openers_by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, template) in templates.iter().enumerate() {
        for opened in &template.opens {
            openers_by_name
                .entry(opened.as_str())
                .or_default()
                .push(index);
        }
    }
    templates
        .iter()
        .enumerate()
        .map(|(index, template)| {
            if file_opens.contains(&template.name) {
                return vec![file_scope];
            }
            let mut ranges = Vec::new();
            let mut seen = vec![false; templates.len()];
            let mut frontier = vec![index];
            seen[index] = true;
            while let Some(current) = frontier.pop() {
                ranges.push((templates[current].start_byte, templates[current].end_byte));
                for opener in openers_by_name
                    .get(templates[current].name.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    if !seen[*opener] {
                        seen[*opener] = true;
                        frontier.push(*opener);
                    }
                }
            }
            ranges
        })
        .collect()
}

/// Every published term declaration in the file, paired with its owner scope.
fn collect_declarations(
    root: Node<'_>,
    source: &str,
    templates: &[ScalaTemplate],
) -> Vec<(String, ScalaDeclarationOwner)> {
    let mut declarations = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !TYPE_ONLY_DECLARATION_KINDS.contains(&node.kind()) {
            let names = declaration_names(node, source);
            if let Some(owner) = (!names.is_empty())
                .then(|| declaration_owner(node, templates))
                .flatten()
            {
                declarations.extend(names.into_iter().map(|name| (name, owner)));
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    declarations
}

/// The scope a declaration node belongs to, or `None` when the enclosing
/// container publishes nothing: a block, a lambda, a `case` clause and a
/// `new T { ... }` body all bind names the declaration index does not hold, so
/// a name matched there is not the same-file declaration the census found.
fn declaration_owner(node: Node<'_>, templates: &[ScalaTemplate]) -> Option<ScalaDeclarationOwner> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if TEMPLATE_KINDS.contains(&parent.kind()) {
            return templates
                .iter()
                .position(|template| {
                    template.start_byte == parent.start_byte()
                        && template.end_byte == parent.end_byte()
                })
                .map(ScalaDeclarationOwner::Template);
        }
        if matches!(parent.kind(), "compilation_unit" | "package_clause") {
            return Some(ScalaDeclarationOwner::File);
        }
        if LOCAL_CONTAINER_KINDS.contains(&parent.kind()) {
            return None;
        }
        current = parent;
    }
    None
}

/// The names a declaration binds. A `val` name can be a pattern, so every
/// identifier its name node contains is a binder.
fn declaration_names(node: Node<'_>, source: &str) -> Vec<String> {
    let name = node.child_by_field_name("name").or_else(|| {
        // A class parameter carries its name as its first named child.
        (node.kind() == "class_parameter")
            .then(|| node.named_child(0))
            .flatten()
    });
    let Some(name) = name else {
        return Vec::new();
    };
    if name.named_child_count() == 0 {
        return identifier_text(name, source).into_iter().collect();
    }
    named_segments(name, source)
}

/// Identifier and type-identifier leaves under `node`, in no particular order.
fn named_segments(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "type_identifier") {
            names.extend(identifier_text(current, source));
            continue;
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    names
}

fn identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source).trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn build(source: &str) -> ScalaBareNameDeclarationScopes {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        let tree = parser.parse(source, None).expect("Scala tree");
        ScalaBareNameDeclarationScopes::build(tree.root_node(), source)
    }

    fn byte_of(source: &str, needle: &str) -> usize {
        source.find(needle).expect("witness site")
    }

    #[test]
    fn a_type_member_never_binds_a_bare_name() {
        let source = concat!(
            "trait Combine[A1] {\n",
            "  type Left = A1\n",
            "  def use(value: Int): Any = Left(value)\n",
            "}\n",
        );
        assert!(
            !build(source).is_bound_at("Left", byte_of(source, "Left(value)")),
            "a type member is in the type namespace, not the term namespace"
        );
    }

    #[test]
    fn a_member_of_an_unrelated_template_does_not_bind() {
        let source = concat!(
            "final class Oneshot[A](var more: () => Int)\n",
            "object Stream {\n",
            "  def run(): Int = more()\n",
            "}\n",
        );
        let scopes = build(source);
        assert!(
            !scopes.is_bound_at("more", byte_of(source, "more()")),
            "a field of a class that does not enclose the site is unreachable"
        );
        assert!(
            scopes.is_bound_at("more", byte_of(source, "() => Int")),
            "the same field is reachable inside its own class"
        );
    }

    #[test]
    fn file_scope_supertype_self_type_and_import_members_bind() {
        let source = concat!(
            "trait Tokens { def ws(): Boolean = true }\n",
            "trait Rules { this: Tokens =>\n",
            "  def rule(): Boolean = ws()\n",
            "}\n",
            "trait Base { def shared(): Int = 1 }\n",
            "trait Child extends Base { def go(): Int = shared() }\n",
            "object Encoding { def table(): Int = 1 }\n",
            "object User {\n",
            "  import Encoding.*\n",
            "  def use(): Int = table()\n",
            "}\n",
        );
        let scopes = build(source);
        for (name, site) in [("ws", "ws()"), ("shared", "shared()"), ("table", "table()")] {
            assert!(
                scopes.is_bound_at(name, byte_of(source, site)),
                "`{name}` must stay reachable at `{site}`"
            );
        }
    }

    #[test]
    fn an_enclosing_template_member_binds_a_nested_site() {
        let source = concat!(
            "object Outer {\n",
            "  def helper(): Int = 1\n",
            "  class Inner {\n",
            "    def go(): Int = helper()\n",
            "  }\n",
            "}\n",
        );
        assert!(
            build(source).is_bound_at("helper", byte_of(source, "helper()")),
            "an enclosing template's member is reachable from a nested template"
        );
    }

    #[test]
    fn a_local_binder_is_not_a_published_declaration() {
        let source = concat!(
            "object Runner {\n",
            "  def run(): Int = {\n",
            "    def helper(): Int = 1\n",
            "    helper()\n",
            "  }\n",
            "}\n",
        );
        assert!(
            !build(source).is_bound_at("helper", byte_of(source, "helper()\n")),
            "a block-local def has no CodeUnit, so it is not same-file declaration evidence"
        );
    }
}
