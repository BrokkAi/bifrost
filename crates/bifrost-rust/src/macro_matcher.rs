//! Structured `macro_rules!` matcher-to-invocation binding.
//!
//! This module maps tokens in a macro invocation argument group onto the
//! selected arm's matcher bindings. It does not expand macros and it does not
//! consult imports. Callers that have an indexed `macro_rules!` definition
//! feed that definition's syntax tree and the invocation argument `token_tree`.

use crate::declarations::rust_node_text;
use crate::lexical_scope::parse_rust_tree;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::semantic_diagnostics::contains_node as node_within;
use brokk_bifrost_core::analyzer::tree_walk::find_ancestor;
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

#[path = "macro_canonical_matcher.rs"]
mod canonical;
pub use canonical::{match_captured_macro_rules, match_macro_rules};

pub use brokk_bifrost_core::analyzer::rust_facts::{MacroFragmentKind, MacroIdentRole};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacroBinding {
    pub name: String,
    pub fragment: MacroFragmentKind,
    pub start_byte: usize,
    pub end_byte: usize,
    pub repetition_path: Vec<usize>,
    pub ident_role: Option<MacroIdentRole>,
}

impl MacroBinding {
    pub fn contains(&self, start: usize, end: usize) -> bool {
        Range {
            start_byte: self.start_byte,
            end_byte: self.end_byte,
            start_line: 0,
            end_line: 0,
        }
        .contains(&Range {
            start_byte: start,
            end_byte: end,
            start_line: 0,
            end_line: 0,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacroArmMatch {
    pub arm_index: usize,
    pub bindings: Vec<MacroBinding>,
}

impl MacroArmMatch {
    pub fn binding_containing(&self, start: usize, end: usize) -> Option<&MacroBinding> {
        self.bindings
            .iter()
            .filter(|binding| binding.contains(start, end))
            .min_by_key(|binding| binding.end_byte - binding.start_byte)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroMatchError {
    NotMacroRules,
    EmptyRules,
    NoArmMatched,
    Interrupted,
}

/// The exported macro definitions visible to procedures lowered from one file.
#[derive(Clone, Debug)]
pub struct ExportedMacroDefinitions<'tree> {
    definitions: Vec<Node<'tree>>,
}

impl<'tree> ExportedMacroDefinitions<'tree> {
    /// Filter macro definitions discovered during the file's charged syntax walk.
    pub fn from_candidates(candidates: Vec<Node<'tree>>, source: &str) -> Self {
        let mut cfg_cache = HashMap::default();
        let definitions = candidates
            .into_iter()
            .filter(|node| {
                node.kind() == "macro_definition"
                    && !crate::ownership::has_macro_ancestor(*node)
                    && node.child_by_field_name("name").is_some_and(|name| {
                        !name.is_missing()
                            && !name.is_error()
                            && crate::declarations::rust_item_has_simple_attribute(
                                *node,
                                source,
                                "macro_export",
                            )
                    })
                    && macro_definition_is_unconditionally_active(*node, source, &mut cfg_cache)
            })
            .collect();
        Self { definitions }
    }

    pub(crate) fn from_root(root: Node<'tree>, source: &str) -> Self {
        let mut pending = vec![(root, None)];
        let mut definitions = Vec::new();
        while let Some((node, parent)) = pending.pop() {
            if matches!(node.kind(), "macro_invocation" | "token_tree")
                || crate::lexical_scope::rust_cfg_condition_with_parent(node, parent, source)
                    != crate::lexical_scope::RustCfgCondition::Always
            {
                continue;
            }
            if node.kind() == "macro_definition" {
                if node.child_by_field_name("name").is_some_and(|name| {
                    !name.is_missing()
                        && !name.is_error()
                        && crate::declarations::rust_item_has_simple_attribute(
                            node,
                            source,
                            "macro_export",
                        )
                }) {
                    definitions.push(node);
                }
                continue;
            }
            let mut cursor = node.walk();
            pending.extend(
                node.named_children(&mut cursor)
                    .map(|child| (child, Some(node))),
            );
        }
        Self { definitions }
    }

    fn unique_named(&self, name: &str, source: &str) -> Option<Node<'tree>> {
        let mut candidates = self.definitions.iter().copied().filter(|node| {
            node.child_by_field_name("name")
                .is_some_and(|node| rust_node_text(node, source) == name)
        });
        let definition = candidates.next()?;
        candidates.next().is_none().then_some(definition)
    }
}

fn macro_definition_is_unconditionally_active(
    mut node: Node<'_>,
    source: &str,
    cfg_cache: &mut HashMap<usize, crate::lexical_scope::RustCfgCondition>,
) -> bool {
    while node.kind() != "source_file" {
        let condition = cfg_cache
            .entry(node.id())
            .or_insert_with(|| crate::lexical_scope::rust_cfg_condition(node, source));
        if *condition != crate::lexical_scope::RustCfgCondition::Always {
            return false;
        }
        let Some(parent) = crate::syntax::parent_outside_attributes(node) else {
            return true;
        };
        node = parent;
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroNamespaceEvidence {
    Type,
    Value,
    Pattern,
    Declaration,
    NoNamespace,
    Interior(MacroFragmentKind),
}

pub(crate) fn is_macro_rules_definition(definition: Node<'_>) -> bool {
    if definition.kind() != "macro_definition" {
        return false;
    }
    let mut cursor = definition.walk();
    definition
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "macro_rules" | "macro_rules!"))
}

pub fn ident_transcriber_role(
    arm_right: Node<'_>,
    definition_source: &str,
    metavar: &str,
) -> MacroIdentRole {
    let wanted = metavar_spelling(metavar);
    let mut uses = Vec::new();
    let mut stack = vec![arm_right];
    while let Some(node) = stack.pop() {
        if node.kind() == "metavariable"
            && metavar_spelling(rust_node_text(node, definition_source)) == wanted
        {
            uses.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    if uses.is_empty() {
        return MacroIdentRole::Unused;
    }
    if let Some(role) = ident_role_from_reparsed_transcriber(arm_right, definition_source, &wanted)
    {
        return role;
    }
    let mut roles = Vec::new();
    for use_node in uses {
        roles.push(ident_role_from_siblings(use_node));
    }
    collapse_ident_roles(&roles)
}

pub fn enclosing_macro_invocation_for_argument(mut node: Node<'_>) -> Option<Node<'_>> {
    let focused = node;
    loop {
        if node.kind() == "macro_invocation" {
            let in_name = node.child_by_field_name("macro").is_some_and(|macro_name| {
                focused.start_byte() >= macro_name.start_byte()
                    && focused.end_byte() <= macro_name.end_byte()
            });
            return (!in_name).then_some(node);
        }
        node = node.parent()?;
    }
}

/// Replay the nearest textually visible source macro without consulting a
/// workspace route. Definitions outside this source remain a selected boundary.
pub(crate) fn crate_root_macro_invocation_name<'source>(
    invocation: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let head = invocation.child_by_field_name("macro")?;
    if head.kind() != "scoped_identifier"
        || crate::graph_support::rust_path_is_leading_absolute(head)
    {
        return None;
    }
    let path = head.child_by_field_name("path")?;
    if path.kind() != "crate" {
        return None;
    }
    head.child_by_field_name("name")
        .map(|name| rust_node_text(name, source))
}

pub fn match_local_macro_invocation(
    invocation: Node<'_>,
    source: &str,
) -> Option<Result<MacroArmMatch, MacroMatchError>> {
    match_local_macro_invocation_using_definitions(invocation, source, None, invocation)
}

pub fn match_local_macro_invocation_with_definitions<'tree>(
    invocation: Node<'tree>,
    source: &str,
    exported_definitions: &ExportedMacroDefinitions<'tree>,
    lexical_context: Node<'tree>,
) -> Option<Result<MacroArmMatch, MacroMatchError>> {
    match_local_macro_invocation_using_definitions(
        invocation,
        source,
        Some(exported_definitions),
        lexical_context,
    )
}

/// Same-file evidence that a macro name is not supplied solely by the
/// standard prelude. Conditional declarations remain possible shadows.
/// Imports use the parser's binding projection: grouped `self`, globs and
/// unnamed imports do not bind a macro under the requested name.
pub fn macro_invocation_is_locally_bound<'tree>(
    invocation: Node<'tree>,
    source: &str,
    exported_definitions: &ExportedMacroDefinitions<'tree>,
    lexical_context: Node<'tree>,
) -> bool {
    use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
    let Some(name) =
        crate::declarations::rust_unqualified_macro_invocation_name(invocation, source)
    else {
        return false;
    };
    let name = strip_raw_identifier_prefix(name);
    if exported_definitions.definitions.iter().any(|definition| {
        definition
            .child_by_field_name("name")
            .is_some_and(|declared| {
                strip_raw_identifier_prefix(rust_node_text(declared, source)) == name
            })
    }) {
        return true;
    }
    macro_lexical_scopes(invocation, lexical_context).any(|scope| {
        let mut cursor = scope.walk();
        scope.named_children(&mut cursor).any(|item| {
            if item.kind() == "macro_definition" && item.end_byte() <= invocation.start_byte() {
                return item.child_by_field_name("name").is_some_and(|declared| {
                    strip_raw_identifier_prefix(rust_node_text(declared, source)) == name
                });
            }
            item.kind() == "use_declaration"
                && crate::imports::rust_imports_with_visibility_from_use_declaration(item, source)
                    .iter()
                    .any(|import| {
                        !import.module_self
                            && crate::imports::rust_import_binding_name(&import.info)
                                .named()
                                .is_some_and(|bound| strip_raw_identifier_prefix(bound) == name)
                    })
        })
    })
}

/// Fragment scopes precede the real source scope that contains their anchor.
fn macro_lexical_scopes<'tree>(
    invocation: Node<'tree>,
    lexical_context: Node<'tree>,
) -> impl Iterator<Item = Node<'tree>> {
    let mut parent = invocation.parent();
    let mut outer_context = (lexical_context.id() != invocation.id()).then_some(lexical_context);
    std::iter::from_fn(move || {
        let scope = parent?;
        parent = scope.parent().or_else(|| outer_context.take());
        Some(scope)
    })
}

fn match_local_macro_invocation_using_definitions<'tree>(
    invocation: Node<'tree>,
    source: &str,
    exported_definitions: Option<&ExportedMacroDefinitions<'tree>>,
    lexical_context: Node<'tree>,
) -> Option<Result<MacroArmMatch, MacroMatchError>> {
    let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)?;
    let definition =
        local_macro_definition(invocation, source, exported_definitions, lexical_context)?;
    Some(match_syntax_macro_rules(
        definition, source, arguments, source,
    ))
}

fn local_macro_definition<'tree>(
    invocation: Node<'tree>,
    source: &str,
    exported_definitions: Option<&ExportedMacroDefinitions<'tree>>,
    lexical_context: Node<'tree>,
) -> Option<Node<'tree>> {
    let textual_name =
        crate::declarations::rust_unqualified_macro_invocation_name(invocation, source);
    let name = textual_name.or_else(|| crate_root_macro_invocation_name(invocation, source))?;
    let mut root = invocation;
    // Match through the same original-coordinate scopes as explicit imports.
    for scope in macro_lexical_scopes(invocation, lexical_context) {
        let mut cursor = scope.walk();
        let definition = scope
            .named_children(&mut cursor)
            .filter(|child| {
                textual_name.is_some()
                    && child.kind() == "macro_definition"
                    && child.end_byte() <= invocation.start_byte()
                    && child
                        .child_by_field_name("name")
                        .is_some_and(|node| rust_node_text(node, source) == name)
            })
            .last();
        if let Some(definition) = definition {
            if crate::lexical_scope::rust_cfg_condition(definition, source)
                != crate::lexical_scope::RustCfgCondition::Always
            {
                return None;
            }
            return Some(definition);
        }
        root = scope;
    }
    if let Some(exported_definitions) = exported_definitions {
        exported_definitions.unique_named(name, source)
    } else {
        ExportedMacroDefinitions::from_root(root, source).unique_named(name, source)
    }
}

/// A matched arm can authorize ordinary item replay even if an unselected
/// arm is not a passthrough. Require all input tokens to belong to the item
/// captures, since declaration replay reparses the original input as a whole.
/// The inventory predicate cannot prove this: repetition separators are not
/// emitted as child nodes by the grammar and can sit outside Item captures.
pub(crate) fn local_macro_invocation_replays_items_only(
    invocation: Node<'_>,
    source: &str,
    exported_definitions: &ExportedMacroDefinitions<'_>,
) -> bool {
    let Some(arguments) = crate::declarations::rust_macro_invocation_arguments(invocation) else {
        return false;
    };
    let Some(definition) =
        local_macro_definition(invocation, source, Some(exported_definitions), invocation)
    else {
        return false;
    };
    let mut cursor = definition.walk();
    let item_arms = definition
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "macro_rule")
        .map(|rule| {
            crate::declarations::rust_macro_rule_expands_to_its_arguments_only(rule, source)
        })
        .collect::<Vec<_>>();
    // Ordinary expression/type macros cannot authorize item replay. Avoid
    // matching (and reparsing their captures) a second time for this question.
    if !item_arms.iter().any(|item_arm| *item_arm) {
        return false;
    }
    let Ok(matched) = match_syntax_macro_rules(definition, source, arguments, source) else {
        return false;
    };
    if !item_arms[matched.arm_index] {
        return false;
    }
    // The arguments-only rule refuses meta bindings and separated repetitions,
    // so a successful match of an item-only arm leaves every input token inside
    // an Item capture. A failure here means that rule has a hole.
    debug_assert!(
        item_captures_cover_input(arguments, &matched),
        "item-only arm {} left input outside its Item captures: {:?}",
        matched.arm_index,
        &source[arguments.byte_range()]
    );
    true
}

fn item_captures_cover_input(arguments: Node<'_>, matched: &MacroArmMatch) -> bool {
    let mut pending = interior_tokens(arguments).0;
    while let Some(node) = pending.pop() {
        if node.is_extra() {
            continue;
        }
        if matched.bindings.iter().any(|binding| {
            binding.fragment == MacroFragmentKind::Item
                && binding.contains(node.start_byte(), node.end_byte())
        }) {
            continue;
        }
        if node.child_count() == 0 {
            return false;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    true
}

/// Read root-path macro authority once from real syntax, excluding generated
/// token trees and scopes whose activation is not source-owned.
pub(crate) fn exported_macro_definition_nodes<'tree>(
    root: Node<'tree>,
    source: &str,
) -> Vec<Node<'tree>> {
    ExportedMacroDefinitions::from_root(root, source).definitions
}

pub fn classify_fragment_interior(
    fragment: MacroFragmentKind,
    fragment_source: &str,
    rel_start: usize,
    rel_end: usize,
) -> Option<MacroNamespaceEvidence> {
    let (wrapped, prefix_len) = wrap_fragment(fragment, fragment_source);
    let tree = parse_rust_tree(&wrapped)?;
    let target_start = prefix_len + rel_start;
    let target_end = prefix_len + rel_end;
    let node = tree
        .root_node()
        .descendant_for_byte_range(target_start, target_end)?;
    let named = node
        .child_by_field_name("name")
        .filter(|name| name.start_byte() == target_start && name.end_byte() == target_end);
    Some(namespace_from_parsed_ident(named.unwrap_or(node)))
}

fn namespace_from_parsed_ident(node: Node<'_>) -> MacroNamespaceEvidence {
    match parsed_dummy_ident_role(node) {
        MacroIdentRole::Type => MacroNamespaceEvidence::Type,
        MacroIdentRole::Value => MacroNamespaceEvidence::Value,
        MacroIdentRole::Pattern => MacroNamespaceEvidence::Pattern,
        MacroIdentRole::Declaration => MacroNamespaceEvidence::Declaration,
        MacroIdentRole::Mixed | MacroIdentRole::Unused | MacroIdentRole::Undetermined => {
            if node.kind() == "type_identifier" {
                MacroNamespaceEvidence::Type
            } else {
                MacroNamespaceEvidence::Value
            }
        }
    }
}

pub fn token_namespace_evidence(
    arm_match: &MacroArmMatch,
    token_start: usize,
    token_end: usize,
) -> Option<MacroNamespaceEvidence> {
    let binding = arm_match.binding_containing(token_start, token_end)?;
    let whole = token_start == binding.start_byte && token_end == binding.end_byte;
    match binding.fragment {
        MacroFragmentKind::Ty => Some(if whole {
            MacroNamespaceEvidence::Type
        } else {
            MacroNamespaceEvidence::Interior(MacroFragmentKind::Ty)
        }),
        MacroFragmentKind::Path => Some(if whole {
            MacroNamespaceEvidence::Type
        } else {
            MacroNamespaceEvidence::Interior(MacroFragmentKind::Path)
        }),
        MacroFragmentKind::Expr => Some(if whole {
            MacroNamespaceEvidence::Value
        } else {
            MacroNamespaceEvidence::Interior(MacroFragmentKind::Expr)
        }),
        MacroFragmentKind::Pat => Some(if whole {
            MacroNamespaceEvidence::Pattern
        } else {
            MacroNamespaceEvidence::Interior(MacroFragmentKind::Pat)
        }),
        MacroFragmentKind::Item => Some(MacroNamespaceEvidence::Interior(MacroFragmentKind::Item)),
        MacroFragmentKind::Stmt => Some(MacroNamespaceEvidence::Interior(MacroFragmentKind::Stmt)),
        MacroFragmentKind::Block => {
            Some(MacroNamespaceEvidence::Interior(MacroFragmentKind::Block))
        }
        MacroFragmentKind::Ident => Some(
            match binding
                .ident_role
                .expect("matched ident has a transcriber role")
            {
                MacroIdentRole::Type => MacroNamespaceEvidence::Type,
                MacroIdentRole::Value => MacroNamespaceEvidence::Value,
                MacroIdentRole::Pattern => MacroNamespaceEvidence::Pattern,
                MacroIdentRole::Declaration => MacroNamespaceEvidence::Declaration,
                MacroIdentRole::Mixed | MacroIdentRole::Unused | MacroIdentRole::Undetermined => {
                    MacroNamespaceEvidence::NoNamespace
                }
            },
        ),
        MacroFragmentKind::Tt
        | MacroFragmentKind::Meta
        | MacroFragmentKind::Vis
        | MacroFragmentKind::Lifetime
        | MacroFragmentKind::Literal => Some(MacroNamespaceEvidence::NoNamespace),
    }
}

fn consume_fragment(
    fragment: MacroFragmentKind,
    input: &mut TokenCursor<'_>,
    source: &str,
) -> Option<(usize, usize)> {
    match fragment {
        MacroFragmentKind::Ident => consume_ident(input),
        MacroFragmentKind::Tt => consume_tt(input),
        MacroFragmentKind::Vis => consume_vis(input),
        MacroFragmentKind::Lifetime => consume_lifetime(input),
        MacroFragmentKind::Literal => consume_literal(input),
        MacroFragmentKind::Ty
        | MacroFragmentKind::Path
        | MacroFragmentKind::Expr
        | MacroFragmentKind::Pat
        | MacroFragmentKind::Stmt
        | MacroFragmentKind::Block
        | MacroFragmentKind::Item
        | MacroFragmentKind::Meta => consume_parsed_fragment(fragment, input, source),
    }
}

fn consume_ident(input: &mut TokenCursor<'_>) -> Option<(usize, usize)> {
    let token = input.current()?;
    if !identifier_like(token) {
        return None;
    }
    let range = (token.start_byte(), token.end_byte());
    input.advance();
    Some(range)
}

/// Narrow a metavariable's transcriber role to one captured `ident` token.
/// The role is derived for an ordinary name, but an `ident` matcher also
/// accepts keywords such as `self` and `crate`. A token that does not parse
/// as a whole type or expression names nothing in that namespace.
pub(crate) fn captured_ident_role(role: MacroIdentRole, token: &str) -> MacroIdentRole {
    let fragment = match role {
        MacroIdentRole::Type => MacroFragmentKind::Ty,
        MacroIdentRole::Value => MacroFragmentKind::Expr,
        _ => return role,
    };
    let (wrapped, prefix_len) = wrap_fragment(fragment, token);
    let parsed = parse_rust_tree(&wrapped)
        .and_then(|tree| parsed_prefix_len(fragment, tree.root_node(), &wrapped, prefix_len));
    if parsed == Some(token.len()) {
        role
    } else {
        MacroIdentRole::Unused
    }
}

fn consume_tt(input: &mut TokenCursor<'_>) -> Option<(usize, usize)> {
    let token = input.current()?;
    let range = (token.start_byte(), token.end_byte());
    input.advance();
    Some(range)
}

fn consume_vis(input: &mut TokenCursor<'_>) -> Option<(usize, usize)> {
    let Some(token) = input.current() else {
        return Some((input.end_byte, input.end_byte));
    };
    if token.kind() != "pub"
        && token.kind() != "visibility_modifier"
        && token.text().trim() != "pub"
    {
        return Some((token.start_byte(), token.start_byte()));
    }
    let start = token.start_byte();
    let mut end = token.end_byte();
    input.advance();
    if let Some(next) = input.current()
        && next.kind() == "token_tree"
        && next.child(0).is_some_and(|open| open.kind() == "(")
    {
        end = next.end_byte();
        input.advance();
    }
    Some((start, end))
}

fn consume_lifetime(input: &mut TokenCursor<'_>) -> Option<(usize, usize)> {
    let token = input.current()?;
    let spelling = token.text().trim();
    if token.kind() == "lifetime" || spelling.starts_with('\'') && spelling.len() > 1 {
        let range = (token.start_byte(), token.end_byte());
        input.advance();
        return Some(range);
    }
    if token.kind() != "'" {
        return None;
    }
    let name = *input.tokens.get(input.index + 1)?;
    if token.end_byte() != name.start_byte()
        || !matches!(
            name.kind(),
            "identifier" | "type_identifier" | "static" | "_"
        )
    {
        return None;
    }
    let range = (token.start_byte(), name.end_byte());
    input.advance();
    input.advance();
    Some(range)
}

fn consume_literal(input: &mut TokenCursor<'_>) -> Option<(usize, usize)> {
    let token = input.current()?;
    if !token.kind().contains("literal")
        && !matches!(
            token.kind(),
            "string_literal"
                | "raw_string_literal"
                | "char_literal"
                | "integer_literal"
                | "float_literal"
                | "boolean_literal"
                | "byte_literal"
                | "byte_string_literal"
        )
    {
        return None;
    }
    let range = (token.start_byte(), token.end_byte());
    input.advance();
    Some(range)
}

fn consume_parsed_fragment(
    fragment: MacroFragmentKind,
    input: &mut TokenCursor<'_>,
    source: &str,
) -> Option<(usize, usize)> {
    let start = input.remaining_start()?;
    let rest = source.get(start - input.source_start..input.end_byte - input.source_start)?;
    if rest.trim().is_empty() {
        return None;
    }
    let (wrapped, prefix_len) = wrap_fragment(fragment, rest);
    let tree = parse_rust_tree(&wrapped)?;
    let expected_start = prefix_len + leading_ws_len(&wrapped[prefix_len..]);
    let macro_invocation_len = if fragment == MacroFragmentKind::Expr {
        canonical::macro_invocation_prefix_len(
            tree.root_node(),
            expected_start,
            prefix_len,
            start,
            input,
        )
    } else {
        None
    };
    let consumed = macro_invocation_len
        .or_else(|| parsed_prefix_len(fragment, tree.root_node(), &wrapped, prefix_len))?;
    if consumed == 0 {
        return None;
    }
    let end = start + consumed;
    if !input.advance_through(end) {
        return None;
    }
    Some((start, end))
}

/// An operand parsed by the same fragment machinery used by native resolution.
/// The tree is owned by one file derivation; its nodes use original coordinates.
#[derive(Debug)]
pub struct ParsedMacroOperand {
    pub binding: MacroBinding,
    pub tree: tree_sitter::Tree,
}

impl ParsedMacroOperand {
    pub fn node(&self) -> Node<'_> {
        self.tree
            .root_node()
            .descendant_for_byte_range(self.binding.start_byte, self.binding.end_byte)
            .expect("validated macro fragment retains its exact operand")
    }
}

/// Read separators from token-tree structure, then parse every group using
/// native fragment grammar. Items and malformed groups retain the caller's gap.
pub fn parse_macro_operands(invocation: Node<'_>, source: &str) -> Option<Vec<ParsedMacroOperand>> {
    let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)?;
    let path = invocation.child_by_field_name("macro")?;
    let matches_macro = crate::graph_support::rust_path_segments(path)
        .and_then(|segments| segments.last().copied())
        .is_some_and(|name| rust_node_text(name, source) == "matches");
    let captured = capture_macro_input(arguments, source, &|| true).ok()?;
    let input_tree = MacroInputTree::new(&captured, &|| true).ok()?;
    let (tokens, end_byte) = input_tree.root().interior(&|| true).ok()?;
    let mut input = TokenCursor {
        tokens,
        index: 0,
        end_byte,
        source_start: captured.start_byte,
    };
    let mut spans = Vec::new();
    while input.current().is_some() {
        let fragment = if matches_macro && spans.len() == 1 {
            MacroFragmentKind::Pat
        } else {
            MacroFragmentKind::Expr
        };
        spans.push(consume_parsed_fragment(
            fragment,
            &mut input,
            &captured.source,
        )?);
        if let Some(separator) = input.current() {
            if !matches!(separator.kind(), "," | ";") {
                return None;
            }
            input.advance();
        }
    }
    if matches_macro && spans.len() != 2 {
        return None;
    }
    spans
        .into_iter()
        .enumerate()
        .map(|(index, (start_byte, end_byte))| {
            let binding = MacroBinding {
                name: String::new(),
                fragment: if matches_macro && index == 1 {
                    MacroFragmentKind::Pat
                } else {
                    MacroFragmentKind::Expr
                },
                start_byte,
                end_byte,
                repetition_path: Vec::new(),
                ident_role: None,
            };
            let tree = parse_bound_fragment(&binding, source)?;
            let node = tree
                .root_node()
                .descendant_for_byte_range(start_byte, end_byte)?;
            if tree.root_node().has_error()
                || node.start_byte() != start_byte
                || node.end_byte() != end_byte
                || crate::declarations::rust_node_is_item(node)
            {
                return None;
            }
            Some(ParsedMacroOperand { binding, tree })
        })
        .collect()
}

/// Parse a captured fragment and retain its original source coordinates.
/// The edit changes only the synthetic wrapper before the fragment; every
/// fragment node can therefore be lowered against the original source bytes.
pub fn parse_bound_fragment(binding: &MacroBinding, source: &str) -> Option<tree_sitter::Tree> {
    let (wrapped, prefix) = wrap_fragment(
        binding.fragment,
        &source[binding.start_byte..binding.end_byte],
    );
    // Source collectors key live nodes by identity. Cached Tree clones share
    // subtree IDs, even after edits shift their coordinates. Each invocation
    // therefore needs fresh nodes before rebasing, or a repeated closure's
    // parameter can inherit the previous invocation's declaration occurrence.
    let mut tree = crate::lexical_scope::parse_rust_tree_uncached(&wrapped)?;
    let before = &source[..binding.start_byte];
    let row = before.bytes().filter(|&byte| byte == b'\n').count();
    let column = before
        .as_bytes()
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(before.len(), |last| before.len() - last - 1);
    tree.edit(&tree_sitter::InputEdit {
        start_byte: 0,
        old_end_byte: prefix,
        new_end_byte: binding.start_byte,
        start_position: tree_sitter::Point::new(0, 0),
        old_end_position: tree_sitter::Point::new(0, prefix),
        new_end_position: tree_sitter::Point::new(row, column),
    });
    Some(tree)
}

/// Parse the static paths in a transcriber while retaining source offsets.
/// Repetition markers and metavariables are rewritten from their AST nodes;
/// placeholder ranges are excluded by the reference producer.
pub(crate) struct ParsedMacroTranscriber {
    pub tree: tree_sitter::Tree,
    pub metavariables: Vec<(usize, usize)>,
    pub definition_crate_anchors: Vec<usize>,
    pub ordinary_crate_anchors: Vec<usize>,
}

pub(crate) fn parse_macro_transcriber(node: Node<'_>, source: &str) -> ParsedMacroTranscriber {
    let start = node.start_byte();
    let mut bytes = source.as_bytes()[node.byte_range()].to_vec();
    let mut metavariables = Vec::new();
    let mut definition_crate_anchors = Vec::new();
    let mut ordinary_crate_anchors = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if current.kind() == "token_repetition" {
            let (contents, _) = interior_tokens(current);
            for byte in &mut bytes[current.start_byte() - start..current.end_byte() - start] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            for child in &contents {
                bytes[child.start_byte() - start..child.end_byte() - start]
                    .copy_from_slice(&source.as_bytes()[child.byte_range()]);
            }
            pending.extend(contents);
            continue;
        }
        if current.kind() == "crate" {
            ordinary_crate_anchors.push(current.start_byte());
        }
        if current.kind() == "metavariable" {
            if rust_node_text(current, source) == "$crate" {
                bytes[current.start_byte() - start] = b' ';
                definition_crate_anchors.push(current.start_byte() + 1);
            } else {
                bytes[current.start_byte() - start..current.end_byte() - start].fill(b'_');
                metavariables.push((current.start_byte(), current.end_byte()));
            }
            continue;
        }
        let mut cursor = current.walk();
        pending.extend(current.named_children(&mut cursor));
    }
    let mut rewritten = source.to_owned();
    rewritten.replace_range(
        node.byte_range(),
        std::str::from_utf8(&bytes).expect("AST token rewrites preserve UTF-8"),
    );
    let binding = MacroBinding {
        name: String::new(),
        fragment: MacroFragmentKind::Expr,
        start_byte: start,
        end_byte: node.end_byte(),
        repetition_path: Vec::new(),
        ident_role: None,
    };
    let tree = parse_bound_fragment(&binding, &rewritten)
        .expect("transcriber token tree parses with recovery");
    ParsedMacroTranscriber {
        tree,
        metavariables,
        definition_crate_anchors,
        ordinary_crate_anchors,
    }
}

fn wrap_fragment(fragment: MacroFragmentKind, rest: &str) -> (String, usize) {
    match fragment {
        MacroFragmentKind::Ty | MacroFragmentKind::Path => {
            let prefix = "type __BifrostFrag = ";
            (format!("{prefix}{rest};"), prefix.len())
        }
        MacroFragmentKind::Expr | MacroFragmentKind::Stmt => {
            let prefix = "fn __bifrost_frag() { ";
            (format!("{prefix}{rest} }}"), prefix.len())
        }
        MacroFragmentKind::Pat => {
            let prefix = "fn __bifrost_frag(";
            (format!("{prefix}{rest}: ()) {{}}"), prefix.len())
        }
        MacroFragmentKind::Item => (rest.to_string(), 0),
        MacroFragmentKind::Block => (rest.to_string(), 0),
        MacroFragmentKind::Meta => {
            let prefix = "#[";
            (
                format!("{prefix}{rest}]\nstruct __BifrostFrag;"),
                prefix.len(),
            )
        }
        _ => (rest.to_string(), 0),
    }
}

fn parsed_prefix_len(
    fragment: MacroFragmentKind,
    root: Node<'_>,
    wrapped: &str,
    prefix_len: usize,
) -> Option<usize> {
    let expected_start = prefix_len + leading_ws_len(&wrapped[prefix_len..]);
    match fragment {
        MacroFragmentKind::Ty | MacroFragmentKind::Path => {
            let node = largest_clean_node_starting_at(root, expected_start)?;
            let fragment_source = wrapped.get(expected_start..node.end_byte())?;
            let (fragment_wrapper, fragment_prefix) = wrap_fragment(fragment, fragment_source);
            let fragment_tree = parse_rust_tree(&fragment_wrapper)?;
            let wrapper = fragment_tree.root_node().named_child(0)?;
            if wrapper.kind() != "type_item" {
                return None;
            }
            let ty = wrapper.child_by_field_name("type")?;
            if ty.start_byte() != fragment_prefix
                || ty.end_byte() != fragment_prefix + fragment_source.len()
                || ty.has_error()
            {
                return None;
            }
            Some(node.end_byte() - prefix_len)
        }
        MacroFragmentKind::Expr | MacroFragmentKind::Stmt => {
            let node = largest_clean_node_starting_at(root, expected_start)?;
            let node =
                if fragment == MacroFragmentKind::Expr && node.kind() == "expression_statement" {
                    node.named_child(0)?
                } else {
                    node
                };
            Some(node.end_byte() - prefix_len)
        }
        MacroFragmentKind::Pat => {
            let parameters =
                named_descendant(root, "function_item")?.child_by_field_name("parameters")?;
            let parameter = named_child_of_kind(parameters, "parameter")?;
            let pat = parameter.child_by_field_name("pattern")?;
            if pat.start_byte() != expected_start || pat.has_error() {
                return None;
            }
            Some(pat.end_byte() - prefix_len)
        }
        MacroFragmentKind::Item => {
            let item = first_source_item(root)?;
            if item.start_byte() != expected_start || item.has_error() {
                return None;
            }
            Some(item.end_byte() - prefix_len)
        }
        MacroFragmentKind::Block => {
            let block = named_descendant(root, "block")?;
            if block.start_byte() != expected_start || block.has_error() {
                return None;
            }
            Some(block.end_byte() - prefix_len)
        }
        MacroFragmentKind::Meta => {
            let meta = named_descendant(root, "attribute")?;
            if meta.start_byte() != expected_start {
                return None;
            }
            let path = meta.named_child(0)?;
            if path.start_byte() != expected_start || path.has_error() {
                return None;
            }
            let mut pending = vec![meta];
            let mut arguments_end = None;
            while let Some(node) = pending.pop() {
                if node.start_byte() == path.end_byte() && node.kind() == "token_tree" {
                    if node.has_error() {
                        return None;
                    }
                    arguments_end = Some(node.end_byte());
                }
                let mut cursor = node.walk();
                pending.extend(node.children(&mut cursor));
            }
            let end = arguments_end
                .or_else(|| {
                    meta.child_by_field_name("value").and_then(|value| {
                        largest_clean_node_starting_at(value, value.start_byte())
                            .map(|value| value.end_byte())
                    })
                })
                .unwrap_or(path.end_byte());
            Some(end - prefix_len)
        }
        _ => None,
    }
}

pub(crate) use brokk_bifrost_core::analyzer::rust_facts::RustMacroRepetitionOperator as RepetitionOp;

pub(crate) struct RepetitionSpec<'a> {
    pub(crate) contents: Vec<Node<'a>>,
    pub(crate) separator: Option<String>,
    pub(crate) operator: RepetitionOp,
}

pub(crate) fn parse_repetition<'a>(
    repetition: Node<'a>,
    source: &str,
) -> Option<RepetitionSpec<'a>> {
    let mut cursor = repetition.walk();
    let children: Vec<_> = repetition.children(&mut cursor).collect();
    let mut index = 0;
    if children.get(index).is_some_and(|child| child.kind() == "$") {
        index += 1;
    }
    if children.get(index).is_none_or(|child| child.kind() != "(") {
        return None;
    }
    index += 1;
    let close = children
        .iter()
        .rposition(|child| child.kind() == ")")
        .filter(|&close| close > index.saturating_sub(1))?;
    let contents = children[index..close].to_vec();
    let operator_node = children
        .get(close + 1..)?
        .iter()
        .find(|token| matches!(token.kind(), "*" | "+" | "?"))?;
    let operator = match operator_node.kind() {
        "*" => RepetitionOp::Star,
        "+" => RepetitionOp::Plus,
        "?" => RepetitionOp::Optional,
        _ => return None,
    };
    // tree-sitter-rust matches the separator as /[^+*?]+/ and does not emit a
    // child node for it. The separator is the source between `)` and the operator.
    let gap = source.get(children[close].end_byte()..operator_node.start_byte())?;
    let separator = {
        let trimmed = gap.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    Some(RepetitionSpec {
        contents,
        separator,
        operator,
    })
}

#[derive(Clone, Debug)]
pub(crate) struct MacroTranscriber {
    instructions: Vec<MacroTranscriberInstruction>,
}

#[derive(Clone, Debug)]
enum MacroTranscriberInstruction {
    Literal {
        text: String,
        source_start: usize,
    },
    Binding(String),
    RepeatStart {
        end: usize,
        separator: Option<String>,
        operator: RepetitionOp,
        names: Vec<String>,
    },
    RepeatEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacroTranscribedPathRole {
    Type,
    Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacroTranscriberParseContext {
    Item,
    Expression,
    Type,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacroTranscribedSource {
    Definition,
    Invocation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MacroTranscribedReferenceRole {
    Type,
    Call,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacroTranscribedPath {
    pub(crate) segments: Vec<(usize, usize)>,
    pub(crate) role: MacroTranscribedPathRole,
    pub(crate) is_call: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MacroTranscribedOutput {
    pub(crate) paths: Vec<MacroTranscribedPath>,
    pub(crate) fragments: Vec<MacroTranscribedFragment>,
    /// A completely replayed AST contains no construct that can introduce
    /// unindexed members or change which traits supply them.
    pub(crate) member_surface_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacroTranscribedFragment {
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) syntax_kind: String,
    pub(crate) fragment: MacroFragmentKind,
    pub(crate) source: MacroTranscribedSource,
    pub(crate) reference_role: Option<MacroTranscribedReferenceRole>,
}

struct TranscribedSourceChunk {
    output_start: usize,
    output_end: usize,
    input_start: usize,
    source: MacroTranscribedSource,
}

struct TranscriberRepeatFrame {
    body_start: usize,
    end: usize,
    indices: Vec<usize>,
    next_index: usize,
    prefix_path: Vec<usize>,
    separator: Option<String>,
}

enum TranscriberCaptureStep<'tree> {
    Node(Node<'tree>),
    EndRepeat(usize),
}

impl MacroTranscriber {
    fn capture(right: Node<'_>, source: &str) -> Option<Self> {
        let (interior, _) = interior_tokens(right);
        let mut pending = interior
            .into_iter()
            .rev()
            .map(TranscriberCaptureStep::Node)
            .collect::<Vec<_>>();
        let mut instructions = Vec::new();
        while let Some(step) = pending.pop() {
            match step {
                TranscriberCaptureStep::EndRepeat(start) => {
                    let end = instructions.len();
                    instructions.push(MacroTranscriberInstruction::RepeatEnd);
                    let names = instructions[start + 1..end]
                        .iter()
                        .filter_map(|instruction| match instruction {
                            MacroTranscriberInstruction::Binding(name) => Some(name.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    let MacroTranscriberInstruction::RepeatStart {
                        end: repeat_end,
                        names: repeat_names,
                        ..
                    } = &mut instructions[start]
                    else {
                        unreachable!("transcriber repetition start owns its end marker")
                    };
                    *repeat_end = end;
                    *repeat_names = names;
                }
                TranscriberCaptureStep::Node(node) if node.is_extra() => {}
                TranscriberCaptureStep::Node(node) if node.kind() == "token_repetition" => {
                    let spec = parse_repetition(node, source)?;
                    let start = instructions.len();
                    instructions.push(MacroTranscriberInstruction::RepeatStart {
                        end: usize::MAX,
                        separator: spec.separator,
                        operator: spec.operator,
                        names: Vec::new(),
                    });
                    pending.push(TranscriberCaptureStep::EndRepeat(start));
                    pending.extend(
                        spec.contents
                            .into_iter()
                            .rev()
                            .map(TranscriberCaptureStep::Node),
                    );
                }
                TranscriberCaptureStep::Node(node) if node.kind() == "metavariable" => {
                    instructions.push(MacroTranscriberInstruction::Binding(
                        metavar_spelling(rust_node_text(node, source)).to_string(),
                    ));
                }
                TranscriberCaptureStep::Node(node) if node.child_count() == 0 => {
                    instructions.push(MacroTranscriberInstruction::Literal {
                        text: rust_node_text(node, source).to_string(),
                        source_start: node.start_byte(),
                    });
                }
                TranscriberCaptureStep::Node(node) => {
                    let mut cursor = node.walk();
                    pending.extend(
                        node.children(&mut cursor)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .map(TranscriberCaptureStep::Node),
                    );
                }
            }
        }
        Some(Self { instructions })
    }

    pub(crate) fn replayed_tt_output(
        &self,
        bindings: &[MacroBinding],
        source: &str,
        context: MacroTranscriberParseContext,
    ) -> MacroTranscribedOutput {
        let Some((output, chunks)) = self.replay(bindings, source) else {
            return MacroTranscribedOutput::default();
        };
        let (prefix, suffix) = match context {
            MacroTranscriberParseContext::Item => ("", ""),
            MacroTranscriberParseContext::Expression => ("fn __bifrost_macro_expansion() { ", " }"),
            MacroTranscriberParseContext::Type => ("type __BifrostMacroExpansion = ", ";"),
        };
        let mut expanded = String::with_capacity(prefix.len() + output.len() + suffix.len());
        expanded.push_str(prefix);
        expanded.push_str(&output);
        expanded.push_str(suffix);
        let Some(tree) = parse_rust_tree(&expanded) else {
            return MacroTranscribedOutput::default();
        };
        if tree.root_node().has_error() {
            return MacroTranscribedOutput::default();
        }
        let mut paths = Vec::<MacroTranscribedPath>::new();
        let mut fragments = Vec::<MacroTranscribedFragment>::new();
        let mut conflicts = Vec::<Vec<(usize, usize)>>::new();
        let mut member_surface_closed = true;
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if matches!(
                node.kind(),
                "impl_item"
                    | "macro_invocation"
                    | "attribute_item"
                    | "inner_attribute_item"
                    | "mod_item"
                    | "use_declaration"
                    | "extern_crate_declaration"
                    | "trait_item"
                    | "macro_definition"
            ) {
                member_surface_closed = false;
            }
            if node.start_byte() >= prefix.len()
                && node.end_byte() <= prefix.len() + output.len()
                && let Some((source, start_byte, end_byte)) = transcriber_source_span(
                    node.start_byte(),
                    node.end_byte(),
                    prefix.len(),
                    &expanded,
                    &chunks,
                )
            {
                // A literal crate-qualified path is resolved in the same
                // crate as this source-local invocation, even for an exported
                // macro. This relies on source-local replay: literal `crate::`
                // and `$crate::` have the same crate only when definition and
                // invocation belong to that crate. Cross-crate replay must use
                // ordinary_crate_anchors and definition_crate_anchors separately.
                // This transcriber carries no crate identities to assert here.
                // The definition by itself supplied no such authority.
                let crate_qualified =
                    matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier")
                        && crate::graph_support::rust_path_segments(node).is_some_and(|segments| {
                            segments.first().is_some_and(|head| head.kind() == "crate")
                        });
                let reference_role =
                    if crate::resolution::rust_enclosing_item_generic_parameter_namespace(
                        node, &expanded,
                    )
                    .is_some()
                    {
                        None
                    } else if crate_qualified {
                        if node.kind() == "scoped_type_identifier" {
                            Some(MacroTranscribedReferenceRole::Type)
                        } else if node.parent().is_some_and(|parent| {
                            parent.kind() == "call_expression"
                                && parent.child_by_field_name("function") == Some(node)
                        }) {
                            Some(MacroTranscribedReferenceRole::Call)
                        } else {
                            None
                        }
                    } else {
                        match crate::structural::rust_occurrence_role(node) {
                        Some(brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole::TypeOperand)
                            if node.kind() == "type_identifier"
                                && !node.parent().is_some_and(|parent| {
                                    matches!(
                                        parent.kind(),
                                        "scoped_identifier" | "scoped_type_identifier"
                                    )
                                }) =>
                        {
                            Some(MacroTranscribedReferenceRole::Type)
                        }
                        Some(brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole::ValueReference)
                            if node.kind() == "identifier"
                                && node.parent().is_some_and(|parent| {
                                    parent.kind() == "call_expression"
                                        && parent.child_by_field_name("function") == Some(node)
                                }) =>
                        {
                            Some(MacroTranscribedReferenceRole::Call)
                        }
                        _ => None,
                    }
                    };
                for fragment in [MacroFragmentKind::Expr, MacroFragmentKind::Ty] {
                    let candidate = MacroTranscribedFragment {
                        start_byte,
                        end_byte,
                        syntax_kind: node.kind().to_owned(),
                        fragment,
                        source,
                        reference_role,
                    };
                    if !fragments.contains(&candidate) {
                        fragments.push(candidate);
                    }
                }
            }
            if matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier")
                && !node.has_error()
                && let Some(segments) = crate::graph_support::rust_path_segments(node)
            {
                let Some(segments) = segments
                    .into_iter()
                    .map(|segment| {
                        transcriber_source_range(
                            segment.start_byte(),
                            segment.end_byte(),
                            prefix.len(),
                            &chunks,
                        )
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    let mut cursor = node.walk();
                    pending.extend(node.named_children(&mut cursor));
                    continue;
                };
                let all_tt_bindings = segments.iter().all(|&(start, end)| {
                    bindings.iter().any(|binding| {
                        binding.fragment == MacroFragmentKind::Tt && binding.contains(start, end)
                    })
                });
                let ordered = segments.windows(2).all(|pair| pair[0].1 <= pair[1].0);
                if all_tt_bindings && ordered {
                    let candidate = MacroTranscribedPath {
                        segments,
                        role: if node.kind() == "scoped_type_identifier" {
                            MacroTranscribedPathRole::Type
                        } else {
                            MacroTranscribedPathRole::Value
                        },
                        is_call: node.parent().is_some_and(|parent| {
                            parent.kind() == "call_expression"
                                && parent.child_by_field_name("function") == Some(node)
                        }),
                    };
                    if let Some(existing) = paths
                        .iter()
                        .find(|existing| existing.segments == candidate.segments)
                    {
                        if existing != &candidate && !conflicts.contains(&candidate.segments) {
                            conflicts.push(candidate.segments.clone());
                        }
                    } else {
                        paths.push(candidate);
                    }
                }
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        paths.retain(|path| !conflicts.contains(&path.segments));
        MacroTranscribedOutput {
            paths,
            fragments,
            member_surface_closed,
        }
    }

    fn replay(
        &self,
        bindings: &[MacroBinding],
        source: &str,
    ) -> Option<(String, Vec<TranscribedSourceChunk>)> {
        let mut output = String::new();
        let mut chunks = Vec::new();
        let mut path = Vec::new();
        let mut repeats = Vec::<TranscriberRepeatFrame>::new();
        let mut pc = 0;
        while pc < self.instructions.len() {
            match &self.instructions[pc] {
                MacroTranscriberInstruction::Literal { text, source_start } => {
                    let output_start = output.len();
                    output.push_str(text);
                    let output_end = output.len();
                    if output_start < output_end {
                        chunks.push(TranscribedSourceChunk {
                            output_start,
                            output_end,
                            input_start: *source_start,
                            source: MacroTranscribedSource::Definition,
                        });
                    }
                    output.push(' ');
                    pc += 1;
                }
                MacroTranscriberInstruction::Binding(name) => {
                    let binding = transcriber_binding(name, &path, bindings)?;
                    let text = source.get(binding.start_byte..binding.end_byte)?;
                    let output_start = output.len();
                    output.push_str(text);
                    let output_end = output.len();
                    if output_start < output_end {
                        chunks.push(TranscribedSourceChunk {
                            output_start,
                            output_end,
                            input_start: binding.start_byte,
                            source: MacroTranscribedSource::Invocation,
                        });
                    }
                    output.push(' ');
                    pc += 1;
                }
                MacroTranscriberInstruction::RepeatStart {
                    end,
                    separator,
                    operator,
                    names,
                } => {
                    assert!(pc < *end, "transcriber repetition closes after it opens");
                    let indices = transcriber_repeat_indices(names, &path, bindings)?;
                    if indices.is_empty() {
                        if *operator == RepetitionOp::Plus {
                            return None;
                        }
                        pc = end + 1;
                        continue;
                    }
                    if *operator == RepetitionOp::Optional && indices.len() != 1 {
                        return None;
                    }
                    let mut next_path = path.clone();
                    next_path.push(indices[0]);
                    repeats.push(TranscriberRepeatFrame {
                        body_start: pc + 1,
                        end: *end,
                        indices,
                        next_index: 1,
                        prefix_path: path.clone(),
                        separator: separator.clone(),
                    });
                    path = next_path;
                    pc += 1;
                }
                MacroTranscriberInstruction::RepeatEnd => {
                    let frame = repeats
                        .last_mut()
                        .expect("transcriber repetition end has an active frame");
                    assert_eq!(frame.end, pc, "transcriber repetition frame owns its end");
                    if frame.next_index < frame.indices.len() {
                        if let Some(separator) = &frame.separator {
                            output.push_str(separator);
                            output.push(' ');
                        }
                        let mut next_path = frame.prefix_path.clone();
                        next_path.push(frame.indices[frame.next_index]);
                        frame.next_index += 1;
                        path = next_path;
                        pc = frame.body_start;
                    } else {
                        path.clone_from(&frame.prefix_path);
                        repeats.pop();
                        pc += 1;
                    }
                }
            }
        }
        assert!(
            repeats.is_empty(),
            "transcriber replay closes every repetition"
        );
        Some((output, chunks))
    }
}

pub(crate) fn capture_macro_transcribers(
    definition: Node<'_>,
    source: &str,
) -> Vec<Option<MacroTranscriber>> {
    let mut cursor = definition.walk();
    definition
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .map(|arm| {
            arm.child_by_field_name("right")
                .and_then(|right| MacroTranscriber::capture(right, source))
        })
        .collect()
}

fn transcriber_source_range(
    output_start: usize,
    output_end: usize,
    prefix_len: usize,
    chunks: &[TranscribedSourceChunk],
) -> Option<(usize, usize)> {
    let output_start = output_start.checked_sub(prefix_len)?;
    let output_end = output_end.checked_sub(prefix_len)?;
    chunks.iter().find_map(|chunk| {
        (chunk.source == MacroTranscribedSource::Invocation
            && output_start >= chunk.output_start
            && output_end <= chunk.output_end)
            .then(|| {
                (
                    chunk.input_start + output_start - chunk.output_start,
                    chunk.input_start + output_end - chunk.output_start,
                )
            })
    })
}

fn transcriber_source_span(
    expanded_start: usize,
    expanded_end: usize,
    prefix_len: usize,
    expanded: &str,
    chunks: &[TranscribedSourceChunk],
) -> Option<(MacroTranscribedSource, usize, usize)> {
    let start = expanded_start.checked_sub(prefix_len)?;
    let end = expanded_end.checked_sub(prefix_len)?;
    if start >= end {
        return None;
    }
    let mut cursor = start;
    let mut source_start = None;
    let mut source_end = None;
    let mut source = None;
    for chunk in chunks
        .iter()
        .filter(|chunk| chunk.output_start < end && start < chunk.output_end)
    {
        let output_start = start.max(chunk.output_start);
        let output_end = end.min(chunk.output_end);
        if output_start > cursor
            && !expanded
                .get(prefix_len + cursor..prefix_len + output_start)?
                .trim()
                .is_empty()
        {
            return None;
        }
        let input_start = chunk.input_start + output_start - chunk.output_start;
        let input_end = chunk.input_start + output_end - chunk.output_start;
        if source.is_some_and(|previous| previous != chunk.source)
            || source_end.is_some_and(|previous_end| input_start < previous_end)
        {
            return None;
        }
        source = Some(chunk.source);
        source_start.get_or_insert(input_start);
        source_end = Some(input_end);
        cursor = output_end;
    }
    if cursor < end
        && !expanded
            .get(prefix_len + cursor..prefix_len + end)?
            .trim()
            .is_empty()
    {
        return None;
    }
    Some((source?, source_start?, source_end?))
}

fn transcriber_binding<'a>(
    name: &str,
    path: &[usize],
    bindings: &'a [MacroBinding],
) -> Option<&'a MacroBinding> {
    let mut selected = None;
    let mut selected_depth = None;
    for binding in bindings
        .iter()
        .filter(|binding| binding.name == name && path.starts_with(&binding.repetition_path))
    {
        let depth = binding.repetition_path.len();
        match selected_depth {
            Some(selected_depth) if depth < selected_depth => {}
            Some(selected_depth) if depth == selected_depth => return None,
            _ => {
                selected = Some(binding);
                selected_depth = Some(depth);
            }
        }
    }
    selected
}

fn transcriber_repeat_indices(
    names: &[String],
    path: &[usize],
    bindings: &[MacroBinding],
) -> Option<Vec<usize>> {
    let mut indices = Vec::new();
    for binding in bindings.iter().filter(|binding| {
        names.contains(&binding.name)
            && binding.repetition_path.starts_with(path)
            && binding.repetition_path.len() > path.len()
    }) {
        indices.push(binding.repetition_path[path.len()]);
    }
    indices.sort_unstable();
    indices.dedup();
    if indices
        .iter()
        .enumerate()
        .any(|(expected, &actual)| expected != actual)
    {
        return None;
    }
    Some(indices)
}

fn match_separator(
    separator: &str,
    input: &mut TokenCursor<'_>,
    keep_going: &dyn Fn() -> bool,
) -> Result<bool, MacroMatchError> {
    let wanted = separator.trim();
    if wanted.is_empty() {
        return Ok(true);
    }
    let saved = input.index;
    let mut acc = String::new();
    while let Some(token) = input.current() {
        if !keep_going() {
            return Err(MacroMatchError::Interrupted);
        }
        acc.push_str(token.text().trim());
        input.advance();
        if acc == wanted {
            return Ok(true);
        }
        if !wanted.starts_with(&acc) {
            break;
        }
    }
    input.index = saved;
    Ok(false)
}

fn identifier_like(node: MacroInputNode<'_>) -> bool {
    let spelling = node.text().trim();
    spelling != "_"
        && (identifier_kind_like(node.kind())
            || matches!(
                spelling,
                "abstract"
                    | "as"
                    | "async"
                    | "await"
                    | "become"
                    | "box"
                    | "break"
                    | "const"
                    | "continue"
                    | "crate"
                    | "default"
                    | "do"
                    | "dyn"
                    | "else"
                    | "enum"
                    | "extern"
                    | "false"
                    | "final"
                    | "fn"
                    | "for"
                    | "gen"
                    | "if"
                    | "impl"
                    | "in"
                    | "let"
                    | "loop"
                    | "macro"
                    | "match"
                    | "mod"
                    | "move"
                    | "mut"
                    | "override"
                    | "priv"
                    | "pub"
                    | "raw"
                    | "ref"
                    | "return"
                    | "safe"
                    | "Self"
                    | "self"
                    | "static"
                    | "struct"
                    | "super"
                    | "trait"
                    | "true"
                    | "try"
                    | "type"
                    | "typeof"
                    | "union"
                    | "unsafe"
                    | "unsized"
                    | "use"
                    | "virtual"
                    | "where"
                    | "while"
                    | "yield"
            ))
}

fn identifier_kind_like(kind: &str) -> bool {
    crate::syntax::rust_identifier_kind_like(kind)
        || matches!(kind, "type_identifier" | "primitive_type" | "_")
}

pub(crate) fn macro_children_from_parents(
    child_count: usize,
    mut parent_at: impl FnMut(usize) -> Result<Option<usize>, MacroMatchError>,
) -> Result<Vec<Vec<usize>>, MacroMatchError> {
    assert!(child_count > 0, "a macro tree has one root node");
    let mut children = vec![Vec::new(); child_count];
    for child in 0..child_count {
        if let Some(parent) = parent_at(child)? {
            assert!(parent < child, "macro parent precedes its children");
            children[parent].push(child);
        } else {
            assert_eq!(child, 0, "a macro tree has one root node");
        }
    }
    Ok(children)
}

pub(crate) fn macro_delimiter(
    node: Node<'_>,
) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter> {
    rust_macro_delimiter_from_opening(node.child(0)?.kind())
}

fn rust_macro_delimiter_from_opening(
    opening: &str,
) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter> {
    use brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter;
    match opening {
        "(" => Some(RustMacroDelimiter::Parenthesis),
        "[" => Some(RustMacroDelimiter::Bracket),
        "{" => Some(RustMacroDelimiter::Brace),
        _ => None,
    }
}

pub(crate) fn interior_tokens(node: Node<'_>) -> (Vec<Node<'_>>, usize) {
    interior_tokens_while(node, &|| true).expect("uninterruptible source capture")
}

fn interior_tokens_while<'tree>(
    node: Node<'tree>,
    keep_going: &dyn Fn() -> bool,
) -> Result<(Vec<Node<'tree>>, usize), MacroMatchError> {
    let mut cursor = node.walk();
    let mut children = Vec::new();
    for child in node.children(&mut cursor) {
        if !keep_going() {
            return Err(MacroMatchError::Interrupted);
        }
        children.push(child);
    }
    if children.len() < 2 {
        return Ok((Vec::new(), node.end_byte()));
    }
    let close = children[children.len() - 1];
    children.pop();
    children.remove(0);
    Ok((children, close.start_byte()))
}

/// Capture token structure while the source producer owns the syntax tree.
/// The matcher uses this same representation for live and persisted inputs.
pub fn capture_macro_input(
    arguments: Node<'_>,
    source: &str,
    keep_going: &dyn Fn() -> bool,
) -> Result<brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree, MacroMatchError> {
    capture_macro_input_with(arguments, source, keep_going, |_| ()).map(|(tree, _)| tree)
}

pub(crate) fn capture_macro_input_with<T>(
    arguments: Node<'_>,
    source: &str,
    keep_going: &dyn Fn() -> bool,
    mut capture: impl FnMut(Node<'_>) -> T,
) -> Result<
    (
        brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
        Vec<T>,
    ),
    MacroMatchError,
> {
    use brokk_bifrost_core::analyzer::rust_facts::{RustMacroInputToken, RustMacroTokenTree};
    let mut tokens = Vec::new();
    let mut captured = Vec::new();
    let mut pending = vec![(arguments, None)];
    while let Some((node, parent)) = pending.pop() {
        if !keep_going() {
            return Err(MacroMatchError::Interrupted);
        }
        let index = u32::try_from(tokens.len()).expect("macro token count exceeds u32");
        captured.push(capture(node));
        tokens.push(RustMacroInputToken {
            parent,
            syntax_kind: node.kind().to_owned(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        });
        let mut cursor = node.walk();
        let children = node.children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev().map(|child| (child, Some(index))));
    }
    Ok((
        RustMacroTokenTree {
            start_byte: arguments.start_byte(),
            source: rust_node_text(arguments, source).to_owned(),
            tokens,
        },
        captured,
    ))
}

struct MacroInputTree<'a> {
    source: &'a brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    children: Vec<Vec<usize>>,
}

impl<'a> MacroInputTree<'a> {
    fn new(
        source: &'a brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, MacroMatchError> {
        let children = macro_children_from_parents(source.tokens.len(), |index| {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            let token = &source.tokens[index];
            assert!(
                source.start_byte <= token.start_byte
                    && token.start_byte <= token.end_byte
                    && token.end_byte <= source.start_byte + source.source.len()
            );
            if let Some(parent) = token.parent {
                let parent = parent as usize;
                assert!(parent < index, "macro input parent precedes its children");
                let bounds = &source.tokens[parent];
                assert!(bounds.start_byte <= token.start_byte && token.end_byte <= bounds.end_byte);
                Ok(Some(parent))
            } else {
                assert_eq!(index, 0, "macro input has one root");
                Ok(None)
            }
        })?;
        Ok(Self { source, children })
    }
    fn root(&self) -> MacroInputNode<'_> {
        MacroInputNode {
            tree: self,
            index: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct MacroInputNode<'a> {
    tree: &'a MacroInputTree<'a>,
    index: usize,
}

impl<'a> MacroInputNode<'a> {
    fn kind(self) -> &'a str {
        &self.tree.source.tokens[self.index].syntax_kind
    }
    fn start_byte(self) -> usize {
        self.tree.source.tokens[self.index].start_byte
    }
    fn end_byte(self) -> usize {
        self.tree.source.tokens[self.index].end_byte
    }
    fn text(self) -> &'a str {
        self.tree
            .source
            .token_text(&self.tree.source.tokens[self.index])
    }
    fn is_ordinary_comment(self) -> bool {
        matches!(self.kind(), "line_comment" | "block_comment") && !self.is_doc_comment()
    }
    fn is_outer_doc_comment(self) -> bool {
        let text = self.text().trim_start();
        match self.kind() {
            "line_comment" => text.starts_with("///") && !text.starts_with("////"),
            "block_comment" => text.starts_with("/**") && !text.starts_with("/***"),
            _ => false,
        }
    }
    fn is_inner_doc_comment(self) -> bool {
        let text = self.text().trim_start();
        match self.kind() {
            "line_comment" => text.starts_with("//!"),
            "block_comment" => text.starts_with("/*!"),
            _ => false,
        }
    }
    fn is_doc_comment(self) -> bool {
        self.is_outer_doc_comment() || self.is_inner_doc_comment()
    }
    fn child(self, index: usize) -> Option<Self> {
        self.tree.children[self.index]
            .get(index)
            .map(|&index| Self {
                tree: self.tree,
                index,
            })
    }
    fn delimiter(self) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter> {
        rust_macro_delimiter_from_opening(self.child(0)?.kind())
    }
    fn has_balanced_delimiters(self) -> bool {
        let children = &self.tree.children[self.index];
        let Some((&first_index, rest)) = children.split_first() else {
            return false;
        };
        let Some(&last_index) = rest.last() else {
            return false;
        };
        let first = Self {
            tree: self.tree,
            index: first_index,
        };
        let last = Self {
            tree: self.tree,
            index: last_index,
        };
        let closes_with = match first.kind() {
            "(" => ")",
            "[" => "]",
            "{" => "}",
            _ => return false,
        };
        last.kind() == closes_with && last.end_byte() > last.start_byte()
    }
    fn interior(
        self,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<(Vec<Self>, usize), MacroMatchError> {
        let children = &self.tree.children[self.index];
        if children.len() < 2 {
            return Ok((Vec::new(), self.end_byte()));
        }
        let close = self
            .child(children.len() - 1)
            .expect("macro delimiter child exists");
        let mut tokens = Vec::with_capacity(children.len() - 2);
        for &index in &children[1..children.len() - 1] {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            let token = Self {
                tree: self.tree,
                index,
            };
            if !token.is_ordinary_comment() {
                tokens.push(token);
            }
        }
        Ok((tokens, close.start_byte()))
    }
}

struct TokenCursor<'a> {
    tokens: Vec<MacroInputNode<'a>>,
    index: usize,
    end_byte: usize,
    source_start: usize,
}

impl<'a> TokenCursor<'a> {
    fn current(&self) -> Option<MacroInputNode<'a>> {
        self.tokens.get(self.index).copied()
    }

    fn remaining_start(&self) -> Option<usize> {
        self.current()
            .map(|node| node.start_byte())
            .or_else(|| (self.index == self.tokens.len()).then_some(self.end_byte))
    }

    fn advance(&mut self) {
        if self.index < self.tokens.len() {
            self.index += 1;
        }
    }

    fn advance_through(&mut self, end_byte: usize) -> bool {
        let start_index = self.index;
        while self.index < self.tokens.len() {
            let token = self.tokens[self.index];
            if token.end_byte() <= end_byte {
                self.index += 1;
                continue;
            }
            if token.start_byte() < end_byte {
                return false;
            }
            break;
        }
        self.index > start_index || end_byte == self.remaining_start().unwrap_or(self.end_byte)
    }
}

pub(crate) fn metavar_spelling(text: &str) -> String {
    text.trim().trim_start_matches('$').to_string()
}

fn leading_ws_len(text: &str) -> usize {
    text.len() - text.trim_start().len()
}

fn named_descendant<'a>(root: Node<'a>, kind: &str) -> Option<Node<'a>> {
    brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(root, kind)
}

use brokk_bifrost_core::analyzer::tree_walk::first_named_child_of_kind as named_child_of_kind;

fn first_source_item(root: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        // Retain the grammar's attribute wrapper: an item fragment owns its
        // outer attributes as well as the declaration they decorate.
        .find(|child| {
            crate::declarations::rust_is_indexable_item_kind(
                crate::syntax::unwrap_attributes(*child).kind(),
            )
        })
}

fn largest_clean_node_starting_at(root: Node<'_>, start: usize) -> Option<Node<'_>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() == start
            && node.kind() != "ERROR"
            && node.kind() != "source_file"
            && !node.has_error()
        {
            let span = node.end_byte().saturating_sub(node.start_byte());
            if span > 0 && best.is_none_or(|(_, best_span)| span > best_span) {
                best = Some((node, span));
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    best.map(|(node, _)| node)
}

fn ident_role_from_siblings(node: Node<'_>) -> MacroIdentRole {
    let previous = node.prev_sibling();
    if previous.is_some_and(|token| {
        matches!(
            token.kind(),
            "struct"
                | "enum"
                | "union"
                | "trait"
                | "type"
                | "fn"
                | "mod"
                | "const"
                | "static"
                | "let"
        )
    }) {
        return MacroIdentRole::Declaration;
    }
    if previous.is_some_and(|token| matches!(token.kind(), ":" | "->")) {
        return MacroIdentRole::Type;
    }
    MacroIdentRole::Value
}

fn ident_role_from_reparsed_transcriber(
    arm_right: Node<'_>,
    source: &str,
    metavar: &str,
) -> Option<MacroIdentRole> {
    let dummy = "DummyIdent";
    let mut rewritten = String::new();
    let mut saw_metavar = false;
    let (interior, _) = interior_tokens(arm_right);
    for child in interior {
        emit_transcriber_for_ident_role_reparse(
            child,
            source,
            metavar,
            dummy,
            &mut rewritten,
            &mut saw_metavar,
        );
    }
    if !saw_metavar {
        return Some(MacroIdentRole::Unused);
    }
    // `Self` in an impl transcriber may not produce a clean module-level
    // parse. Keep the ordinary parse first, then provide that item context
    // while still letting Tree-sitter determine the placeholder role.
    let wrapped = format!(
        "impl __BifrostMacroExpansion {{ fn __bifrost_macro_expansion() {{ {rewritten} }} }}"
    );
    let (parsed_source, tree) = parse_rust_tree(&rewritten)
        .filter(|tree| !tree.root_node().has_error())
        .map(|tree| (rewritten.as_str(), tree))
        .or_else(|| {
            parse_rust_tree(&wrapped)
                .filter(|tree| !tree.root_node().has_error())
                .map(|tree| (wrapped.as_str(), tree))
        })?;
    let mut roles = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "type_identifier")
            && parsed_source.get(node.byte_range()) == Some(dummy)
        {
            roles.push(parsed_dummy_ident_role(node));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    if roles.is_empty() {
        return None;
    }
    Some(collapse_ident_roles(&roles))
}

#[cfg(test)]
fn emit_transcriber_for_reparse(
    node: Node<'_>,
    source: &str,
    metavar: &str,
    dummy: &str,
    out: &mut String,
    saw_metavar: &mut bool,
) {
    emit_transcriber_with_repetition(node, source, metavar, dummy, out, saw_metavar, |node| {
        interior_tokens(node).0
    });
}

fn emit_transcriber_for_ident_role_reparse(
    node: Node<'_>,
    source: &str,
    metavar: &str,
    dummy: &str,
    out: &mut String,
    saw_metavar: &mut bool,
) {
    emit_transcriber_with_repetition(
        node,
        source,
        metavar,
        dummy,
        out,
        saw_metavar,
        repetition_body_for_ident_role_reparse,
    );
}

fn repetition_body_for_ident_role_reparse(node: Node<'_>) -> Vec<Node<'_>> {
    let (mut interior, _) = interior_tokens(node);
    let opening = interior
        .first()
        .expect("macro repetition has a delimited body");
    let closing = match opening.kind() {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        kind => panic!("unexpected macro repetition delimiter {kind:?}"),
    };
    assert_eq!(
        interior
            .last()
            .expect("macro repetition has a closing delimiter")
            .kind(),
        closing
    );
    // The repetition delimiters group the transcriber body; they do not
    // belong to the expanded syntax used for identifier-role classification.
    interior.remove(0);
    interior.pop();
    interior
}

fn emit_transcriber_with_repetition<'tree>(
    node: Node<'tree>,
    source: &str,
    metavar: &str,
    dummy: &str,
    out: &mut String,
    saw_metavar: &mut bool,
    mut repetition_body: impl FnMut(Node<'tree>) -> Vec<Node<'tree>>,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if node.kind() == "token_repetition" {
            pending.extend(repetition_body(node).into_iter().rev());
            continue;
        }
        if node.kind() == "metavariable" {
            if metavar_spelling(rust_node_text(node, source)) == metavar {
                *saw_metavar = true;
                out.push_str(dummy);
                out.push(' ');
            } else {
                out.push_str("DummyOther ");
            }
            continue;
        }
        if node.child_count() == 0 {
            let text = rust_node_text(node, source).trim();
            if !text.is_empty() {
                out.push_str(text);
                out.push(' ');
            }
            continue;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();
        pending.extend(children.into_iter().rev());
    }
}

#[cfg(test)]
#[path = "macro_transcriber_tests.rs"]
mod transcriber_tests;

#[cfg(test)]
#[path = "macro_matcher_stack_tests.rs"]
mod stack_tests;

fn match_syntax_macro_rules(
    definition: Node<'_>,
    definition_source: &str,
    arguments: Node<'_>,
    invocation_source: &str,
) -> Result<MacroArmMatch, MacroMatchError> {
    let facts = capture_syntax_macro_definition(definition, definition_source);
    match_macro_rules(&facts, arguments, invocation_source, &|| true)
}

pub(crate) fn capture_syntax_macro_definition(
    definition: Node<'_>,
    definition_source: &str,
) -> brokk_bifrost_core::analyzer::rust_facts::RustMacroDefinitionSourceFact {
    use brokk_bifrost_core::analyzer::source_facts::{
        PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
        SourceOccurrenceProvenance, SourceOccurrenceSink,
    };
    struct Sink<'a>(PrimarySourceFactCollector<'a>);
    impl SourceOccurrenceSink for Sink<'_> {
        fn intern_node(&mut self, node: Node<'_>) -> SourceOccurrenceId {
            self.0.intern_node(node)
        }
        fn intern_subspan_bytes(
            &mut self,
            start: usize,
            end: usize,
            provenance: SourceOccurrenceProvenance,
        ) -> SourceOccurrenceId {
            self.0.intern_subspan_bytes(start, end, provenance)
        }
    }
    impl crate::item_sources::RustItemSourceSink for Sink<'_> {
        fn declare_node(&mut self, node: Node<'_>) -> SourceDeclarationId {
            crate::item_sources::declare_primary_node(&mut self.0, node)
        }
    }
    let mut sink = Sink(PrimarySourceFactCollector::new(definition_source));
    let context = sink.0.intern_node(
        definition
            .parent()
            .expect("macro definition has a containing context"),
    );
    crate::macro_source_capture::capture_macro_definition(
        definition,
        definition_source,
        &mut sink,
        context,
    )
}

fn parsed_dummy_ident_role(node: Node<'_>) -> MacroIdentRole {
    let Some(parent) = node.parent() else {
        return MacroIdentRole::Undetermined;
    };
    // Reparse turns `&$receiver` into a reference type with no parameter
    // pattern. It is a self receiver placeholder, not a type reference.
    if node.kind() == "type_identifier"
        && parent.kind() == "reference_type"
        && parent
            .child_by_field_name("type")
            .is_some_and(|ty| ty.id() == node.id())
        && parent
            .parent()
            .is_some_and(|parameters| parameters.kind() == "parameters")
    {
        return MacroIdentRole::Unused;
    }
    // A type_identifier can still be the receiver operand of a field
    // expression in macro output. Use the same structural role as source
    // lowering before falling back to the token kind.
    if crate::structural::rust_occurrence_role(node)
        == Some(
            brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole::ValueReference,
        )
    {
        return MacroIdentRole::Value;
    }
    if parent
        .child_by_field_name("name")
        .is_some_and(|name| name.id() == node.id())
        && matches!(
            parent.kind(),
            "function_item"
                | "struct_item"
                | "enum_item"
                | "union_item"
                | "trait_item"
                | "type_item"
                | "mod_item"
                | "const_item"
                | "static_item"
                | "field_declaration"
                | "enum_variant"
                | "macro_definition"
                | "type_parameter"
                | "const_parameter"
        )
    {
        return MacroIdentRole::Declaration;
    }
    if node.kind() == "type_identifier"
        || matches!(
            parent.kind(),
            "generic_type"
                | "reference_type"
                | "pointer_type"
                | "bounded_type"
                | "abstract_type"
                | "dynamic_type"
                | "trait_bounds"
        )
    {
        return MacroIdentRole::Type;
    }
    if matches!(parent.kind(), "parameters" | "parameter")
        && parent
            .child_by_field_name("type")
            .is_some_and(|ty| node_within(ty, node))
    {
        return MacroIdentRole::Type;
    }
    if parent.kind() == "parameter"
        && parent
            .child_by_field_name("type")
            .is_some_and(|ty| node_within(ty, node))
    {
        return MacroIdentRole::Type;
    }
    if let Some(function) = find_ancestor(node, |parent| parent.kind() == "function_item")
        && function
            .child_by_field_name("return_type")
            .is_some_and(|ty| node_within(ty, node))
    {
        return MacroIdentRole::Type;
    }
    MacroIdentRole::Value
}

fn collapse_ident_roles(roles: &[MacroIdentRole]) -> MacroIdentRole {
    if roles.contains(&MacroIdentRole::Declaration) {
        return MacroIdentRole::Declaration;
    }
    let interesting: Vec<_> = roles
        .iter()
        .copied()
        .filter(|role| !matches!(role, MacroIdentRole::Unused | MacroIdentRole::Undetermined))
        .collect();
    if interesting.is_empty() {
        return if roles.contains(&MacroIdentRole::Undetermined) {
            MacroIdentRole::Undetermined
        } else {
            MacroIdentRole::Unused
        };
    }
    if interesting.iter().all(|role| *role == MacroIdentRole::Type) {
        return MacroIdentRole::Type;
    }
    if interesting
        .iter()
        .all(|role| *role == MacroIdentRole::Value)
    {
        return MacroIdentRole::Value;
    }
    if interesting
        .iter()
        .all(|role| *role == MacroIdentRole::Pattern)
    {
        return MacroIdentRole::Pattern;
    }
    MacroIdentRole::Mixed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexical_scope::parse_rust_tree;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str) -> tree_sitter::Tree {
        parse_rust_tree(source).expect("parse rust fixture")
    }

    fn definition_and_invocation<'a>(
        tree: &'a tree_sitter::Tree,
        _source: &str,
    ) -> (Node<'a>, Node<'a>) {
        let root = tree.root_node();
        let definition = named_descendant(root, "macro_definition").expect("macro definition");
        let invocation = named_descendant(root, "macro_invocation").expect("macro invocation");
        let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)
            .expect("invocation arguments");
        (definition, arguments)
    }

    fn binding_text<'a>(source: &'a str, binding: &MacroBinding) -> &'a str {
        &source[binding.start_byte..binding.end_byte]
    }

    #[test]
    #[ignore = "finds real bug (#6861): expression fragment accepts a lone comma argument outside an opaque macro"]
    #[hardwon("#6861: the pinned Rust grammar accepts a lone comma in call arguments")]
    fn grammar_macro_expression_lone_comma_argument() {
        let direct = parse("fn f() { nested!().method(,); }");
        assert!(
            direct.root_node().has_error(),
            "the pinned grammar accepted a lone comma outside opaque macro input: {}",
            direct.root_node().to_sexp()
        );
        let source = "macro_rules! take { ($e:expr) => {}; } take!(nested!().method(,));";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        assert_eq!(
            match_syntax_macro_rules(definition, source, arguments, source),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    fn grammar_macro_expression_recovery_boundary() {
        for (expression, accepted) in [
            ("nested!(,)", true),
            ("nested!().method()", true),
            ("nested!(,).method()", true),
            ("nested!().method(, value)", false),
        ] {
            let source = format!("macro_rules! take {{ ($e:expr) => {{}}; }} take!({expression});");
            let tree = parse(&source);
            let (definition, arguments) = definition_and_invocation(&tree, &source);
            if !accepted {
                let (wrapped, prefix) = wrap_fragment(MacroFragmentKind::Expr, expression);
                let recovered = parse(&wrapped);
                let node = recovered
                    .root_node()
                    .descendant_for_byte_range(prefix, prefix + expression.len())
                    .unwrap();
                assert_ne!(node.kind(), "macro_invocation");
                assert!(node.has_error(), "{}", node.to_sexp());
            }
            let result = match_syntax_macro_rules(definition, &source, arguments, &source);
            if accepted {
                let matched = result.unwrap();
                assert_eq!(binding_text(&source, &matched.bindings[0]), expression);
            } else {
                assert_eq!(result, Err(MacroMatchError::NoArmMatched));
            }
        }
    }

    #[test]
    fn grammar_macro_identifier_role_positions() {
        for (body, role) in [
            ("fn generated(&$t) {}", MacroIdentRole::Unused),
            ("fn generated(_: &$t) {}", MacroIdentRole::Type),
            ("fn generated() -> $t { loop {} }", MacroIdentRole::Type),
            ("fn generated() { $t(); }", MacroIdentRole::Value),
        ] {
            let source = format!("macro_rules! take {{ ($t:ident) => {{ {body} }}; }}");
            let tree = parse(&source);
            let right = named_descendant(tree.root_node(), "macro_rule")
                .unwrap()
                .child_by_field_name("right")
                .unwrap();
            assert_eq!(
                ident_transcriber_role(right, &source, "t"),
                role,
                "{source}"
            );
            if body == "fn generated() -> $t { loop {} }" {
                let metavar = named_descendant(right, "metavariable").unwrap();
                assert_eq!(metavar.prev_sibling().unwrap().kind(), "->");
                assert_eq!(ident_role_from_siblings(metavar), MacroIdentRole::Type);
            }
        }
    }

    #[test]
    fn grammar_exported_macro_inventory() {
        let source = "mod hidden { #[macro_export] macro_rules! yes { () => {}; } macro_rules! no { () => {}; } } #[cfg(any())] mod disabled { #[macro_export] macro_rules! absent { () => {}; } }";
        let tree = parse(source);
        assert!(!tree.root_node().has_error());
        let exports = ExportedMacroDefinitions::from_root(tree.root_node(), source);
        assert_eq!(exports.definitions.len(), 1);
        let exported = exports.unique_named("yes", source).unwrap();
        assert_eq!(exported.kind(), "macro_definition");
        assert!(exports.unique_named("no", source).is_none());
        assert!(exports.unique_named("absent", source).is_none());
    }

    #[test]
    fn grammar_macro_fragment_inherits_source_scope() {
        let source = "macro_rules! inner { ($t:ty) => {}; } fn run() { outer!(inner!(Item)); }";
        let tree = parse(source);
        let outer = named_descendant(tree.root_node(), "macro_invocation").unwrap();
        let arguments = crate::declarations::rust_macro_invocation_arguments(outer).unwrap();
        let start = source.find("inner!(Item)").unwrap();
        let binding = MacroBinding {
            name: "e".to_owned(),
            fragment: MacroFragmentKind::Expr,
            start_byte: start,
            end_byte: start + "inner!(Item)".len(),
            repetition_path: Vec::new(),
            ident_role: None,
        };
        let fragment = parse_bound_fragment(&binding, source).unwrap();
        let inner = named_descendant(fragment.root_node(), "macro_invocation").unwrap();
        let matched =
            match_local_macro_invocation_using_definitions(inner, source, None, arguments)
                .expect("lexical source scope supplies inner")
                .unwrap();
        assert_eq!(binding_text(source, &matched.bindings[0]), "Item");
    }

    #[test]
    fn grammar_transcriber_repetition_static_path_coordinates() {
        let source = "macro_rules! take { ($($t:ty),*) => {\n    $(\n        fn generated(_: $t) {\n            crate::target();\n        }\n    )*\n}; }";
        let tree = parse(source);
        let definition = named_descendant(tree.root_node(), "macro_definition").unwrap();
        let rule = named_descendant(definition, "macro_rule").unwrap();
        let right = rule.child_by_field_name("right").unwrap();
        let parsed = parse_macro_transcriber(right, source);
        // The static reparse tolerates surrounding recovery; selected clean
        // paths must still retain their original byte and point coordinates.
        let path = named_descendant(parsed.tree.root_node(), "scoped_identifier").unwrap();
        let start = source.find("crate::target").unwrap();
        assert_eq!(path.byte_range(), start..start + "crate::target".len());
        assert_eq!(path.start_position(), tree_sitter::Point::new(3, 12));
    }

    #[test]
    fn grammar_tt_replay_reference_spans() {
        let source = "macro_rules! take { ($($t:tt)*) => { fn generated() { $($t)* } }; } take!(target(); crate::other());";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched = match_syntax_macro_rules(definition, source, arguments, source).unwrap();
        let transcriber = capture_macro_transcribers(definition, source)
            .remove(0)
            .unwrap();
        let output = transcriber.replayed_tt_output(
            &matched.bindings,
            source,
            MacroTranscriberParseContext::Item,
        );
        let target = source.rfind("target").unwrap();
        assert!(
            output
                .fragments
                .iter()
                .any(|fragment| fragment.start_byte == target
                    && fragment.end_byte == target + 6
                    && fragment.source == MacroTranscribedSource::Invocation
                    && fragment.reference_role == Some(MacroTranscribedReferenceRole::Call)),
            "{output:#?}"
        );
        assert!(
            output
                .fragments
                .iter()
                .any(|fragment| fragment.start_byte == target
                    && fragment.end_byte == target + "target()".len()
                    && fragment.syntax_kind == "call_expression"
                    && fragment.source == MacroTranscribedSource::Invocation),
            "{output:#?}"
        );
        let other = source.rfind("other").unwrap();
        assert!(
            output
                .paths
                .iter()
                .any(|path| path.segments.contains(&(other, other + 5))),
            "{output:#?}"
        );
    }

    #[test]
    fn grammar_macro_replay_substitution() {
        // Each expected expansion is authored independently from the macro
        // substitution rules. Compare grammar trees, so trivia is irrelevant.
        for (rule, input, expected) in [
            (
                "(#![$m:meta]) => { fn generated() {} }",
                "#![doc = \"text\"]",
                "fn generated() {}",
            ),
            (
                "(#[$m:meta]) => { fn generated() {} }",
                "#[doc = \"text\"]",
                "fn generated() {}",
            ),
            (
                "($v:vis $t:ty) => { $v fn generated(_: $t) {} }",
                "pub(crate) Item",
                "pub(crate) fn generated(_: Item) {}",
            ),
            (
                "($v:vis $t:ty) => { $v fn generated(_: $t) {} }",
                "Item",
                "fn generated(_: Item) {}",
            ),
            ("($($t:ty),*) => { $(fn generated(_: $t) {})* }", "", ""),
            (
                "($($t:ty),*) => { $(fn generated(_: $t) {})* }",
                "Item, Other",
                "fn generated(_: Item) {} fn generated(_: Other) {}",
            ),
            ("($($t:ty)?) => { $(fn generated(_: $t) {})? }", "", ""),
            (
                "($($t:ty)?) => { $(fn generated(_: $t) {})? }",
                "Item",
                "fn generated(_: Item) {}",
            ),
            (
                "($($t:ty),+) => { $(fn generated(_: $t) {})+ }",
                "Item, Other",
                "fn generated(_: Item) {} fn generated(_: Other) {}",
            ),
            (
                "($($t:tt)*) => { fn generated() { $($t)* } }",
                "target();",
                "fn generated() { target(); }",
            ),
            (
                "($t:ident) => { fn generated() -> $t { loop {} } }",
                "Item",
                "fn generated() -> Item { loop {} }",
            ),
            (
                "($t:ident) => { fn generated(&$t) {} }",
                "self",
                "fn generated(&self) {}",
            ),
        ] {
            let source = format!("macro_rules! take {{ {rule}; }} take!({input});");
            let tree = parse(&source);
            let (definition, arguments) = definition_and_invocation(&tree, &source);
            let matched =
                match_syntax_macro_rules(definition, &source, arguments, &source).unwrap();
            let transcriber = capture_macro_transcribers(definition, &source)
                .remove(0)
                .unwrap();
            let (expanded, _) = transcriber
                .replay(&matched.bindings, &source)
                .expect("valid substitution");
            let actual = parse(&expanded);
            assert!(!actual.root_node().has_error(), "{expanded}");
            assert_eq!(
                actual.root_node().to_sexp(),
                parse(expected).root_node().to_sexp(),
                "{source}"
            );
        }
    }

    #[test]
    fn grammar_macro_binding_coordinates_and_namespaces() {
        for (matcher, argument, fragment, evidence) in [
            (
                "$t:ty",
                "Item",
                MacroFragmentKind::Ty,
                MacroNamespaceEvidence::Type,
            ),
            (
                "$t:expr",
                "target()",
                MacroFragmentKind::Expr,
                MacroNamespaceEvidence::Value,
            ),
            (
                "$t:ident",
                "true",
                MacroFragmentKind::Ident,
                MacroNamespaceEvidence::Value,
            ),
        ] {
            let source = format!(
                "// non-ASCII: \u{e9}\nmacro_rules! take {{ ({matcher}) => {{ $t }}; }}\nfn f() {{\n    take!({argument});\n}} "
            );
            let tree = parse(&source);
            let (definition, arguments) = definition_and_invocation(&tree, &source);
            let matched =
                match_syntax_macro_rules(definition, &source, arguments, &source).unwrap();
            let binding = &matched.bindings[0];
            assert_eq!(binding.fragment, fragment);
            assert_eq!(binding_text(&source, binding), argument);
            if fragment != MacroFragmentKind::Ident {
                assert_eq!(
                    token_namespace_evidence(&matched, binding.start_byte, binding.end_byte),
                    Some(evidence)
                );
                let parsed = parse_bound_fragment(binding, &source).unwrap();
                let node = parsed
                    .root_node()
                    .descendant_for_byte_range(binding.start_byte, binding.end_byte)
                    .unwrap();
                assert_eq!(node.start_position(), tree_sitter::Point::new(3, 10));
                assert_eq!(node.byte_range(), binding.start_byte..binding.end_byte);
                let input = capture_macro_input(arguments, &source, &|| true).unwrap();
                let lowered = lower_selected_macro_input_with_sources(
                    &input,
                    &matched,
                    RustMacroItemContainer::Lexical,
                );
                let occurrences = lowered
                    .sources
                    .occurrences()
                    .iter()
                    .filter(|row| {
                        row.range.start_byte == binding.start_byte
                            && row.range.end_byte == binding.end_byte
                    })
                    .collect::<Vec<_>>();
                assert!(
                    !occurrences.is_empty(),
                    "selected fragment publishes its source span"
                );
                assert!(occurrences.iter().all(|row| row.provenance == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded), "{occurrences:?}");
            }
        }
    }

    #[test]
    fn grammar_macro_fragment_offsets() {
        use MacroFragmentKind::{Expr, Item, Pat, Ty};
        use MacroNamespaceEvidence::{Declaration, Type, Value};

        let source = "// \u{e9}\nty!(&Caf\u{e9});\nexpr!(<Caf\u{e9} as Trait>::make(nested!(value)));\npat!(Some(ref caf\u{e9}));\nitem!(struct Caf\u{e9};);\n";
        let tree = parse(source);
        assert!(!tree.root_node().has_error());
        // Fragment interior, original token, wrapped token, grammar parent and
        // field. These coordinates are literal UTF-8 byte counts, not outputs
        // from the wrapper or namespace classifier.
        for (fragment, interior, original, wrapped_span, kind, parent_kind, field, evidence) in [
            (
                Ty,
                10..16,
                11..16,
                22..27,
                "type_identifier",
                "reference_type",
                Some("type"),
                Type,
            ),
            (
                Expr,
                25..63,
                26..31,
                23..28,
                "type_identifier",
                "qualified_type",
                Some("type"),
                Type,
            ),
            (
                Expr,
                25..63,
                35..40,
                32..37,
                "type_identifier",
                "qualified_type",
                Some("alias"),
                Type,
            ),
            (
                Expr,
                25..63,
                43..47,
                40..44,
                "identifier",
                "scoped_identifier",
                Some("name"),
                Value,
            ),
            (
                Pat,
                71..86,
                80..85,
                27..32,
                "identifier",
                "ref_pattern",
                None,
                Value,
            ),
            (
                Item,
                95..108,
                102..107,
                7..12,
                "type_identifier",
                "struct_item",
                Some("name"),
                Declaration,
            ),
        ] {
            let token = tree
                .root_node()
                .descendant_for_byte_range(original.start, original.end)
                .unwrap();
            let invocation =
                enclosing_macro_invocation_for_argument(token).expect("argument invocation");
            let name = invocation.child_by_field_name("macro").unwrap();
            assert!(enclosing_macro_invocation_for_argument(name).is_none());
            let arguments =
                crate::declarations::rust_macro_invocation_arguments(invocation).unwrap();
            assert_eq!(arguments.child(0).unwrap().end_byte(), interior.start);
            assert_eq!(
                arguments
                    .child(arguments.child_count() - 1)
                    .unwrap()
                    .start_byte(),
                interior.end
            );
            let fragment_source = &source[interior.clone()];
            let (wrapped, prefix) = wrap_fragment(fragment, fragment_source);
            let parsed = parse(&wrapped);
            assert!(
                !parsed.root_node().has_error(),
                "{}",
                parsed.root_node().to_sexp()
            );
            let node = parsed
                .root_node()
                .descendant_for_byte_range(wrapped_span.start, wrapped_span.end)
                .unwrap();
            assert_eq!(node.kind(), kind);
            assert_eq!(node.byte_range(), wrapped_span);
            assert_eq!(node.parent().unwrap().kind(), parent_kind);
            if let Some(field) = field {
                assert_eq!(
                    node.parent().unwrap().child_by_field_name(field),
                    Some(node)
                );
            } else {
                assert_eq!(node.parent().unwrap().named_child(0), Some(node));
            }
            assert_eq!(&wrapped[wrapped_span.clone()], &source[original.clone()]);
            assert_eq!(wrapped_span.start - prefix + interior.start, original.start);
            assert_eq!(wrapped_span.end - prefix + interior.start, original.end);
            assert_eq!(
                classify_fragment_interior(
                    fragment,
                    fragment_source,
                    original.start - interior.start,
                    original.end - interior.start
                ),
                Some(evidence)
            );
            if fragment == Expr {
                // The inner invocation is syntax only after the outer argument
                // is reparsed. Its name is still excluded from its arguments.
                let nested = parsed
                    .root_node()
                    .descendant_for_byte_range(45, 51)
                    .unwrap();
                assert_eq!(nested.kind(), "identifier");
                assert_eq!(nested.utf8_text(wrapped.as_bytes()).unwrap(), "nested");
                assert!(enclosing_macro_invocation_for_argument(nested).is_none());
                let value = parsed
                    .root_node()
                    .descendant_for_byte_range(53, 58)
                    .unwrap();
                assert_eq!(
                    enclosing_macro_invocation_for_argument(value)
                        .unwrap()
                        .child_by_field_name("macro"),
                    Some(nested)
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "c355a27ef45c: Repeated transcriber expansion retains definition-owned type-reference ranges for literal tokens."
    )]
    fn transcriber_replay_maps_repeated_literals_to_definition_source() {
        let source = r#"
macro_rules! gen_tuple {
    ($($M:ident),*) => {
        fn generated<$($M,)* EC>()
        where
            $(TestOutput<EC>: Adaptor<$M>,)*
        {}
    };
}

gen_tuple!(Metric);
"#;
        let tree = parse(source);
        let definition =
            named_descendant(tree.root_node(), "macro_definition").expect("macro definition");
        let invocation =
            named_descendant(tree.root_node(), "macro_invocation").expect("macro invocation");
        let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)
            .expect("invocation arguments");
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("matching arm");
        let transcriber = capture_macro_transcribers(definition, source)
            .into_iter()
            .next()
            .flatten()
            .expect("captured transcriber");
        let output = transcriber.replayed_tt_output(
            &matched.bindings,
            source,
            MacroTranscriberParseContext::Item,
        );
        assert!(
            output.fragments.iter().any(|fragment| {
                fragment.source == MacroTranscribedSource::Definition
                    && fragment.syntax_kind == "type_identifier"
                    && fragment.reference_role == Some(MacroTranscribedReferenceRole::Type)
                    && source.get(fragment.start_byte..fragment.end_byte) == Some("TestOutput")
            }),
            "replayed where-clause literal must retain its definition range: {output:#?}"
        );
    }

    #[test]
    fn ty_fragment_binds_the_type_argument() {
        let source =
            "macro_rules! convert { ($t:ty) => { fn decode(_: $t) {} }; } convert!(Timestamp);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.arm_index, 0);
        assert_eq!(matched.bindings.len(), 1);
        assert_eq!(matched.bindings[0].name, "t");
        assert_eq!(matched.bindings[0].fragment, MacroFragmentKind::Ty);
        assert_eq!(binding_text(source, &matched.bindings[0]), "Timestamp");
    }

    #[test]
    #[hardwon("6dc4d18752fb: tree-sitter recovery accepted a lifetime as a path fragment")]
    fn recovered_lifetime_uses_the_lifetime_arm_instead_of_the_path_arm() {
        let source = r#"//@ check-pass

macro_rules! foo {
    ($(: $p:path)? $(: $l:lifetime)? ) => { bar! {$(: $p)? $(: $l)? } };
}

macro_rules! bar {
    ($(: $p:path)? $(: $l:lifetime)? ) => {};
}

foo! {: 'a }

fn main() {}
"#;
        assert_eq!(source.len(), 206);
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match arm");

        assert!(matched.bindings.iter().any(|binding| {
            binding.name == "l"
                && binding.fragment == MacroFragmentKind::Lifetime
                && binding_text(source, binding) == "'a"
        }));
        assert!(!matched.bindings.iter().any(|binding| binding.name == "p"));
    }

    #[test]
    fn keyword_ident_capture_does_not_take_the_type_role() {
        // rustc_metadata's parameterized_over_tcx! and rust-analyzer's
        // quote.rs: an `ident` capture whose transcriber role is a type can
        // receive `crate` or `self`, which is not a type.
        let source = r#"macro_rules! parameterized_over_tcx {
    ($($( $fake_path:ident )::+ ),+ $(,)?) => {
        $( impl ParameterizedOverTcx for $( $fake_path )::+ <'static> {
            type Value<'tcx> = $( $fake_path )::+ <'tcx>;
        } )*
    }
}
parameterized_over_tcx! { crate::rmeta::DefPathHashMapRef, rustc_middle::ty::Ty }

macro_rules! impl_to_tokens {
    ($($ty:ty => $this:ident $im:block;)*) => {
        $( impl ToTokenTree for $ty { fn to_tokens($this, span: Span) { $im } } )*
    }
}
impl_to_tokens! { u32 => self { self.to_string() }; }
"#;
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match arm");
        let roles = matched
            .bindings
            .iter()
            .map(|binding| (binding_text(source, binding), binding.ident_role))
            .collect::<Vec<_>>();
        assert_eq!(roles[0], ("crate", Some(MacroIdentRole::Unused)));
        assert_eq!(roles[1], ("rmeta", Some(MacroIdentRole::Type)));

        crate::test_helpers::parse_rust_fixture(source);
    }

    #[test]
    #[hardwon("6dc4d18752fb: a valid path before trailing macro arguments must remain matched")]
    fn path_fragment_stops_before_issue_7911_trailing_arguments() {
        let source = r#"macro_rules! generate_test { ($type_:path, $slf:ident, $field:expr) => (
    impl Test for $type_ {
        fn get_immut(&$slf) -> &dyn FooBar { &$field as &dyn FooBar }
        fn get_mut(&mut $slf) -> &mut dyn FooBar { &mut $field as &mut dyn FooBar }
    }
)}
generate_test!(Foo, self, self.bar);
"#;
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match arm");

        let ty = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "type_")
            .expect("path binding");
        assert_eq!(ty.fragment, MacroFragmentKind::Path);
        assert_eq!(binding_text(source, ty), "Foo");
        assert_eq!(
            matched
                .bindings
                .iter()
                .find(|binding| binding.name == "slf")
                .expect("self receiver binding")
                .ident_role,
            Some(MacroIdentRole::Unused)
        );
    }

    #[test]
    fn serde_conv_doc_binds_ty_not_the_closure_types() {
        let source = concat!(
            "macro_rules! serde_conv_doc { ($(#[$meta:meta])* $vis:vis $m:ident, $t:ty, $ser:expr, $de:expr) => {}; } ",
            "serde_conv_doc!(pub Convert, Timestamp, |value: &Timestamp| -> Result<u32, String> { Ok(0) }, ",
            "|value: u32| -> Result<Timestamp, String> { Ok(Timestamp { time: value }) });"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        let ty = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "t")
            .expect("t binding");
        assert_eq!(ty.fragment, MacroFragmentKind::Ty);
        assert_eq!(binding_text(source, ty), "Timestamp");
        let ident = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "m")
            .expect("m binding");
        assert_eq!(binding_text(source, ident), "Convert");
    }

    #[test]
    fn repeated_ident_tt_ident_binds_each_slot() {
        let source = concat!(
            "macro_rules! adapters { ($( $ty:ident, $ser:tt, $de:ident );* $(;)?) => { $( fn generated(value: $ty) -> $ty { value } )* }; } ",
            "adapters! { Timestamp, {}, decode; }"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        let ty = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "ty")
            .expect("ty binding");
        assert_eq!(ty.fragment, MacroFragmentKind::Ident);
        assert_eq!(binding_text(source, ty), "Timestamp");
        let ser = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "ser")
            .expect("ser binding");
        assert_eq!(binding_text(source, ser), "{}");
        let de = matched
            .bindings
            .iter()
            .find(|binding| binding.name == "de")
            .expect("de binding");
        assert_eq!(binding_text(source, de), "decode");
        let right = definition
            .named_children(&mut definition.walk())
            .find(|child| child.kind() == "macro_rule")
            .and_then(|rule| rule.child_by_field_name("right"))
            .expect("transcriber");
        assert_eq!(
            ident_transcriber_role(right, source, "ty"),
            MacroIdentRole::Type
        );
    }

    #[test]
    fn first_matching_arm_wins() {
        let source = concat!(
            "macro_rules! take { ($e:expr) => { $e }; ($t:ty) => { let _: $t; }; } ",
            "take!(Timestamp);"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.arm_index, 0);
        assert_eq!(matched.bindings[0].fragment, MacroFragmentKind::Expr);
    }

    #[test]
    #[hardwon("#4482: expr macro calls followed by an optional comma failed to match")]
    fn expr_macro_call_and_optional_trailing_comma_match() {
        let source = r#"
macro_rules! cut_error { ($message:expr, $span:expr $(,)?) => {}; }
cut_error!(format!("only expected `{allowed}` digits for `0{base}` integers, found `{digit}`"), span,);
"#;
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.bindings.len(), 2);
        assert_eq!(
            binding_text(source, &matched.bindings[0]),
            "format!(\"only expected `{allowed}` digits for `0{base}` integers, found `{digit}`\")"
        );
        assert_eq!(binding_text(source, &matched.bindings[1]), "span");

        let with_suffix = r#"
macro_rules! cut_error { ($message:expr, $span:expr $(,)?) => {}; }
cut_error!(format!("bad").to_owned(), span);
"#;
        let tree = parse(with_suffix);
        let (definition, arguments) = definition_and_invocation(&tree, with_suffix);
        let matched = match_syntax_macro_rules(definition, with_suffix, arguments, with_suffix)
            .expect("match full macro expression");
        assert_eq!(
            binding_text(with_suffix, &matched.bindings[0]),
            "format!(\"bad\").to_owned()"
        );

        let nonmatching = r#"
macro_rules! cut_error { ($message:expr, $span:expr $(,)?) => {}; }
cut_error!(format!("bad"),);
"#;
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon("#4482: expr fragments in semicolon-terminated repetitions failed to match")]
    fn expr_fragments_followed_by_fat_arrow_match_in_semicolon_repetitions() {
        let source = concat!(
            "macro_rules! ensure_spanned { ",
            "($($condition:expr, $span:expr => $msg:expr;)*) => {}; } ",
            "ensure_spanned!(c1, s1 => m1; c2, s2 => m2;);"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(
            matched
                .bindings
                .iter()
                .map(|binding| (binding.name.as_str(), binding_text(source, binding)))
                .collect::<Vec<_>>(),
            [
                ("condition", "c1"),
                ("span", "s1"),
                ("msg", "m1"),
                ("condition", "c2"),
                ("span", "s2"),
                ("msg", "m2"),
            ]
        );

        let nonmatching = concat!(
            "macro_rules! ensure_spanned { ",
            "($($condition:expr, $span:expr => $msg:expr;)*) => {}; } ",
            "ensure_spanned!(c1, s1 => m1 c2, s2 => m2;);"
        );
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon("#4482: ident fragments rejected the self keyword in an identifier position")]
    fn ident_fragment_matches_keyword_self() {
        let source = "macro_rules! m { ($name:ident) => {}; } m!(self);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.bindings.len(), 1);
        assert_eq!(binding_text(source, &matched.bindings[0]), "self");

        let nonmatching = "macro_rules! m { ($name:ident) => {}; } m!(_);";
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon("#4482: meta fragments stopped before parenthesized meta arguments")]
    fn meta_fragments_include_nested_arguments_in_repetitions() {
        let source = concat!(
            "macro_rules! m { ",
            "($src:ty { $($(#[$cfg:meta])? $variant:ident => $value:literal),* $(,)? }) => {}; } ",
            "m!(Scheme { #[cfg(feature = \"services-a\")] A => \"a\", B => \"b\", });"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(
            matched
                .bindings
                .iter()
                .map(|binding| (binding.name.as_str(), binding_text(source, binding)))
                .collect::<Vec<_>>(),
            [
                ("src", "Scheme"),
                ("cfg", "cfg(feature = \"services-a\")"),
                ("variant", "A"),
                ("value", "\"a\""),
                ("variant", "B"),
                ("value", "\"b\""),
            ]
        );

        let nonmatching = concat!(
            "macro_rules! m { ",
            "($src:ty { $($(#[$cfg:meta])? $variant:ident => $value:literal),* $(,)? }) => {}; } ",
            "m!(Scheme { A => \"a\" B => \"b\" });"
        );
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon("#4482: meta fragments consumed a following fat-arrow arm separator")]
    fn meta_fragments_stop_before_fat_arrow() {
        let source = concat!(
            "macro_rules! select { ($cfg:meta => $($rest:tt)*) => {}; } ",
            "select! { not(any(Py_LIMITED_API, PyPy, GraalPy)) => { unsafe {} } }"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.bindings[0].name, "cfg");
        assert_eq!(
            binding_text(source, &matched.bindings[0]),
            "not(any(Py_LIMITED_API, PyPy, GraalPy))"
        );
        assert_eq!(
            matched
                .bindings
                .iter()
                .filter(|binding| binding.name == "rest")
                .map(|binding| binding_text(source, binding))
                .collect::<Vec<_>>(),
            ["{ unsafe {} }"]
        );

        let name_value = concat!(
            "macro_rules! select { ($cfg:meta => $tail:tt) => {}; } ",
            "select! { feature = \"limited\" => {} }"
        );
        let tree = parse(name_value);
        let (definition, arguments) = definition_and_invocation(&tree, name_value);
        let matched =
            match_syntax_macro_rules(definition, name_value, arguments, name_value).expect("match");
        assert_eq!(
            binding_text(name_value, &matched.bindings[0]),
            "feature = \"limited\""
        );
        assert_eq!(binding_text(name_value, &matched.bindings[1]), "{}");

        let nonmatching = concat!(
            "macro_rules! select { ($cfg:meta => $($rest:tt)*) => {}; } ",
            "select! { not(any(Py_LIMITED_API, PyPy, GraalPy)) { unsafe {} } }"
        );
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon(
        "#4482: item fragments rejected use declarations; #6861: dropped meta prefixes admitted item replay"
    )]
    #[hardwon("#6912: item fragments rejected leading outer attributes")]
    fn item_fragments_match_use_declarations() {
        let source = "macro_rules! m { ($item:item) => {}; } m!(use alloc::vec::Vec;);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.bindings.len(), 1);
        assert_eq!(
            binding_text(source, &matched.bindings[0]),
            "use alloc::vec::Vec;"
        );

        // The inventory and selected-arm paths must agree when an arm drops
        // an input attribute instead of replaying it as part of the item, and
        // when a separated repetition consumes a comma that no Item capture
        // holds (the grammar emits no node for the separator).
        for (pattern, expansion, input, admitted) in [
            ("$item:item", "$item", "fn ordinary() {}", true),
            (
                "$item:item",
                "$item",
                "#[derive(Debug)] pub struct Carried;",
                true,
            ),
            (
                "$($item:item)*",
                "$($item)*",
                "#[allow(dead_code)] /* between */ #[derive(Debug)] pub struct First; #[derive(Clone)] struct Second;",
                true,
            ),
            (
                "#[$m:meta] $item:item",
                "$item",
                "#[cfg(any())] fn hidden() {}",
                false,
            ),
            (
                "$($item:item)*",
                "$($item)*",
                "fn a() {} /* extra */ fn b() {}",
                true,
            ),
            (
                "$($item:item),*",
                "$($item)*",
                "fn a() {}, fn b() {}",
                false,
            ),
        ] {
            let source =
                format!("macro_rules! m {{ ({pattern}) => {{ {expansion} }}; }} m!({input});");
            let tree = parse(&source);
            let (definition, arguments) = definition_and_invocation(&tree, &source);
            match_syntax_macro_rules(definition, &source, arguments, &source).unwrap_or_else(
                |error| panic!("arm must match before admission: {error:?}: {source}"),
            );
            assert_eq!(
                crate::declarations::rust_macro_definition_expands_to_its_arguments_only(
                    definition, &source,
                ),
                admitted,
                "inventory: {source}",
            );
            let exports = ExportedMacroDefinitions::from_root(tree.root_node(), &source);
            assert_eq!(
                local_macro_invocation_replays_items_only(
                    arguments.parent().expect("invocation"),
                    &source,
                    &exports,
                ),
                admitted,
                "selected arm: {source}",
            );
        }

        let nonmatching = "macro_rules! m { ($item:item) => {}; } m!(let value = 1;);";
        let tree = parse(nonmatching);
        let (definition, arguments) = definition_and_invocation(&tree, nonmatching);
        assert_eq!(
            match_syntax_macro_rules(definition, nonmatching, arguments, nonmatching),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    #[hardwon("#4482: doc comments in macro input were not matched as doc attributes")]
    fn doc_comments_match_meta_attribute_repetitions() {
        let source = concat!(
            "macro_rules! m { ($(#[$doc:meta])* fn $name:ident() $body:block) => {}; } ",
            "m! { /// line docs\n fn answer() {} }"
        );
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.bindings.len(), 3);
        assert_eq!(matched.bindings[0].name, "doc");
        assert_eq!(
            binding_text(source, &matched.bindings[0]),
            "/// line docs\n"
        );
        assert_eq!(matched.bindings[1].name, "name");
        assert_eq!(binding_text(source, &matched.bindings[1]), "answer");
        assert_eq!(matched.bindings[2].name, "body");
        assert_eq!(binding_text(source, &matched.bindings[2]), "{}");

        let block_docs = concat!(
            "macro_rules! m { ($(#[$doc:meta])* fn $name:ident() $body:block) => {}; } ",
            "m! { /** block docs */ fn answer() {} }"
        );
        let tree = parse(block_docs);
        let (definition, arguments) = definition_and_invocation(&tree, block_docs);
        let matched =
            match_syntax_macro_rules(definition, block_docs, arguments, block_docs).expect("match");
        assert_eq!(
            binding_text(block_docs, &matched.bindings[0]),
            "/** block docs */"
        );

        let ordinary_comment = concat!(
            "macro_rules! m { ($(#[$doc:meta])* fn $name:ident() $body:block) => {}; } ",
            "m! { // ordinary comment\n fn answer() {} }"
        );
        let tree = parse(ordinary_comment);
        let (definition, arguments) = definition_and_invocation(&tree, ordinary_comment);
        assert!(
            match_syntax_macro_rules(definition, ordinary_comment, arguments, ordinary_comment)
                .is_ok()
        );

        let inner_macro = concat!(
            "macro_rules! m { (#![$doc:meta] fn $name:ident() $body:block) => {}; } ",
            "m! { //! inner docs\n fn answer() {} }"
        );
        let tree = parse(inner_macro);
        let (definition, arguments) = definition_and_invocation(&tree, inner_macro);
        let matched = match_syntax_macro_rules(definition, inner_macro, arguments, inner_macro)
            .expect("match");
        assert_eq!(matched.bindings[0].name, "doc");
        assert_eq!(
            binding_text(inner_macro, &matched.bindings[0]),
            "//! inner docs\n"
        );

        let inner_doc = concat!(
            "macro_rules! m { ($(#[$doc:meta])* fn $name:ident() $body:block) => {}; } ",
            "m! { //! inner docs\n fn answer() {} }"
        );
        let tree = parse(inner_doc);
        let (definition, arguments) = definition_and_invocation(&tree, inner_doc);
        assert_eq!(
            match_syntax_macro_rules(definition, inner_doc, arguments, inner_doc),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    #[test]
    fn generated_declaration_ident_is_declaration() {
        let source = "macro_rules! make { ($name:ident) => { struct $name; }; } make!(Item);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched =
            match_syntax_macro_rules(definition, source, arguments, source).expect("match");
        let evidence = token_namespace_evidence(
            &matched,
            matched.bindings[0].start_byte,
            matched.bindings[0].end_byte,
        );
        assert_eq!(evidence, Some(MacroNamespaceEvidence::Declaration));
    }

    #[test]
    fn captured_type_and_expression_fragments_retain_original_reference_ranges() {
        let source = "macro_rules! take { ($t:ty, $e:expr) => {}; }\nfn run() { take!(crate::Row, value + 1); }";
        let tree = parse_rust_tree(source).expect("fixture syntax");
        let mut pending = vec![tree.root_node()];
        let mut invocation = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_invocation" {
                invocation = Some(node);
                break;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let invocation = invocation.expect("fixture invocation");
        let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)
            .expect("invocation arguments");
        let input = capture_macro_input(arguments, source, &|| true).expect("canonical input");
        let arm = match_local_macro_invocation(invocation, source)
            .expect("visible definition")
            .expect("matching arm");
        let facts = lower_selected_macro_input(&input, &arm, RustMacroItemContainer::Lexical);
        for (name, namespace) in [
            ("Row", ResolutionNamespace::Type),
            ("value", ResolutionNamespace::Value),
        ] {
            let identifier = facts
                .identifiers
                .iter()
                .find(|identifier| {
                    identifier.role == ResolutionIdentifierRole::Reference
                        && identifier.namespace == namespace
                        && facts.names[identifier.name.index()].spelling == name
                })
                .expect("captured reference");
            let site = facts
                .sites
                .iter()
                .find(|site| site.id == identifier.site)
                .expect("reference site");
            assert_eq!(&source[site.start_byte..site.end_byte], name);
            assert!(input.tokens.iter().any(
                |token| token.start_byte == site.start_byte && token.end_byte == site.end_byte
            ));
        }
    }

    #[test]
    #[hardwon("671de562afc1: lowering a selected type fragment interned its synthetic alias name")]
    fn selected_generic_type_fragment_does_not_lower_its_synthetic_alias() {
        let source = "macro_rules! take { ($ty:ty,) => {}; }\ntake!(Vec::<String>,);";
        let tree = parse(source);
        let invocation =
            named_descendant(tree.root_node(), "macro_invocation").expect("fixture invocation");
        let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)
            .expect("invocation arguments");
        let input = capture_macro_input(arguments, source, &|| true).expect("canonical input");
        let type_text = "Vec::<String>";
        let type_start = input.start_byte + input.source.find(type_text).unwrap();
        let arm = MacroArmMatch {
            arm_index: 0,
            bindings: vec![MacroBinding {
                name: "ty".to_owned(),
                fragment: MacroFragmentKind::Ty,
                start_byte: type_start,
                end_byte: type_start + type_text.len(),
                repetition_path: Vec::new(),
                ident_role: None,
            }],
        };

        let facts = lower_selected_macro_input(&input, &arm, RustMacroItemContainer::Lexical);

        assert!(facts.names.iter().all(|name| !name.spelling.is_empty()));
        assert!(facts.identifiers.iter().any(|identifier| {
            identifier.role == ResolutionIdentifierRole::Reference
                && facts.names[identifier.name.index()].spelling == "Vec"
        }));
        assert!(
            facts
                .identifiers
                .iter()
                .all(|identifier| { identifier.role != ResolutionIdentifierRole::Declaration })
        );
    }

    #[test]
    #[hardwon("#4848: each macro invocation rescanned the source tree for exported definitions")]
    fn indexed_exported_macro_definitions_match_repeated_crate_root_calls() {
        let source = concat!(
            "#[macro_export] macro_rules! exported { ($value:expr) => { $value }; }\n",
            "#[cfg(any())] #[macro_export] macro_rules! disabled { ($value:expr) => { $value }; }\n",
            "fn first() { crate::exported!(1); }\n",
            "fn second() { crate::exported!(2); }\n",
            "fn inactive() { crate::disabled!(3); }\n",
        );
        let tree = parse(source);
        let mut macro_definitions = Vec::new();
        let mut invocations = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.kind() == "macro_definition" {
                macro_definitions.push(node);
            } else if node.kind() == "macro_invocation" {
                invocations.push(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let definitions = ExportedMacroDefinitions::from_candidates(macro_definitions, source);
        assert_eq!(definitions.definitions.len(), 1);

        let mut matches = 0;
        for invocation in invocations {
            match match_local_macro_invocation_with_definitions(
                invocation,
                source,
                &definitions,
                invocation,
            ) {
                Some(Ok(_)) => matches += 1,
                None if crate::declarations::rust_node_text(
                    invocation.child_by_field_name("macro").expect("macro path"),
                    source,
                ) == "crate::disabled" => {}
                other => panic!("unexpected indexed macro match: {other:?}"),
            }
        }
        assert_eq!(matches, 2);
    }
}

/// Where a matched invocation's `item` fragments land once it is expanded.
///
/// Declaration replay records this structurally: the invocation's item context
/// and that context's parent. An invocation written in the body of an `impl`
/// or a trait expands to that owner's associated items, which Rust never puts
/// in unqualified lexical scope, so a capsule must not bind their names there.
/// Everywhere else (a file root, a module body, a block) the expansion's items
/// are ordinary items, and their names are lexical binders of that scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustMacroItemContainer {
    Lexical,
    Associated,
}

impl RustMacroItemContainer {
    /// The container of an expansion whose item context has kind `context`
    /// and whose context's parent has kind `parent`. An `impl` or trait body
    /// is a `DeclarationBody` whose parent is the `impl` or trait; a module
    /// body is a `DeclarationBody` too, and its items are lexical.
    pub fn of_expansion_context(
        context: brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind,
        parent: Option<brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind>,
    ) -> Self {
        use brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind as Kind;
        match (context, parent) {
            (Kind::DeclarationBody, Some(Kind::Impl | Kind::Trait)) => Self::Associated,
            _ => Self::Lexical,
        }
    }
}

/// Instantiate native fragment facts after the selected consumer has matched a
/// canonical definition. Only the invocation snapshot is parsed. The returned
/// root scope must be attached to the invocation's native lexical scope before
/// these operation-local facts can answer a query.
pub fn lower_selected_macro_input(
    input: &brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    arm: &MacroArmMatch,
    container: RustMacroItemContainer,
) -> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts {
    lower_selected_macro_input_with_sources(input, arm, container).facts
}

pub struct SelectedMacroInputLowering {
    pub facts: brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    pub sources: brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
    pub declarations: Vec<(
        brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
        brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId,
    )>,
}

pub fn lower_selected_macro_input_with_sources(
    input: &brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    arm: &MacroArmMatch,
    container: RustMacroItemContainer,
) -> SelectedMacroInputLowering {
    let mut source = " ".repeat(input.start_byte);
    source.push_str(&input.source);
    let tree = parse_rust_tree(&source).expect("Rust parser accepts an invocation capsule");
    let mut builder = crate::resolution::RustResolutionBuilder::new_for_macro_input(
        tree.root_node(),
        &source,
        input,
    );
    builder.lower_capsule_macro_bindings(tree.root_node(), arm, container);
    let output = builder.finish();
    SelectedMacroInputLowering {
        facts: output.facts,
        sources: output.source_facts,
        declarations: output.declaration_sources,
    }
}
