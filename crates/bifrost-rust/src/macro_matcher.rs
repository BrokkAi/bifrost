//! Structured `macro_rules!` matcher-to-invocation binding.
//!
//! This module maps tokens in a macro invocation argument group onto the
//! selected arm's matcher bindings. It does not expand macros and it does not
//! consult imports. Callers that have an indexed `macro_rules!` definition
//! feed that definition's syntax tree and the invocation argument `token_tree`.

use crate::declarations::rust_node_text;
use crate::lexical_scope::parse_rust_tree;
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
        start >= self.start_byte && end <= self.end_byte
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
    let textual_name =
        crate::declarations::rust_unqualified_macro_invocation_name(invocation, source);
    let name = textual_name.or_else(|| crate_root_macro_invocation_name(invocation, source))?;
    let arguments = crate::declarations::rust_macro_invocation_arguments(invocation)?;
    let mut root = invocation;
    let mut parent = invocation.parent();
    while let Some(scope) = parent {
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
            let facts = capture_syntax_macro_definition(definition, source);
            return Some(match_macro_rules(&facts, arguments, source, &|| true));
        }
        root = scope;
        parent = scope.parent();
    }
    let exported = exported_macro_definition_nodes(root, source);
    let mut candidates = exported.into_iter().filter(|node| {
        node.child_by_field_name("name")
            .is_some_and(|node| rust_node_text(node, source) == name)
    });
    let definition = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    let facts = capture_syntax_macro_definition(definition, source);
    Some(match_macro_rules(&facts, arguments, source, &|| true))
}

/// Read root-path macro authority once from real syntax, excluding generated
/// token trees and scopes whose activation is not source-owned.
pub(crate) fn exported_macro_definition_nodes<'tree>(
    root: Node<'tree>,
    source: &str,
) -> Vec<Node<'tree>> {
    let mut pending = vec![root];
    let mut exported = Vec::new();
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "macro_invocation" | "token_tree")
            || crate::lexical_scope::rust_cfg_condition(node, source)
                != crate::lexical_scope::RustCfgCondition::Always
        {
            continue;
        }
        if node.kind() == "macro_definition" {
            if node.child_by_field_name("name").is_some()
                && crate::declarations::rust_item_has_simple_attribute(node, source, "macro_export")
            {
                exported.push(node);
            }
            continue;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    exported
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
    if token.kind() != "lifetime" && !token.text().trim().starts_with('\'') {
        return None;
    }
    let range = (token.start_byte(), token.end_byte());
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
    let consumed = parsed_prefix_len(fragment, tree.root_node(), &wrapped, prefix_len)?;
    if consumed == 0 {
        return None;
    }
    let end = start + consumed;
    if !input.advance_through(end) {
        return None;
    }
    Some((start, end))
}

/// Parse a captured fragment and retain its original source coordinates.
/// The edit changes only the synthetic wrapper before the fragment; every
/// fragment node can therefore be lowered against the original source bytes.
pub(crate) fn parse_bound_fragment(
    binding: &MacroBinding,
    source: &str,
) -> Option<tree_sitter::Tree> {
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
            Some(node.end_byte() - prefix_len)
        }
        MacroFragmentKind::Expr | MacroFragmentKind::Stmt => {
            let node = largest_clean_node_starting_at(root, expected_start)?;
            Some(node.end_byte() - prefix_len)
        }
        MacroFragmentKind::Pat => {
            let parameters =
                named_descendant(root, "function_item")?.child_by_field_name("parameters")?;
            let parameter = named_child_of_kind(parameters, "parameter")?;
            let pat = parameter.child_by_field_name("pattern")?;
            if pat.start_byte() != expected_start {
                return None;
            }
            Some(pat.end_byte() - prefix_len)
        }
        MacroFragmentKind::Item => {
            let item = first_source_item(root)?;
            if item.start_byte() != expected_start {
                return None;
            }
            Some(item.end_byte() - prefix_len)
        }
        MacroFragmentKind::Block => {
            let block = named_descendant(root, "block")?;
            if block.start_byte() != expected_start {
                return None;
            }
            Some(block.end_byte() - prefix_len)
        }
        MacroFragmentKind::Meta => {
            let attribute = named_descendant(root, "attribute_item")?;
            let inner = attribute
                .child_by_field_name("value")
                .or_else(|| named_child_of_kind(attribute, "token_tree"))
                .or_else(|| attribute.named_child(0))?;
            // `#[rest]` — the meta is the interior of the attribute after `#[`.
            // Prefer the first named child that starts at expected_start.
            if let Some(node) = find_starting_at(attribute, expected_start) {
                return Some(node.end_byte() - prefix_len);
            }
            if inner.start_byte() <= expected_start && inner.end_byte() > expected_start {
                return Some(inner.end_byte() - prefix_len);
            }
            None
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
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
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
                let reference_role =
                    if crate::resolution::rust_enclosing_item_generic_parameter_namespace(
                        node, &expanded,
                    )
                    .is_some()
                    {
                        None
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
        MacroTranscribedOutput { paths, fragments }
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
    identifier_kind_like(node.kind())
}

fn identifier_kind_like(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "reserved_identifier"
            | "_reserved_identifier"
            | "primitive_type"
            | "_"
    )
}

pub(crate) fn macro_delimiter(
    node: Node<'_>,
) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter> {
    use brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter;
    match node.child(0)?.kind() {
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
        assert!(!source.tokens.is_empty(), "macro input has a root token");
        let mut children = vec![Vec::new(); source.tokens.len()];
        for (index, token) in source.tokens.iter().enumerate() {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
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
                children[parent].push(index);
            } else {
                assert_eq!(index, 0, "macro input has one root");
            }
        }
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
    fn child(self, index: usize) -> Option<Self> {
        self.tree.children[self.index]
            .get(index)
            .map(|&index| Self {
                tree: self.tree,
                index,
            })
    }
    fn delimiter(self) -> Option<brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter> {
        use brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter;
        match self.child(0)?.kind() {
            "(" => Some(RustMacroDelimiter::Parenthesis),
            "[" => Some(RustMacroDelimiter::Bracket),
            "{" => Some(RustMacroDelimiter::Brace),
            _ => None,
        }
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
            tokens.push(Self {
                tree: self.tree,
                index,
            });
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
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn first_source_item(root: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = root.walk();
    root.named_children(&mut cursor).find(|child| {
        child.kind().ends_with("_item")
            || matches!(child.kind(), "macro_definition" | "macro_invocation")
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

fn find_starting_at<'a>(root: Node<'a>, start: usize) -> Option<Node<'a>> {
    let mut stack = vec![root];
    let mut best = None;
    while let Some(node) = stack.pop() {
        if node.start_byte() == start && node.kind() != "attribute_item" {
            let span = node.end_byte() - node.start_byte();
            if best.is_none_or(|(_, best_span)| span < best_span) {
                best = Some((node, span));
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
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
        emit_transcriber_for_reparse(
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
    let tree = parse_rust_tree(&rewritten)?;
    if tree.root_node().has_error() {
        return None;
    }
    let mut roles = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "type_identifier")
            && rewritten.get(node.byte_range()) == Some(dummy)
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

fn emit_transcriber_for_reparse(
    node: Node<'_>,
    source: &str,
    metavar: &str,
    dummy: &str,
    out: &mut String,
    saw_metavar: &mut bool,
) {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        if node.kind() == "token_repetition" {
            let (interior, _) = interior_tokens(node);
            pending.extend(interior.into_iter().rev());
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

#[cfg(test)]
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
            let occurrence = self.0.intern_node(node);
            let name = node
                .child_by_field_name("name")
                .map(|name| self.0.intern_node(name));
            self.0.declare(occurrence, name)
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
    if let Some(function) = parent_of_kind(node, "function_item")
        && function
            .child_by_field_name("return_type")
            .is_some_and(|ty| node_within(ty, node))
    {
        return MacroIdentRole::Type;
    }
    MacroIdentRole::Value
}

fn parent_of_kind<'a>(mut node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn node_within(parent: Node<'_>, child: Node<'_>) -> bool {
    child.start_byte() >= parent.start_byte() && child.end_byte() <= parent.end_byte()
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

    #[test]
    fn failed_match_is_reported() {
        let source = "macro_rules! convert { (ready $t:ty) => {}; } convert!(Timestamp);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        assert!(is_macro_rules_definition(definition));
        assert_eq!(
            match_syntax_macro_rules(definition, source, arguments, source),
            Err(MacroMatchError::NoArmMatched)
        );
    }

    fn binding_text<'a>(source: &'a str, binding: &MacroBinding) -> &'a str {
        &source[binding.start_byte..binding.end_byte]
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
    let mut builder = crate::resolution::RustResolutionBuilder::new(tree.root_node(), &source);
    builder.lower_capsule_macro_bindings(tree.root_node(), arm, container);
    let output = builder.finish();
    SelectedMacroInputLowering {
        facts: output.facts,
        sources: output.source_facts,
        declarations: output.declaration_sources,
    }
}

#[cfg(test)]
mod selected_input_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };

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
}
