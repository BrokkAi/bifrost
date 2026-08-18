//! Structured `macro_rules!` matcher-to-invocation binding.
//!
//! This module maps tokens in a macro invocation argument group onto the
//! selected arm's matcher bindings. It does not expand macros and it does not
//! consult imports. Callers that have an indexed `macro_rules!` definition
//! feed that definition's syntax tree and the invocation argument `token_tree`.

use crate::declarations::rust_node_text;
use crate::lexical_scope::parse_rust_tree;
use tree_sitter::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroFragmentKind {
    Ident,
    Path,
    Expr,
    Ty,
    Pat,
    Stmt,
    Block,
    Item,
    Meta,
    Tt,
    Vis,
    Lifetime,
    Literal,
}

impl MacroFragmentKind {
    pub fn from_specifier(text: &str) -> Option<Self> {
        Some(match text.trim() {
            "ident" => Self::Ident,
            "path" => Self::Path,
            "expr" | "expr_2021" => Self::Expr,
            "ty" => Self::Ty,
            "pat" | "pat_param" => Self::Pat,
            "stmt" => Self::Stmt,
            "block" => Self::Block,
            "item" => Self::Item,
            "meta" => Self::Meta,
            "tt" => Self::Tt,
            "vis" => Self::Vis,
            "lifetime" => Self::Lifetime,
            "literal" => Self::Literal,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ident => "ident",
            Self::Path => "path",
            Self::Expr => "expr",
            Self::Ty => "ty",
            Self::Pat => "pat",
            Self::Stmt => "stmt",
            Self::Block => "block",
            Self::Item => "item",
            Self::Meta => "meta",
            Self::Tt => "tt",
            Self::Vis => "vis",
            Self::Lifetime => "lifetime",
            Self::Literal => "literal",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacroIdentRole {
    Type,
    Value,
    Pattern,
    Declaration,
    Mixed,
    Unused,
    Undetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacroBinding {
    pub name: String,
    pub fragment: MacroFragmentKind,
    pub start_byte: usize,
    pub end_byte: usize,
    pub repetition_path: Vec<usize>,
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

pub fn is_macro_rules_definition(definition: Node<'_>, source: &str) -> bool {
    if definition.kind() != "macro_definition" {
        return false;
    }
    let mut cursor = definition.walk();
    definition.children(&mut cursor).any(|child| {
        matches!(child.kind(), "macro_rules" | "macro_rules!")
            || rust_node_text(child, source).trim().trim_end_matches('!') == "macro_rules"
    })
}

pub fn match_macro_rules(
    definition: Node<'_>,
    definition_source: &str,
    invocation_arguments: Node<'_>,
    invocation_source: &str,
) -> Result<MacroArmMatch, MacroMatchError> {
    if !is_macro_rules_definition(definition, definition_source) {
        return Err(MacroMatchError::NotMacroRules);
    }
    let mut cursor = definition.walk();
    let rules: Vec<_> = definition
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "macro_rule")
        .collect();
    if rules.is_empty() {
        return Err(MacroMatchError::EmptyRules);
    }
    for (arm_index, rule) in rules.into_iter().enumerate() {
        let Some(pattern) = rule.child_by_field_name("left") else {
            continue;
        };
        if let Some(bindings) = match_token_tree_pattern(
            pattern,
            definition_source,
            invocation_arguments,
            invocation_source,
        ) {
            return Ok(MacroArmMatch {
                arm_index,
                bindings,
            });
        }
    }
    Err(MacroMatchError::NoArmMatched)
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
    definition: Node<'_>,
    definition_source: &str,
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
        MacroFragmentKind::Ident => {
            let mut cursor = definition.walk();
            let right = definition
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "macro_rule")
                .nth(arm_match.arm_index)
                .and_then(|rule| rule.child_by_field_name("right"));
            let Some(right) = right else {
                return Some(MacroNamespaceEvidence::NoNamespace);
            };
            Some(
                match ident_transcriber_role(right, definition_source, &binding.name) {
                    MacroIdentRole::Type => MacroNamespaceEvidence::Type,
                    MacroIdentRole::Value => MacroNamespaceEvidence::Value,
                    MacroIdentRole::Pattern => MacroNamespaceEvidence::Pattern,
                    MacroIdentRole::Declaration => MacroNamespaceEvidence::Declaration,
                    MacroIdentRole::Mixed
                    | MacroIdentRole::Unused
                    | MacroIdentRole::Undetermined => MacroNamespaceEvidence::NoNamespace,
                },
            )
        }
        MacroFragmentKind::Tt
        | MacroFragmentKind::Meta
        | MacroFragmentKind::Vis
        | MacroFragmentKind::Lifetime
        | MacroFragmentKind::Literal => Some(MacroNamespaceEvidence::NoNamespace),
    }
}

fn match_token_tree_pattern(
    pattern: Node<'_>,
    definition_source: &str,
    input_tree: Node<'_>,
    invocation_source: &str,
) -> Option<Vec<MacroBinding>> {
    // Invocation delimiters are independent of matcher delimiters. Only nested
    // groups must agree.
    let (pattern_tokens, _) = interior_tokens(pattern);
    let (input_tokens, input_end) = interior_tokens(input_tree);
    let mut input = TokenCursor {
        tokens: input_tokens,
        index: 0,
        end_byte: input_end,
    };
    let mut bindings = Vec::new();
    if !match_seq(
        &pattern_tokens,
        definition_source,
        &mut input,
        invocation_source,
        &mut bindings,
        &[],
    ) {
        return None;
    }
    if input.index != input.tokens.len() {
        return None;
    }
    Some(bindings)
}

fn match_seq(
    patterns: &[Node<'_>],
    definition_source: &str,
    input: &mut TokenCursor<'_>,
    invocation_source: &str,
    bindings: &mut Vec<MacroBinding>,
    repetition_path: &[usize],
) -> bool {
    for pattern in patterns {
        if !match_element(
            *pattern,
            definition_source,
            input,
            invocation_source,
            bindings,
            repetition_path,
        ) {
            return false;
        }
    }
    true
}

fn match_element(
    pattern: Node<'_>,
    definition_source: &str,
    input: &mut TokenCursor<'_>,
    invocation_source: &str,
    bindings: &mut Vec<MacroBinding>,
    repetition_path: &[usize],
) -> bool {
    match pattern.kind() {
        "token_binding_pattern" => consume_binding(
            pattern,
            definition_source,
            input,
            invocation_source,
            bindings,
            repetition_path,
        ),
        "token_repetition_pattern" => match_repetition(
            pattern,
            definition_source,
            input,
            invocation_source,
            bindings,
            repetition_path,
        ),
        "token_tree_pattern" => {
            let Some(current) = input.current() else {
                return false;
            };
            if current.kind() != "token_tree" || !delimiters_match(pattern, current) {
                return false;
            }
            let (pattern_tokens, _) = interior_tokens(pattern);
            let (inner_tokens, inner_end) = interior_tokens(current);
            let mut inner = TokenCursor {
                tokens: inner_tokens,
                index: 0,
                end_byte: inner_end,
            };
            if !match_seq(
                &pattern_tokens,
                definition_source,
                &mut inner,
                invocation_source,
                bindings,
                repetition_path,
            ) {
                return false;
            }
            if inner.index != inner.tokens.len() {
                return false;
            }
            input.advance();
            true
        }
        _ => match_literal(pattern, definition_source, input, invocation_source),
    }
}

fn consume_binding(
    binding: Node<'_>,
    definition_source: &str,
    input: &mut TokenCursor<'_>,
    invocation_source: &str,
    bindings: &mut Vec<MacroBinding>,
    repetition_path: &[usize],
) -> bool {
    let Some(name_node) = binding.child_by_field_name("name") else {
        return false;
    };
    let Some(fragment_node) = binding.child_by_field_name("type") else {
        return false;
    };
    let name = metavar_spelling(rust_node_text(name_node, definition_source));
    if name.is_empty() {
        return false;
    }
    let Some(fragment) =
        MacroFragmentKind::from_specifier(rust_node_text(fragment_node, definition_source))
    else {
        return false;
    };
    let Some((start_byte, end_byte)) = consume_fragment(fragment, input, invocation_source) else {
        return false;
    };
    bindings.push(MacroBinding {
        name,
        fragment,
        start_byte,
        end_byte,
        repetition_path: repetition_path.to_vec(),
    });
    true
}

fn consume_fragment(
    fragment: MacroFragmentKind,
    input: &mut TokenCursor<'_>,
    source: &str,
) -> Option<(usize, usize)> {
    match fragment {
        MacroFragmentKind::Ident => consume_ident(input),
        MacroFragmentKind::Tt => consume_tt(input),
        MacroFragmentKind::Vis => consume_vis(input, source),
        MacroFragmentKind::Lifetime => consume_lifetime(input, source),
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

fn consume_vis(input: &mut TokenCursor<'_>, source: &str) -> Option<(usize, usize)> {
    let Some(token) = input.current() else {
        return Some((input.end_byte, input.end_byte));
    };
    if token.kind() != "pub"
        && token.kind() != "visibility_modifier"
        && rust_node_text(token, source).trim() != "pub"
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

fn consume_lifetime(input: &mut TokenCursor<'_>, source: &str) -> Option<(usize, usize)> {
    let token = input.current()?;
    if token.kind() != "lifetime" && !rust_node_text(token, source).trim().starts_with('\'') {
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
    let rest = source.get(start..input.end_byte)?;
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

fn match_repetition(
    repetition: Node<'_>,
    definition_source: &str,
    input: &mut TokenCursor<'_>,
    invocation_source: &str,
    bindings: &mut Vec<MacroBinding>,
    repetition_path: &[usize],
) -> bool {
    let Some(spec) = parse_repetition(repetition, definition_source) else {
        return false;
    };
    let mut count = 0;
    let mut after_last_group = None;
    loop {
        let saved = input.index;
        let binding_len = bindings.len();
        let mut path = repetition_path.to_vec();
        path.push(count);
        if match_seq(
            &spec.contents,
            definition_source,
            input,
            invocation_source,
            bindings,
            &path,
        ) {
            if input.index == saved {
                bindings.truncate(binding_len);
                return false;
            }
            after_last_group = Some(input.index);
            count += 1;
            if spec.operator == RepetitionOp::Optional {
                return true;
            }
            if let Some(separator) = spec.separator.as_deref() {
                if match_separator(separator, input, invocation_source) {
                    continue;
                }
            } else {
                continue;
            }
            return true;
        }
        input.index = saved;
        bindings.truncate(binding_len);
        if count == 0 {
            return spec.operator != RepetitionOp::Plus;
        }
        input.index = after_last_group.expect("a successful group leaves a resume index");
        return true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepetitionOp {
    Star,
    Plus,
    Optional,
}

struct RepetitionSpec<'a> {
    contents: Vec<Node<'a>>,
    separator: Option<String>,
    operator: RepetitionOp,
}

fn parse_repetition<'a>(repetition: Node<'a>, source: &str) -> Option<RepetitionSpec<'a>> {
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

fn match_separator(separator: &str, input: &mut TokenCursor<'_>, source: &str) -> bool {
    let wanted = separator.trim();
    if wanted.is_empty() {
        return true;
    }
    let saved = input.index;
    let mut acc = String::new();
    while let Some(token) = input.current() {
        acc.push_str(rust_node_text(token, source).trim());
        input.advance();
        if acc == wanted {
            return true;
        }
        if !wanted.starts_with(&acc) {
            break;
        }
    }
    input.index = saved;
    false
}

fn match_literal(
    pattern: Node<'_>,
    definition_source: &str,
    input: &mut TokenCursor<'_>,
    invocation_source: &str,
) -> bool {
    let Some(token) = input.current() else {
        return false;
    };
    if !tokens_match(pattern, definition_source, token, invocation_source) {
        return false;
    }
    input.advance();
    true
}

fn tokens_match(left: Node<'_>, left_source: &str, right: Node<'_>, right_source: &str) -> bool {
    if left.kind() == right.kind() {
        return rust_node_text(left, left_source).trim()
            == rust_node_text(right, right_source).trim();
    }
    if identifier_like(left) && identifier_like(right) {
        return rust_node_text(left, left_source).trim()
            == rust_node_text(right, right_source).trim();
    }
    false
}

fn identifier_like(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "type_identifier"
            | "reserved_identifier"
            | "_reserved_identifier"
            | "primitive_type"
    ) || rust_node_kind_is_underscore(node)
}

fn rust_node_kind_is_underscore(node: Node<'_>) -> bool {
    node.kind() == "_"
}

fn delimiters_match(left: Node<'_>, right: Node<'_>) -> bool {
    let Some(left_open) = left.child(0) else {
        return false;
    };
    let Some(right_open) = right.child(0) else {
        return false;
    };
    matches!(
        (left_open.kind(), right_open.kind()),
        ("(", "(") | ("[", "[") | ("{", "{")
    )
}

fn interior_tokens(node: Node<'_>) -> (Vec<Node<'_>>, usize) {
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    if children.len() < 2 {
        return (Vec::new(), node.end_byte());
    }
    let close = children[children.len() - 1];
    (children[1..children.len() - 1].to_vec(), close.start_byte())
}

struct TokenCursor<'a> {
    tokens: Vec<Node<'a>>,
    index: usize,
    end_byte: usize,
}

impl<'a> TokenCursor<'a> {
    fn current(&self) -> Option<Node<'a>> {
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

fn metavar_spelling(text: &str) -> String {
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
    if node.kind() == "token_repetition" {
        let (interior, _) = interior_tokens(node);
        for child in interior {
            emit_transcriber_for_reparse(child, source, metavar, dummy, out, saw_metavar);
        }
        return;
    }
    if node.kind() == "metavariable" {
        if metavar_spelling(rust_node_text(node, source)) == metavar {
            *saw_metavar = true;
            out.push_str(dummy);
            out.push(' ');
        } else {
            out.push_str("DummyOther ");
        }
        return;
    }
    if node.child_count() == 0 {
        let text = rust_node_text(node, source).trim();
        if !text.is_empty() {
            out.push_str(text);
            out.push(' ');
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        emit_transcriber_for_reparse(child, source, metavar, dummy, out, saw_metavar);
    }
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
        assert!(is_macro_rules_definition(definition, source));
        assert_eq!(
            match_macro_rules(definition, source, arguments, source),
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
        let matched = match_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.arm_index, 0);
        assert_eq!(matched.bindings.len(), 1);
        assert_eq!(matched.bindings[0].name, "t");
        assert_eq!(matched.bindings[0].fragment, MacroFragmentKind::Ty);
        assert_eq!(binding_text(source, &matched.bindings[0]), "Timestamp");
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
        let matched = match_macro_rules(definition, source, arguments, source).expect("match");
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
        let matched = match_macro_rules(definition, source, arguments, source).expect("match");
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
        let matched = match_macro_rules(definition, source, arguments, source).expect("match");
        assert_eq!(matched.arm_index, 0);
        assert_eq!(matched.bindings[0].fragment, MacroFragmentKind::Expr);
    }

    #[test]
    fn generated_declaration_ident_is_declaration() {
        let source = "macro_rules! make { ($name:ident) => { struct $name; }; } make!(Item);";
        let tree = parse(source);
        let (definition, arguments) = definition_and_invocation(&tree, source);
        let matched = match_macro_rules(definition, source, arguments, source).expect("match");
        let evidence = token_namespace_evidence(
            &matched,
            definition,
            source,
            matched.bindings[0].start_byte,
            matched.bindings[0].end_byte,
        );
        assert_eq!(evidence, Some(MacroNamespaceEvidence::Declaration));
    }
}
