//! C++ structural spec for `query_code`.

use brokk_bifrost_core::analyzer::common::try_node_source_text as node_text;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, unquoted_string_content_span,
};
use brokk_bifrost_core::analyzer::structural::body_relations::{
    BodyOwner, BodyState, body_relation_for_block,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallShapeCoverage, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    CPP_MATERIALIZATION_SUPPORT, DeclarationMaterializationSupport,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, LexicalEnvironmentSupport,
    ScopeFormation, default_scope_formation,
};
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseIndex, CallResultUseOpenReason, CallResultUseSite,
    IntentionalDiscardKind,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityAxis, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, named_children_iter, node_range};
use brokk_bifrost_core::analyzer::{Language, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct CppStructuralSpec;

pub static CPP_STRUCTURAL_SPEC: CppStructuralSpec = CppStructuralSpec;

/// Whether this is a C++ preprocessor conditional node.
///
/// The linked tree-sitter-cpp grammar uses `preproc_ifdef` for both `#ifdef`
/// and `#ifndef`; `preproc_ifndef` remains accepted for trees that expose it
/// as a distinct node kind.
pub(crate) fn is_cpp_preprocessor_conditional(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "preproc_if"
            | "preproc_ifdef"
            | "preproc_ifndef"
            | "preproc_elif"
            | "preproc_elifdef"
            | "preproc_else"
    )
}

/// Classify one exact C or C++ call expression.  The C grammar is the same
/// parser route as C++, so the syntax classifier deliberately does not use a
/// source-file extension or a text-search fallback.
pub fn cpp_call_result_use(call: Node<'_>, source: &str) -> CallResultUseSite {
    let default = if !matches!(call.kind(), "call_expression" | "new_expression")
        || call.has_error()
        || has_recovery_ancestor(call)
    {
        CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
    } else if has_deferred_ancestor(call) {
        CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
    } else {
        let mut expression = call;
        loop {
            let Some(parent) = expression.parent() else {
                break CallResultUse::Open(CallResultUseOpenReason::UnclassifiedSyntax);
            };
            if parent.is_error() || parent.is_missing() {
                break CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax);
            }
            match parent.kind() {
                "parenthesized_expression" | "comma_expression"
                    if parent
                        .named_children(&mut parent.walk())
                        .any(|child| child.id() == expression.id()) =>
                {
                    expression = parent;
                }
                "expression_statement"
                    if parent
                        .named_children(&mut parent.walk())
                        .any(|child| child.id() == expression.id()) =>
                {
                    break CallResultUse::Discarded;
                }
                "for_statement"
                    if matches!(
                        field_name_in_parent(parent, expression),
                        Some("initializer" | "update")
                    ) =>
                {
                    break CallResultUse::Discarded;
                }
                "cast_expression"
                    if field_name_in_parent(parent, expression) == Some("value")
                        && parent
                            .child_by_field_name("type")
                            .is_some_and(|type_node| cpp_type_is_void(type_node, source)) =>
                {
                    break CallResultUse::IntentionalDiscard(IntentionalDiscardKind::CppVoidCast);
                }
                "argument_list"
                    if parent
                        .parent()
                        .is_some_and(|outer_call| cpp_static_cast_to_void(outer_call, source)) =>
                {
                    break CallResultUse::IntentionalDiscard(IntentionalDiscardKind::CppVoidCast);
                }
                "lambda_expression" => {
                    break CallResultUse::Open(CallResultUseOpenReason::DeferredContext);
                }
                _ => break CallResultUse::Consumed,
            }
        }
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), default)
}

fn cpp_type_is_void(type_node: Node<'_>, source: &str) -> bool {
    let mut stack = vec![type_node];
    while let Some(node) = stack.pop() {
        if node.kind() == "primitive_type" && node_text(node, source) == Some("void") {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            stack.push(node.named_child(index).expect("named child exists"));
        }
    }
    false
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        node = parent;
    }
    false
}

fn has_deferred_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "lambda_expression" {
            return true;
        }
        node = parent;
    }
    false
}

fn cpp_static_cast_to_void(call: Node<'_>, source: &str) -> bool {
    if call.kind() != "call_expression" {
        return false;
    }
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "template_function"
        || function
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source))
            != Some("static_cast")
    {
        return false;
    }
    function
        .child_by_field_name("arguments")
        .and_then(|arguments| arguments.named_child(0))
        .is_some_and(|type_node| cpp_type_is_void(type_node, source))
}

fn cpp_cast_call(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "template_function" {
        return false;
    }
    matches!(
        function
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source)),
        Some("static_cast" | "reinterpret_cast" | "const_cast" | "dynamic_cast")
    )
}

/// One source-snapshot index of exact C/C++ call spans.
#[derive(Debug, Clone)]
pub struct CppCallResultUseIndex {
    inner: CallResultUseIndex,
}

impl CppCallResultUseIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "call_expression" | "new_expression")
                && !cpp_cast_call(node, source)
            {
                sites.push(cpp_call_result_use(node, source));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        Self {
            inner: CallResultUseIndex::new(sites),
        }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        self.inner.at_span(start_byte, end_byte)
    }

    pub fn sites(&self) -> &[CallResultUseSite] {
        self.inner.sites()
    }
}

pub const CPP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("comment", NormalizedKind::Comment),
    ("call_expression", NormalizedKind::Call),
    ("new_expression", NormalizedKind::Call),
    ("field_expression", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("class_specifier", NormalizedKind::Class),
    ("struct_specifier", NormalizedKind::Class),
    ("union_specifier", NormalizedKind::Class),
    ("alias_declaration", NormalizedKind::Declaration),
    ("namespace_definition", NormalizedKind::Module),
    ("assignment_expression", NormalizedKind::Assignment),
    ("init_declarator", NormalizedKind::Assignment),
    ("preproc_include", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("field_identifier", NormalizedKind::Identifier),
    ("namespace_identifier", NormalizedKind::Identifier),
    ("qualified_identifier", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("template_function", NormalizedKind::Identifier),
    ("template_method", NormalizedKind::Identifier),
    ("template_type", NormalizedKind::Identifier),
    ("dependent_name", NormalizedKind::Identifier),
    ("destructor_name", NormalizedKind::Identifier),
    ("operator_name", NormalizedKind::Identifier),
    ("primitive_type", NormalizedKind::Identifier),
    ("char_literal", NormalizedKind::StringLiteral),
    ("string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("number_literal", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("for_range_loop", NormalizedKind::Loop),
    ("compound_statement", NormalizedKind::Block),
    ("switch_statement", NormalizedKind::Switch),
    ("case_statement", NormalizedKind::Case),
    ("labeled_statement", NormalizedKind::Label),
    ("goto_statement", NormalizedKind::Goto),
    ("break_statement", NormalizedKind::Break),
    ("continue_statement", NormalizedKind::Continue),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
];

fn cpp_escape_codepoint(digits: &str, radix: u32, byte_escape: bool) -> Option<char> {
    let value = u32::from_str_radix(digits, radix).ok()?;
    if byte_escape && value > 0x7f {
        return None;
    }
    char::from_u32(value)
}

fn cpp_cooked_string_escape(escape: &str) -> Option<Option<char>> {
    let escaped = escape.strip_prefix('\\')?;
    if matches!(escaped, "\n" | "\r\n") {
        return Some(None);
    }
    let character = match escaped {
        "a" => '\x07',
        "b" => '\x08',
        "f" => '\x0c',
        "n" => '\n',
        "r" => '\r',
        "t" => '\t',
        "v" => '\x0b',
        "0" => '\0',
        "\\" => '\\',
        "'" => '\'',
        "\"" => '\"',
        "?" => '?',
        _ if escaped.starts_with('x') => {
            let digits = escaped.get(1..)?;
            (!digits.is_empty()
                && digits.len() <= 4
                && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(())?;
            cpp_escape_codepoint(digits, 16, true)?
        }
        _ if escaped.starts_with('u') => {
            let digits = escaped.get(1..)?;
            (digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then_some(())?;
            cpp_escape_codepoint(digits, 16, false)?
        }
        _ if escaped.starts_with('U') => {
            let digits = escaped.get(1..)?;
            (digits.len() == 8 && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then_some(())?;
            cpp_escape_codepoint(digits, 16, false)?
        }
        _ if escaped.len() <= 3 && escaped.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) => {
            cpp_escape_codepoint(escaped, 8, true)?
        }
        _ => return None,
    };
    Some(Some(character))
}

fn cpp_string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    let spelling = node_text(node, source)?;
    match node.kind() {
        "string_literal" => {
            // Wide and UTF-prefixed literals have implementation-specific code
            // unit encodings. Only the ordinary narrow form has a portable
            // decoded UTF-8 value for this fact axis.
            if !spelling.starts_with('"') {
                return None;
            }
            let mut decoded = String::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let text = node_text(child, source)?;
                match child.kind() {
                    "string_content" => decoded.push_str(text),
                    "escape_sequence" => {
                        if let Some(character) = cpp_cooked_string_escape(text)? {
                            decoded.push(character);
                        }
                    }
                    _ => return None,
                }
            }
            Some(decoded)
        }
        "raw_string_literal" => {
            if !spelling.starts_with("R\"") {
                return None;
            }
            let mut content = None;
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "raw_string_content" => {
                        if content.is_some() {
                            return None;
                        }
                        content = Some(node_text(child, source)?);
                    }
                    "raw_string_delimiter" => {}
                    _ => return None,
                }
            }
            content.map(str::to_owned)
        }
        _ => None,
    }
}

fn direct_code_children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    named_children_iter(node).filter(|child| {
        !child.is_extra() && !child.kind().starts_with("preproc_") && child.kind() != "comment"
    })
}

fn direct_code_child_count(node: Node<'_>) -> usize {
    direct_code_children(node).count()
}

fn loop_body_is_complex(loop_node: Node<'_>) -> bool {
    loop_node
        .child_by_field_name("body")
        .is_some_and(|body| direct_code_child_count(body) > 6)
}

fn complex_statement_count(block: Node<'_>) -> usize {
    direct_code_children(block)
        .filter(|child| {
            matches!(
                child.kind(),
                "for_statement"
                    | "for_range_loop"
                    | "while_statement"
                    | "do_statement"
                    | "switch_statement"
            )
        })
        .filter(|child| child.kind() == "switch_statement" || loop_body_is_complex(*child))
        .count()
}

fn operator_kind(node: Node<'_>) -> Option<&'static str> {
    let operator = node.child_by_field_name("operator")?;
    match operator.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

fn logical_operator_count(expression: Node<'_>) -> usize {
    let mut count = 0usize;
    let mut stack = vec![expression];
    while let Some(node) = stack.pop() {
        if let Some(operator) = operator_kind(node) {
            let parent_operator = node.parent().and_then(operator_kind);
            if parent_operator != Some(operator) {
                count = count.saturating_add(1);
            }
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    count
}

fn condition_expression(node: Node<'_>) -> Option<Node<'_>> {
    let condition = node.child_by_field_name("condition")?;
    if condition.kind() == "condition_clause" {
        condition
            .child_by_field_name("value")
            .or_else(|| condition.named_child(0))
    } else {
        Some(condition)
    }
}

fn switch_cases(body: Node<'_>) -> Vec<Node<'_>> {
    let mut cases = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body
            && matches!(
                node.kind(),
                "switch_statement" | "function_definition" | "lambda_expression"
            )
        {
            continue;
        }
        if node != body && node.kind() == "case_statement" {
            cases.push(node);
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    cases.sort_unstable_by_key(Node::start_byte);
    cases
}

fn switch_case_is_long(switch: Node<'_>) -> bool {
    let Some(body) = switch.child_by_field_name("body") else {
        return false;
    };
    let cases = switch_cases(body);
    cases.iter().enumerate().any(|(index, case)| {
        let end_line = cases.get(index + 1).map_or_else(
            || switch.end_position().row + 1,
            |next| next.start_position().row + 1,
        );
        end_line.saturating_sub(case.start_position().row + 1) > 30
    })
}

fn enum_name_sets(root: Node<'_>, source: &str) -> Vec<HashSet<String>> {
    let mut names = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "enum_specifier" {
            let mut declared = HashSet::default();
            let mut enum_stack = vec![node];
            while let Some(enum_node) = enum_stack.pop() {
                if enum_node.kind() == "enumerator"
                    && let Some(name) = enum_node.child_by_field_name("name")
                    && let Some(text) = node_text(name, source)
                {
                    declared.insert(text.to_owned());
                }
                enum_stack.extend(
                    named_children_iter(enum_node)
                        .filter(|child| !child.is_extra() && child.kind() != "enum_specifier"),
                );
            }
            if !declared.is_empty() {
                names.push(declared);
            }
            continue;
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    names
}

fn switch_case_names(switch: Node<'_>, source: &str) -> HashSet<String> {
    let Some(body) = switch.child_by_field_name("body") else {
        return HashSet::default();
    };
    switch_cases(body)
        .into_iter()
        .filter_map(|case| case.child_by_field_name("value"))
        .filter_map(|value| {
            expression_name_node(value)
                .and_then(|name| node_text(name, source))
                .map(str::to_owned)
        })
        .collect()
}

fn switch_has_default(switch: Node<'_>) -> bool {
    switch
        .child_by_field_name("body")
        .map(switch_cases)
        .is_some_and(|cases| {
            cases
                .iter()
                .any(|case| case.child_by_field_name("value").is_none())
        })
}

fn enum_switch_is_missing_case(switch: Node<'_>, source: &str) -> bool {
    if switch_has_default(switch) {
        return false;
    }
    let mut root = switch;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let cases = switch_case_names(switch, source);
    if cases.is_empty() {
        return false;
    }
    enum_name_sets(root, source)
        .into_iter()
        .filter(|declared| cases.iter().all(|name| declared.contains(name)))
        .min_by_key(HashSet::len)
        .is_some_and(|declared| declared.iter().any(|name| !cases.contains(name)))
}

fn declarator_identifier<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "statement_identifier" => return Some(current),
            "init_declarator"
            | "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => {
                current = current.child_by_field_name("declarator")?;
            }
            "qualified_identifier" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

fn loop_variable<'tree>(loop_node: Node<'tree>, source: &'tree str) -> Option<&'tree str> {
    let declarator = if loop_node.kind() == "for_range_loop" {
        loop_node.child_by_field_name("declarator")
    } else {
        let initializer = loop_node.child_by_field_name("initializer")?;
        if initializer.kind() == "declaration" {
            initializer
                .child_by_field_name("declarator")
                .and_then(declarator_identifier)
        } else if initializer.kind() == "assignment_expression" {
            initializer
                .child_by_field_name("left")
                .and_then(expression_name_node)
        } else {
            None
        }
    }?;
    let name = declarator_identifier(declarator).or(Some(declarator))?;
    node_text(name, source)
}

fn numeric_literal_value(node: Node<'_>, source: &str) -> Option<i64> {
    if node.kind() != "number_literal" {
        return None;
    }
    node_text(node, source)?.parse().ok()
}

fn for_loop_has_small_literal_bound(loop_node: Node<'_>, source: &str) -> bool {
    let Some(condition) = loop_node.child_by_field_name("condition") else {
        return false;
    };
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if node.kind() == "binary_expression"
            && let Some(operator) = node.child_by_field_name("operator")
        {
            let bound = match operator.kind() {
                "<" | "<=" => node
                    .child_by_field_name("right")
                    .and_then(|value| numeric_literal_value(value, source)),
                ">" | ">=" => node
                    .child_by_field_name("left")
                    .and_then(|value| numeric_literal_value(value, source)),
                _ => None,
            };
            if bound.is_some_and(|value| (0..=1).contains(&value)) {
                return true;
            }
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    false
}

fn alloca_is_in_unbounded_loop(call: Node<'_>, source: &str) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if !matches!(
        node_text(function, source),
        Some("alloca" | "__builtin_alloca" | "_alloca" | "_malloca")
    ) {
        return false;
    }
    let mut current = call.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "for_statement" | "for_range_loop") {
            if parent
                .child_by_field_name("initializer")
                .is_some_and(|initializer| {
                    initializer.start_byte() <= call.start_byte()
                        && call.end_byte() <= initializer.end_byte()
                })
            {
                return false;
            }
            return !for_loop_has_small_literal_bound(parent, source);
        }
        if matches!(parent.kind(), "while_statement" | "do_statement") {
            return true;
        }
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            break;
        }
        current = parent.parent();
    }
    false
}

fn goto_counts(function: Node<'_>, source: &str) -> (usize, usize) {
    let mut labels = HashMap::<String, usize>::default();
    let mut gotos = Vec::new();
    let mut stack = vec![function];
    while let Some(node) = stack.pop() {
        if node != function && matches!(node.kind(), "function_definition" | "lambda_expression") {
            continue;
        }
        match node.kind() {
            "labeled_statement" => {
                if let Some(label) = node.child_by_field_name("label")
                    && let Some(text) = node_text(label, source)
                {
                    labels.insert(text.to_owned(), node.start_position().row);
                }
            }
            "goto_statement" => {
                if let Some(label) = node.child_by_field_name("label")
                    && let Some(text) = node_text(label, source)
                {
                    gotos.push((text.to_owned(), node.start_position().row));
                }
            }
            _ => {}
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    gotos
        .into_iter()
        .fold((0, 0), |(forward, backward), (name, line)| {
            match labels.get(&name).copied() {
                Some(target) if line < target => (forward + 1, backward),
                Some(target) if target < line => (forward, backward + 1),
                _ => (forward, backward),
            }
        })
}

fn conditional_block_is_empty(block: Node<'_>) -> bool {
    body_relation_for_block(block, Language::Cpp).is_some_and(|relation| {
        relation.state == BodyState::Empty
            && matches!(
                relation.owner_kind,
                BodyOwner::IfConsequence | BodyOwner::IfAlternative
            )
    })
}

/// Classify one C++ AST node for the statement-level CodeQL parity facts.
///
/// Every branch is anchored to a tree-sitter node and reads only structured
/// fields or values selected from those nodes. The same classifier is used by
/// structural construct labels and by the C++ statement relation producer.
pub fn statement_fact_kind(node: Node<'_>, source: &str) -> Option<StatementFactKind> {
    match node.kind() {
        "call_expression" if alloca_is_in_unbounded_loop(node, source) => {
            Some(StatementFactKind::AllocaInLoop)
        }
        "compound_statement" => {
            if complex_statement_count(node) > 3 {
                Some(StatementFactKind::ComplexBlock)
            } else if conditional_block_is_empty(node) {
                Some(StatementFactKind::EmptyBlock)
            } else {
                None
            }
        }
        "if_statement"
            if condition_expression(node)
                .is_some_and(|condition| logical_operator_count(condition) > 5) =>
        {
            Some(StatementFactKind::ComplexCondition)
        }
        "switch_statement" => {
            if switch_case_is_long(node) {
                Some(StatementFactKind::LongSwitch)
            } else if enum_switch_is_missing_case(node, source) {
                Some(StatementFactKind::MissingCaseInSwitch)
            } else {
                None
            }
        }
        "function_definition" => {
            let (forward, backward) = goto_counts(node, source);
            (forward > 0 && backward > 0 && forward != 1 && backward != 1)
                .then_some(StatementFactKind::UseOfGoto)
        }
        _ => None,
    }
}

/// Capture the source-owned statement rows while the parsed tree is available.
/// The rows retain only bounded, file-local facts; semantic CFG joins remain in
/// the query layer and are never rebuilt here.
pub(crate) fn capture_statement_fact_rows(
    node: Node<'_>,
    source: &str,
    rows: &mut brokk_bifrost_core::analyzer::statement_facts::CppStatementFactRows,
) {
    use brokk_bifrost_core::analyzer::statement_facts::{
        CppConditionFact, CppEnumFact, CppEnumeratorFact, CppGotoFact, CppLabelFact, CppLoopFact,
        CppStatementFact, CppSwitchCaseFact, CppSwitchFact,
    };

    let range = node_range(node);
    if let Some(kind) = statement_fact_kind(node, source) {
        rows.statements.push(CppStatementFact { range, kind });
    }
    if node.kind() == "switch_statement" {
        let long_case = switch_case_is_long(node);
        let missing_case = enum_switch_is_missing_case(node, source);
        if long_case
            && !rows
                .statements
                .iter()
                .any(|fact| fact.range == range && fact.kind == StatementFactKind::LongSwitch)
        {
            rows.statements.push(CppStatementFact {
                range,
                kind: StatementFactKind::LongSwitch,
            });
        }
        if missing_case
            && !rows.statements.iter().any(|fact| {
                fact.range == range && fact.kind == StatementFactKind::MissingCaseInSwitch
            })
        {
            rows.statements.push(CppStatementFact {
                range,
                kind: StatementFactKind::MissingCaseInSwitch,
            });
        }
        let cases = node
            .child_by_field_name("body")
            .map(switch_cases)
            .unwrap_or_default();
        for case in &cases {
            let value = case
                .child_by_field_name("value")
                .and_then(expression_name_node)
                .and_then(|name| node_text(name, source))
                .map(str::to_owned);
            rows.switch_cases.push(CppSwitchCaseFact {
                range: node_range(*case),
                value,
            });
        }
        rows.switches.push(CppSwitchFact {
            range,
            case_count: cases.len(),
            default_present: switch_has_default(node),
            long_case,
            missing_enum_case: missing_case,
        });
    }
    if node.kind() == "if_statement"
        && let Some(condition) = condition_expression(node)
    {
        rows.conditions.push(CppConditionFact {
            range: node_range(condition),
            logical_operator_count: logical_operator_count(condition),
        });
    }
    if matches!(
        node.kind(),
        "for_statement" | "for_range_loop" | "while_statement" | "do_statement"
    ) {
        let body_statement_count = node
            .child_by_field_name("body")
            .map(direct_code_child_count)
            .unwrap_or_default();
        let variable = if matches!(node.kind(), "for_statement" | "for_range_loop") {
            loop_variable(node, source).map(str::to_owned)
        } else {
            None
        };
        rows.loops.push(CppLoopFact {
            range,
            variable,
            body_statement_count,
            tightly_bounded: node.kind() == "for_statement"
                && for_loop_has_small_literal_bound(node, source),
        });
    }
    if node.kind() == "labeled_statement"
        && let Some(label) = node.child_by_field_name("label")
        && let Some(name) = node_text(label, source)
    {
        rows.labels.push(CppLabelFact {
            range,
            name: name.to_owned(),
        });
    }
    if node.kind() == "goto_statement"
        && let Some(label) = node.child_by_field_name("label")
        && let Some(name) = node_text(label, source)
    {
        let forward = goto_target_line(node, name, source)
            .is_some_and(|target| node.start_position().row < target);
        rows.gotos.push(CppGotoFact {
            range,
            target: name.to_owned(),
            forward,
        });
    }
    if node.kind() == "enum_specifier" {
        let name = node
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source))
            .map(str::to_owned);
        rows.enums.push(CppEnumFact { range, name });
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current != node && current.kind() == "enum_specifier" {
                continue;
            }
            if current.kind() == "enumerator"
                && let Some(name) = current.child_by_field_name("name")
                && let Some(text) = node_text(name, source)
            {
                rows.enumerators.push(CppEnumeratorFact {
                    range: node_range(current),
                    enum_range: range,
                    name: text.to_owned(),
                });
            }
            stack.extend(named_children_iter(current).filter(|child| !child.is_extra()));
        }
    }
}

fn goto_target_line(goto: Node<'_>, target: &str, source: &str) -> Option<usize> {
    let mut function = goto;
    while let Some(parent) = function.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            function = parent;
            break;
        }
        function = parent;
    }
    let mut stack = vec![function];
    while let Some(node) = stack.pop() {
        if node != function && matches!(node.kind(), "function_definition" | "lambda_expression") {
            continue;
        }
        if node.kind() == "labeled_statement"
            && let Some(label) = node.child_by_field_name("label")
            && node_text(label, source) == Some(target)
        {
            return Some(node.start_position().row);
        }
        stack.extend(named_children_iter(node).filter(|child| !child.is_extra()));
    }
    None
}

/// Whether tree-sitter recovered `.field = value` as a declaration child pair:
/// an `ERROR` containing only the anonymous dot immediately followed by an
/// `init_declarator` whose declarator is a real identifier.
///
/// This is intentionally narrower than rejecting declarators below `ERROR` in
/// general: macro-decorated declarations and ordinary comma-separated initialized
/// declarations also use recovery nodes and remain real declarations.
pub fn is_recovered_designator_init_declarator(node: Node<'_>) -> bool {
    if node.kind() != "init_declarator" {
        return false;
    }
    let Some(identifier) = node.child_by_field_name("declarator") else {
        return false;
    };
    if identifier.kind() != "identifier" || identifier.is_missing() {
        return false;
    }
    let Some(previous) = node.prev_named_sibling() else {
        return false;
    };
    if previous.kind() != "ERROR"
        || previous.named_child_count() != 0
        || previous.child_count() != 1
        || previous.end_byte() != node.start_byte()
    {
        return false;
    }
    previous.child(0).is_some_and(|child| {
        child.kind() == "."
            && !child.is_named()
            && child.start_byte() == previous.start_byte()
            && child.end_byte() == previous.end_byte()
    })
}

use brokk_bifrost_core::analyzer::tree_walk::last_named_field_child;

/// The declared name of a `namespace_definition`.
///
/// `namespace a::b { }` spells a `nested_namespace_specifier` that nests to
/// the right, so the innermost specifier's last child is the terminal segment.
/// An anonymous namespace has no `name` field at all and stays unnamed.
fn namespace_name_node<'tree>(namespace: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = namespace.child_by_field_name("name")?;
    while current.kind() == "nested_namespace_specifier" {
        current = current.named_child(current.named_child_count().checked_sub(1)?)?;
    }
    Some(current)
}

pub fn declarator_name_node<'tree>(declarator: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = declarator;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "operator_cast"
            | "primitive_type" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator" => current = current.child_by_field_name("declarator")?,
            "attributed_declarator" => current = first_named_child(current)?,
            "reference_declarator" | "parenthesized_declarator" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "field_identifier"
            | "namespace_identifier"
            | "type_identifier"
            | "destructor_name"
            | "operator_name"
            | "primitive_type"
            | "this" => return Some(current),
            "qualified_identifier" => current = last_named_field_child(current, "name")?,
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current = current.child_by_field_name("name")?;
            }
            "field_expression" => current = current.child_by_field_name("field")?,
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("type")?,
            "parenthesized_expression" => current = first_named_child(current)?,
            _ => return declarator_name_node(current),
        }
    }
}

fn attach_qualified_scope_receiver(sink: &mut RoleSink<'_>, function: Node<'_>) {
    if function.kind() != "qualified_identifier" {
        return;
    }
    if let Some(scope) = function.child_by_field_name("scope") {
        attach_role_with_derived_name(sink, Role::Receiver, scope, expression_name_node);
    }
}

fn qualified_declarator_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "qualified_identifier" {
            return Some(node);
        }
        node = node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| first_named_child(node))?;
    }
}

fn scoped_function_definition(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| qualified.child_by_field_name("scope"))
}

pub fn constructor_scope_matches_name(scope: Node<'_>, name: Node<'_>, source: &str) -> bool {
    node_text(scope, source) == node_text(name, source)
}

fn is_constructor_definition(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("declarator")
        .and_then(qualified_declarator_node)
        .and_then(|qualified| {
            Some((
                expression_name_node(qualified.child_by_field_name("scope")?)?,
                expression_name_node(last_named_field_child(qualified, "name")?)?,
            ))
        })
        .is_some_and(|(scope, name)| constructor_scope_matches_name(scope, name, source))
}

fn unquoted_include_span(node: Node<'_>) -> Option<Span> {
    if !matches!(node.kind(), "string_literal" | "system_lib_string") {
        return None;
    }
    unquoted_string_content_span(node)
}

/// The names of every function-like macro this translation unit defines, read
/// from `preproc_function_def` name fields.
///
/// The walk is iterative and descends only through preprocessor conditional
/// blocks, which is where a definition can nest. A `#define` written inside a
/// function body is not collected; that is a known and stated boundary, not an
/// approximation of one.
fn function_like_macro_names(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        for child in named_children_iter(node) {
            match child.kind() {
                "preproc_function_def" => {
                    if let Some(name) = child.child_by_field_name("name") {
                        names.insert(source[name.start_byte()..name.end_byte()].to_owned());
                    }
                }
                "preproc_if" | "preproc_ifdef" | "preproc_else" | "preproc_elif"
                | "preproc_elifdef" => stack.push(child),
                _ => {}
            }
        }
    }
    names
}

fn cpp_member_terminal_name<'tree>(field: Node<'tree>) -> Option<Node<'tree>> {
    let field = if field.kind() == "dependent_name" {
        first_named_child(field)?
    } else {
        field
    };
    expression_name_node(field)
}

/// Return the one identifier-bearing node that spells a member in a C++
/// `field_expression`.
///
/// The grammar permits the `field` child to be a qualified name, a dependent
/// name, a template method, or a destructor name. `expression_name_node`
/// already follows those wrappers to their terminal name. Walking upward from
/// the candidate and comparing that terminal node keeps receiver identifiers,
/// declaration names, field-designator labels, and path prefixes out of the
/// member role without looking at source text.
fn cpp_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier" | "operator_name" | "destructor_name"
    ) {
        return None;
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression" {
            let field = parent.child_by_field_name("field")?;
            return cpp_member_terminal_name(field)
                .filter(|name| name.id() == node.id())
                .map(|_| OccurrenceRole::MemberPosition);
        }

        // These are the only named wrappers that can occur between the
        // terminal field name and its owning field expression.
        if matches!(
            parent.kind(),
            "qualified_identifier" | "dependent_name" | "template_method" | "destructor_name"
        ) {
            current = parent;
        } else {
            return None;
        }
    }
    None
}

/// What declares a C or C++ binder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CppBinderOwner<'tree> {
    /// A parameter of a function definition, a lambda or a `catch` clause.
    Parameter,
    /// A local declaration; the node is the declarator the name completes.
    Local(Node<'tree>),
    /// A range-based `for` variable; the node is the loop.
    RangeFor(Node<'tree>),
    /// A structured binding; the node is the binding declarator.
    StructuredBinding(Node<'tree>),
    /// A lambda init-capture (`[x = y]`).
    InitCapture,
}

/// Declarator wrappers that carry a name inward through their `declarator`
/// field or their single named child.
const CPP_DECLARATOR_WRAPPERS: &[&str] = &[
    "pointer_declarator",
    "array_declarator",
    "reference_declarator",
    "parenthesized_declarator",
    "attributed_declarator",
    "variadic_declarator",
];

/// What declares `node` as a C or C++ variable, or `None` when it is not a
/// variable binder.
///
/// The name is found by walking up the declarator chain. A name that reaches
/// a function declarator without passing a pointer or reference declarator
/// names a function; one that does names a function pointer variable. A
/// parameter binds only in a function definition, a lambda or a `catch`
/// clause; a prototype's parameter names bind nothing. A file-scope or
/// member declaration names a member or a global, not a lexical binding.
fn cpp_binder_owner<'tree>(
    node: Node<'tree>,
    parent: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
    mut field_name: impl FnMut(Node<'tree>, Node<'tree>) -> Option<&'static str>,
) -> Option<CppBinderOwner<'tree>> {
    if node.kind() != "identifier" {
        return None;
    }
    let mut child = node;
    let mut current = parent(node)?;
    let mut indirect = false;
    loop {
        // This field lookup scans earlier siblings. Generated C initializer
        // lists can be enormous, so only ask for fields on binder-shaped nodes.
        match current.kind() {
            kind if CPP_DECLARATOR_WRAPPERS.contains(&kind) => {
                let field = field_name(current, child);
                if field.is_some() && field != Some("declarator") {
                    return None;
                }
                indirect |= matches!(kind, "pointer_declarator" | "reference_declarator");
            }
            "function_declarator" => {
                let field = field_name(current, child);
                if field != Some("declarator") || !indirect {
                    return None;
                }
            }
            "init_declarator" => {
                let field = field_name(current, child);
                if field != Some("declarator") {
                    return None;
                }
            }
            "declaration" => {
                let field = field_name(current, child);
                if field != Some("declarator") {
                    return None;
                }
                let local = std::iter::successors(parent(current), |node| parent(*node))
                    .take_while(|node| {
                        !matches!(
                            node.kind(),
                            "translation_unit"
                                | "field_declaration_list"
                                | "declaration_list"
                                | "namespace_definition"
                        )
                    })
                    .any(|node| {
                        matches!(
                            node.kind(),
                            "compound_statement" | "for_statement" | "condition_clause"
                        )
                    });
                // The name's scope starts at the end of its declarator, before
                // any initializer.
                let declarator = if child.kind() == "init_declarator" {
                    child.child_by_field_name("declarator")?
                } else {
                    child
                };
                return local.then_some(CppBinderOwner::Local(declarator));
            }
            "parameter_declaration"
            | "optional_parameter_declaration"
            | "variadic_parameter_declaration" => {
                let field = field_name(current, child);
                if field != Some("declarator") {
                    return None;
                }
                let parameter_parent = parent(current)?;
                let list = if parameter_parent.kind() == "explicit_object_parameter_declaration" {
                    // The explicit-object wrapper owns exactly `this` and this
                    // parameter; only then may its parent supply the list.
                    if parameter_parent.named_child(0).map(|node| node.kind()) != Some("this")
                        || parameter_parent.named_child(1) != Some(current)
                    {
                        return None;
                    }
                    parent(parameter_parent)?
                } else {
                    parameter_parent
                };
                if list.kind() != "parameter_list" {
                    return None;
                }
                let owner = parent(list)?;
                let binds = match owner.kind() {
                    "catch_clause" => true,
                    "lambda_declarator" | "abstract_function_declarator" => parent(owner)
                        .is_some_and(|lambda| {
                            lambda.kind() == "lambda_expression"
                                && lambda.child_by_field_name("declarator") == Some(owner)
                        }),
                    "function_declarator" => {
                        let mut declarator = owner;
                        loop {
                            let Some(up) = parent(declarator) else {
                                break false;
                            };
                            if up.kind() == "function_definition" {
                                break field_name_in_parent(up, declarator) == Some("declarator");
                            }
                            if !CPP_DECLARATOR_WRAPPERS.contains(&up.kind()) {
                                break false;
                            }
                            declarator = up;
                        }
                    }
                    _ => false,
                };
                return binds.then_some(CppBinderOwner::Parameter);
            }
            "for_range_loop" => {
                let field = field_name(current, child);
                return (field == Some("declarator")).then_some(CppBinderOwner::RangeFor(current));
            }
            "structured_binding_declarator" => {
                return Some(CppBinderOwner::StructuredBinding(current));
            }
            "lambda_capture_initializer" => {
                let field = field_name(current, child);
                return (field == Some("left")).then_some(CppBinderOwner::InitCapture);
            }
            _ => return None,
        }
        child = current;
        current = parent(current)?;
    }
}

/// Whether `node` declares a C or C++ variable, climbing through the walk's
/// parent index: asking `Node::parent` re-descends from the root, which is
/// quadratic over a large file.
fn cpp_is_binder<'tree>(node: Node<'tree>, parents: &ParentIndex<'tree>) -> bool {
    cpp_binder_owner(node, |node| parents.parent(node), field_name_in_parent).is_some()
}

/// The binding one C or C++ binder token introduces, and the interval it is
/// in effect over.
///
/// A parameter or init-capture is in effect over its whole function, lambda
/// or catch clause. A local is in effect from the end of its declarator: C
/// and C++ start a name's scope there, before its initializer, so in
/// `int x = x;` the right side reads the new `x`. A condition declaration is
/// therefore in effect over the rest of its `if`, including `else`. A
/// range-`for` variable is in effect over the loop body, and a structured
/// binding from the end of its binding declarator.
fn cpp_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let binding = |kind, hoisting, activation| {
        Some(BindingActivation {
            kind,
            hoisting,
            activation,
        })
    };
    let after = |node: Node<'_>| Range {
        start_byte: node.end_byte(),
        end_byte: scope.end_byte,
        start_line: node.end_position().row + 1,
        end_line: scope.end_line,
    };
    match cpp_binder_owner(binder, |node| node.parent(), field_name_in_parent)? {
        CppBinderOwner::Parameter | CppBinderOwner::InitCapture => {
            binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope)
        }
        CppBinderOwner::Local(declarator) => binding(
            BindingKind::Local,
            HoistingClass::SourceOrder,
            after(declarator),
        ),
        CppBinderOwner::RangeFor(loop_node) => binding(
            BindingKind::LoopVariable,
            HoistingClass::DeclaredHead,
            node_range(loop_node.child_by_field_name("body")?),
        ),
        CppBinderOwner::StructuredBinding(declarator) => binding(
            BindingKind::Local,
            HoistingClass::SourceOrder,
            after(declarator),
        ),
    }
}

impl StructuralSpec for CppStructuralSpec {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value_may_be_absent(&self, node: Node<'_>, source: &str) -> bool {
        matches!(node.kind(), "string_literal" | "raw_string_literal")
            && cpp_string_literal_value(node, source).is_none()
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        cpp_string_literal_value(node, source)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CPP_KIND_TABLE
    }

    fn generator_construct(
        &self,
        node: Node<'_>,
        _kind: NormalizedKind,
        source: &str,
    ) -> Option<&'static str> {
        statement_fact_kind(node, source).map(StatementFactKind::construct)
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        enclosing: Option<NormalizedKind>,
        source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function
            && (enclosing == Some(NormalizedKind::Class)
                || scoped_function_definition(node).is_some())
        {
            if is_constructor_definition(node, source) {
                NormalizedKind::Constructor
            } else {
                NormalizedKind::Method
            }
        } else {
            kind
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        matches!(
            kind,
            NormalizedKind::Method | NormalizedKind::Constructor | NormalizedKind::SyntaxError
        ) || self
            .kind_table()
            .iter()
            .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn supports_role(&self, role: Role) -> bool {
        !matches!(
            role,
            Role::Kwarg | Role::Decorator | Role::Iterable | Role::Element
        )
    }

    fn call_site_context(&self, root: Node<'_>, source: &str) -> CallSiteContext {
        CallSiteContext::with_macro_derived_callees(function_like_macro_names(root, source))
    }

    /// A `new_expression` is a constructor call, and a call whose callee names
    /// a function-like macro of this translation unit has an argument list
    /// that belongs to the macro, not to the callable that finally runs
    /// (#1478). `CALL_TWICE(2)` parses as an ordinary call of two source
    /// arguments even when the expansion calls a three-parameter callable, so
    /// the honest answer is unknown coverage and no argument rows at all —
    /// never a fabricated list an exact-arity assertion could read as clean.
    ///
    /// The boundary is deliberate: only macros defined in this file are
    /// known here, because that is what this file's parse tree contains. A
    /// macro defined in an included header leaves the site exact, which is
    /// the same answer the analyzer gives today.
    fn call_site_facts(
        &self,
        node: Node<'_>,
        source: &str,
        context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        if node.kind() == "new_expression" {
            return Some(CallSiteFacts::of_kind(CallKind::Constructor));
        }
        let callee = node.child_by_field_name("function")?;
        (callee.kind() == "identifier"
            && context.is_macro_derived_callee(&source[callee.start_byte()..callee.end_byte()]))
        .then(|| CallSiteFacts::of_coverage(CallShapeCoverage::UnknownMacroDerived))
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        static SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
            .supported(OccurrenceRole::MemberPosition)
            .supported(OccurrenceRole::ValueReference)
            .supported(OccurrenceRole::Binder);
        &SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        // C and C++ derive scopes and binding intervals; import binders and
        // the package clause are not derived. The call seams report
        // per-candidate callable applicability (#1478 M3).
        static SUPPORT: LexicalEnvironmentSupport = LexicalEnvironmentSupport::NONE
            .supported(EnvironmentAxis::Scopes)
            .supported(EnvironmentAxis::BindingIntervals)
            .supported(EnvironmentAxis::CallableApplicability);
        &SUPPORT
    }

    /// An `if` statement is a scope: a C++ condition or init-statement
    /// declaration is in effect in both branches and nowhere after.
    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        if matches!(kind, NormalizedKind::If | NormalizedKind::Switch) {
            ScopeFormation::BindingScope
        } else {
            default_scope_formation(kind)
        }
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        cpp_binding_activation(binder, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &CPP_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // C++'s occurrence adapter is shallow, so it claims no path axes. Its
        // declaration layer keeps prototype/body occurrences distinct, which
        // the physical-grouping axis carries, and the analyzer now labels each
        // of those occurrences a head or a body and pairs a prototype with the
        // out-of-line callable body that defines it, so the
        // declaration-definition peer relation is supplied as typed rows with
        // the body occurrence's own range as provenance (#1650). Classes stay
        // outside that relation: a same-file forward declaration is not a
        // distinct occurrence, and across files a class carries no linkage
        // evidence to pair on.
        static SUPPORT: IdentityRouteSupport = IdentityRouteSupport::NONE
            .supported_axis(IdentityAxis::CanonicalIdentity)
            .supported_axis(IdentityAxis::PhysicalGrouping)
            .supported_relation(RouteHopKind::NestedOwner)
            .supported_relation(RouteHopKind::DeclarationDefinitionPeer);
        &SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = cpp_member_position(node) {
            sink.occurrence_role(node, role);
        } else if cpp_is_binder(node, sink.parents()) {
            sink.occurrence_role(node, OccurrenceRole::Binder);
        }

        match kind {
            NormalizedKind::Call => {
                let function_field = if node.kind() == "new_expression" {
                    "type"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(function_field) {
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    // The callee token of a free-function call is a plain value
                    // read, and it is the only occurrence the call site leaves
                    // behind when the function is not indexed (#3466). Member
                    // calls are excluded: their terminal field is already the
                    // member-position occurrence, and classifying it twice would
                    // report one call site as two. A composite callee
                    // expression names its own callee at an inner node
                    // (`f()()`), so it is excluded too.
                    if node.kind() == "call_expression"
                        && !matches!(function.kind(), "field_expression" | "call_expression")
                        && let Some(callee) = expression_name_node(function)
                        && self.kind_table().iter().any(|(node_kind, kind)| {
                            *node_kind == callee.kind() && self.should_extract(callee, *kind)
                        })
                    {
                        sink.occurrence_role(callee, OccurrenceRole::ValueReference);
                    }
                    if function.kind() == "field_expression"
                        && let Some(argument) = function.child_by_field_name("argument")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            argument,
                            expression_name_node,
                        );
                    }
                    attach_qualified_scope_receiver(sink, function);
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                if let Some(argument) = node.child_by_field_name("argument") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        argument,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor => {
                if let Some(name) = node
                    .child_by_field_name("declarator")
                    .and_then(declarator_name_node)
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Module => {
                if let Some(name) = namespace_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Class | NormalizedKind::Declaration => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(declarator_name_node)
                    .or_else(|| node.child_by_field_name("name"))
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Assignment => match node.kind() {
                "init_declarator" => {
                    if let Some(declarator) = node.child_by_field_name("declarator") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Left,
                            declarator,
                            declarator_name_node,
                        );
                        if let Some(name) = declarator_name_node(declarator) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                if let Some(path) = node.child_by_field_name("path") {
                    if let Some(name) = unquoted_include_span(path) {
                        sink.role_named_span(Role::Module, path, name);
                    } else {
                        attach_role_with_derived_name(
                            sink,
                            Role::Module,
                            path,
                            expression_name_node,
                        );
                    }
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CPP_STRUCTURAL_SPEC;
    use super::cpp_binder_owner;
    use super::cpp_member_position;
    use super::field_name_in_parent;
    use super::node_range;
    use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
    use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
    use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;
    use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_core::analyzer::structural::resolution::BindingKind;
    use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, RoleSink, StructuralSpec};
    use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
    use brokk_bifrost_core::hash::HashMap;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Parser;

    fn collect_cpp_structural_facts(source: &str) {
        collect_structural_rows(source);
    }

    fn collect_structural_rows(source: &str) -> StructuralFactRows {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        let root = tree.root_node();
        let context = super::CPP_STRUCTURAL_SPEC.call_site_context(root, source);
        let compiled = CompiledKinds::compile(
            &tree_sitter_cpp::LANGUAGE.into(),
            super::CPP_STRUCTURAL_SPEC.kind_table(),
        );
        let mut structural = StructuralFactCollector::new(
            &super::CPP_STRUCTURAL_SPEC,
            source,
            &context,
            ParentIndex::new(root),
            usize::MAX,
            None,
        );
        let mut source_facts = PrimarySourceFactCollector::new(source);
        let mut pending = vec![(root, None)];
        while let Some((node, parent)) = pending.pop() {
            let mut child_parent = parent;
            if node.is_named()
                && let Some(raw_kind) = compiled.kind_of(&node)
                && super::CPP_STRUCTURAL_SPEC.should_extract(node, raw_kind)
            {
                let kind = super::CPP_STRUCTURAL_SPEC.refine_kind(
                    node,
                    raw_kind,
                    parent.map(|id| structural.normalized_kind(id)),
                    source,
                    &context,
                );
                let id = structural
                    .enter(node, kind, parent, &mut source_facts)
                    .expect("unbounded C++ structural collector");
                let mut sink = structural.role_sink(&mut source_facts);
                super::CPP_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
                structural
                    .accept_roles(id, sink.into_parts())
                    .expect("unbounded C++ structural roles");
                child_parent = Some(id);
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    pending.push((child, child_parent));
                }
            }
        }
        structural
            .finish(root)
            .expect("C++ structural collection finishes")
    }

    fn member_occurrences(source: &str) -> Vec<(usize, &str, OccurrenceRole)> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut found = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if let Some(role) = cpp_member_position(node) {
                found.push((
                    node.start_byte(),
                    &source[node.start_byte()..node.end_byte()],
                    role,
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    pending.push(child);
                }
            }
        }
        found
    }

    #[test]
    #[hardwon("#4505: generated C initializer identifiers triggered repeated sibling scans")]
    fn binder_classification_scans_large_initializer_lists_linearly() {
        use std::fmt::Write as _;

        let mut source = String::from("int values[] = {");
        for index in 0..4096 {
            write!(source, "item_{index},").expect("append generated initializer item");
        }
        source.push_str("};\n");

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(&source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let parents = ParentIndex::new(tree.root_node());
        let mut pending = vec![tree.root_node()];
        let mut identifiers = 0usize;
        let mut sibling_steps = 0usize;
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier" {
                identifiers += 1;
                let _ = cpp_binder_owner(
                    node,
                    |node| parents.parent(node),
                    |parent, child| {
                        let mut cursor = parent.walk();
                        if !cursor.goto_first_child() {
                            return None;
                        }
                        loop {
                            sibling_steps += 1;
                            if cursor.node() == child {
                                return cursor.field_name();
                            }
                            if !cursor.goto_next_sibling() {
                                return None;
                            }
                        }
                    },
                );
            }
            let mut cursor = node.walk();
            let children = node.children(&mut cursor).collect::<Vec<_>>();
            pending.extend(children.into_iter().rev());
        }

        assert!(
            identifiers >= 4096,
            "parsed {identifiers} initializer identifiers"
        );
        assert!(
            sibling_steps <= identifiers * 4,
            "binder field lookup walked {sibling_steps} siblings for {identifiers} identifiers"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4407: ABI 15 lambda declarators lost parameter binder identity"
    )]
    fn lambda_parameters_are_binders_without_leaking_into_callable_bodies() {
        let source = concat!(
            "int enclosing(int outer) {\n",
            "    return [outer](int lambda) {\n",
            "        return [lambda](int nested) {\n",
            "            return outer + lambda + nested;\n",
            "        }(lambda);\n",
            "    }(outer);\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );

        let identifier_at = |start_byte| {
            let mut pending = vec![tree.root_node()];
            while let Some(node) = pending.pop() {
                if node.kind() == "identifier" && node.start_byte() == start_byte {
                    return Some(node);
                }
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        pending.push(child);
                    }
                }
            }
            None
        };
        let outer_parameter =
            identifier_at(source.find("int outer").expect("outer parameter") + "int ".len())
                .expect("outer parameter");
        let lambda_parameter =
            identifier_at(source.find("int lambda").expect("lambda parameter") + "int ".len())
                .expect("lambda parameter");
        let nested_parameter =
            identifier_at(source.find("int nested").expect("nested parameter") + "int ".len())
                .expect("nested parameter");

        for parameter in [outer_parameter, lambda_parameter, nested_parameter] {
            assert_eq!(
                cpp_binder_owner(parameter, |node| node.parent(), field_name_in_parent),
                Some(super::CppBinderOwner::Parameter)
            );
            assert_eq!(
                super::cpp_binding_activation(parameter, node_range(tree.root_node()))
                    .map(|activation| activation.kind),
                Some(BindingKind::Parameter)
            );
        }

        for (start, name) in [
            (
                source
                    .find("return outer + lambda")
                    .expect("outer reference")
                    + "return ".len(),
                "outer",
            ),
            (
                source
                    .find("outer + lambda + nested")
                    .expect("lambda reference")
                    + "outer + ".len(),
                "lambda",
            ),
            (
                source.find("lambda + nested;").expect("nested reference") + "lambda + ".len(),
                "nested",
            ),
        ] {
            let reference = identifier_at(start).expect("body reference identifier");
            assert_eq!(
                cpp_binder_owner(reference, |node| node.parent(), field_name_in_parent),
                None,
                "body reference {name:?} was classified as a binder"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4407: ABI 15 explicit-object receivers lost parameter binder identity"
    )]
    fn cpp_explicit_object_parameter_is_a_parameter_binder_without_body_leak() {
        let source = concat!(
            "struct Visitor {\n",
            "    int visit(this Visitor const& self, int ordinary) {\n",
            "        return self.value + ordinary;\n",
            "    }\n",
            "};\n",
            "using Callback = void (*)(int nested);\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );

        let identifier_at = |start: usize, len: usize| {
            tree.root_node()
                .descendant_for_byte_range(start, start + len)
                .filter(|node| node.kind() == "identifier")
                .expect("identifier at source span")
        };
        let receiver = identifier_at(source.find("self,").expect("receiver binder"), 4);
        let receiver_body = identifier_at(
            source.find("return self").expect("receiver body reference") + "return ".len(),
            4,
        );
        let function_type_parameter =
            identifier_at(source.find("nested").expect("function type"), 6);
        let parents = ParentIndex::new(tree.root_node());

        assert_eq!(receiver.kind(), "identifier");
        assert_eq!(
            cpp_binder_owner(receiver, |node| node.parent(), field_name_in_parent),
            Some(super::CppBinderOwner::Parameter)
        );
        assert!(super::cpp_is_binder(receiver, &parents));
        assert_eq!(
            super::cpp_binding_activation(receiver, node_range(tree.root_node()))
                .map(|activation| activation.kind),
            Some(BindingKind::Parameter)
        );
        assert_eq!(
            cpp_binder_owner(receiver_body, |node| node.parent(), field_name_in_parent),
            None,
            "the receiver read in the body is not another binder"
        );
        assert!(!super::cpp_is_binder(receiver_body, &parents));
        assert_eq!(
            cpp_binder_owner(
                function_type_parameter,
                |node| node.parent(),
                field_name_in_parent
            ),
            None,
            "a function-type parameter remains outside callable binding ownership"
        );
    }

    #[test]
    fn attributed_declarator_resolves_its_declared_name() {
        let source = "int x [[maybe_unused]]; struct Widget { operator bool() const; };";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );

        let mut pending = vec![tree.root_node()];
        let mut attributed = None;
        let mut conversion = None;
        while let Some(node) = pending.pop() {
            match node.kind() {
                "attributed_declarator" => attributed = Some(node),
                "operator_cast" => conversion = Some(node),
                _ => {}
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    pending.push(child);
                }
            }
        }
        let attributed = attributed.expect("attributed declarator");
        let name = super::declarator_name_node(attributed).expect("declarator name");

        assert_eq!(&source[name.byte_range()], "x");
        let conversion = conversion.expect("conversion operator");
        assert_eq!(
            super::declarator_name_node(conversion).map(|node| node.kind()),
            Some("operator_cast")
        );
    }

    #[test]
    fn cpp_member_position_is_limited_to_member_access_and_calls() {
        let source = concat!(
            "struct Widget {\n",
            "    int value;\n",
            "    int method(int label) {\n",
            "        return this->value + label.value + label.method()\n",
            "            + label.template convert<int>() + label.ns::member;\n",
            "    }\n",
            "};\n",
            "int build(Widget widget) {\n",
            "    Widget result{.value = widget.value};\n",
            "    return widget.method(result.value);\n",
            "}\n",
        );
        let found = member_occurrences(source);
        let member_texts = found
            .iter()
            .map(|(_, text, role)| (*text, *role))
            .collect::<Vec<_>>();

        assert_eq!(
            member_texts,
            vec![
                ("value", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
                ("method", OccurrenceRole::MemberPosition),
                ("convert", OccurrenceRole::MemberPosition),
                ("member", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
                ("method", OccurrenceRole::MemberPosition),
                ("value", OccurrenceRole::MemberPosition),
            ]
        );

        let at = |needle: &str| source.find(needle).expect("fixture token");
        for receiver in ["this->", "label.value", "widget.value", "result.value"] {
            let receiver_start = at(receiver);
            assert!(
                found.iter().all(|(offset, _, _)| *offset != receiver_start),
                "receiver was classified: {receiver:?}"
            );
        }
        let non_members = [
            at("Widget {"),
            at("int value") + "int ".len(),
            at("int method") + "int ".len(),
            at(".value =") + 1,
        ];
        for unrelated_start in non_members {
            assert!(
                found
                    .iter()
                    .all(|(offset, _, _)| *offset != unrelated_start),
                "non-member identifier at byte {unrelated_start} was classified"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3466: C and C++ free-function calls published no resolver occurrence"
    )]
    fn cpp_occurrence_support_declares_member_position_and_free_callees() {
        let support = super::CPP_STRUCTURAL_SPEC.occurrence_role_support();
        assert!(support.is_supported(OccurrenceRole::MemberPosition));
        assert!(support.is_supported(OccurrenceRole::ValueReference));
        for role in [
            OccurrenceRole::ReceiverPosition,
            OccurrenceRole::LabelOrKey,
            OccurrenceRole::DeclarationName,
        ] {
            assert!(
                !support.is_supported(role),
                "unexpected C++ support for {role:?}"
            );
        }
    }

    #[test]
    fn cpp_string_literals_publish_decoded_values() {
        let source = r#"
const char *ordinary = "http://example.test/a\n";
const char *raw = R"(https://example.test/path)";
const char *wide = L"wide";
const char character = 'x';
"#;
        let rows = collect_structural_rows(source);
        let values = rows
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::StringLiteral)
            .map(|node| node.string_value.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            values,
            vec![
                Some("http://example.test/a\n".to_owned()),
                Some("https://example.test/path".to_owned()),
                None,
                None,
            ]
        );
    }

    /// The callee token of a free-function call is the only occurrence a call
    /// site leaves behind when the function is not indexed (#3466). Member
    /// calls stay member-position-only, and a composite callee expression
    /// names its own callee at an inner node.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3466: C/C++ resolver call sites had no boundary row or callee occurrence"
    )]
    fn cpp_free_function_callees_are_value_references() {
        let source = concat!(
            "int bound(void) { return 1; }\n",
            "struct Widget { int method(void) { return 0; } };\n",
            "int go(struct Widget *widget) {\n",
            "    return getenv(\"PATH\") != 0\n",
            "        + ns::getenv(\"USER\") != 0\n",
            "        + bound()\n",
            "        + widget->method()\n",
            "        + bound()();\n",
            "}\n",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("C++ parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );

        // Drive the same extraction entry the file walk drives: every fact
        // node admitted by the compiled kind table, through a real RoleSink.
        // The sink addresses occurrences by fact id, so the test keeps the
        // fact id to start byte mapping to name the tokens.
        let language: tree_sitter::Language = tree_sitter_cpp::LANGUAGE.into();
        let compiled = CompiledKinds::compile(&language, CPP_STRUCTURAL_SPEC.kind_table());
        let mut start_by_fact = HashMap::default();
        let mut extractions = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if node.is_named()
                && let Some(kind) = compiled.kind_of(&node)
                && CPP_STRUCTURAL_SPEC.should_extract(node, kind)
            {
                start_by_fact.insert(node.id(), node.start_byte());
                extractions.push((node.start_byte(), node, kind));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    pending.push(child);
                }
            }
        }
        extractions.sort_by_key(|(start, _, _)| *start);
        let mut source_facts =
            brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector::new(source);
        let parents = ParentIndex::new(tree.root_node());
        let mut sink = RoleSink::new(source, &mut source_facts, 64, None, &parents);
        for (_, node, kind) in extractions {
            CPP_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
        }
        let (_, _, occurrences, stop) = sink.into_parts();
        assert_eq!(stop, None);

        let roles_at = |needle: &str| {
            let start = source.find(needle).expect("fixture token");
            occurrences
                .iter()
                .filter(|occurrence| start_by_fact[&occurrence.target_node] == start)
                .map(|occurrence| occurrence.role)
                .collect::<Vec<_>>()
        };
        // Free-function callees are value reads, including a qualified callee
        // whose terminal name is the identifier and the callee of the inner
        // call in `bound()()`.
        assert_eq!(
            roles_at("getenv(\"PATH\")"),
            vec![OccurrenceRole::ValueReference]
        );
        assert_eq!(
            roles_at("getenv(\"USER\")"),
            vec![OccurrenceRole::ValueReference],
            "the terminal name of a qualified callee is the value read"
        );
        assert_eq!(roles_at("bound()\n"), vec![OccurrenceRole::ValueReference]);
        // A member call's terminal field stays one member-position occurrence;
        // the call itself adds no second row for the same token.
        assert_eq!(roles_at("method()"), vec![OccurrenceRole::MemberPosition]);
        // The receiver of a member call is neither a value read of the callee
        // nor a member position.
        assert!(roles_at("widget->").is_empty());
    }

    /// Tree-sitter recovers the valid `this->operator[](...)` expression as a
    /// call whose function is the unfactored `this` node. That node must not
    /// receive a value-reference occurrence role.
    #[test]
    fn cpp_subscript_operator_through_this_does_not_emit_role_for_non_fact() {
        collect_cpp_structural_facts(
            "struct Channel { int operator[](int); int at(int i) { return this->operator[](i); } };",
        );
    }
}

#[cfg(test)]
mod result_use_tests {
    use super::{CppCallResultUseIndex, cpp_call_result_use};
    use brokk_bifrost_core::analyzer::structural::result_use::{
        CallResultUse, CallResultUseOpenReason, IntentionalDiscardKind,
    };
    use tree_sitter::Parser;

    fn tree(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        parser.parse(source, None).expect("C++ tree")
    }

    fn calls<'tree>(tree: &'tree tree_sitter::Tree, source: &str) -> Vec<tree_sitter::Node<'tree>> {
        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" && !super::cpp_cast_call(node, source) {
                found.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        found.sort_by_key(|node| node.start_byte());
        found
    }

    #[test]
    fn expression_statement_void_cast_and_nested_contexts_are_distinct() {
        let source = concat!(
            "int f();\n",
            "void sink(int);\n",
            "void run() {\n",
            "    f();\n",
            "    (void)f();\n",
            "    static_cast<void>(f());\n",
            "    sink(f());\n",
            "    return;\n",
            "}\n",
        );
        let tree = tree(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let calls = calls(&tree, source);
        assert_eq!(calls.len(), 5);
        assert_eq!(
            cpp_call_result_use(calls[0], source).for_port(0),
            CallResultUse::Discarded
        );
        assert!(matches!(
            cpp_call_result_use(calls[1], source).for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::CppVoidCast)
        ));
        assert!(matches!(
            cpp_call_result_use(calls[2], source).for_port(0),
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::CppVoidCast)
        ));
        assert_eq!(
            cpp_call_result_use(calls[3], source).for_port(0),
            CallResultUse::Discarded
        );
        assert_eq!(
            cpp_call_result_use(calls[4], source).for_port(0),
            CallResultUse::Consumed
        );
    }

    #[test]
    fn lambda_tail_and_recovered_syntax_are_open() {
        let source = "int f(); void run() { auto value = [] { return f(); }; f(,); }";
        let tree = tree(source);
        assert!(tree.root_node().has_error());
        let calls = calls(&tree, source);
        assert!(matches!(
            cpp_call_result_use(calls[0], source).for_port(0),
            CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
        ));
        assert_eq!(
            cpp_call_result_use(calls[1], source).for_port(0),
            CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
        );
    }

    #[test]
    fn exact_index_keeps_call_spans_separate() {
        let source = "int f(); void run() { f(); }";
        let tree = tree(source);
        let calls = calls(&tree, source);
        let index = CppCallResultUseIndex::new(tree.root_node(), source);
        assert_eq!(
            index
                .at_span(calls[0].start_byte(), calls[0].end_byte())
                .expect("indexed call")
                .for_port(0),
            CallResultUse::Discarded
        );
        assert!(index.at_span(source.len(), source.len()).is_err());
    }
}
