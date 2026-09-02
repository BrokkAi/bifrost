//! Overload disambiguation for C++ call sites.
//!
//! The only C++-only module that lived outside `cpp_graph/`: given a candidate
//! set of same-named callables and the argument list at a call site, narrow by
//! parameter type shape. Pure text and AST work over the signatures the
//! declaration walk already emitted.

use crate::declarations::{node_text as cpp_node_text, normalize_cpp_whitespace};
use brokk_bifrost_core::analyzer::CodeUnit;
use tree_sitter::Node;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CppArgType {
    pub name: String,
    pub unit: Option<CodeUnit>,
    pub indirection: i32,
    pub pointee_const: bool,
}

pub fn cpp_signature_param_types(signature: &str) -> Option<Vec<String>> {
    let inner = cpp_signature_parameter_text(signature)
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() || inner == "void" {
        return Some(Vec::new());
    }
    Some(
        cpp_split_top_level_commas(inner)
            .map(cpp_parameter_type_text)
            .collect(),
    )
}

pub fn cpp_parameter_type_text(parameter: &str) -> String {
    let mut text = parameter
        .split_once('=')
        .map(|(before, _)| before)
        .unwrap_or(parameter)
        .trim()
        .trim_end_matches(';')
        .trim();
    let pointer_depth = cpp_type_text_pointer_depth(text);
    if let Some((before, last)) = text.rsplit_once(char::is_whitespace)
        && cpp_parameter_name_token(last)
    {
        text = before.trim();
    }
    let pointee_const = pointer_depth > 0 && cpp_type_text_pointee_is_const(text);
    format!(
        "{}{}{}",
        if pointee_const { "const " } else { "" },
        normalize_cpp_type_name(text),
        "*".repeat(pointer_depth as usize)
    )
}

pub fn normalize_cpp_type_name(text: &str) -> String {
    let normalized = normalize_cpp_whitespace(text);
    let base = cpp_type_text_base(&normalized)
        .trim_start_matches("const ")
        .trim();
    strip_tag_type_prefix(base.strip_suffix(" const").unwrap_or(base)).to_string()
}

pub fn cpp_type_text_pointer_depth(text: &str) -> i32 {
    cpp_type_text_shape(text).1
}

fn cpp_type_text_shape(text: &str) -> (usize, i32) {
    let mut depth = 0i32;
    let mut nesting = 0i32;
    let mut base_end = text.len();
    for (offset, ch) in text.char_indices() {
        match ch {
            '<' | '(' | '[' => nesting += 1,
            '>' | ')' | ']' => nesting -= 1,
            '*' if nesting <= 0 => {
                base_end = base_end.min(offset);
                depth += 1;
            }
            '&' if nesting <= 0 => base_end = base_end.min(offset),
            _ => {}
        }
    }
    (base_end, depth)
}

/// The single argument a `std::move` or `std::forward` call forwards, or `None`
/// for every other call.
///
/// As far as an overload's parameter types are concerned these two are the
/// identity: the argument's type is the call's type. Without that,
/// `Montgomery_Int(m_params, std::move(t))` had one argument of unknown type,
/// the argument filter kept every candidate rather than guess, and the call
/// reported *ambiguous* between the `secure_vector<word>` and
/// `std::span<const word>` overloads (#2552).
///
/// Recognized structurally, from the callee's `scope` and `name` fields: a
/// `qualified_identifier` whose scope is `std` and whose name is `move` or
/// `forward`, with the template arguments of `std::forward<T>(t)` unwrapped
/// wherever the grammar attached them. A local `move(x)` or
/// another namespace's `move` is not this, and neither is a call with any
/// argument count but one -- that is not the standard signature, so the
/// argument type stays unknown and the filter keeps every candidate.
pub fn cpp_forwarding_call_argument<'tree>(call: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let mut callee = call.child_by_field_name("function")?;
    if callee.kind() == "template_function" {
        callee = callee.child_by_field_name("name")?;
    }
    if callee.kind() != "qualified_identifier" {
        return None;
    }
    let scope = callee.child_by_field_name("scope")?;
    if !matches!(scope.kind(), "namespace_identifier" | "identifier")
        || cpp_node_text(scope, source).trim() != "std"
    {
        return None;
    }
    let mut name = callee.child_by_field_name("name")?;
    // `std::forward<T>(t)` attaches its template arguments to the name half of
    // the qualified name, so the `name` field is a `template_function` whose own
    // `name` is the identifier.
    if name.kind() == "template_function" {
        name = name.child_by_field_name("name")?;
    }
    if !matches!(name.kind(), "identifier" | "field_identifier")
        || !matches!(cpp_node_text(name, source).trim(), "move" | "forward")
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let forwarded = arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() != "comment")
        .collect::<Vec<_>>();
    let [argument] = forwarded.as_slice() else {
        return None;
    };
    Some(*argument)
}

pub fn cpp_literal_arg_type(node: Node<'_>, source: &str) -> Option<CppArgType> {
    let scalar = |name: &str| CppArgType {
        name: name.to_string(),
        unit: None,
        indirection: 0,
        pointee_const: false,
    };
    match node.kind() {
        "number_literal" => {
            let text = cpp_node_text(node, source);
            if cpp_number_literal_is_float(text) {
                Some(scalar("double"))
            } else {
                Some(scalar("int"))
            }
        }
        "true" | "false" => Some(scalar("bool")),
        "char_literal" => Some(scalar("char")),
        "string_literal" => {
            let text = cpp_node_text(node, source).trim_start();
            (text.starts_with('"') || text.starts_with("R\"")).then(|| CppArgType {
                name: "char".to_string(),
                unit: None,
                indirection: 1,
                pointee_const: true,
            })
        }
        "unary_expression" => {
            let operator = node.child_by_field_name("operator")?;
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            matches!(operator.kind(), "+" | "-")
                .then(|| cpp_literal_arg_type(inner, source))
                .flatten()
        }
        _ => None,
    }
}

pub fn cpp_filter_candidates_by_args(
    candidates: Vec<CodeUnit>,
    arg_types: &[Option<CppArgType>],
    resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
    assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    cpp_filter_candidates_by_args_with_parameter_types(
        candidates,
        arg_types,
        &|candidate| cpp_signature_param_types(candidate.signature().unwrap_or_default()),
        resolve_type,
        assignable,
    )
}

pub fn cpp_filter_candidates_by_args_with_parameter_types(
    candidates: Vec<CodeUnit>,
    arg_types: &[Option<CppArgType>],
    parameter_types: &dyn Fn(&CodeUnit) -> Option<Vec<String>>,
    resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
    assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    if candidates.len() <= 1 || arg_types.iter().any(Option::is_none) {
        return candidates;
    }
    let args: Vec<&CppArgType> = arg_types.iter().flatten().collect();
    debug_assert_eq!(args.len(), arg_types.len());

    // Exact matches first; standard conversions decide only when nothing
    // matches exactly. That order is C++'s own -- an identity conversion
    // sequence beats every other one -- and it is what keeps
    // `own(std::vector<uint8_t>)` winning over `own(std::span<const uint8_t>)`
    // for a `std::vector<uint8_t>` argument now that the second is viable too.
    let exact = cpp_candidates_matching(
        &candidates,
        &args,
        parameter_types,
        &|param, arg, template_candidate| {
            cpp_param_matches_arg(param, arg, template_candidate, resolve_type, assignable)
        },
    );
    let filtered = if exact.is_empty() {
        cpp_candidates_matching(
            &candidates,
            &args,
            parameter_types,
            &|param, arg, template_candidate| {
                cpp_param_matches_arg(param, arg, template_candidate, resolve_type, assignable)
                    || cpp_standard_conversion_applies(arg, param)
            },
        )
    } else {
        exact
    };
    if filtered.is_empty() {
        candidates
    } else if filtered.iter().any(cpp_signature_is_template_candidate) {
        // A matching function template keeps the entire arity-compatible
        // overload set alive. The parameter metadata has no template
        // substitution or constraint ordering, so it cannot prove that a
        // concrete sibling wins over a macro-constrained template (#2203).
        candidates
    } else {
        filtered
    }
}

/// The candidates whose parameter list has the call's arity and whose every
/// parameter accepts the argument in that position under `matches`.
fn cpp_candidates_matching(
    candidates: &[CodeUnit],
    args: &[&CppArgType],
    parameter_types: &dyn Fn(&CodeUnit) -> Option<Vec<String>>,
    matches: &dyn Fn(&str, &CppArgType, bool) -> bool,
) -> Vec<CodeUnit> {
    candidates
        .iter()
        .filter(|candidate| {
            let template_candidate = cpp_signature_is_template_candidate(candidate);
            parameter_types(candidate).is_some_and(|params| {
                params.len() == args.len()
                    && params
                        .iter()
                        .zip(args.iter())
                        .all(|(param, arg)| matches(param, arg, template_candidate))
            })
        })
        .cloned()
        .collect()
}

fn cpp_signature_is_template_candidate(candidate: &CodeUnit) -> bool {
    candidate
        .signature()
        .is_some_and(|signature| signature.trim_start().starts_with('<'))
}

fn cpp_param_matches_arg(
    param: &str,
    arg: &CppArgType,
    template_candidate: bool,
    resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
    assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
) -> bool {
    if cpp_type_text_pointer_depth(param) != arg.indirection {
        return false;
    }
    if arg.pointee_const && !cpp_type_text_pointee_is_const(param) {
        return false;
    }
    // Parameter metadata records the declared spelling, but it does not carry
    // template substitution or constraint semantics. Once pointer shape and
    // constness agree, a function template remains a live overload candidate:
    // a type-only comparison such as `Vec256<T>` versus `Vec256<int>` cannot
    // prove that deduction or a macro-shaped constraint fails (#2203).
    if template_candidate {
        return true;
    }
    let param_name = normalize_cpp_type_name(param);
    match (resolve_type(&param_name), arg.unit.as_ref()) {
        (Some(param_unit), Some(arg_unit)) => assignable(arg_unit, &param_unit),
        _ => param_name == arg.name,
    }
}

/// Whether an argument of type `arg` satisfies a parameter written `param`
/// through a standard conversion. Asked only after name equality and
/// derived-to-base have both failed for every candidate.
///
/// This is a closed list, not a conversion engine. Every entry is a conversion
/// the analyzer can state from the two spellings alone -- no user-defined
/// conversion operator, no converting-constructor lookup, no template
/// deduction -- and every entry is here because a corpus call site is ambiguous
/// without it:
///
/// - an owning contiguous range (`std::vector<T>`, `std::array<T, N>`)
///   satisfies `std::span<T>` and `std::span<const T>`. `return DL_Group(ber,
///   format);` with `const std::vector<uint8_t> ber` matched no candidate at
///   all, so the filter kept the whole overload set (#2894).
/// - `std::string` and a `char*` or `const char*` satisfy `std::string_view`.
///
/// Deliberately absent:
///
/// - `T*` to `std::span<T>`: viable only paired with a count argument, which is
///   arity's decision rather than a per-parameter one.
/// - `T[N]` to `std::span<T>`: an array argument arrives here spelled as its
///   bare element type, because [`CppArgType`] records pointer depth and an
///   array declarator adds none. Accepting it would accept every scalar `T`.
/// - an alias of a listed container, such as Botan's `secure_vector<T>` for
///   `std::vector<T>`: the argument carries the written spelling, and resolving
///   the alias here would make `Montgomery_Int(m_params, std::move(t))` satisfy
///   both its `secure_vector<word>` and its `std::span<const word>` overload.
/// - the argument's own top-level `const`: [`CppArgType`] does not record it,
///   so `const std::vector<uint8_t>` and `std::vector<uint8_t>` are one type
///   here and both satisfy `std::span<uint8_t>`. Element `const` is recorded,
///   and is checked.
fn cpp_standard_conversion_applies(arg: &CppArgType, param: &str) -> bool {
    if cpp_type_text_pointer_depth(param) != 0 {
        return false;
    }
    let param_name = normalize_cpp_type_name(param);
    let span_element = cpp_template_arguments(&param_name, "std::span")
        .and_then(|arguments| arguments.first().copied());
    if let Some(span_element) = span_element {
        return arg.indirection == 0
            && cpp_contiguous_range_element(&arg.name)
                .is_some_and(|element| cpp_span_element_accepts(span_element, element));
    }
    if param_name == "std::string_view" {
        return (arg.indirection == 0 && arg.name == "std::string")
            || (arg.indirection == 1 && arg.name == "char");
    }
    false
}

/// The template arguments of `text` when it names a specialization of `base`.
///
/// Bracket aware like the parameter-list reader beside it: the argument split is
/// [`cpp_split_top_level_commas`], so `std::array<std::pair<int, int>, 4>` reads
/// as two arguments rather than three, and `std::vector<int>::iterator` is not a
/// specialization of `std::vector` at all.
fn cpp_template_arguments<'a>(text: &'a str, base: &str) -> Option<Vec<&'a str>> {
    let inner = text
        .strip_prefix(base)?
        .trim_start()
        .strip_prefix('<')?
        .trim_end()
        .strip_suffix('>')?;
    Some(cpp_split_top_level_commas(inner).collect())
}

/// The element type of an owning contiguous range: the `T` of `std::vector<T>`
/// or of `std::array<T, N>`.
fn cpp_contiguous_range_element(name: &str) -> Option<&str> {
    ["std::vector", "std::array"]
        .into_iter()
        .find_map(|base| cpp_template_arguments(name, base))
        .and_then(|arguments| arguments.first().copied())
}

/// Whether a `std::span` over `param_element` accepts a range over
/// `arg_element`. A span may add `const` to its element type, never drop it.
fn cpp_span_element_accepts(param_element: &str, arg_element: &str) -> bool {
    cpp_type_text_pointer_depth(param_element) == cpp_type_text_pointer_depth(arg_element)
        && normalize_cpp_type_name(param_element) == normalize_cpp_type_name(arg_element)
        && (cpp_type_text_pointee_is_const(param_element)
            || !cpp_type_text_pointee_is_const(arg_element))
}

fn cpp_type_text_pointee_is_const(text: &str) -> bool {
    let normalized = normalize_cpp_whitespace(text);
    let base = cpp_type_text_base(&normalized).trim();
    base.starts_with("const ") || base.ends_with(" const")
}

fn cpp_type_text_base(text: &str) -> &str {
    text[..cpp_type_text_shape(text).0].trim()
}

pub fn cpp_split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    struct TopLevelCommaSplit<'a> {
        value: &'a str,
        start: usize,
        angle: usize,
        paren: usize,
        brace: usize,
        bracket: usize,
    }

    impl<'a> Iterator for TopLevelCommaSplit<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.start > self.value.len() {
                return None;
            }
            for (offset, ch) in self.value[self.start..].char_indices() {
                let absolute = self.start + offset;
                match ch {
                    '<' => self.angle += 1,
                    '>' => self.angle = self.angle.saturating_sub(1),
                    '(' => self.paren += 1,
                    ')' => self.paren = self.paren.saturating_sub(1),
                    '{' => self.brace += 1,
                    '}' => self.brace = self.brace.saturating_sub(1),
                    '[' => self.bracket += 1,
                    ']' => self.bracket = self.bracket.saturating_sub(1),
                    ',' if self.angle == 0
                        && self.paren == 0
                        && self.brace == 0
                        && self.bracket == 0 =>
                    {
                        let item = self.value[self.start..absolute].trim();
                        self.start = absolute + ch.len_utf8();
                        return Some(item);
                    }
                    _ => {}
                }
            }
            let item = self.value[self.start..].trim();
            self.start = self.value.len() + 1;
            Some(item)
        }
    }

    TopLevelCommaSplit {
        value,
        start: 0,
        angle: 0,
        paren: 0,
        brace: 0,
        bracket: 0,
    }
    .filter(|item| !item.is_empty())
}

/// The byte offsets of a signature's outermost parameter-list parentheses.
fn cpp_signature_parameter_span(signature: &str) -> Option<(usize, usize)> {
    let open = signature.find('(')?;
    let mut depth = 0i32;
    for (offset, ch) in signature[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + offset));
                }
            }
            _ => {}
        }
    }
    None
}

fn cpp_signature_parameter_text(signature: &str) -> Option<&str> {
    let (open, close) = cpp_signature_parameter_span(signature)?;
    Some(signature[open + 1..close].trim())
}

/// What a signature carries after its parameter list: the trailing
/// cv-/ref-qualifiers and `noexcept` that the signature identity records
/// (#1827).
///
/// Two member declarations with the same parameter types but different
/// trailing qualifiers are distinct declarations, so a caller deciding whether
/// one declaration hides another has to compare this alongside the parameter
/// types.
pub fn cpp_signature_trailing_qualifiers(signature: &str) -> &str {
    match cpp_signature_parameter_span(signature) {
        Some((_, close)) => signature[close + 1..].trim(),
        None => "",
    }
}

fn cpp_parameter_name_token(token: &str) -> bool {
    let token = token.trim_start_matches('*').trim_start_matches('&').trim();
    token
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
        && token
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn strip_tag_type_prefix(value: &str) -> &str {
    let value = value.trim_start_matches("const ");
    value
        .strip_prefix("struct ")
        .or_else(|| value.strip_prefix("class "))
        .or_else(|| value.strip_prefix("enum "))
        .unwrap_or(value)
        .trim()
}

fn cpp_number_literal_is_float(text: &str) -> bool {
    let text = text.trim();
    text.contains('.') || text.contains('e') || text.contains('E') || text.ends_with(['f', 'F'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;
    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    fn test_file() -> ProjectFile {
        ProjectFile::new(std::env::temp_dir(), "test.cpp")
    }

    fn function(name: &str, signature: &str) -> CodeUnit {
        CodeUnit::with_signature(
            test_file(),
            CodeUnitType::Function,
            "ns",
            name,
            Some(signature.to_string()),
            false,
        )
    }

    fn class(name: &str) -> CodeUnit {
        CodeUnit::new(test_file(), CodeUnitType::Class, "ns", name)
    }

    #[test]
    fn cpp_filter_candidates_matches_named_unindexed_types() {
        let candidates = vec![
            function("format", "std::string format(const std::string& value)"),
            function("format", "std::string format(int value)"),
        ];
        let filtered = cpp_filter_candidates_by_args(
            candidates,
            &[Some(CppArgType {
                name: "std::string".to_string(),
                unit: None,
                indirection: 0,
                pointee_const: false,
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(1, filtered.len());
        assert!(filtered[0].signature().unwrap().contains("std::string&"));
    }

    #[test]
    fn cpp_filter_candidates_matches_assignable_units() {
        let arg = class("Arg");
        let param = class("Param");
        let filtered = cpp_filter_candidates_by_args(
            vec![function("take", "void take(Param value)")],
            &[Some(CppArgType {
                name: "Arg".to_string(),
                unit: Some(arg.clone()),
                indirection: 0,
                pointee_const: false,
            })],
            &|name| (name == "Param").then(|| param.clone()),
            &|from, to| from == &arg && to == &param,
        );
        assert_eq!(1, filtered.len());
    }

    #[test]
    fn cpp_filter_candidates_rejects_pointer_depth_mismatch() {
        let candidates = vec![
            function("take", "void take(int* value)"),
            function("take", "void take(int value)"),
        ];
        let filtered = cpp_filter_candidates_by_args(
            candidates,
            &[Some(CppArgType {
                name: "int".to_string(),
                unit: None,
                indirection: 0,
                pointee_const: false,
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(1, filtered.len());
        assert_eq!("void take(int value)", filtered[0].signature().unwrap());
    }

    #[test]
    fn cpp_filter_candidates_uses_const_string_literal_pointer_evidence() {
        let literal = Some(CppArgType {
            name: "char".to_string(),
            unit: None,
            indirection: 1,
            pointee_const: true,
        });
        let direct = cpp_filter_candidates_by_args(
            vec![
                function("select", "int select(int value)"),
                function("select", "int select(const char* value)"),
            ],
            std::slice::from_ref(&literal),
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(1, direct.len());
        assert_eq!(
            "int select(const char* value)",
            direct[0].signature().unwrap()
        );

        for candidates in [
            vec![
                function("select", "int select(int value)"),
                function("select", "int select(char* value)"),
            ],
            vec![
                function("format", "int format(int value)"),
                function("format", "int format(std::string value)"),
            ],
        ] {
            let filtered = cpp_filter_candidates_by_args(
                candidates.clone(),
                std::slice::from_ref(&literal),
                &|_| None,
                &|_, _| false,
            );
            assert_eq!(
                candidates, filtered,
                "unmodeled or invalid conversions must remain conservative"
            );
        }
    }

    #[test]
    fn cpp_parameter_type_keeps_pointer_const_distinct_from_pointee_const() {
        assert_eq!("char*", cpp_parameter_type_text("char * const value"));
        assert_eq!(
            "const char*",
            cpp_parameter_type_text("const char * const value")
        );
        assert_eq!("char", normalize_cpp_type_name("char * const"));
    }

    #[test]
    fn cpp_filter_candidates_keeps_all_for_unknown_arguments() {
        let candidates = vec![
            function("format", "void format(std::string value)"),
            function("format", "void format(int value)"),
        ];
        let filtered =
            cpp_filter_candidates_by_args(candidates.clone(), &[None], &|_| None, &|_, _| false);
        assert_eq!(candidates, filtered);
    }

    #[test]
    fn cpp_filter_candidates_keeps_all_when_no_candidate_matches() {
        let candidates = vec![
            function("format", "void format(std::string value)"),
            function("format", "void format(int value)"),
        ];
        let filtered = cpp_filter_candidates_by_args(
            candidates.clone(),
            &[Some(CppArgType {
                name: "double".to_string(),
                unit: None,
                indirection: 0,
                pointee_const: false,
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(candidates, filtered);
    }

    /// Every `call_expression` in `source`, in source order.
    fn call_expressions(tree: &tree_sitter::Tree) -> Vec<Node<'_>> {
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                calls.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        calls.sort_by_key(Node::start_byte);
        calls
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("the C++ grammar loads");
        parser.parse(source, None).expect("the fixture parses")
    }

    /// #2552 shape 4. `std::move` and `std::forward` forward one argument, and
    /// its type is the call's type. Nothing else is that, including the same
    /// names outside `std` and a call with the wrong argument count.
    #[test]
    fn a_forwarding_call_reports_the_one_argument_it_forwards() {
        let source = r#"void f() {
   sink(std::move(a));
   sink(std::forward<T>(b));
   sink(std::move(c, 1));
   sink(std::swap(d, e));
   sink(move(g));
   sink(other::move(h));
   sink(std::vector<int>(i));
}
"#;
        let tree = parse(source);
        let forwarded = call_expressions(&tree)
            .into_iter()
            .filter_map(|call| cpp_forwarding_call_argument(call, source))
            .map(|argument| cpp_node_text(argument, source).to_string())
            .collect::<Vec<_>>();
        assert_eq!(forwarded, vec!["a".to_string(), "b".to_string()]);
    }

    fn value_arg(name: &str) -> Option<CppArgType> {
        Some(CppArgType {
            name: name.to_string(),
            unit: None,
            indirection: 0,
            pointee_const: false,
        })
    }

    /// #2894 gap 2. `DL_Group(ber, format)` with a `std::vector<uint8_t> ber`
    /// matched neither two-parameter constructor, so the filter kept both.
    /// A contiguous owning range now satisfies a span over the same element,
    /// including a span that adds `const`.
    #[test]
    fn a_contiguous_range_satisfies_a_span_over_its_element() {
        for arg in ["std::vector<uint8_t>", "std::array<uint8_t, 16>"] {
            for param in ["std::span<const uint8_t>", "std::span<uint8_t>"] {
                let candidates = vec![
                    function("take", &format!("void take({param} bytes)")),
                    function("take", "void take(int count)"),
                ];
                let filtered = cpp_filter_candidates_by_args(
                    candidates,
                    &[value_arg(arg)],
                    &|_| None,
                    &|_, _| false,
                );
                assert_eq!(filtered.len(), 1, "{arg} -> {param}");
                assert!(
                    filtered[0].signature().unwrap().contains(param),
                    "{arg} -> {param}: {:?}",
                    filtered[0].signature()
                );
            }
        }
    }

    /// The near misses the issue asked for: a different element type, and an
    /// element that would lose its `const`.
    #[test]
    fn a_range_over_another_element_does_not_satisfy_a_span() {
        for (arg, param) in [
            ("std::vector<int>", "std::span<const uint8_t>"),
            ("std::vector<const uint8_t>", "std::span<uint8_t>"),
            ("std::vector<uint8_t>", "std::span<const uint8_t*>"),
            ("std::deque<uint8_t>", "std::span<const uint8_t>"),
        ] {
            let candidates = vec![
                function("take", &format!("void take({param} bytes)")),
                function("take", "void take(int count)"),
            ];
            let filtered = cpp_filter_candidates_by_args(
                candidates.clone(),
                &[value_arg(arg)],
                &|_| None,
                &|_, _| false,
            );
            assert_eq!(
                candidates, filtered,
                "{arg} must not satisfy {param}, so every candidate stays"
            );
        }
    }

    #[test]
    fn an_owned_string_and_a_character_pointer_satisfy_a_string_view() {
        let literal = Some(CppArgType {
            name: "char".to_string(),
            unit: None,
            indirection: 1,
            pointee_const: true,
        });
        for arg in [value_arg("std::string"), literal] {
            let filtered = cpp_filter_candidates_by_args(
                vec![
                    function("label", "void label(std::string_view text)"),
                    function("label", "void label(int count)"),
                ],
                std::slice::from_ref(&arg),
                &|_| None,
                &|_, _| false,
            );
            assert_eq!(filtered.len(), 1, "{:?}", arg.as_ref().map(|arg| &arg.name));
            assert!(
                filtered[0]
                    .signature()
                    .unwrap()
                    .contains("std::string_view"),
                "{:?}",
                filtered[0].signature()
            );
        }
    }

    /// A standard conversion never outranks an exact match: the overload set
    /// that has both keeps resolving to the exact one, as it did before the
    /// conversion table existed.
    #[test]
    fn an_exact_match_outranks_a_standard_conversion() {
        let candidates = vec![
            function("own", "void own(std::vector<uint8_t> bytes)"),
            function("own", "void own(std::span<const uint8_t> bytes)"),
        ];
        let filtered = cpp_filter_candidates_by_args(
            candidates,
            &[value_arg("std::vector<uint8_t>")],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            "void own(std::vector<uint8_t> bytes)",
            filtered[0].signature().unwrap()
        );
    }

    #[test]
    fn cpp_filter_candidates_keeps_templates_when_only_type_shape_is_unknown() {
        let candidates = vec![
            function("take", "void take(Vec256<float> value)"),
            function("take", "<typename T>(Vec256<T>)"),
        ];
        let filtered = cpp_filter_candidates_by_args(
            candidates.clone(),
            &[Some(CppArgType {
                name: "Vec256<int>".to_string(),
                unit: Some(class("Vec256")),
                indirection: 0,
                pointee_const: false,
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(filtered, candidates);
    }
}
