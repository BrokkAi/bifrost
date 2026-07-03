use crate::analyzer::{CodeUnit, cpp_node_text, normalize_cpp_whitespace};
use tree_sitter::Node;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(in crate::analyzer::usages) struct CppArgType {
    pub name: String,
    pub unit: Option<CodeUnit>,
    pub indirection: i32,
}

pub(in crate::analyzer::usages) fn cpp_signature_param_types(
    signature: &str,
) -> Option<Vec<String>> {
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

pub(in crate::analyzer::usages) fn cpp_parameter_type_text(parameter: &str) -> String {
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
    format!(
        "{}{}",
        normalize_cpp_type_name(text),
        "*".repeat(pointer_depth as usize)
    )
}

pub(in crate::analyzer::usages) fn normalize_cpp_type_name(text: &str) -> String {
    strip_tag_type_prefix(
        normalize_cpp_whitespace(text)
            .trim_start_matches("const ")
            .trim_end_matches('*')
            .trim_end_matches('&')
            .trim(),
    )
    .to_string()
}

pub(in crate::analyzer::usages) fn cpp_type_text_pointer_depth(text: &str) -> i32 {
    let mut depth = 0i32;
    let mut bracket = 0i32;
    for ch in text.chars() {
        match ch {
            '<' | '(' | '[' => bracket += 1,
            '>' | ')' | ']' => bracket -= 1,
            '*' if bracket <= 0 => depth += 1,
            _ => {}
        }
    }
    depth
}

pub(in crate::analyzer::usages) fn cpp_literal_type_name(
    node: Node<'_>,
    source: &str,
) -> Option<&'static str> {
    match node.kind() {
        "number_literal" => {
            let text = cpp_node_text(node, source);
            if cpp_number_literal_is_float(text) {
                Some("double")
            } else {
                Some("int")
            }
        }
        "true" | "false" => Some("bool"),
        "char_literal" => Some("char"),
        "string_literal" => None,
        "unary_expression" => {
            let operator = node.child_by_field_name("operator")?;
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            matches!(operator.kind(), "+" | "-")
                .then(|| cpp_literal_type_name(inner, source))
                .flatten()
        }
        _ => None,
    }
}

pub(in crate::analyzer::usages) fn cpp_filter_candidates_by_args(
    candidates: Vec<CodeUnit>,
    arg_types: &[Option<CppArgType>],
    resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
    assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    if candidates.len() <= 1 || arg_types.iter().any(Option::is_none) {
        return candidates;
    }

    let filtered: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            cpp_signature_param_types(candidate.signature().unwrap_or_default()).is_some_and(
                |params| {
                    params.len() == arg_types.len()
                        && params.iter().zip(arg_types.iter()).all(|(param, arg)| {
                            cpp_param_matches_arg(param, arg, resolve_type, assignable)
                        })
                },
            )
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn cpp_param_matches_arg(
    param: &str,
    arg: &Option<CppArgType>,
    resolve_type: &dyn Fn(&str) -> Option<CodeUnit>,
    assignable: &dyn Fn(&CodeUnit, &CodeUnit) -> bool,
) -> bool {
    let Some(arg) = arg else {
        return false;
    };
    if cpp_type_text_pointer_depth(param) != arg.indirection {
        return false;
    }
    let param_name = normalize_cpp_type_name(param);
    match (resolve_type(&param_name), arg.unit.as_ref()) {
        (Some(param_unit), Some(arg_unit)) => assignable(arg_unit, &param_unit),
        _ => param_name == arg.name,
    }
}

pub(in crate::analyzer::usages) fn cpp_split_top_level_commas(
    value: &str,
) -> impl Iterator<Item = &str> {
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

fn cpp_signature_parameter_text(signature: &str) -> Option<&str> {
    let open = signature.find('(')?;
    let mut depth = 0i32;
    for (offset, ch) in signature[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(signature[open + 1..open + offset].trim());
                }
            }
            _ => {}
        }
    }
    None
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
    use crate::analyzer::{CodeUnitType, ProjectFile};

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
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(1, filtered.len());
        assert_eq!("void take(int value)", filtered[0].signature().unwrap());
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
            })],
            &|_| None,
            &|_, _| false,
        );
        assert_eq!(candidates, filtered);
    }
}
