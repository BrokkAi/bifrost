//! Canonical PHP import projections.
//!
//! [`crate::aliases::parse_php_import_syntax`] owns the parser interpretation
//! of one `namespace_use_declaration`. This module only lowers those already
//! interpreted leaves into the generic import DTO and the source-owned import
//! arena; neither path reparses the declaration text.

use brokk_bifrost_core::analyzer::common::{node_span, try_node_source_text};
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind,
};
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::php_facts::{PhpAliasKind, PhpAliasSourceFact};
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceImportId};
use tree_sitter::Node;

pub use crate::aliases::{PhpImport, PhpImportKind, PhpImportSyntax, parse_php_import_syntax};

/// Project a PHP include/require expression into the canonical source import
/// arena. The expression is interpreted from its AST, with string decoding
/// applied only after the grammar selected a plain string literal.
pub fn project_include_source_fact(
    include: Node<'_>,
    expression: Option<Node<'_>>,
    source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
) -> SourceImportFact {
    let static_segments = expression
        .and_then(|node| fold_include_expression(node, source))
        .and_then(|path| path_segments(&path));
    let (kind, segments) = static_segments.map_or_else(
        || (StructuredImportPathKind::DynamicInclude, Vec::new()),
        |segments| (StructuredImportPathKind::FileInclude, segments),
    );
    let declaration = source_collector.intern_node(include);
    SourceImportFact::from_import(
        ImportInfo {
            raw_snippet: declaration_text(include, source),
            is_wildcard: false,
            is_global: false,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments,
                kind: Some(kind),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: include.start_byte(),
            }),
            binder_span: None,
        },
        declaration,
        None,
        None,
        Vec::new(),
    )
}

#[derive(Debug)]
enum IncludePath {
    Relative(String),
    FileAnchor,
    Directory { parents: usize, suffix: String },
}

fn fold_include_expression(node: Node<'_>, source: &str) -> Option<IncludePath> {
    enum Action<'tree> {
        Fold(Node<'tree>),
        Concatenate,
        ApplyDirname(usize),
    }

    let mut actions = vec![Action::Fold(node)];
    let mut paths = Vec::new();
    while let Some(action) = actions.pop() {
        match action {
            Action::Fold(node) => match node.kind() {
                "string" | "encapsed_string" => {
                    paths.push(IncludePath::Relative(decode_php_string(node, source)?));
                }
                "parenthesized_expression" => {
                    let mut cursor = node.walk();
                    actions.push(Action::Fold(
                        node.named_children(&mut cursor)
                            .find(|child| !child.is_extra())?,
                    ));
                }
                "name" if node_text(node, source).eq_ignore_ascii_case("__DIR__") => {
                    paths.push(IncludePath::Directory {
                        parents: 0,
                        suffix: String::new(),
                    });
                }
                "name" if node_text(node, source).eq_ignore_ascii_case("__FILE__") => {
                    paths.push(IncludePath::FileAnchor);
                }
                "binary_expression" if binary_operator_is_dot(node, source) => {
                    let left = node.child_by_field_name("left")?;
                    let right = node.child_by_field_name("right")?;
                    actions.push(Action::Concatenate);
                    actions.push(Action::Fold(right));
                    actions.push(Action::Fold(left));
                }
                "function_call_expression" => {
                    let (operand, levels) = dirname_operand(node, source)?;
                    actions.push(Action::ApplyDirname(levels));
                    actions.push(Action::Fold(operand));
                }
                _ => return None,
            },
            Action::Concatenate => {
                let right = paths.pop()?;
                let left = paths.pop()?;
                let path = match left {
                    IncludePath::Relative(left) => {
                        let IncludePath::Relative(right) = right else {
                            return None;
                        };
                        IncludePath::Relative(left + &right)
                    }
                    IncludePath::Directory { parents, suffix } => {
                        let IncludePath::Relative(right) = right else {
                            return None;
                        };
                        IncludePath::Directory {
                            parents,
                            suffix: suffix + &right,
                        }
                    }
                    IncludePath::FileAnchor => return None,
                };
                paths.push(path);
            }
            Action::ApplyDirname(levels) => {
                let path = paths.pop()?;
                let path = match path {
                    IncludePath::Directory { parents, suffix } if suffix.is_empty() => {
                        IncludePath::Directory {
                            parents: parents.checked_add(levels)?,
                            suffix,
                        }
                    }
                    IncludePath::FileAnchor => IncludePath::Directory {
                        parents: levels.checked_sub(1)?,
                        suffix: String::new(),
                    },
                    _ => return None,
                };
                paths.push(path);
            }
        }
    }
    (paths.len() == 1).then(|| paths.pop()).flatten()
}

fn binary_operator_is_dot(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("operator")
        .is_some_and(|operator| node_text(operator, source) == ".")
}

fn dirname_operand<'tree>(node: Node<'tree>, source: &str) -> Option<(Node<'tree>, usize)> {
    let function = node.child_by_field_name("function")?;
    if !node_text(function, source).eq_ignore_ascii_case("dirname") {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut arguments_cursor = arguments.walk();
    let mut args = arguments.named_children(&mut arguments_cursor);
    let first = args.next()?;
    if first.kind() != "argument" || first.child_by_field_name("name").is_some() {
        return None;
    }
    let mut first_cursor = first.walk();
    let expression = first.named_children(&mut first_cursor).next()?;
    let levels = if let Some(second) = args.next() {
        if second.kind() != "argument" || second.child_by_field_name("name").is_some() {
            return None;
        }
        let mut second_cursor = second.walk();
        let value = second.named_children(&mut second_cursor).next()?;
        parse_positive_php_integer(value, source)?
    } else {
        1
    };
    if args.next().is_some() {
        return None;
    }
    Some((expression, levels))
}

fn parse_positive_php_integer(node: Node<'_>, source: &str) -> Option<usize> {
    if node.kind() != "integer" {
        return None;
    }
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    let literal = crate::structural::PHP_STRUCTURAL_SPEC.integer_literal_value(node, source)?;
    let value = literal.signed_decimal()?.parse::<usize>().ok()?;
    (value > 0).then_some(value)
}

fn path_segments(path: &IncludePath) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    if let IncludePath::Directory { parents, suffix } = path {
        let suffix = trim_leading_path_separators(suffix);
        if !is_workspace_relative(suffix) {
            return None;
        }
        segments.extend(std::iter::repeat_n("..".to_owned(), *parents));
        segments.extend(path_components(suffix));
    } else if let IncludePath::Relative(value) = path {
        if !is_workspace_relative(value) {
            return None;
        }
        segments.extend(path_components(value));
    }
    Some(segments)
}

fn path_components(value: &str) -> Vec<String> {
    use std::path::Component;
    std::path::Path::new(value)
        .components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            Component::ParentDir => Some("..".to_owned()),
            Component::Normal(value) => value.to_str().map(str::to_owned),
            Component::RootDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn trim_leading_path_separators(value: &str) -> &str {
    #[cfg(windows)]
    {
        value.trim_start_matches(['/', '\\'])
    }
    #[cfg(not(windows))]
    {
        value.trim_start_matches('/')
    }
}

fn is_workspace_relative(value: &str) -> bool {
    !value.starts_with(['/', '\\'])
        && !value.contains("://")
        && !value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

fn decode_php_string(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "string" | "encapsed_string") {
        return None;
    }
    // A double-quoted literal has the same grammar kind as interpolation.
    // Accept only literal content and escapes, never embedded expressions.
    let mut cursor = node.walk();
    if node
        .named_children(&mut cursor)
        .any(|child| !matches!(child.kind(), "string_content" | "escape_sequence"))
    {
        return None;
    }
    let raw = node_text(node, source);
    let quote = *raw.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"') || raw.as_bytes().last() != Some(&quote) {
        return None;
    }
    let bytes = &raw.as_bytes()[1..raw.len() - 1];
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' || index + 1 >= bytes.len() {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let escaped = bytes[index + 1];
        if quote == b'\'' {
            if matches!(escaped, b'\\' | b'\'') {
                decoded.push(escaped);
                index += 2;
            } else {
                decoded.extend_from_slice(&bytes[index..index + 2]);
                index += 2;
            }
            continue;
        }
        let simple = match escaped {
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(0x0b),
            b'e' => Some(0x1b),
            b'f' => Some(0x0c),
            b'\\' => Some(b'\\'),
            b'$' => Some(b'$'),
            b'"' => Some(b'"'),
            _ => None,
        };
        if let Some(value) = simple {
            decoded.push(value);
            index += 2;
        } else if escaped == b'x' && index + 2 < bytes.len() && bytes[index + 2].is_ascii_hexdigit()
        {
            let mut end = index + 2;
            while end < bytes.len() && end < index + 4 && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            decoded.push(
                u8::from_str_radix(std::str::from_utf8(&bytes[index + 2..end]).ok()?, 16).ok()?,
            );
            index = end;
        } else if escaped == b'u' && bytes.get(index + 2) == Some(&b'{') {
            let start = index + 3;
            let length = bytes[start..].iter().position(|byte| *byte == b'}')?;
            let end = start + length;
            let scalar =
                u32::from_str_radix(std::str::from_utf8(&bytes[start..end]).ok()?, 16).ok()?;
            let character = char::from_u32(scalar)?;
            let mut buffer = [0; 4];
            decoded.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            index = end + 1;
        } else if escaped.is_ascii_digit() && escaped < b'8' {
            let mut end = index + 1;
            while end < bytes.len() && end < index + 4 && (b'0'..=b'7').contains(&bytes[end]) {
                end += 1;
            }
            decoded.push(
                // PHP keeps only the low byte of a three-digit octal escape.
                u16::from_str_radix(std::str::from_utf8(&bytes[index + 1..end]).ok()?, 8)
                    .ok()?
                    .to_le_bytes()[0],
            );
            index = end;
        } else {
            decoded.extend_from_slice(&bytes[index..index + 2]);
            index += 2;
        }
    }
    String::from_utf8(decoded).ok()
}

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    try_node_source_text(node, source)
        .expect("PHP parser nodes must point into UTF-8 source")
        .trim()
}

fn declaration_text(declaration: Node<'_>, source: &str) -> String {
    node_text(declaration, source).to_owned()
}

impl<'tree> PhpImport<'tree> {
    /// Lower one parser-derived PHP clause to the generic import model.
    ///
    /// The enclosing declaration remains the statement text, including a
    /// grouped declaration's braces and sibling clauses. Canonical source
    /// facts may split that statement into one leaf per clause, while generic
    /// callers can retain their existing one-statement query behavior.
    pub fn to_import_info(&self, declaration: Node<'tree>, source: &str) -> ImportInfo {
        let identifier = self.path_segments.last().cloned();
        let alias = self.alias.map(|alias| node_text(alias, source).to_owned());
        let path = (!self.path_segments.is_empty()).then(|| StructuredImportPath {
            segments: self.path_segments.clone(),
            kind: Some(StructuredImportPathKind::Namespace),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: declaration.start_byte(),
        });
        let binder_span = self.alias.or(self.target).map(node_span);

        ImportInfo {
            raw_snippet: declaration_text(declaration, source),
            is_wildcard: false,
            is_global: self.is_global,
            identifier,
            alias,
            path,
            binder_span,
        }
    }

    /// Project one clause into the canonical source import arena while the
    /// primary AST is live. The declaration, terminal target, and alias
    /// identities all come from the exact nodes retained by [`PhpImport`].
    pub fn to_source_import_fact(
        &self,
        declaration: Node<'tree>,
        source: &str,
        source_collector: &mut PrimarySourceFactCollector<'_>,
    ) -> SourceImportFact {
        let declaration_occurrence = source_collector.intern_node(declaration);
        let target = self
            .target
            .map(|target| source_collector.intern_node(target));
        let alias_occurrence = self.alias.map(|alias| source_collector.intern_node(alias));
        SourceImportFact::from_import(
            self.to_import_info(declaration, source),
            declaration_occurrence,
            target,
            alias_occurrence,
            Vec::new(),
        )
    }

    /// Project the alias introduced by this clause into PHP's canonical alias
    /// arena. Each leaf references its exact canonical SourceImportId; PHP
    /// contributes only the namespace (type/function/constant) binding kind.
    pub fn to_alias_source_fact(&self, import: SourceImportId) -> Option<PhpAliasSourceFact> {
        self.path_segments.last()?;
        if self
            .alias
            .is_some_and(|alias| alias.start_byte() == alias.end_byte())
        {
            return None;
        }
        let kind = match self.kind {
            PhpImportKind::Type => PhpAliasKind::Type,
            PhpImportKind::Function => PhpAliasKind::Function,
            PhpImportKind::Const => PhpAliasKind::Constant,
        };
        Some(PhpAliasSourceFact { import, kind })
    }
}

/// Project every parser-derived leaf from one PHP import statement.
pub fn project_source_imports<'tree>(
    syntax: &PhpImportSyntax<'tree>,
    declaration: Node<'tree>,
    source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
) -> Vec<SourceImportFact> {
    syntax
        .imports
        .iter()
        .map(|import| import.to_source_import_fact(declaration, source, source_collector))
        .collect()
}

/// Project every valid alias from one PHP import statement, preserving source
/// order and skipping only clauses for which the parser produced no path.
pub fn project_alias_source_facts(
    syntax: &PhpImportSyntax<'_>,
    first_import: usize,
) -> Vec<PhpAliasSourceFact> {
    syntax
        .imports
        .iter()
        .enumerate()
        .filter_map(|(ordinal, import)| {
            let id = SourceImportId::try_from_index(first_import + ordinal)
                .expect("PHP source import ids fit in u32");
            import.to_alias_source_fact(id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn parse(source: &str) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file = brokk_bifrost_core::analyzer::ProjectFile::new(
            std::env::current_dir().unwrap(),
            "include.php",
        );
        crate::declarations::parse_php_file(&file, source, &tree)
    }

    #[test]
    #[hardwon("#7228: review: parenthesized include comments hid static paths")]
    fn parenthesized_include_extras() {
        let parsed = parse("<?php require (/* audited */ __DIR__ . '/t.php');");
        let path = parsed.imports[0].path.as_ref().unwrap();
        assert_eq!(path.kind, Some(StructuredImportPathKind::FileInclude));
        assert_eq!(path.segments, ["t.php"]);
    }

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: include concatenation loses separators and rejects static strings and octal levels"
    )]
    fn static_include_facts_follow_php_literal_rules() {
        // PHP string/integer language rules, independent expected path components.
        let cases = [
            ("'target.php'", vec!["target.php"]),
            (r#""target.php""#, vec!["target.php"]),
            (
                "__DIR__ . '/sub' . '/target.php'",
                vec!["sub", "target.php"],
            ),
            (
                "__DIR__ . ('/sub' . '/target.php')",
                vec!["sub", "target.php"],
            ),
            (
                "dirname(__DIR__, 010) . '/target.php'",
                vec!["..", "..", "..", "..", "..", "..", "..", "..", "target.php"],
            ),
            (
                "dirname(__DIR__, 8) . '/target.php'",
                vec!["..", "..", "..", "..", "..", "..", "..", "..", "target.php"],
            ),
            (
                r"'literal\n.php'",
                if cfg!(windows) {
                    vec!["literal", "n.php"]
                } else {
                    vec![r"literal\n.php"]
                },
            ),
            (r#""\x74arget.php""#, vec!["target.php"]),
            (r#""\164arget.php""#, vec!["target.php"]),
            (r#""\u{74}arget.php""#, vec!["target.php"]),
            (r#""\564arget.php""#, vec!["target.php"]),
        ];
        let mut failures = Vec::new();
        for (expression, expected) in cases {
            let parsed = parse(&format!("<?php require {expression};"));
            let import = &parsed.imports[0];
            let path = import.path.as_ref().unwrap();
            if path.kind != Some(StructuredImportPathKind::FileInclude) || path.segments != expected
            {
                failures.push(format!("{expression}: {path:?}; expected {expected:?}"));
            }
            assert!(!import.is_wildcard);
        }
        assert!(failures.is_empty(), "{failures:#?}");
        for expression in [r#""$target.php""#, r#""{$target}.php""#] {
            let parsed = parse(&format!("<?php require {expression};"));
            assert_eq!(
                parsed.imports[0].path.as_ref().unwrap().kind,
                Some(StructuredImportPathKind::DynamicInclude)
            );
        }
    }
    #[test]
    fn import_projection_preserves_grammar_order_and_provenance() {
        let source = "<?php require 'target.php'; use Vendor\\{First as A, function second as B, const THIRD as C};";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().unwrap();
        let include = &facts.imports[0];
        assert_eq!(
            include.path.as_ref().unwrap().kind,
            Some(StructuredImportPathKind::FileInclude)
        );
        assert!(!include.is_wildcard);
        assert!(include.identifier.is_none());
        assert!(include.alias.is_none());
        let aliases = &facts.php.as_ref().unwrap().aliases;
        let expected = [
            ("First", "A", PhpAliasKind::Type),
            ("second", "B", PhpAliasKind::Function),
            ("THIRD", "C", PhpAliasKind::Constant),
        ];
        assert_eq!(aliases.len(), expected.len());
        let mut preceding_target_end = 0;
        for (alias, (target, binder, kind)) in aliases.iter().zip(expected) {
            let import = &facts.imports[alias.import.index()];
            let target_range = facts.occurrences.occurrence(import.target.unwrap()).range;
            assert!(target_range.start_byte > preceding_target_end);
            preceding_target_end = target_range.end_byte;
            assert_eq!(
                &source[target_range.start_byte..target_range.end_byte],
                target
            );
            let binder_range = facts
                .occurrences
                .occurrence(import.alias_occurrence.unwrap())
                .range;
            assert_eq!(
                &source[binder_range.start_byte..binder_range.end_byte],
                binder
            );
            assert_eq!(alias.kind, kind);
            assert!(!import.is_wildcard);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_anchored_include_accepts_backslash_suffix() {
        let parsed = parse(r"<?php require __DIR__ . '\\\\target.php';");
        let path = parsed.imports[0].path.as_ref().unwrap();
        assert_eq!(path.kind, Some(StructuredImportPathKind::FileInclude));
        assert_eq!(path.segments, ["target.php"]);
    }
}
