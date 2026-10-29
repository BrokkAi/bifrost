//! Primary Java regex production. All nomination and binding walks use AST nodes.
use super::declarations::node_text as text;
use super::imports::parse_import_syntax;
use super::string_literal::{DecodedLiteral, decode};
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{linear_chain_tokens, node_range};
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::structural::regex::{RegexFlags, RegexParser, facts_to_embedded};
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedLeafFact, StructuralSpec};
use tree_sitter::Node;

use super::regex_syntax::JavaRegexSyntax;

fn contains(scope: Node<'_>, site: Node<'_>) -> bool {
    scope.start_byte() <= site.start_byte() && site.end_byte() <= scope.end_byte()
}
fn ancestor<'t>(node: Node<'t>, kinds: &[&str]) -> Option<Node<'t>> {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::nearest_ancestor(node, |kind| {
        kinds.contains(&kind)
    })
}

/// Return the scope in which a declaration can affect a name. Unknown pattern
/// binding forms deliberately use the enclosing callable, refusing certainty.
fn binding_scope(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "variable_declarator"
            if node.parent().is_some_and(|p| {
                matches!(p.kind(), "field_declaration" | "constant_declaration")
            }) =>
        {
            ancestor(
                node,
                &[
                    "class_body",
                    "interface_body",
                    "enum_body",
                    "annotation_type_body",
                ],
            )
        }
        "variable_declarator" => ancestor(
            node,
            &["block", "for_statement", "try_with_resources_statement"],
        ),
        "formal_parameter" | "spread_parameter" | "receiver_parameter" | "type_parameter" => {
            ancestor(
                node,
                &[
                    "lambda_expression",
                    "record_declaration",
                    "method_declaration",
                    "constructor_declaration",
                    "class_declaration",
                    "interface_declaration",
                ],
            )
        }
        "catch_formal_parameter" => ancestor(node, &["catch_clause"]),
        "resource" => ancestor(node, &["try_with_resources_statement"]),
        "enhanced_for_statement" => Some(node),
        "enum_constant" => ancestor(node, &["enum_body"]),
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "annotation_type_declaration" => node.parent(),
        "inferred_parameters" | "lambda_expression" => Some(node),
        "instanceof_expression" | "type_pattern" | "record_pattern_component" => {
            ancestor(node, &["method_declaration", "constructor_declaration"])
        }
        _ => None,
    }
}
fn binder_name(node: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) = super::structural::java_pattern_binding_name(node) {
        return Some(name);
    }
    if node.kind() == "spread_parameter" {
        return super::declarations::spread_parameter_name(node);
    }
    if matches!(node.kind(), "type_parameter") {
        return super::graph_support::java_type_parameter_name_node(node);
    }
    node.child_by_field_name("name")
}
fn visible(node: Node<'_>, site: Node<'_>) -> bool {
    let Some(scope) = binding_scope(node) else {
        return false;
    };
    if !contains(scope, site) {
        return false;
    }
    if node.kind() == "resource"
        && let Some(resources) = ancestor(node, &["resource_specification"])
        && contains(resources, site)
        && node.end_byte() < site.start_byte()
    {
        return true;
    }
    if matches!(
        node.kind(),
        "formal_parameter"
            | "spread_parameter"
            | "catch_formal_parameter"
            | "resource"
            | "enhanced_for_statement"
    ) && let Some(name) = binder_name(node)
        && let Some(binding) = super::structural::java_binding_activation(name, node_range(scope))
    {
        return binding.activation.start_byte <= site.start_byte()
            && site.end_byte() <= binding.activation.end_byte;
    }
    if node.kind() == "variable_declarator"
        && node
            .parent()
            .is_some_and(|p| p.kind() == "local_variable_declaration")
    {
        return node.start_byte() < site.start_byte();
    }
    // A local class has source-order scope; member types have scope-wide scope.
    if matches!(node.kind(), "class_declaration" | "record_declaration") && scope.kind() == "block"
    {
        return node.start_byte() < site.start_byte();
    }
    true
}

fn lambda_binds(name: &str, mut site: Node<'_>, source: &str) -> bool {
    while let Some(parent) = site.parent() {
        if parent.kind() == "lambda_expression"
            && let Some(parameters) = parent.child_by_field_name("parameters")
        {
            if parameters.kind() == "identifier" && text(parameters, source) == name {
                return true;
            }
            if parameters.kind() == "inferred_parameters"
                && parameters
                    .named_children(&mut parameters.walk())
                    .any(|p| text(p, source) == name || text(p, source).contains('\\'))
            {
                return true;
            }
        }
        site = parent;
    }
    false
}

struct FileContext<'t, 's> {
    source: &'s str,
    declarations: Vec<Node<'t>>,
    imported: bool,
    wildcard: bool,
    conflicting_import: bool,
    java_import: bool,
    static_wildcard: bool,
    recovered: bool,
}
impl<'t> FileContext<'t, '_> {
    fn binder(&self, object: Node<'t>, site: Node<'t>) -> Result<bool, &'static str> {
        let tokens = linear_chain_tokens(object, &[("field_access", Some("field"))], &[]);
        let Some(path) = tokens
            .iter()
            .map(|&token| (token.kind() == "identifier").then(|| text(token, self.source)))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(false);
        };
        let name = match path.as_slice() {
            ["Pattern"] if self.imported || self.wildcard => "Pattern",
            ["java", "util", "regex", "Pattern"] => "java",
            _ => return Ok(false),
        };
        if self.static_wildcard || (name == "java" && self.java_import) {
            return Err("java-imported-binding-not-settled");
        }
        if self.recovered {
            return Err("java-recovered-binding-scope");
        }
        if self.declarations.iter().any(|&decl| {
            visible(decl, site)
                && binder_name(decl).is_some_and(|n| {
                    text(n, self.source) == name || text(n, self.source).contains('\\')
                })
        }) {
            return Err("java-shadowed-pattern-binder");
        }
        if lambda_binds(name, site, self.source) {
            return Err("java-shadowed-pattern-binder");
        }
        let mut current = site;
        while let Some(parent) = current.parent() {
            // Inherited names cannot be ruled out by a same-file lexical scan.
            if parent.kind() == "object_creation_expression" {
                return Err("java-inherited-binding-not-settled");
            }
            if !super::declarations::extract_raw_supertypes(parent, self.source).is_empty() {
                return Err("java-inherited-binding-not-settled");
            }
            current = parent;
        }
        if name == "Pattern" && (!self.imported || self.conflicting_import) {
            return Err("java-pattern-import-not-certain");
        }
        Ok(true)
    }

    fn constant(&self, expression: Node<'t>) -> Result<DecodedLiteral, &'static str> {
        let mut pending = vec![expression];
        let mut value = String::new();
        let mut source_start = None;
        let mut chars = Vec::new();
        let mut steps = 0;
        while let Some(node) = pending.pop() {
            steps += 1;
            if steps > 4096 {
                return Err("java-constant-expansion-budget");
            }
            match node.kind() {
                "string_literal" => {
                    let decoded = decode(text(node, self.source), node.start_byte())?;
                    source_start =
                        Some(source_start.map_or(decoded.source_start, |start: usize| {
                            start.min(decoded.source_start)
                        }));
                    value.push_str(&decoded.value);
                    chars.extend(decoded.chars);
                    if chars.len() > 8192 {
                        return Err("java-pattern-budget");
                    }
                }
                "parenthesized_expression" => {
                    pending.push(node.named_child(0).ok_or("java-invalid-constant")?)
                }
                "binary_expression"
                    if node
                        .child_by_field_name("operator")
                        .is_some_and(|op| text(op, self.source) == "+") =>
                {
                    pending.push(
                        node.child_by_field_name("right")
                            .ok_or("java-invalid-constant")?,
                    );
                    pending.push(
                        node.child_by_field_name("left")
                            .ok_or("java-invalid-constant")?,
                    );
                }
                "identifier" => {
                    let name = text(node, self.source);
                    if lambda_binds(name, node, self.source) {
                        return Err("java-nonconstant-pattern");
                    }
                    let mut candidates = self
                        .declarations
                        .iter()
                        .copied()
                        .filter(|&decl| {
                            visible(decl, node)
                                && binder_name(decl).is_some_and(|n| text(n, self.source) == name)
                        })
                        .collect::<Vec<_>>();
                    candidates.sort_by_key(|decl| {
                        binding_scope(*decl).map_or(usize::MAX, |s| s.end_byte() - s.start_byte())
                    });
                    let declaration = *candidates.first().ok_or("java-dynamic-pattern")?;
                    if candidates
                        .get(1)
                        .is_some_and(|next| binding_scope(*next) == binding_scope(declaration))
                    {
                        return Err("java-ambiguous-constant");
                    }
                    let statement = declaration.parent().ok_or("java-dynamic-pattern")?;
                    if declaration.kind() != "variable_declarator"
                        || !matches!(
                            statement.kind(),
                            "local_variable_declaration"
                                | "field_declaration"
                                | "constant_declaration"
                        )
                    {
                        return Err("java-nonconstant-pattern");
                    }
                    let final_modifier = statement
                        .named_children(&mut statement.walk())
                        .find(|n| n.kind() == "modifiers")
                        .is_some_and(|modifiers| {
                            modifiers
                                .children(&mut modifiers.walk())
                                .any(|n| n.kind() == "final")
                        });
                    let string_type = statement.child_by_field_name("type").is_some_and(|ty| {
                        let tokens =
                            super::structural::JAVA_STRUCTURAL_SPEC.path_segment_tokens(ty);
                        let names: Vec<_> = tokens
                            .iter()
                            .map(|&token| text(token, self.source))
                            .collect();
                        matches!(names.as_slice(), ["String"] | ["java", "lang", "String"])
                            || (names == ["var"]
                                && statement.kind() == "local_variable_declaration")
                    });
                    if (!final_modifier && statement.kind() != "constant_declaration")
                        || !string_type
                    {
                        return Err("java-nonconstant-pattern");
                    }
                    pending.push(
                        declaration
                            .child_by_field_name("value")
                            .ok_or("java-uninitialized-constant")?,
                    );
                }
                _ => return Err("java-dynamic-pattern"),
            }
        }
        Ok(DecodedLiteral {
            value,
            chars,
            source_start: source_start.unwrap_or(expression.start_byte()),
        })
    }

    fn flags(
        &self,
        expression: Node<'t>,
        site: Node<'t>,
        flags: &mut RegexFlags,
    ) -> Result<(), &'static str> {
        let mut pending = vec![expression];
        while let Some(node) = pending.pop() {
            if node.kind() == "parenthesized_expression" {
                pending.push(node.named_child(0).ok_or("java-unknown-regex-flags")?);
                continue;
            }
            if node.kind() == "binary_expression"
                && node
                    .child_by_field_name("operator")
                    .is_some_and(|op| text(op, self.source) == "|")
            {
                pending.push(
                    node.child_by_field_name("left")
                        .ok_or("java-unknown-regex-flags")?,
                );
                pending.push(
                    node.child_by_field_name("right")
                        .ok_or("java-unknown-regex-flags")?,
                );
                continue;
            }
            if node.kind() != "field_access"
                || !self.binder(
                    node.child_by_field_name("object")
                        .ok_or("java-unknown-regex-flags")?,
                    site,
                )?
            {
                return Err("java-unknown-regex-flags");
            }
            match text(
                node.child_by_field_name("field")
                    .ok_or("java-unknown-regex-flags")?,
                self.source,
            ) {
                "CASE_INSENSITIVE" => flags.ignorecase = true,
                "COMMENTS" => flags.verbose = true,
                "DOTALL" => flags.dotall = true,
                "MULTILINE" => flags.multiline = true,
                "UNIX_LINES" => flags.dialect_flags |= 1,
                "UNICODE_CASE" => flags.dialect_flags |= 2,
                "UNICODE_CHARACTER_CLASS" => flags.dialect_flags |= 6,
                "LITERAL" | "CANON_EQ" => return Err("java-unmodeled-regex-flags"),
                _ => return Err("java-unknown-regex-flags"),
            }
        }
        if flags.verbose && flags.dialect_flags & 1 != 0 {
            return Err("java-comments-unix-lines-not-modeled");
        }
        flags.ascii = flags.dialect_flags & 4 == 0;
        if flags.ignorecase && flags.dialect_flags & 2 != 0 {
            return Err("java-unicode-case-folding-not-modeled");
        }
        Ok(())
    }
}
fn incomplete(node: Node<'_>, reason: &str) -> EmbeddedLeafFact {
    EmbeddedLeafFact {
        kind: NormalizedKind::RegexIncomplete,
        range: node_range(node),
        parent: None,
        construct: Some(reason.to_owned()),
        occurrence_role: None,
    }
}

pub(super) fn file_facts(anchor: Node<'_>, source: &str) -> Vec<EmbeddedLeafFact> {
    let mut root = anchor;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut context = FileContext {
        source,
        declarations: Vec::new(),
        imported: false,
        wildcard: false,
        conflicting_import: false,
        java_import: false,
        static_wildcard: false,
        recovered: false,
    };
    let mut calls = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        // The literal decoder owns the value grammar, including multiple-u
        // Unicode escapes that tree-sitter recovers inside a string node.
        // Recovery elsewhere can change lexical binding and refuses certainty.
        if (node.is_error() || node.is_missing()) && ancestor(node, &["string_literal"]).is_none() {
            context.recovered = true;
        }
        if node.kind() == "import_declaration" {
            let import = parse_import_syntax(node, source);
            context.static_wildcard |= import.is_static && import.is_wildcard;
            if let Some(segments) = import.segments {
                let names: Vec<_> = segments.iter().map(|(_, name)| *name).collect();
                context.java_import |= !import.is_wildcard && names.last() == Some(&"java");
                if !import.is_static
                    && !import.is_wildcard
                    && names == ["java", "util", "regex", "Pattern"]
                {
                    context.imported = true;
                } else if !import.is_wildcard && names.last() == Some(&"Pattern") {
                    context.conflicting_import = true;
                }
                if !import.is_static && import.is_wildcard && names == ["java", "util", "regex"] {
                    context.wildcard = true;
                }
            }
        }
        if binding_scope(node).is_some() {
            context.declarations.push(node);
        }
        if node.kind() == "method_invocation" && contains(anchor, node) {
            calls.push(node);
        }
        stack.extend(node.children(&mut node.walk()));
    }
    calls.sort_by_key(Node::start_byte);
    let mut result = Vec::new();
    for call in calls {
        let Some(method) = call.child_by_field_name("name") else {
            continue;
        };
        if !matches!(text(method, source), "compile" | "matches") {
            continue;
        }
        let Some(object) = call.child_by_field_name("object") else {
            continue;
        };
        match context.binder(object, call) {
            Ok(false) => continue,
            Err(reason) => {
                result.push(incomplete(call, reason));
                continue;
            }
            Ok(true) => {}
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args: Vec<_> = arguments
            .named_children(&mut arguments.walk())
            .filter(|n| !n.is_extra())
            .collect();
        let is_compile = text(method, source) == "compile";
        if args.is_empty() || args.len() > 2 || (!is_compile && args.len() != 2) {
            result.push(incomplete(call, "java-regex-call-arity"));
            continue;
        }
        let decoded = match context.constant(args[0]) {
            Ok(value) => value,
            Err(reason) => {
                result.push(incomplete(args[0], reason));
                continue;
            }
        };
        let mut flags = RegexFlags {
            dialect_flags: 0,
            dotall: false,
            multiline: false,
            ignorecase: false,
            ascii: true,
            verbose: false,
            complete: true,
        };
        if is_compile
            && args.len() == 2
            && let Err(reason) = context.flags(args[1], call, &mut flags)
        {
            result.push(incomplete(args[1], reason));
            continue;
        }
        let syntax = JavaRegexSyntax::default();
        let facts = RegexParser::new(&decoded.value, flags, false, &syntax).parse();
        // Java refusals publish only incompleteness. Once the dialect admits
        // a pattern, pass core's output unchanged, including its risk facts
        // together with any diagnostics (for example descending ranges).
        if let Some(reason) = syntax.refusal.get() {
            result.push(incomplete(args[0], reason));
            continue;
        }
        let source_range = Range {
            start_byte: decoded
                .chars
                .iter()
                .map(|c| c.source_start)
                .min()
                .unwrap_or(decoded.source_start),
            end_byte: decoded
                .chars
                .iter()
                .map(|c| c.source_end)
                .max()
                .unwrap_or(decoded.source_start),
            start_line: 1,
            end_line: 1,
        };
        let mut embedded = facts_to_embedded(facts, &decoded.chars, source_range, source);
        let base = result.len();
        for fact in &mut embedded {
            fact.parent = fact.parent.map(|id| id + base);
        }
        result.extend(embedded);
    }
    result
}
