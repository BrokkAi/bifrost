//! Kotlin declaration extraction (issue #1236).
//!
//! Walks the pinned Kotlin tree-sitter grammar (`vendor/tree-sitter-kotlin`)
//! and produces the language-neutral [`ParsedFile`] model: packages, types,
//! callables, fields, ranges, ownership, and signatures.
//!
//! Identity rules: fully-qualified names are source-level — dotted package
//! segments, simple type names, member names. No compiler-generated JVM names
//! ever appear in an identity: no `FooKt` file facades, no `$` encodings, and
//! companion objects use their declared source name (default `Companion`)
//! joined with an ordinary dot. `.kts` scripts are indexed through the same
//! walk; top-level script *statements* are not declarations and are skipped.
//!
//! Boundaries owned by sibling issues: structured imports and supertype
//! hierarchy (#1237), navigation (#1238), usage graphs (#1239), RQL (#1240),
//! CFG (#1241). Local functions, lambdas, and anonymous objects inside bodies
//! are deliberately not indexed as declarations in this tier.

use crate::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::{
    CallableArity, CodeUnit, CodeUnitType, ParameterMetadata, ProjectFile, SignatureMetadata,
};
use tree_sitter::{Node, Tree};

fn kotlin_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Build the structured package prefix for a Kotlin declaration: each dotted
/// component of `package a.b.c` becomes a [`SegmentKind::Package`] segment.
fn kotlin_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in package_name
        .split('.')
        .filter(|component| !component.is_empty())
    {
        fq.push(kotlin_segment(component, SegmentKind::Package));
    }
    fq
}

/// The [`FqName`] a child declaration extends: its enclosing declaration's
/// structured name when nested, otherwise the file's package prefix.
fn kotlin_child_fq_base(parent: Option<&CodeUnit>, package_name: &str) -> FqName {
    match parent {
        Some(parent) => parent.fq().clone(),
        None => kotlin_package_fq(package_name),
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

/// Collapse a header slice to a single-line signature.
fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
    }
    out
}

fn named_children_of(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn first_named_child<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn has_token_child(node: Node<'_>, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == token)
}

pub(crate) fn parse_kotlin_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let root = tree.root_node();
    let package_name = kotlin_package_name(root, source);
    let mut parsed = ParsedFile::new(package_name.clone());
    collect_kotlin_imports(root, source, &mut parsed);

    let mut visitor = KotlinVisitor {
        file,
        source,
        package_name: &package_name,
        parsed: &mut parsed,
    };
    visitor.walk(root);
    parsed
}

fn kotlin_package_name(root: Node<'_>, source: &str) -> String {
    first_named_child(root, "package_header")
        .and_then(|header| first_named_child(header, "identifier"))
        .map(|identifier| {
            // The `identifier` node is a dotted qualified name; strip any
            // interior whitespace/newlines from odd formatting.
            node_text(identifier, source)
                .split_whitespace()
                .collect::<String>()
        })
        .unwrap_or_default()
}

fn collect_kotlin_imports(root: Node<'_>, source: &str, parsed: &mut ParsedFile) {
    // Structured `ImportInfo` modeling belongs to issue #1237; this tier
    // records the raw statements for `import_statements()` display only.
    for import_list in named_children_of(root)
        .into_iter()
        .filter(|child| child.kind() == "import_list")
    {
        for import in named_children_of(import_list)
            .into_iter()
            .filter(|child| child.kind() == "import_header")
        {
            let raw = collapse_whitespace(node_text(import, source));
            if !raw.is_empty() {
                parsed.import_statements.push(raw);
            }
        }
    }
}

/// One container whose declaration-position children remain to be visited.
struct KotlinWork<'tree> {
    node: Node<'tree>,
    parent: Option<CodeUnit>,
}

struct KotlinVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    package_name: &'a str,
    parsed: &'a mut ParsedFile,
}

impl<'a> KotlinVisitor<'a> {
    fn walk(&mut self, root: Node<'_>) {
        let mut stack = vec![KotlinWork {
            node: root,
            parent: None,
        }];
        while let Some(work) = stack.pop() {
            let parent = work.parent;
            for child in named_children_of(work.node) {
                self.visit_declaration_candidate(child, parent.as_ref(), &mut stack);
            }
        }
    }

    /// Dispatch one declaration-position node. Non-declaration statements
    /// (script/expression code) are skipped; `ERROR` recovery containers are
    /// re-entered so declarations behind malformed code stay indexed.
    fn visit_declaration_candidate<'tree>(
        &mut self,
        node: Node<'tree>,
        parent: Option<&CodeUnit>,
        stack: &mut Vec<KotlinWork<'tree>>,
    ) {
        match node.kind() {
            "class_declaration" => self.visit_class(node, parent, stack),
            "object_declaration" => self.visit_object_like(node, parent, false, stack),
            "companion_object" => self.visit_object_like(node, parent, true, stack),
            "function_declaration" => self.visit_function(node, parent),
            "property_declaration" => self.visit_property(node, parent),
            "secondary_constructor" => self.visit_secondary_constructor(node, parent),
            "type_alias" => self.visit_type_alias(node, parent),
            "enum_entry" => self.visit_enum_entry(node, parent, stack),
            "ERROR" => stack.push(KotlinWork {
                node,
                parent: parent.cloned(),
            }),
            _ => {}
        }
    }

    fn declare(
        &mut self,
        kind: CodeUnitType,
        segment_kind: SegmentKind,
        name: &str,
        node: Node<'_>,
        parent: Option<&CodeUnit>,
    ) -> CodeUnit {
        let short_name = match parent {
            Some(parent) => format!("{}.{name}", parent.short_name()),
            None => name.to_string(),
        };
        let fq = kotlin_child_fq_base(parent, self.package_name)
            .with_pushed(kotlin_segment(name, segment_kind));
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            kind,
            self.package_name.to_string(),
            short_name,
            fq,
        );
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        code_unit
    }

    fn visit_class<'tree>(
        &mut self,
        node: Node<'tree>,
        parent: Option<&CodeUnit>,
        stack: &mut Vec<KotlinWork<'tree>>,
    ) {
        let Some(name_node) = first_named_child(node, "type_identifier") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let already_declared = {
            let probe = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Class,
                self.package_name.to_string(),
                match parent {
                    Some(parent) => format!("{}.{name}", parent.short_name()),
                    None => name.to_string(),
                },
                kotlin_child_fq_base(parent, self.package_name)
                    .with_pushed(kotlin_segment(name, SegmentKind::Type)),
            );
            self.parsed.contains_declaration(&probe)
        };
        if already_declared {
            return;
        }

        let code_unit = self.declare(CodeUnitType::Class, SegmentKind::Type, name, node, parent);
        self.parsed
            .add_signature(code_unit.clone(), kotlin_class_signature(node, self.source));

        if let Some(primary) = first_named_child(node, "primary_constructor") {
            self.visit_primary_constructor(primary, name, &code_unit);
        }

        if let Some(body) = first_named_child(node, "class_body")
            .or_else(|| first_named_child(node, "enum_class_body"))
        {
            stack.push(KotlinWork {
                node: body,
                parent: Some(code_unit),
            });
        }
    }

    fn visit_object_like<'tree>(
        &mut self,
        node: Node<'tree>,
        parent: Option<&CodeUnit>,
        companion: bool,
        stack: &mut Vec<KotlinWork<'tree>>,
    ) {
        let declared_name = first_named_child(node, "type_identifier")
            .map(|name_node| node_text(name_node, self.source).trim().to_string());
        let name = match declared_name {
            Some(name) if !name.is_empty() => name,
            // An unnamed companion object is spelled `Companion` in source
            // references (`Owner.Companion.member`); a plain `object` without
            // a name is an expression (`object_literal`), never this node.
            _ if companion => "Companion".to_string(),
            _ => return,
        };

        let code_unit = self.declare(CodeUnitType::Class, SegmentKind::Type, &name, node, parent);
        let keyword = if companion {
            "companion object"
        } else {
            "object"
        };
        let prefix = kotlin_modifier_prefix(node, self.source);
        self.parsed
            .add_signature(code_unit.clone(), format!("{prefix}{keyword} {name} {{"));

        if let Some(body) = first_named_child(node, "class_body") {
            stack.push(KotlinWork {
                node: body,
                parent: Some(code_unit),
            });
        }
    }

    fn visit_function(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        let Some(name_node) = first_named_child(node, "simple_identifier") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let code_unit = self.declare(
            CodeUnitType::Function,
            SegmentKind::Member,
            name,
            node,
            parent,
        );
        let signature = kotlin_callable_header(node, self.source);
        let metadata = kotlin_callable_signature_metadata(signature, node, self.source);
        self.parsed.add_signature_with_metadata(code_unit, metadata);
    }

    fn visit_primary_constructor(&mut self, primary: Node<'_>, class_name: &str, owner: &CodeUnit) {
        let parameters: Vec<Node<'_>> = named_children_of(primary)
            .into_iter()
            .filter(|child| child.kind() == "class_parameter")
            .collect();
        if !parameters.is_empty() {
            let constructor = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Function,
                self.package_name.to_string(),
                format!("{}.{class_name}", owner.short_name()),
                owner
                    .fq()
                    .clone()
                    .with_pushed(kotlin_segment(class_name, SegmentKind::Member)),
            )
            .with_synthetic(true);
            self.parsed.add_code_unit(
                constructor.clone(),
                primary,
                self.source,
                Some(owner.clone()),
                None,
            );
            let params_text = collapse_whitespace(node_text(primary, self.source));
            let signature = if params_text.starts_with('(') {
                format!("{class_name}{params_text}")
            } else {
                format!("{class_name} {params_text}")
            };
            let metadata =
                kotlin_parameters_signature_metadata(signature, &parameters, self.source);
            self.parsed
                .add_signature_with_metadata(constructor, metadata);
        }

        // `val`/`var` class parameters declare real properties.
        for parameter in parameters {
            let Some(binding) = kotlin_binding_keyword(parameter, self.source) else {
                continue;
            };
            let Some(name_node) = first_named_child(parameter, "simple_identifier") else {
                continue;
            };
            let name = node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let field = self.declare(
                CodeUnitType::Field,
                SegmentKind::Member,
                name,
                parameter,
                Some(owner),
            );
            let type_text = kotlin_declared_type_text(parameter, self.source)
                .map(|text| format!(": {text}"))
                .unwrap_or_default();
            self.parsed
                .add_signature(field, format!("{binding} {name}{type_text}"));
        }
    }

    fn visit_secondary_constructor(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        // A secondary constructor is only meaningful inside a class body; its
        // callable identity is the class name (constructors and their class
        // share a spelling, not an identity — the constructor is a Function).
        let Some(owner) = parent else {
            return;
        };
        let class_name = owner
            .short_name()
            .rsplit('.')
            .next()
            .unwrap_or(owner.short_name())
            .to_string();
        let code_unit = self.declare(
            CodeUnitType::Function,
            SegmentKind::Member,
            &class_name,
            node,
            parent,
        );
        let header_end = first_named_child(node, "function_value_parameters")
            .map(|parameters| parameters.end_byte())
            .unwrap_or(node.end_byte());
        let signature = collapse_whitespace(&self.source[node.start_byte()..header_end]);
        let parameters: Vec<Node<'_>> = first_named_child(node, "function_value_parameters")
            .map(|list| {
                named_children_of(list)
                    .into_iter()
                    .filter(|child| child.kind() == "parameter")
                    .collect()
            })
            .unwrap_or_default();
        let metadata = kotlin_parameters_signature_metadata(signature, &parameters, self.source);
        self.parsed.add_signature_with_metadata(code_unit, metadata);
    }

    fn visit_property(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        let binding = kotlin_binding_keyword(node, self.source).unwrap_or("val");
        let receiver = node
            .child_by_field_name("receiver")
            .map(|receiver| node_text(receiver, self.source).trim().to_string());

        let mut variables = Vec::new();
        if let Some(variable) = first_named_child(node, "variable_declaration") {
            variables.push(variable);
        } else if let Some(multi) = first_named_child(node, "multi_variable_declaration") {
            variables.extend(
                named_children_of(multi)
                    .into_iter()
                    .filter(|child| child.kind() == "variable_declaration"),
            );
        }

        for variable in variables {
            let Some(name_node) = first_named_child(variable, "simple_identifier") else {
                continue;
            };
            let name = node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit =
                self.declare(CodeUnitType::Field, SegmentKind::Member, name, node, parent);
            let type_text = kotlin_declared_type_text(variable, self.source)
                .map(|text| format!(": {text}"))
                .unwrap_or_default();
            let receiver_prefix = receiver
                .as_deref()
                .map(|receiver| format!("{receiver}."))
                .unwrap_or_default();
            let prefix = kotlin_modifier_prefix(node, self.source);
            self.parsed.add_signature(
                code_unit,
                format!("{prefix}{binding} {receiver_prefix}{name}{type_text}"),
            );
        }
    }

    fn visit_type_alias(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        let Some(name_node) = first_named_child(node, "type_identifier") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = self.declare(CodeUnitType::Field, SegmentKind::Member, name, node, parent);
        self.parsed.add_signature(
            code_unit.clone(),
            collapse_whitespace(node_text(node, self.source)),
        );
        self.parsed.mark_type_alias(code_unit);
    }

    fn visit_enum_entry<'tree>(
        &mut self,
        node: Node<'tree>,
        parent: Option<&CodeUnit>,
        stack: &mut Vec<KotlinWork<'tree>>,
    ) {
        let Some(owner) = parent else {
            return;
        };
        let Some(name_node) = first_named_child(node, "simple_identifier") else {
            return;
        };
        let name = node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = self.declare(CodeUnitType::Field, SegmentKind::Member, name, node, parent);
        let arguments = first_named_child(node, "value_arguments")
            .map(|arguments| collapse_whitespace(node_text(arguments, self.source)))
            .unwrap_or_default();
        self.parsed
            .add_signature(code_unit, format!("{name}{arguments}"));

        // Members declared in an entry's body are owned by the enum class:
        // the entry itself is a Field, and Fields do not own children in the
        // shared declaration model.
        if let Some(body) = first_named_child(node, "class_body") {
            stack.push(KotlinWork {
                node: body,
                parent: Some(owner.clone()),
            });
        }
    }
}

/// The `val`/`var` binding keyword of a property-like node, when present.
fn kotlin_binding_keyword<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if let Some(binding) = first_named_child(node, "binding_pattern_kind") {
        return Some(node_text(binding, source).trim());
    }
    if has_token_child(node, "val") {
        return Some("val");
    }
    if has_token_child(node, "var") {
        return Some("var");
    }
    None
}

const KOTLIN_TYPE_NODE_KINDS: &[&str] = &[
    "user_type",
    "nullable_type",
    "not_nullable_type",
    "function_type",
    "parenthesized_type",
];

/// The declared type of a `variable_declaration`/`class_parameter`: the type
/// node following its `:` token, when the declaration is explicitly typed.
fn kotlin_declared_type_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut seen_colon = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if !child.is_named() {
            if child.kind() == ":" {
                seen_colon = true;
            } else if child.kind() == "=" {
                break;
            }
            continue;
        }
        if seen_colon && KOTLIN_TYPE_NODE_KINDS.contains(&child.kind()) {
            return Some(node_text(child, source).trim());
        }
    }
    None
}

/// Non-annotation modifier keywords (`private sealed data ...`) as a signature
/// prefix with a trailing space, or an empty string.
fn kotlin_modifier_prefix(node: Node<'_>, source: &str) -> String {
    let Some(modifiers) = first_named_child(node, "modifiers") else {
        return String::new();
    };
    let mut prefix = String::new();
    let mut cursor = modifiers.walk();
    for modifier in modifiers.children(&mut cursor) {
        if modifier.kind() == "annotation" {
            continue;
        }
        let text = node_text(modifier, source).trim();
        if text.is_empty() {
            continue;
        }
        prefix.push_str(text);
        prefix.push(' ');
    }
    prefix
}

/// Class/interface signature: the source header (modifiers through primary
/// constructor and supertype list) with whitespace collapsed, opened with `{`
/// to pair with the skeleton renderer's closing `}`.
fn kotlin_class_signature(node: Node<'_>, source: &str) -> String {
    let body_start = first_named_child(node, "class_body")
        .or_else(|| first_named_child(node, "enum_class_body"))
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let header = collapse_whitespace(&source[node.start_byte()..body_start]);
    format!("{header} {{")
}

/// Callable signature: the function header (modifiers, `fun`, receiver, name,
/// parameters, return type) with the body elided.
fn kotlin_callable_header(node: Node<'_>, source: &str) -> String {
    let body_start = first_named_child(node, "function_body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    collapse_whitespace(&source[node.start_byte()..body_start])
}

struct KotlinParameterFacts {
    metadata: Vec<ParameterMetadata>,
    required: usize,
    repeated: bool,
}

/// Parameter labels, arity, and variadic facts for a parameter list.
///
/// Defaults (`= expr`) and `vararg` modifiers are siblings of the parameter
/// node inside the list, so this scans the list's token stream in order.
fn kotlin_parameter_facts(
    list: Node<'_>,
    parameter_kind: &str,
    source: &str,
) -> KotlinParameterFacts {
    let mut metadata = Vec::new();
    let mut optional = 0usize;
    let mut repeated = false;
    // A parameter's `vararg` modifier and `= default` are siblings of the
    // parameter node inside the list (`parameter_modifiers? parameter
    // ('=' expression)?`), so this scans the list's children in order.
    let mut pending_vararg = false;
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if child.is_named() && child.kind() == "parameter_modifiers" {
            pending_vararg = has_token_child(child, "vararg")
                || named_children_of(child).into_iter().any(|modifier| {
                    modifier.kind() == "parameter_modifier"
                        && node_text(modifier, source).trim() == "vararg"
                });
        } else if child.is_named() && child.kind() == parameter_kind {
            // `class_parameter` keeps its modifiers inline rather than as a
            // preceding sibling.
            if pending_vararg
                || first_named_child(child, "parameter_modifiers")
                    .or_else(|| first_named_child(child, "modifiers"))
                    .is_some_and(|modifiers| {
                        named_children_of(modifiers)
                            .into_iter()
                            .any(|modifier| node_text(modifier, source).trim() == "vararg")
                            || has_token_child(modifiers, "vararg")
                    })
            {
                repeated = true;
                // A `vararg` parameter accepts zero arguments, so it is not
                // required.
                optional += 1;
            }
            pending_vararg = false;
            metadata.push(ParameterMetadata::new(
                collapse_whitespace(node_text(child, source)),
                child.start_byte(),
                child.end_byte(),
            ));
        } else if !child.is_named() && child.kind() == "=" {
            optional += 1;
        }
    }
    let required = metadata.len().saturating_sub(optional);
    KotlinParameterFacts {
        metadata,
        required,
        repeated,
    }
}

fn kotlin_callable_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let parameters = first_named_child(node, "function_value_parameters");
    let facts = parameters
        .map(|list| kotlin_parameter_facts(list, "parameter", source))
        .unwrap_or(KotlinParameterFacts {
            metadata: Vec::new(),
            required: 0,
            repeated: false,
        });
    SignatureMetadata::new(signature, facts.metadata.clone()).with_callable_arity(
        CallableArity::new(facts.required, facts.metadata.len(), facts.repeated),
    )
}

fn kotlin_parameters_signature_metadata(
    signature: String,
    parameters: &[Node<'_>],
    source: &str,
) -> SignatureMetadata {
    let list = parameters.first().and_then(Node::parent);
    let facts = list
        .map(|list| {
            kotlin_parameter_facts(
                list,
                parameters
                    .first()
                    .map(|parameter| parameter.kind())
                    .unwrap_or("parameter"),
                source,
            )
        })
        .unwrap_or(KotlinParameterFacts {
            metadata: Vec::new(),
            required: 0,
            repeated: false,
        });
    SignatureMetadata::new(signature, facts.metadata.clone()).with_callable_arity(
        CallableArity::new(facts.required, facts.metadata.len(), facts.repeated),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashMap;
    use tree_sitter::Parser;

    fn parse(source: &str) -> (ProjectFile, ParsedFile) {
        let file = ProjectFile::new(
            std::env::temp_dir().join("kotlin-declarations-tests"),
            "sample/Sample.kt",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&super::super::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse Kotlin source");
        let parsed = parse_kotlin_file(&file, source, &tree);
        (file, parsed)
    }

    fn fq_names(parsed: &ParsedFile) -> Vec<String> {
        let mut names: Vec<String> = parsed
            .declarations()
            .iter()
            .map(|unit| unit.fq_name())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn extracts_principal_declarations_with_source_level_identities() {
        let source = r#"package com.example

import kotlin.math.abs

class Outer(val seed: Int, label: String) {
    val cached: Int = seed

    fun render(prefix: String): String = prefix

    class Inner {
        fun poke() {}
    }

    companion object {
        fun of(seed: Int): Outer = Outer(seed, "label")
    }
}

fun topLevel(count: Int): Int = abs(count)

val topProperty: Long = 42L

typealias Rows = List<String>
"#;
        let (_, parsed) = parse(source);
        assert_eq!(parsed.package_name, "com.example");
        assert_eq!(parsed.import_statements, vec!["import kotlin.math.abs"]);
        let names = fq_names(&parsed);
        for expected in [
            "com.example.Outer",
            "com.example.Outer.Outer",
            "com.example.Outer.seed",
            "com.example.Outer.cached",
            "com.example.Outer.render",
            "com.example.Outer.Inner",
            "com.example.Outer.Inner.poke",
            "com.example.Outer.Companion",
            "com.example.Outer.Companion.of",
            "com.example.topLevel",
            "com.example.topProperty",
            "com.example.Rows",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected} in {names:#?}"
            );
        }
        // `label` has no val/var: not a property.
        assert!(!names.iter().any(|name| name.ends_with("Outer.label")));
        // No JVM-generated identities.
        assert!(names.iter().all(|name| !name.contains('$')));
        assert!(names.iter().all(|name| !name.contains("Kt")));
    }

    #[test]
    fn signatures_render_headers_without_bodies() {
        let source = r#"package sig

sealed class Shape(val edges: Int) {
    open fun area(scale: Double = 1.0): Double = 0.0
}

fun String.shout(): String = uppercase()
"#;
        let (_, parsed) = parse(source);
        let by_name: HashMap<String, Vec<String>> = parsed
            .declarations()
            .iter()
            .map(|unit| {
                (
                    unit.fq_name(),
                    parsed.signatures.get(unit).cloned().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            by_name["sig.Shape"],
            vec!["sealed class Shape(val edges: Int) {"]
        );
        assert_eq!(
            by_name["sig.Shape.area"],
            vec!["open fun area(scale: Double = 1.0): Double"]
        );
        assert_eq!(by_name["sig.shout"], vec!["fun String.shout(): String"]);
        assert_eq!(by_name["sig.Shape.edges"], vec!["val edges: Int"]);
    }

    #[test]
    fn callable_arity_tracks_defaults_and_vararg() {
        let source = r#"package arity

fun spread(vararg parts: String): String = parts.joinToString()
fun mixed(a: Int, b: Int = 2, c: String = "x"): Int = a + b
"#;
        let (_, parsed) = parse(source);
        let arity_of = |fq: &str| {
            parsed
                .declarations()
                .iter()
                .find(|unit| unit.fq_name() == fq)
                .and_then(|unit| parsed.signature_metadata.get(unit))
                .and_then(|entries| entries.first())
                .and_then(SignatureMetadata::callable_arity)
                .expect("callable arity")
        };
        let spread = arity_of("arity.spread");
        assert!(spread.accepts(0) && spread.accepts(5));
        let mixed = arity_of("arity.mixed");
        assert!(mixed.accepts(1) && mixed.accepts(3) && !mixed.accepts(0) && !mixed.accepts(4));
    }

    #[test]
    fn enums_objects_and_scripts_index_expected_units() {
        let source = r#"package shapes

enum class Direction(val degrees: Int) {
    NORTH(0),
    EAST(90) {
        override fun describe(): String = "east"
    };

    open fun describe(): String = name
}

object Registry {
    fun register(direction: Direction) {}
}

interface Drawable {
    fun draw()
}
"#;
        let (_, parsed) = parse(source);
        let names = fq_names(&parsed);
        for expected in [
            "shapes.Direction",
            "shapes.Direction.NORTH",
            "shapes.Direction.EAST",
            "shapes.Direction.describe",
            "shapes.Registry",
            "shapes.Registry.register",
            "shapes.Drawable",
            "shapes.Drawable.draw",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected} in {names:#?}"
            );
        }
    }

    #[test]
    fn malformed_source_recovers_surrounding_declarations() {
        let source = r#"package broken

fun ok(): Int = 1

fun bad(value: Int): Int = when (value) {
    0 ->
    else -> value
}

class Survivor {
    fun still(): Int = 2
}
"#;
        let (_, parsed) = parse(source);
        let names = fq_names(&parsed);
        assert!(names.iter().any(|name| name == "broken.ok"));
        assert!(names.iter().any(|name| name == "broken.Survivor"));
        assert!(names.iter().any(|name| name == "broken.Survivor.still"));
    }

    #[test]
    fn kts_scripts_index_declarations_but_not_statements() {
        let source = r#"val greeting = "hello"

fun shoutGreeting(): String = greeting.uppercase()

class ScriptHelper {
    fun help(): String = shoutGreeting()
}

println(shoutGreeting())
"#;
        let (_, parsed) = parse(source);
        let names = fq_names(&parsed);
        assert!(names.iter().any(|name| name == "greeting"));
        assert!(names.iter().any(|name| name == "shoutGreeting"));
        assert!(names.iter().any(|name| name == "ScriptHelper.help"));
        // The trailing println statement is script code, not a declaration.
        assert!(!names.iter().any(|name| name.contains("println")));
    }
}
