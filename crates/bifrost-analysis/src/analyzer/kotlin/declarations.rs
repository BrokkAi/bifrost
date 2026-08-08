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
//! Name-resolution facts this walk records for issue #1237 live alongside the
//! declarations: structured imports (see `super::imports`) and the dotted
//! supertype paths of each class-like declaration (see `super::supertypes`).
//!
//! Boundaries owned by sibling issues: navigation (#1238), usage graphs
//! (#1239), RQL (#1240), CFG (#1241). Local functions, lambdas, and anonymous
//! objects inside bodies are deliberately not indexed as declarations in this
//! tier.

use super::syntax::{
    kotlin_binding_type_text, kotlin_declared_return_type_text, kotlin_extension_receiver_text,
};
use crate::analyzer::common::{
    collapse_whitespace, node_source_text as node_text,
    node_source_text_trimmed as node_text_trimmed,
};
use crate::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_walk::{
    first_named_child_of_kind as first_named_child, has_token_child,
    named_children as named_children_of,
};
use crate::analyzer::{
    CallableArity, CodeUnit, CodeUnitType, ParameterMetadata, ProjectFile, SignatureMetadata,
};
use tree_sitter::{Node, Tree};

fn kotlin_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// The declared name of an identifier node, with Kotlin's backtick quoting
/// removed.
///
/// Kotlin lets any identifier be written `` `like this` `` (routinely used for
/// test method names). The backticks are quoting syntax, not part of the name,
/// so they must not reach an interned segment — otherwise the declaration is
/// unreachable by its real spelling.
pub(crate) fn kotlin_identifier_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    let text = node_text_trimmed(node, source);
    text.strip_prefix('`')
        .and_then(|text| text.strip_suffix('`'))
        .unwrap_or(text)
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

pub(crate) fn parse_kotlin_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let root = tree.root_node();
    let package_name = kotlin_package_name(root, source);
    let mut parsed = ParsedFile::new(package_name.clone());
    collect_kotlin_imports(root, source, &mut parsed);
    collect_kotlin_type_identifiers(root, source, &mut parsed);

    let mut visitor = KotlinVisitor {
        file,
        source,
        package_name: &package_name,
        parsed: &mut parsed,
    };
    visitor.walk(root);
    parsed
}

pub(crate) fn kotlin_package_name(root: Node<'_>, source: &str) -> String {
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
    for import_list in named_children_of(root)
        .into_iter()
        .filter(|child| child.kind() == "import_list")
    {
        for import in named_children_of(import_list)
            .into_iter()
            .filter(|child| child.kind() == "import_header")
        {
            if let Some(info) = super::imports::kotlin_import_info_from_node(import, source) {
                parsed.imports.push(info);
            }
        }
    }
}

/// Record every name this file spells that could name a type or an object.
///
/// This feeds the same-package reference index, which asks "could this file be
/// talking about a declaration in its own package?" — a question that must not
/// miss, so it collects two node shapes:
///
/// * every `type_identifier`, which the grammar uses for all type positions
///   and for declared type names; and
/// * the receiver of a qualified reference (`Registry` in
///   `Registry.register()`), which is a `simple_identifier` and never a
///   `type_identifier`, yet is the only way to name a Kotlin `object`,
///   companion, or enum class in value position.
fn collect_kotlin_type_identifiers(root: Node<'_>, source: &str, parsed: &mut ParsedFile) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_identifier" => {
                let text = kotlin_identifier_text(node, source);
                if !text.is_empty() {
                    parsed.type_identifiers.insert(text.to_string());
                }
            }
            "navigation_expression" => {
                if let Some(receiver) = node.named_child(0)
                    && receiver.kind() == "simple_identifier"
                {
                    let text = kotlin_identifier_text(receiver, source);
                    if !text.is_empty() {
                        parsed.type_identifiers.insert(text.to_string());
                    }
                }
            }
            _ => {}
        }
        stack.extend(named_children_of(node));
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
        let name = kotlin_identifier_text(name_node, self.source);
        if name.is_empty() {
            return;
        }
        let code_unit = self.declare(CodeUnitType::Class, SegmentKind::Type, name, node, parent);
        self.parsed
            .add_signature(code_unit.clone(), kotlin_class_signature(node, self.source));
        self.record_supertypes(&code_unit, node);

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
            .map(|name_node| kotlin_identifier_text(name_node, self.source).to_string());
        let name = match declared_name {
            Some(name) if !name.is_empty() => name,
            // An unnamed companion object is spelled `Companion` in source
            // references (`Owner.Companion.member`); a plain `object` without
            // a name is an expression (`object_literal`), never this node.
            _ if companion => "Companion".to_string(),
            _ => return,
        };

        let code_unit = self.declare(CodeUnitType::Class, SegmentKind::Type, &name, node, parent);
        // Sliced from source like a class header, so a declared supertype
        // (`object Catalog : Shelver`) survives and an anonymous companion
        // renders as written. The `Companion` identity default above is a
        // name-resolution rule and must not leak into rendered source text.
        let signature = kotlin_class_signature(node, self.source);
        if companion {
            // Companion-ness is not derivable from the indexed identity: a
            // companion and an ordinary nested `object` are both nested classes,
            // and the `Companion` name is a default a source file may override.
            // Publishing it here is what lets the usage graphs answer
            // "`Base.of()` and `Base.Companion.of()` are the same call" from the
            // index rather than by re-parsing the declaring file once per callee
            // owner.
            self.parsed.add_signature_with_metadata(
                code_unit.clone(),
                SignatureMetadata::new(signature, Vec::new()).with_companion_object(true),
            );
        } else {
            self.parsed.add_signature(code_unit.clone(), signature);
        }
        self.record_supertypes(&code_unit, node);

        if let Some(body) = first_named_child(node, "class_body") {
            stack.push(KotlinWork {
                node: body,
                parent: Some(code_unit),
            });
        }
    }

    /// Record the dotted paths of what a class-like declaration extends or
    /// implements. The full header text is already the declaration's rendered
    /// signature, so only the resolvable paths are stored here.
    fn record_supertypes(&mut self, code_unit: &CodeUnit, node: Node<'_>) {
        let supertypes = super::supertypes::extract_kotlin_supertypes(node, self.source);
        if !supertypes.is_empty() {
            self.parsed
                .set_raw_supertypes(code_unit.clone(), supertypes);
        }
    }

    fn visit_function(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        let Some(name_node) = first_named_child(node, "simple_identifier") else {
            return;
        };
        let name = kotlin_identifier_text(name_node, self.source);
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
            let metadata = kotlin_signature_metadata(
                signature,
                kotlin_class_parameter_facts(&parameters, self.source),
            );
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
            let name = kotlin_identifier_text(name_node, self.source);
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
            // A `val`/`var` constructor parameter is a property, and what it
            // declares is the type a receiver of it has. Publishing that here
            // (issue #1345) is what lets a consumer type `d.base.greet()`
            // without re-parsing this file.
            self.parsed.add_signature_with_metadata(
                field,
                SignatureMetadata::new(format!("{binding} {name}{type_text}"), Vec::new())
                    .with_return_type_text(kotlin_binding_type_text(parameter, self.source)),
            );
        }
    }

    fn visit_secondary_constructor(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        // A secondary constructor is only meaningful inside a class body. All
        // of a class's constructors share one synthetic callable identity
        // named after the class (`Owner.Owner`, the Scala precedent): each
        // constructor declaration accumulates its own range and signature on
        // that unit, exactly like ordinary overloads sharing a spelling.
        let Some(owner) = parent else {
            return;
        };
        let class_name = owner.identifier().to_string();
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Function,
            self.package_name.to_string(),
            format!("{}.{class_name}", owner.short_name()),
            owner
                .fq()
                .clone()
                .with_pushed(kotlin_segment(&class_name, SegmentKind::Member)),
        )
        .with_synthetic(true);
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.cloned(), None);
        let parameter_list = first_named_child(node, "function_value_parameters");
        let header_end = parameter_list
            .map(|parameters| parameters.end_byte())
            .unwrap_or(node.end_byte());
        let signature = collapse_whitespace(
            self.source
                .get(node.start_byte()..header_end)
                .unwrap_or_default(),
        );
        let facts = parameter_list
            .map(|list| kotlin_function_parameter_facts(list, self.source))
            .unwrap_or_else(|| kotlin_parameter_facts_from(Vec::new(), 0, false));
        self.parsed
            .add_signature_with_metadata(code_unit, kotlin_signature_metadata(signature, facts));
    }

    fn visit_property(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        // `binding_pattern_kind` is mandatory on a well-formed
        // `property_declaration`; its absence means recovery produced
        // something that is not actually a property, so skip rather than
        // guessing a keyword and publishing a wrong signature.
        let Some(binding) = kotlin_binding_keyword(node, self.source) else {
            return;
        };
        let receiver = node
            .child_by_field_name("receiver")
            .map(|receiver| node_text_trimmed(receiver, self.source).to_string());

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
            let name = kotlin_identifier_text(name_node, self.source);
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
            // The written type and, for an extension property, the receiver it
            // extends are published rather than left to be recovered by a
            // re-read of this file (issue #1345). The receiver comes from the
            // `property_declaration`'s `receiver` field; the type from the
            // individual `variable_declaration`, because a destructuring
            // `val (a, b) = pair` types each name separately.
            self.parsed.add_signature_with_metadata(
                code_unit,
                SignatureMetadata::new(
                    format!("{prefix}{binding} {receiver_prefix}{name}{type_text}"),
                    Vec::new(),
                )
                .with_return_type_text(kotlin_binding_type_text(variable, self.source))
                .with_extension_receiver_type(kotlin_extension_receiver_text(node, self.source)),
            );
        }
    }

    fn visit_type_alias(&mut self, node: Node<'_>, parent: Option<&CodeUnit>) {
        let Some(name_node) = first_named_child(node, "type_identifier") else {
            return;
        };
        let name = kotlin_identifier_text(name_node, self.source);
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
        let name = kotlin_identifier_text(name_node, self.source);
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

/// The tree-sitter node kinds that declare a Kotlin class-like type.
pub(crate) const KOTLIN_CLASS_LIKE_KINDS: &[&str] = &[
    "class_declaration",
    "object_declaration",
    "companion_object",
];

/// What a Kotlin class-like declaration actually declares.
///
/// Kotlin spells all of these with one of three node kinds, so the distinction
/// lives in the tokens inside the node (`interface`, `enum class`) or in a
/// `class_modifier` (`annotation class`), never in the node kind alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KotlinClassLikeKind {
    Class,
    Interface,
    Enum,
    Annotation,
    Object,
}

/// Classify a class-like declaration node, or `None` when the node does not
/// declare a type.
pub(crate) fn kotlin_class_like_kind(node: Node<'_>) -> Option<KotlinClassLikeKind> {
    match node.kind() {
        "object_declaration" | "companion_object" => Some(KotlinClassLikeKind::Object),
        "class_declaration" => {
            if has_token_child(node, "interface") {
                return Some(KotlinClassLikeKind::Interface);
            }
            if has_token_child(node, "enum") {
                return Some(KotlinClassLikeKind::Enum);
            }
            if kotlin_has_modifier(node, "annotation") {
                return Some(KotlinClassLikeKind::Annotation);
            }
            Some(KotlinClassLikeKind::Class)
        }
        _ => None,
    }
}

/// The visibility a Kotlin declaration declares, defaulting to `public`.
///
/// Kotlin has no package-private tier: an unmarked declaration is visible
/// everywhere its containing declaration is, and `internal` restricts a
/// declaration to its own compilation module — which, from the perspective of
/// anything consuming a published artifact, is as invisible as `private`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KotlinDeclaredVisibility {
    Public,
    Protected,
    Internal,
    Private,
}

pub(crate) fn kotlin_declared_visibility(node: Node<'_>, source: &str) -> KotlinDeclaredVisibility {
    let Some(modifiers) = first_named_child(node, "modifiers") else {
        return KotlinDeclaredVisibility::Public;
    };
    for modifier in named_children_of(modifiers) {
        if modifier.kind() != "visibility_modifier" {
            continue;
        }
        return match node_text_trimmed(modifier, source) {
            "private" => KotlinDeclaredVisibility::Private,
            "internal" => KotlinDeclaredVisibility::Internal,
            "protected" => KotlinDeclaredVisibility::Protected,
            _ => KotlinDeclaredVisibility::Public,
        };
    }
    KotlinDeclaredVisibility::Public
}

/// Whether the declaration's `modifiers` list contains `keyword` as a modifier
/// node (not as an annotation argument or an identifier that merely spells the
/// same soft keyword elsewhere in the header).
fn kotlin_has_modifier(node: Node<'_>, keyword: &str) -> bool {
    let Some(modifiers) = first_named_child(node, "modifiers") else {
        return false;
    };
    named_children_of(modifiers)
        .into_iter()
        .any(|modifier| has_token_child(modifier, keyword))
}

/// The `val`/`var` binding keyword of a property-like node.
///
/// `binding_pattern_kind` is mandatory on `property_declaration` and optional
/// on `class_parameter` (a plain constructor parameter has none, and is not a
/// property). Absence is therefore meaningful, never a parse artifact to guess
/// around.
fn kotlin_binding_keyword<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    first_named_child(node, "binding_pattern_kind")
        .map(|binding| node_text_trimmed(binding, source))
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
            return Some(node_text_trimmed(child, source));
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
        let text = node_text_trimmed(modifier, source);
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
    let header = collapse_whitespace(
        source
            .get(node.start_byte()..body_start)
            .unwrap_or_default(),
    );
    format!("{header} {{")
}

/// Callable signature: the function header (modifiers, `fun`, receiver, name,
/// parameters, return type) with the body elided.
fn kotlin_callable_header(node: Node<'_>, source: &str) -> String {
    let body_start = first_named_child(node, "function_body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    collapse_whitespace(
        source
            .get(node.start_byte()..body_start)
            .unwrap_or_default(),
    )
}

struct KotlinParameterFacts {
    metadata: Vec<ParameterMetadata>,
    required: usize,
    repeated: bool,
}

/// Whether a parameter's modifier list marks it `vararg`.
fn kotlin_modifiers_mark_vararg(modifiers: Node<'_>, source: &str) -> bool {
    has_token_child(modifiers, "vararg")
        || named_children_of(modifiers)
            .into_iter()
            .any(|modifier| node_text_trimmed(modifier, source) == "vararg")
}

fn kotlin_parameter_metadata(parameter: Node<'_>, source: &str) -> ParameterMetadata {
    ParameterMetadata::new(
        collapse_whitespace(node_text(parameter, source)),
        parameter.start_byte(),
        parameter.end_byte(),
    )
}

fn kotlin_parameter_facts_from(
    metadata: Vec<ParameterMetadata>,
    optional: usize,
    repeated: bool,
) -> KotlinParameterFacts {
    KotlinParameterFacts {
        required: metadata.len().saturating_sub(optional),
        metadata,
        repeated,
    }
}

/// Parameter facts for a `function_value_parameters` list.
///
/// The grammar's `_function_value_parameter` is a *hidden* rule
/// (`parameter_modifiers? parameter ('=' expression)?`), so tree-sitter inlines
/// its parts: both the modifiers and the `=` of a default are direct children
/// of the list, as siblings of the `parameter` they belong to. This therefore
/// walks the list's children in order, attributing each modifier run to the
/// parameter that follows it.
fn kotlin_function_parameter_facts(list: Node<'_>, source: &str) -> KotlinParameterFacts {
    let mut metadata = Vec::new();
    let mut optional = 0usize;
    let mut repeated = false;
    let mut pending_vararg = false;
    let mut cursor = list.walk();
    for child in list.children(&mut cursor) {
        if child.is_named() && child.kind() == "parameter_modifiers" {
            pending_vararg = kotlin_modifiers_mark_vararg(child, source);
        } else if child.is_named() && child.kind() == "parameter" {
            if pending_vararg {
                repeated = true;
                // A `vararg` parameter accepts zero arguments, so it is not
                // required.
                optional += 1;
            }
            pending_vararg = false;
            metadata.push(kotlin_parameter_metadata(child, source));
        } else if !child.is_named() && child.kind() == "=" {
            optional += 1;
        }
    }
    kotlin_parameter_facts_from(metadata, optional, repeated)
}

/// Parameter facts for a `primary_constructor`'s `class_parameter` list.
///
/// Unlike a function parameter list, `class_parameter` is a *visible* rule that
/// owns its own modifiers and its own `("=" expression)?` default. Nothing
/// belonging to a parameter appears as a sibling, so each parameter must be
/// inspected individually — scanning the list's own children for `=` (as the
/// function form does) would never find a default and would report every
/// defaulted constructor parameter as required.
fn kotlin_class_parameter_facts(parameters: &[Node<'_>], source: &str) -> KotlinParameterFacts {
    let mut metadata = Vec::new();
    let mut optional = 0usize;
    let mut repeated = false;
    for parameter in parameters {
        let vararg = first_named_child(*parameter, "modifiers")
            .or_else(|| first_named_child(*parameter, "parameter_modifiers"))
            .is_some_and(|modifiers| kotlin_modifiers_mark_vararg(modifiers, source));
        // The default's `=` is a token child of the parameter itself.
        if vararg || has_token_child(*parameter, "=") {
            optional += 1;
            repeated |= vararg;
        }
        metadata.push(kotlin_parameter_metadata(*parameter, source));
    }
    kotlin_parameter_facts_from(metadata, optional, repeated)
}

fn kotlin_signature_metadata(signature: String, facts: KotlinParameterFacts) -> SignatureMetadata {
    let arity = CallableArity::new(facts.required, facts.metadata.len(), facts.repeated);
    SignatureMetadata::new(signature, facts.metadata).with_callable_arity(arity)
}

fn kotlin_callable_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let facts = first_named_child(node, "function_value_parameters")
        .map(|list| kotlin_function_parameter_facts(list, source))
        .unwrap_or_else(|| kotlin_parameter_facts_from(Vec::new(), 0, false));
    // Publishing the written return type and extension receiver here is what
    // keeps a consumer from having to re-read and re-parse the declaring file to
    // learn them (issue #1345). Both are recorded as *spelled*: resolution
    // belongs to the consumer and its scope, because a spelled type means
    // whatever the file that wrote it says it means.
    kotlin_signature_metadata(signature, facts)
        .with_return_type_text(kotlin_declared_return_type_text(node, source))
        .with_extension_receiver_type(kotlin_extension_receiver_text(node, source))
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
        assert_eq!(
            parsed
                .imports
                .iter()
                .map(|import| import.raw_snippet.as_str())
                .collect::<Vec<_>>(),
            vec!["import kotlin.math.abs"]
        );
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
