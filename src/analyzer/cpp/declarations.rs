use super::*;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{CallableArity, ParameterMetadata, SignatureMetadata};
use regex::Regex;
use tree_sitter::Node;

#[derive(Clone)]
struct ScopeInfo {
    package_name: String,
    module: Option<CodeUnit>,
    class_unit: Option<CodeUnit>,
    template_signature: Option<String>,
}

struct CppContainer<'tree> {
    node: Node<'tree>,
    scope: ScopeInfo,
}

struct CppNodeWork<'tree> {
    node: Node<'tree>,
    scope: ScopeInfo,
}

enum CppWork<'tree> {
    Container(CppContainer<'tree>),
    Node(CppNodeWork<'tree>),
}

fn class_like_name(node: Node<'_>, source: &str) -> Option<String> {
    let best = class_like_name_from_children(node, source);
    if let Some(parent) = node.parent()
        && matches!(
            parent.kind(),
            "declaration" | "field_declaration" | "function_definition"
        )
        && node
            .child_by_field_name("name")
            .map(|name_node| {
                cpp_export_macro_token(&normalize_cpp_whitespace(node_text(name_node, source)))
            })
            .unwrap_or(false)
        && let Some(recovered) = exported_class_name_from_node(parent, source)
        && best.as_deref() != Some(recovered.as_str())
    {
        return Some(recovered);
    }
    best.or_else(|| {
        node.child_by_field_name("name")
            .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
            .filter(|name| !name.is_empty() && !cpp_export_macro_token(name))
    })
}

fn class_like_name_from_children(node: Node<'_>, source: &str) -> Option<String> {
    let mut grammar_name = None;
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = normalize_cpp_whitespace(node_text(name_node, source));
        if name.is_empty() {
            return None;
        }
        if !cpp_export_macro_token(&name) {
            return Some(name);
        }
        grammar_name = Some(name);
    }

    let mut best = None;
    let mut cursor = node.walk();
    let mut stack = Vec::new();
    for child in node.named_children(&mut cursor).collect::<Vec<_>>() {
        if matches!(
            child.kind(),
            "field_declaration_list" | "base_class_clause" | "declaration_list" | "enumerator_list"
        ) {
            break;
        }
        stack.push(child);
    }

    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "type_identifier" | "identifier") {
            let name = normalize_cpp_whitespace(node_text(current, source));
            if !name.is_empty() && !cpp_export_macro_token(&name) {
                best = Some(name);
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    best.or(grammar_name)
}

fn cpp_export_macro_token(token: &str) -> bool {
    token
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

struct RecoveredExportedClass<'tree> {
    declaration_node: Node<'tree>,
    name: String,
    body: Option<Node<'tree>>,
    raw_supertypes: Option<Vec<String>>,
    uses_initializer_body: bool,
}

fn recover_exported_class_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RecoveredExportedClass<'tree>> {
    if let Some(recovered) = recover_malformed_exported_multiple_base_class(node, source) {
        return Some(recovered);
    }

    let class_node = first_class_like_child(node)?;
    if let Some(name_node) = class_node.child_by_field_name("name") {
        let class_name = normalize_cpp_whitespace(node_text(name_node, source));
        if cpp_export_macro_token(&class_name) {
            // Tree-sitter can parse `class EXPORT Name` as an EXPORT class plus a
            // Name declarator. Only a bare declarator can be the displaced class name;
            // wrappers describe an object whose type merely happens to look macro-like.
            let mut cursor = node.walk();
            if node
                .children_by_field_name("declarator", &mut cursor)
                .any(|declarator| !matches!(declarator.kind(), "identifier" | "type_identifier"))
            {
                return None;
            }
        } else if has_direct_cpp_declarator(node) {
            return None;
        }
    }
    let name = exported_class_name_from_node(class_node, source)?;
    Some(RecoveredExportedClass {
        declaration_node: class_node,
        name,
        body: cpp_body_node(class_node),
        raw_supertypes: matches!(class_node.kind(), "class_specifier" | "struct_specifier")
            .then(|| extract_cpp_supertypes(class_node, source)),
        uses_initializer_body: false,
    })
}

fn recover_malformed_exported_multiple_base_class<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RecoveredExportedClass<'tree>> {
    if node.kind() != "declaration" {
        return None;
    }
    let class_node = node.child_by_field_name("type")?;
    if class_node.kind() != "class_specifier" || cpp_body_node(class_node).is_some() {
        return None;
    }
    let macro_name = class_node
        .child_by_field_name("name")
        .and_then(|name| direct_identifier_name(name, source))?;
    if !cpp_export_macro_token(&macro_name) {
        return None;
    }

    let mut named_cursor = node.walk();
    let mut named = node.named_children(&mut named_cursor);
    if named
        .next()
        .is_none_or(|child| !same_node(child, class_node))
    {
        return None;
    }
    let displaced = named.next()?;
    if displaced.kind() != "ERROR" {
        return None;
    }
    let name = displaced_exported_class_name(displaced, source)?;

    let remaining = named.collect::<Vec<_>>();
    let init = *remaining.last()?;
    if init.kind() != "init_declarator" {
        return None;
    }
    let final_base = init
        .child_by_field_name("declarator")
        .and_then(|base| recovered_malformed_base_name(base, source))?;
    let body = init.child_by_field_name("value")?;
    // A complete reduction has a real closing brace here. In Chromium's Widget
    // declaration, tree-sitter instead emits the same direct `}` slot as a
    // zero-width missing node where the first body macro truncates the prefix.
    if body.kind() != "initializer_list" || !has_direct_token(body, "}") {
        return None;
    }

    let mut declarator_cursor = node.walk();
    let direct_declarators = node.children_by_field_name("declarator", &mut declarator_cursor);
    if direct_declarators.count() < 2 {
        return None;
    }
    if remaining[..remaining.len() - 1]
        .iter()
        .any(|child| match child.kind() {
            "qualified_identifier"
            | "scoped_type_identifier"
            | "type_identifier"
            | "identifier" => false,
            "ERROR" => !is_malformed_inheritance_access(*child, source),
            _ => true,
        })
    {
        return None;
    }

    let mut raw_supertypes = Vec::new();
    for base in &remaining[..remaining.len() - 1] {
        if base.kind() == "ERROR" {
            continue;
        }
        raw_supertypes.push(recovered_malformed_base_name(*base, source)?);
    }
    raw_supertypes.push(final_base);

    Some(RecoveredExportedClass {
        declaration_node: node,
        name,
        body: Some(body),
        raw_supertypes: Some(raw_supertypes),
        uses_initializer_body: true,
    })
}

fn displaced_exported_class_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut name = None;
    let mut colon_count = 0;
    let mut access_count = 0;
    for index in 0..node.child_count() {
        let child = node.child(index)?;
        match child.kind() {
            "identifier" | "type_identifier" if child.is_named() => {
                if name.is_some() {
                    return None;
                }
                let candidate = normalize_cpp_whitespace(node_text(child, source));
                if candidate.is_empty() || cpp_export_macro_token(&candidate) {
                    return None;
                }
                name = Some(candidate);
            }
            ":" if !child.is_named() => colon_count += 1,
            "public" | "protected" | "private" if !child.is_named() => access_count += 1,
            _ => return None,
        }
    }
    (colon_count == 1 && access_count == 1)
        .then_some(name)
        .flatten()
}

fn is_malformed_inheritance_access(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "ERROR" || node.named_child_count() != 1 {
        return false;
    }
    node.named_child(0)
        .and_then(|child| direct_identifier_name(child, source))
        .is_some_and(|name| matches!(name.as_str(), "public" | "protected" | "private"))
}

fn has_direct_token(node: Node<'_>, expected_kind: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| !child.is_named() && child.kind() == expected_kind)
    })
}

fn recovered_malformed_base_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" | "namespace_identifier" => {
            recovered_base_atom(node, source)
        }
        "ERROR" => None,
        "qualified_identifier" | "scoped_type_identifier" => {
            let suffix = node
                .child_by_field_name("name")
                .and_then(|name| recovered_malformed_base_name(name, source))?;
            let scope = node
                .child_by_field_name("scope")
                .and_then(|scope| recovered_malformed_base_name(scope, source))?;
            let prefix = if matches!(scope.as_str(), "public" | "protected" | "private") {
                malformed_qualified_prefix(node, source)?
            } else {
                if malformed_qualified_prefix(node, source).is_some() {
                    return None;
                }
                scope
            };
            Some(format!("{prefix}::{suffix}"))
        }
        _ => None,
    }
}

fn recovered_base_atom(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "identifier" | "type_identifier" | "namespace_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(node, source));
    (!name.is_empty()).then_some(name)
}

fn malformed_qualified_prefix(node: Node<'_>, source: &str) -> Option<String> {
    let mut prefix = None;
    let mut cursor = node.walk();
    for error in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR")
    {
        if error.named_child_count() != 1 || prefix.is_some() {
            return None;
        }
        prefix = error
            .named_child(0)
            .and_then(|child| recovered_base_atom(child, source));
        prefix.as_ref()?;
    }
    prefix
}

fn recover_exported_class_function_definition<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, String)> {
    if node.kind() != "function_definition" {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let declarator = node.child_by_field_name("declarator")?;

    if matches!(
        type_node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        if let Some(name) = direct_identifier_name(declarator, source)
            && !cpp_export_macro_token(&name)
        {
            return Some((node, name));
        }
        if declarator.kind() == "parenthesized_declarator"
            && type_node
                .child_by_field_name("name")
                .and_then(|name| direct_identifier_name(name, source))
                .is_some_and(|name| cpp_export_macro_token(&name))
        {
            let body_start = node
                .child_by_field_name("body")
                .map(|body| body.start_byte())
                .unwrap_or(node.end_byte());
            let mut cursor = node.walk();
            if let Some(name) = node
                .named_children(&mut cursor)
                .filter(|child| {
                    child.kind() == "ERROR"
                        && child.start_byte() >= declarator.end_byte()
                        && child.end_byte() <= body_start
                })
                .find_map(|error| declarator_name_from_node(error, source))
            {
                return Some((node, name));
            }
        }
    }

    let declarator_text = direct_identifier_name(declarator, source)?;
    if !matches!(declarator_text.as_str(), "class" | "struct" | "union") {
        return None;
    }
    class_identifier_before_body(node, source).map(|name| (node, name))
}

pub(crate) fn recovered_exported_class_has_body(
    node: Node<'_>,
    source: &str,
    expected_name: &str,
) -> Option<bool> {
    match node.kind() {
        "function_definition" => {
            let (class_node, name) = recover_exported_class_function_definition(node, source)?;
            (name == expected_name).then(|| cpp_body_node(class_node).is_some())
        }
        "declaration" | "field_declaration" => {
            let recovered = recover_exported_class_declaration(node, source)?;
            (recovered.name == expected_name).then(|| recovered.body.is_some())
        }
        _ => None,
    }
}

fn class_identifier_before_body(node: Node<'_>, source: &str) -> Option<String> {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let mut stack = Vec::new();
    for index in (0..node.named_child_count()).rev() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        if child.start_byte() >= body_start {
            continue;
        }
        stack.push(child);
    }

    let mut best = None;
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "type_identifier") {
            let name = normalize_cpp_whitespace(node_text(current, source));
            if !name.is_empty()
                && !cpp_export_macro_token(&name)
                && !matches!(name.as_str(), "class" | "struct" | "union")
            {
                best = Some(name);
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index)
                && child.start_byte() < body_start
            {
                stack.push(child);
            }
        }
    }
    best
}

fn exported_class_name_from_node(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "declaration"
        && node
            .child_by_field_name("type")
            .or_else(|| first_class_like_child(node))
            .is_some_and(|type_node| {
                matches!(
                    type_node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                )
            })
        && let Some(name) = node
            .child_by_field_name("declarator")
            .and_then(|declarator| declarator_name_from_node(declarator, source))
        && !cpp_export_macro_token(&name)
    {
        return Some(name);
    }

    if node.kind() == "function_definition"
        && node.child_by_field_name("type").is_some_and(|type_node| {
            matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            )
        })
        && let Some(name) = node
            .child_by_field_name("declarator")
            .and_then(|declarator| direct_identifier_name(declarator, source))
        && !cpp_export_macro_token(&name)
    {
        return Some(name);
    }

    let class_node = if matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) {
        node
    } else {
        first_class_like_child(node)?
    };
    class_like_name_from_children(class_node, source)
}

fn direct_identifier_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    ) {
        return None;
    }
    let name = normalize_cpp_whitespace(node_text(node, source));
    (!name.is_empty()).then_some(name)
}

fn declarator_name_from_node(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" => {
            let name = normalize_cpp_whitespace(node_text(node, source));
            (!name.is_empty()).then_some(name)
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| declarator_name_from_node(child, source))
        }
    }
}

fn first_class_like_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        )
    })
}

fn push_cpp_child_work<'tree>(
    node: Node<'tree>,
    scope: ScopeInfo,
    stack: &mut Vec<CppWork<'tree>>,
) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(CppWork::Node(CppNodeWork {
                node: child,
                scope: scope.clone(),
            }));
        }
    }
}

pub(super) struct CppVisitor<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CppVisitor<'a> {
    pub(super) fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        module: Option<CodeUnit>,
        class_unit: Option<CodeUnit>,
        template_signature: Option<String>,
    ) {
        let mut stack = vec![CppWork::Container(CppContainer {
            node,
            scope: ScopeInfo {
                package_name: package_name.to_string(),
                module,
                class_unit,
                template_signature,
            },
        })];
        while let Some(work) = stack.pop() {
            match work {
                CppWork::Container(container) => {
                    push_cpp_child_work(container.node, container.scope, &mut stack);
                }
                CppWork::Node(work) => {
                    self.visit_node(work.node, &work.scope, &mut stack);
                }
            }
        }
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        match node.kind() {
            "template_declaration" => {
                for index in (0..node.named_child_count()).rev() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "class_specifier"
                            | "struct_specifier"
                            | "union_specifier"
                            | "enum_specifier"
                            | "function_definition"
                            | "declaration"
                            | "field_declaration"
                            | "alias_declaration"
                            | "namespace_definition"
                    ) {
                        let mut template_scope = scope.clone();
                        template_scope.template_signature =
                            cpp_template_signature(node, child, self.source);
                        stack.push(CppWork::Node(CppNodeWork {
                            node: child,
                            scope: template_scope,
                        }));
                    }
                }
            }
            "namespace_definition" => self.visit_namespace(node, scope, stack),
            "linkage_specification" => {
                if let Some(body) = cpp_body_node(node) {
                    stack.push(CppWork::Container(CppContainer {
                        node: body,
                        scope: scope.clone(),
                    }));
                } else {
                    stack.push(CppWork::Container(CppContainer {
                        node,
                        scope: scope.clone(),
                    }));
                }
            }
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier" => {
                self.visit_class_like(node, scope, stack)
            }
            "function_definition" => self.visit_function_definition(node, scope, stack),
            "declaration" => self.visit_declaration(node, scope, false, stack),
            "field_declaration" => self.visit_declaration(node, scope, true, stack),
            "type_definition" | "alias_declaration" => {
                self.visit_type_declaration(node, scope, stack)
            }
            "ERROR" => stack.push(CppWork::Container(CppContainer {
                node,
                scope: scope.clone(),
            })),
            "preproc_def" | "preproc_function_def" => self.visit_macro(node),
            "preproc_include" => self.visit_include(node),
            "labeled_statement" if scope.class_unit.is_some() => {
                stack.push(CppWork::Container(CppContainer {
                    node,
                    scope: scope.clone(),
                }))
            }
            "preproc_if" | "preproc_ifdef" | "preproc_ifndef" | "preproc_else" | "preproc_elif" => {
                stack.push(CppWork::Container(CppContainer {
                    node,
                    scope: scope.clone(),
                }))
            }
            _ => {}
        }
    }

    fn visit_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let name_node = node.child_by_field_name("name");
        let Some(name_node) = name_node else {
            if let Some(body) = cpp_body_node(node) {
                stack.push(CppWork::Container(CppContainer {
                    node: body,
                    scope: scope.clone(),
                }));
            }
            return;
        };
        let name = normalize_cpp_whitespace(node_text(name_node, self.source));
        if name.is_empty() {
            return;
        }
        let full_name = if scope.package_name.is_empty() {
            name
        } else {
            format!("{}::{}", scope.package_name, name)
        };
        let module = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            full_name.clone(),
        );
        if !self.parsed.contains_declaration(&module) {
            self.parsed
                .add_code_unit(module.clone(), node, self.source, None, None);
        }

        let namespace_scope = ScopeInfo {
            package_name: full_name,
            module: Some(module),
            class_unit: scope.class_unit.clone(),
            template_signature: scope.template_signature.clone(),
        };
        let container = cpp_body_node(node).unwrap_or(node);
        stack.push(CppWork::Container(CppContainer {
            node: container,
            scope: namespace_scope,
        }));
    }

    fn visit_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let Some(name) = class_like_name(node, self.source) else {
            return;
        };
        self.visit_named_class_like(node, name, scope, stack);
    }

    fn visit_named_class_like<'tree>(
        &mut self,
        node: Node<'tree>,
        name: String,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let body = cpp_body_node(node);
        let raw_supertypes = matches!(node.kind(), "class_specifier" | "struct_specifier")
            .then(|| extract_cpp_supertypes(node, self.source));
        self.visit_named_class_like_shape(node, name, body, raw_supertypes, scope, stack);
    }

    fn visit_named_class_like_shape<'tree>(
        &mut self,
        declaration_node: Node<'tree>,
        name: String,
        body: Option<Node<'tree>>,
        raw_supertypes: Option<Vec<String>>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            scope.template_signature.clone(),
            false,
        );
        let has_body = body.is_some();
        if !has_body && self.parsed.contains_declaration(&code_unit) {
            return;
        }
        if has_body {
            self.parsed.replace_code_unit(
                code_unit.clone(),
                declaration_node,
                self.source,
                None,
                None,
            );
        } else {
            self.parsed
                .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        }
        if let Some(raw_supertypes) = raw_supertypes {
            self.parsed
                .set_raw_supertypes(code_unit.clone(), raw_supertypes);
        }
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_type_signature(
                declaration_node,
                self.source,
                scope.template_signature.as_deref(),
            ),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit.clone());
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit.clone());
        }

        if let Some(body) = body {
            let mut nested_scope = scope.clone();
            nested_scope.class_unit = Some(code_unit.clone());
            nested_scope.template_signature = scope.template_signature.clone();
            stack.push(CppWork::Container(CppContainer {
                node: body,
                scope: nested_scope,
            }));
        }
        if declaration_node.kind() == "enum_specifier" {
            self.visit_enum_enumerators(declaration_node, scope, &code_unit);
            if !self.has_enum_enumerator_units(&code_unit) {
                self.visit_enum_enumerators_from_text(declaration_node, scope, &code_unit);
            }
        }
    }

    fn has_enum_enumerator_units(&self, parent: &CodeUnit) -> bool {
        let prefix = format!("{}.", parent.short_name());
        self.parsed.declarations().iter().any(|unit| {
            unit.kind() == CodeUnitType::Field
                && unit.source() == parent.source()
                && unit.package_name() == parent.package_name()
                && unit.short_name().starts_with(&prefix)
        })
    }

    fn visit_enum_enumerators(&mut self, node: Node<'_>, scope: &ScopeInfo, parent: &CodeUnit) {
        walk_named_tree_preorder(node, false, |child| {
            if child.kind() != "enumerator" {
                return WalkControl::Continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                return WalkControl::Continue;
            };
            let name = normalize_cpp_whitespace(node_text(name_node, self.source));
            if name.is_empty() {
                return WalkControl::Continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.contains_declaration(&code_unit) {
                return WalkControl::Continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), child, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                normalize_cpp_whitespace(node_text(child, self.source)),
            );
            self.parsed.add_child(parent.clone(), code_unit);
            WalkControl::Continue
        });
    }

    fn visit_enum_enumerators_from_text(
        &mut self,
        node: Node<'_>,
        scope: &ScopeInfo,
        parent: &CodeUnit,
    ) {
        let text = node_text(node, self.source);
        let Some((_, body)) = text.split_once('{') else {
            return;
        };
        let Some((body, _)) = body.rsplit_once('}') else {
            return;
        };
        for entry in body.split(',') {
            let trimmed = entry.trim();
            let name = trimmed
                .split('=')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            if self.parsed.contains_declaration(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed
                .add_signature(code_unit.clone(), trimmed.to_string());
            self.parsed.add_child(parent.clone(), code_unit);
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if let Some((class_node, name)) =
            recover_exported_class_function_definition(node, self.source)
        {
            let mut stack = Vec::new();
            self.visit_named_class_like(class_node, name, scope, &mut stack);
            while let Some(work) = stack.pop() {
                match work {
                    CppWork::Container(container) => {
                        push_cpp_child_work(container.node, container.scope, &mut stack);
                    }
                    CppWork::Node(work) => self.visit_node(work.node, &work.scope, &mut stack),
                }
            }
            return;
        }
        let Some(declarator) = node.child_by_field_name("declarator") else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(function_declarator) = extract_function_declarator(declarator) else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let Some(function) = extract_function_info(function_declarator, self.source, scope) else {
            self.visit_malformed_function_definition_container(node, scope, stack);
            return;
        };
        let code_unit = function.code_unit(self.file.clone());
        self.parsed
            .replace_code_unit(code_unit.clone(), node, self.source, None, None);
        let signature = render_cpp_function_display_signature_from_node(
            node,
            self.source,
            scope.template_signature.as_deref(),
            true,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, function_declarator, self.source),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_malformed_function_definition_container<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        let Some(body) = cpp_body_node(node) else {
            return;
        };
        if !cpp_contains_namespace_definition(body) {
            return;
        }
        stack.push(CppWork::Container(CppContainer {
            node: body,
            scope: scope.clone(),
        }));
    }

    fn visit_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        in_class_body: bool,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if let Some(recovered) = recover_exported_class_declaration(node, self.source) {
            let uses_initializer_body = recovered.uses_initializer_body;
            self.visit_named_class_like_shape(
                recovered.declaration_node,
                recovered.name,
                recovered.body,
                recovered.raw_supertypes,
                scope,
                stack,
            );
            if uses_initializer_body {
                return;
            }
        }

        let mut handled_function = false;
        let mut handled_declarator = false;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(
                child.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            ) {
                if in_class_body && !has_direct_cpp_declarator(node) {
                    self.visit_class_like(child, scope, stack);
                }
                continue;
            }
        }

        let mut cursor = node.walk();
        for child in node.children_by_field_name("declarator", &mut cursor) {
            if super::structural::is_recovered_designator_init_declarator(child) {
                handled_declarator = true;
                continue;
            }
            if let Some(kind) = classify_declarator(child) {
                handled_declarator = true;
                match kind {
                    DeclaratorKind::Function(function_declarator) => {
                        handled_function = true;
                        self.visit_function_declaration(node, function_declarator, scope);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                        );
                    }
                }
            }
        }

        if !handled_declarator {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if super::structural::is_recovered_designator_init_declarator(child) {
                    handled_declarator = true;
                    continue;
                }
                if !is_unfielded_declarator_candidate(child) {
                    continue;
                }
                let Some(kind) = classify_declarator(child) else {
                    continue;
                };
                handled_declarator = true;
                match kind {
                    DeclaratorKind::Function(function_declarator) => {
                        handled_function = true;
                        self.visit_function_declaration(node, function_declarator, scope);
                    }
                    DeclaratorKind::Variable(variable_declarator) => {
                        self.visit_variable_declaration(
                            node,
                            variable_declarator,
                            scope,
                            in_class_body,
                        );
                    }
                }
            }
        }

        if handled_function {
            return;
        }

        if !handled_declarator {
            if in_class_body {
                self.visit_class_members_from_declaration(node, scope);
            } else {
                self.visit_global_variables_from_declaration(node, scope);
            }
        }
    }

    fn visit_function_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
    ) {
        let Some(function) = extract_function_info(declarator, self.source, scope) else {
            return;
        };
        let code_unit =
            function.code_unit_with_synthetic(self.file.clone(), scope.class_unit.is_some());
        if self.parsed.contains_declaration(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        let signature = render_cpp_function_display_signature_from_node(
            declaration_node,
            self.source,
            scope.template_signature.as_deref(),
            false,
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            cpp_signature_metadata(signature, declarator, self.source),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_variable_declaration(
        &mut self,
        declaration_node: Node<'_>,
        declarator: Node<'_>,
        scope: &ScopeInfo,
        in_class_body: bool,
    ) {
        let Some(name) = extract_variable_name(declarator, self.source) else {
            return;
        };
        let short_name = if in_class_body {
            let Some(parent) = &scope.class_unit else {
                return;
            };
            format!("{}.{}", parent.short_name(), name)
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.contains_declaration(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), declaration_node, self.source, None, None);
        self.parsed.add_signature(
            code_unit.clone(),
            render_cpp_field_signature(declaration_node, declarator, self.source),
        );
        if let Some(parent) = &scope.class_unit {
            self.parsed.add_child(parent.clone(), code_unit);
        } else if let Some(module) = &scope.module {
            self.parsed.add_child(module.clone(), code_unit);
        }
    }

    fn visit_class_members_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, true);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, true);
            }
        }
    }

    fn visit_global_variables_from_declaration(&mut self, node: Node<'_>, scope: &ScopeInfo) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "init_declarator"
                && let Some(inner) = child.child_by_field_name("declarator")
            {
                self.visit_variable_declaration(node, inner, scope, false);
            } else if matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator"
            ) {
                self.visit_variable_declaration(node, child, scope, false);
            }
        }
    }

    fn visit_include(&mut self, node: Node<'_>) {
        let raw = normalize_cpp_whitespace(node_text(node, self.source));
        self.parsed.import_statements.push(raw.clone());
        self.parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
        });
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &ScopeInfo,
        stack: &mut Vec<CppWork<'tree>>,
    ) {
        if let Some(type_node) = node.child_by_field_name("type")
            && matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            )
        {
            self.visit_class_like(type_node, scope, stack);
        }

        let signature = normalize_cpp_whitespace(node_text(node, self.source));
        if signature.is_empty() {
            return;
        }

        let type_name = node
            .child_by_field_name("type")
            .and_then(|type_node| type_node.child_by_field_name("name"))
            .map(|name_node| normalize_cpp_whitespace(node_text(name_node, self.source)));
        let alias_names = match node.kind() {
            "alias_declaration" => extract_alias_declaration_name(node, self.source)
                .into_iter()
                .collect::<Vec<_>>(),
            "type_definition" => extract_typedef_alias_names(node, self.source),
            _ => Vec::new(),
        };
        for alias_name in alias_names {
            if alias_name.is_empty() || type_name.as_deref() == Some(alias_name.as_str()) {
                continue;
            }
            let code_unit = CodeUnit::with_signature(
                self.file.clone(),
                CodeUnitType::Class,
                scope.package_name.clone(),
                alias_name,
                Some(signature.clone()),
                false,
            );
            if self.parsed.contains_declaration_identity(&code_unit) {
                continue;
            }
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, None, None);
            self.parsed
                .add_signature(code_unit.clone(), signature.clone());
            self.parsed.mark_type_alias(code_unit);
        }
    }

    fn visit_macro(&mut self, node: Node<'_>) {
        let Some(name) = extract_macro_name(node, self.source) else {
            return;
        };
        let signature = node_text(node, self.source).trim_end().to_string();
        if signature.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(self.file.clone(), CodeUnitType::Macro, "", name);
        if self.parsed.contains_declaration_identity(&code_unit) {
            return;
        }
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, None, None);
        self.parsed.add_signature(code_unit, signature);
    }
}

pub(crate) fn recover_quoted_includes(
    source: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut in_block_comment = false;
    for line in source.lines() {
        let stripped = strip_cpp_comments_from_line(line, &mut in_block_comment);
        let trimmed = stripped.trim();
        if !looks_like_quoted_include_line(trimmed) {
            continue;
        }

        let raw = normalize_cpp_whitespace(trimmed);
        if parsed.import_statements.contains(&raw) {
            continue;
        }

        parsed.import_statements.push(raw.clone());
        parsed.imports.push(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
        });
    }
}

fn looks_like_quoted_include_line(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let Some(rest) = rest.trim_start().strip_prefix("include") else {
        return false;
    };
    rest.trim_start().starts_with('"')
}

fn extract_cpp_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "base_class_clause" {
            collect_cpp_base_nodes(child, source, &mut raw);
        }
    }
    raw
}

fn collect_cpp_base_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    walk_named_tree_preorder(node, false, |child| match child.kind() {
        "type_identifier" | "qualified_identifier" | "template_type" => {
            let text = normalize_cpp_whitespace(node_text(child, source));
            if !text.is_empty() {
                raw.push(text);
            }
            WalkControl::SkipChildren
        }
        _ => WalkControl::Continue,
    });
}

fn strip_cpp_comments_from_line(line: &str, in_block_comment: &mut bool) -> String {
    let mut out = String::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    let mut in_string = false;
    let mut in_char = false;
    let mut escape = false;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        if *in_block_comment {
            if ch == '*' && next == Some('/') {
                *in_block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if in_char {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '\'' {
                in_char = false;
            }
            index += 1;
            continue;
        }

        if ch == '/' && next == Some('/') {
            break;
        }
        if ch == '/' && next == Some('*') {
            *in_block_comment = true;
            index += 2;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if ch == '\'' {
            in_char = true;
            out.push(ch);
            index += 1;
            continue;
        }

        out.push(ch);
        index += 1;
    }

    out
}

#[derive(Clone)]
struct FunctionInfo {
    package_name: String,
    owner_path: Option<String>,
    name: String,
    signature: String,
}

enum DeclaratorKind<'a> {
    Function(Node<'a>),
    Variable(Node<'a>),
}

impl FunctionInfo {
    fn code_unit(&self, file: ProjectFile) -> CodeUnit {
        self.code_unit_with_synthetic(file, false)
    }

    fn code_unit_with_synthetic(&self, file: ProjectFile, synthetic: bool) -> CodeUnit {
        let short_name = if let Some(owner) = &self.owner_path {
            format!("{owner}.{}", self.name)
        } else {
            self.name.clone()
        };
        CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            self.package_name.clone(),
            short_name,
            Some(self.signature.clone()),
            synthetic,
        )
    }
}

fn extract_function_info(
    declarator: Node<'_>,
    source: &str,
    scope: &ScopeInfo,
) -> Option<FunctionInfo> {
    let parameters_node = declarator.child_by_field_name("parameters")?;
    let parameters_text = cpp_parameter_signature(parameters_node, source);
    let declarator_name_node = declarator
        .child_by_field_name("declarator")
        .or_else(|| last_named_child(declarator))?;
    let raw_name = normalize_cpp_whitespace(&extract_declarator_name(declarator_name_node, source));
    if raw_name.is_empty() {
        return None;
    }

    let (owner_path, name, package_name) = split_cpp_name(&raw_name, scope);
    let full_text = normalize_cpp_whitespace(node_text(declarator, source));
    let suffix = full_text
        .split_once(node_text(parameters_node, source))
        .map(|(_, tail)| normalize_cpp_qualifier_suffix(tail))
        .unwrap_or_default();
    let mut signature = if suffix.is_empty() {
        parameters_text
    } else {
        format!("{parameters_text} {suffix}")
    };
    if let Some(template_signature) = &scope.template_signature {
        signature = format!("{template_signature}{signature}");
    }

    Some(FunctionInfo {
        package_name,
        owner_path,
        name,
        signature,
    })
}

fn extract_function_declarator(node: Node<'_>) -> Option<Node<'_>> {
    match classify_declarator(node)? {
        DeclaratorKind::Function(function_declarator) => Some(function_declarator),
        DeclaratorKind::Variable(_) => None,
    }
}

fn classify_declarator(node: Node<'_>) -> Option<DeclaratorKind<'_>> {
    match node.kind() {
        "function_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| last_named_child(node));
            if inner.is_some_and(is_function_pointer_like_inner_declarator) {
                Some(DeclaratorKind::Variable(node))
            } else {
                Some(DeclaratorKind::Function(node))
            }
        }
        "init_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "attributed_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(classify_declarator),
        "identifier" | "field_identifier" | "qualified_identifier" => {
            Some(DeclaratorKind::Variable(node))
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(classify_declarator),
    }
}

fn is_unfielded_declarator_candidate(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declarator"
            | "init_declarator"
            | "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "array_declarator"
            | "attributed_declarator"
            | "template_function"
            | "identifier"
            | "field_identifier"
            | "qualified_identifier"
    )
}

fn has_direct_cpp_declarator(node: Node<'_>) -> bool {
    let class_like = first_class_like_child(node);
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "init_declarator"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "function_declarator"
                | "parenthesized_declarator"
                | "attributed_declarator"
        ) || matches!(
            child.kind(),
            "identifier" | "field_identifier" | "qualified_identifier"
        ) && class_like.is_none_or(|class_node| {
            child.start_byte() < class_node.start_byte() || child.end_byte() > class_node.end_byte()
        })
    })
}

fn is_function_pointer_like_inner_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "pointer_declarator" | "reference_declarator" | "array_declarator" => true,
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .is_some_and(is_pointer_wrapper_declarator),
        "template_function" => node
            .child_by_field_name("name")
            .is_some_and(is_function_pointer_like_inner_declarator),
        _ => false,
    }
}

fn is_pointer_wrapper_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "pointer_declarator" | "reference_declarator" | "array_declarator" => true,
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .is_some_and(is_pointer_wrapper_declarator),
        _ => false,
    }
}

fn split_cpp_name(raw_name: &str, scope: &ScopeInfo) -> (Option<String>, String, String) {
    let cleaned = raw_name.trim_start_matches("template ").trim();
    let parts: Vec<_> = cleaned.split("::").collect();
    if parts.len() > 1 {
        let name = parts.last().unwrap_or(&cleaned).to_string();
        let owner_parts = &parts[..parts.len() - 1];
        let mut package_name = scope.package_name.clone();
        let owner_path = if let Some(class_unit) = &scope.class_unit {
            Some(class_unit.short_name().to_string())
        } else if owner_parts.len() > 1 {
            package_name = if package_name.is_empty() {
                owner_parts[..owner_parts.len() - 1].join("::")
            } else {
                package_name
            };
            Some(owner_parts.last().unwrap_or(&"").to_string())
        } else {
            Some(owner_parts[0].to_string())
        };
        return (owner_path, name, package_name);
    }

    let package_name = scope.package_name.clone();
    let owner_path = scope
        .class_unit
        .as_ref()
        .map(|parent| parent.short_name().to_string());
    (owner_path, cleaned.to_string(), package_name)
}

fn extract_declarator_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier"
        | "field_identifier"
        | "type_identifier"
        | "operator_name"
        | "destructor_name"
        | "qualified_identifier" => node_text(node, source).to_string(),
        "function_declarator"
        | "pointer_declarator"
        | "reference_declarator"
        | "parenthesized_declarator"
        | "array_declarator"
        | "template_function" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
        _ => node
            .child_by_field_name("name")
            .map(|child| extract_declarator_name(child, source))
            .unwrap_or_else(|| node_text(node, source).to_string()),
    }
}

fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            let name = node_text(node, source).trim().to_string();
            (!name.is_empty()).then_some(name)
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

fn extract_alias_declaration_name(node: Node<'_>, source: &str) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let name = normalize_cpp_whitespace(node_text(name_node, source));
    (!name.is_empty()).then_some(name)
}

fn extract_typedef_alias_names(node: Node<'_>, source: &str) -> Vec<String> {
    let type_node = node.child_by_field_name("type");
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if type_node.is_some_and(|type_node| same_node(child, type_node)) {
            continue;
        }
        if let Some(name) = extract_typedef_declarator_name(child, source)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names
}

fn extract_typedef_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            let name = normalize_cpp_whitespace(node_text(node, source));
            (!name.is_empty()).then_some(name)
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_typedef_declarator_name(child, source)),
    }
}

fn extract_macro_name(node: Node<'_>, source: &str) -> Option<String> {
    let name = node
        .child_by_field_name("name")
        .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| {
                    matches!(
                        child.kind(),
                        "identifier" | "field_identifier" | "type_identifier"
                    )
                })
                .map(|name_node| normalize_cpp_whitespace(node_text(name_node, source)))
        })?;
    (!name.is_empty()).then_some(name)
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
}

fn render_cpp_type_signature(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
) -> String {
    let text = normalize_cpp_whitespace(node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    let rendered = if head.ends_with(';') {
        head.to_string()
    } else {
        format!("{head} {{")
    };
    if let Some(template_signature) = template_signature {
        format!("template {template_signature} {rendered}")
    } else {
        rendered
    }
}

fn render_cpp_field_signature(node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let declaration_text = normalize_cpp_whitespace(node_text(node, source));
    let prefix = cpp_declaration_prefix(node, source);
    let name = extract_variable_name(declarator, source).unwrap_or_default();
    let raw_suffix = cpp_declarator_suffix_without_name(declarator, source);
    let suffix = if (prefix.ends_with('*') && raw_suffix == "*")
        || (prefix.ends_with('&') && raw_suffix == "&")
    {
        String::new()
    } else {
        raw_suffix
    };

    let mut rendered = if suffix.is_empty() {
        format!("{prefix} {name}")
    } else if suffix.starts_with('*') || suffix.starts_with('&') {
        format!("{prefix}{suffix} {name}")
    } else if suffix.starts_with('[') || suffix.starts_with('(') {
        format!("{prefix} {name}{suffix}")
    } else {
        format!("{prefix} {suffix}{name}")
    };
    rendered = collapse_cpp_whitespace(&rendered);

    if let Some(initializer) = cpp_preserved_initializer(node, declarator, source) {
        format!("{rendered} = {initializer};")
    } else if declaration_text.ends_with(';') {
        format!("{rendered};")
    } else {
        rendered
    }
}

fn cpp_declaration_prefix(node: Node<'_>, source: &str) -> String {
    let text = node_text(node, source);
    let mut cursor = node.walk();
    let first_declarator = node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "init_declarator"
                | "identifier"
                | "field_identifier"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "function_declarator"
        )
    });
    let prefix = if let Some(first_declarator) = first_declarator {
        let end = first_declarator
            .start_byte()
            .saturating_sub(node.start_byte());
        let mut prefix = text.get(..end).unwrap_or(text).to_string();
        let declarator_suffix = match first_declarator.kind() {
            "init_declarator" => first_declarator
                .child_by_field_name("declarator")
                .map(|inner| cpp_declarator_suffix_without_name(inner, source))
                .unwrap_or_default(),
            _ => cpp_declarator_suffix_without_name(first_declarator, source),
        };
        if declarator_suffix.starts_with('*') || declarator_suffix.starts_with('&') {
            prefix.push_str(&declarator_suffix);
        }
        return collapse_cpp_whitespace(&prefix)
            .trim_end_matches(',')
            .trim_end_matches(';')
            .trim()
            .to_string();
    } else {
        text
    };
    collapse_cpp_whitespace(prefix)
        .trim_end_matches(',')
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn cpp_preserved_initializer(
    declaration_node: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = extract_variable_name(declarator, source)?;
    let mut cursor = declaration_node.walk();
    for child in declaration_node.named_children(&mut cursor) {
        if child.kind() != "init_declarator" {
            continue;
        }
        let Some(inner) = child.child_by_field_name("declarator") else {
            continue;
        };
        if extract_variable_name(inner, source).as_deref() != Some(name.as_str()) {
            continue;
        }
        let value = child.child_by_field_name("value")?;
        let kind = value.kind();
        if matches!(
            kind,
            "number_literal" | "float_literal" | "char_literal" | "true" | "false"
        ) {
            return Some(normalize_cpp_whitespace(node_text(value, source)));
        }
        break;
    }
    let declaration_text = normalize_cpp_whitespace(node_text(declaration_node, source));
    let pattern = format!(
        r"\b{}\s*=\s*([-+]?[0-9]+(?:\.[0-9]+)?)",
        regex::escape(&name)
    );
    Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(&declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn render_cpp_function_display_signature_from_node(
    node: Node<'_>,
    source: &str,
    template_signature: Option<&str>,
    has_body: bool,
) -> String {
    let root = enclosing_cpp_declaration_node(node).unwrap_or(node);
    let parent_text = node_text(root, source);
    let body_local_start = root
        .child_by_field_name("body")
        .map(|body| body.start_byte().saturating_sub(root.start_byte()))
        .unwrap_or(parent_text.len());
    let display = parent_text
        .get(..body_local_start)
        .unwrap_or(parent_text)
        .trim()
        .trim();
    let display = if let Some(template_signature) = template_signature {
        if display.starts_with("template ") {
            display.to_string()
        } else {
            format!("template {template_signature} {display}")
        }
    } else {
        display.to_string()
    };
    let display = collapse_cpp_whitespace(display.trim_end_matches(';'));
    if has_body {
        format!("{display} {{...}}")
    } else {
        format!("{display};")
    }
}

fn cpp_template_signature(
    template_node: Node<'_>,
    declaration_child: Node<'_>,
    source: &str,
) -> Option<String> {
    let text = source
        .get(template_node.start_byte()..declaration_child.start_byte())
        .unwrap_or("");
    let text = normalize_cpp_whitespace(text);
    let start = text.find('<')?;
    let end = text.rfind('>')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn enclosing_cpp_declaration_node(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "declaration"
            | "function_declaration"
            | "field_declaration"
            | "function_definition" => return Some(node),
            _ => node = node.parent()?,
        }
    }
}

fn cpp_parameter_signature(parameters_node: Node<'_>, source: &str) -> String {
    let mut params = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                params.push(cpp_parameter_type(child, source));
            }
            "variadic_parameter_declaration" => {
                params.push(cpp_parameter_type(child, source));
            }
            "variadic_parameter" | "..." => params.push("...".to_string()),
            _ => {}
        }
    }

    if params.is_empty() {
        "()".to_string()
    } else {
        format!("({})", params.join(", "))
    }
}

fn cpp_signature_metadata(
    signature: String,
    function_declarator: Node<'_>,
    source: &str,
) -> SignatureMetadata {
    let return_type_text = cpp_callable_return_type_text(function_declarator, source);
    let Some(parameters_node) = function_declarator.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_return_type_text(return_type_text);
    };
    let callable_arity = cpp_callable_arity(parameters_node, source);
    let parameter_text = normalize_cpp_whitespace(node_text(parameters_node, source));
    let search_from = cpp_signature_search_start(&signature, function_declarator, source);
    let Some(relative_start) = signature
        .get(search_from..)
        .and_then(|suffix| suffix.find(&parameter_text))
    else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_callable_arity(callable_arity)
            .with_return_type_text(return_type_text);
    };
    let parameters_start = search_from + relative_start;
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = cpp_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = normalize_cpp_whitespace(node_text(label_node, source));
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(&label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
        .with_callable_arity(callable_arity)
        .with_return_type_text(return_type_text)
}

fn cpp_callable_return_type_text(function_declarator: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = function_declarator.walk();
    if let Some(trailing) = function_declarator
        .named_children(&mut cursor)
        .find(|child| child.kind() == "trailing_return_type")
        && let Some(type_descriptor) = trailing.named_child(0)
    {
        let text = normalize_cpp_whitespace(node_text(type_descriptor, source));
        if !text.is_empty() {
            return Some(text);
        }
    }

    let mut current = function_declarator;
    let mut indirection = String::new();
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "declaration" | "field_declaration"
        ) {
            let type_node = parent.child_by_field_name("type")?;
            if cpp_export_macro_token(node_text(type_node, source))
                && (0..parent.named_child_count()).any(|index| {
                    parent
                        .named_child(index)
                        .is_some_and(|child| child.kind() == "ERROR")
                })
            {
                // Export/decorator macros commonly occupy the grammar's `type`
                // field and leave the semantic return type in an ERROR sibling.
                // Do not persist the macro token as a return type. The malformed
                // declaration does not carry enough structured evidence here.
                return None;
            }
            let base = normalize_cpp_whitespace(node_text(type_node, source));
            return (!base.is_empty()).then(|| format!("{base}{indirection}"));
        }
        let wraps_current_declarator = parent.child_by_field_name("declarator") == Some(current)
            || (matches!(parent.kind(), "pointer_declarator" | "reference_declarator")
                && parent.named_child_count() == 1
                && parent.named_child(0) == Some(current));
        if wraps_current_declarator {
            match parent.kind() {
                "pointer_declarator" => indirection.push('*'),
                "reference_declarator" => {
                    let reference = parent
                        .children(&mut parent.walk())
                        .find(|child| !child.is_named())
                        .map(|child| node_text(child, source))
                        .unwrap_or("&");
                    indirection.push_str(reference);
                }
                "init_declarator" | "parenthesized_declarator" => {}
                _ => return None,
            }
            current = parent;
            continue;
        }
        return None;
    }
    None
}

fn cpp_callable_arity(parameters_node: Node<'_>, source: &str) -> CallableArity {
    let mut required = 0;
    let mut total = 0;
    let mut repeated = false;
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                if child.child_by_field_name("declarator").is_none()
                    && child
                        .child_by_field_name("type")
                        .is_some_and(|type_node| node_text(type_node, source).trim() == "void")
                {
                    continue;
                }
                required += 1;
                total += 1;
            }
            "optional_parameter_declaration" => total += 1,
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                repeated = true;
            }
            _ => {}
        }
    }
    CallableArity::new(required, total, repeated)
}

fn cpp_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                if let Some(name_node) = child
                    .child_by_field_name("declarator")
                    .and_then(cpp_declarator_label_node)
                {
                    labels.push(name_node);
                } else {
                    labels.push(child);
                }
            }
            "variadic_parameter" | "variadic_parameter_declaration" | "..." => {
                labels.push(child);
            }
            _ => {}
        }
    }
    labels
}

fn cpp_signature_search_start(
    signature: &str,
    function_declarator: Node<'_>,
    source: &str,
) -> usize {
    let Some(enclosing) = enclosing_cpp_declaration_node(function_declarator) else {
        return 0;
    };
    let raw = node_text(enclosing, source);
    let leading_trim_bytes = raw.len().saturating_sub(raw.trim_start().len());
    let offset = function_declarator
        .start_byte()
        .saturating_sub(enclosing.start_byte())
        .saturating_sub(leading_trim_bytes);
    offset.min(signature.len())
}

fn cpp_declarator_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .and_then(cpp_declarator_label_node),
        "array_declarator" => node
            .child_by_field_name("declarator")
            .and_then(cpp_declarator_label_node),
        "function_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(cpp_declarator_label_node),
        _ => None,
    }
}

fn cpp_parameter_type(parameter: Node<'_>, source: &str) -> String {
    let type_text = parameter
        .child_by_field_name("type")
        .map(|node| normalize_cpp_whitespace(node_text(node, source)))
        .unwrap_or_default();
    let declarator_suffix = parameter
        .child_by_field_name("declarator")
        .map(|node| cpp_declarator_suffix_without_name(node, source))
        .unwrap_or_default();

    let combined = if type_text.is_empty() {
        declarator_suffix
    } else if declarator_suffix.is_empty() {
        type_text
    } else {
        format!("{type_text} {declarator_suffix}")
    };
    normalize_cpp_type_text(&combined)
}

fn cpp_declarator_suffix_without_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "identifier" | "field_identifier" => String::new(),
        "pointer_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| last_named_child(node))
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            format!("*{inner}")
        }
        "reference_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .or_else(|| last_named_child(node))
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            format!("&{inner}")
        }
        "array_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let size = node
                .child_by_field_name("size")
                .map(|child| normalize_cpp_whitespace(node_text(child, source)))
                .unwrap_or_default();
            format!("{inner}[{size}]")
        }
        "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| last_named_child(node))
            .map(|child| format!("({})", cpp_declarator_suffix_without_name(child, source)))
            .unwrap_or_default(),
        "function_declarator" => {
            let inner = node
                .child_by_field_name("declarator")
                .map(|child| cpp_declarator_suffix_without_name(child, source))
                .unwrap_or_default();
            let params = node
                .child_by_field_name("parameters")
                .map(|child| cpp_parameter_signature(child, source))
                .unwrap_or_else(|| "()".to_string());
            format!("{inner}{params}")
        }
        _ => {
            let text = normalize_cpp_whitespace(node_text(node, source));
            let name = extract_declarator_name(node, source);
            if name.is_empty() {
                text
            } else {
                text.replace(&name, "").trim().to_string()
            }
        }
    }
}

fn normalize_cpp_qualifier_suffix(suffix: &str) -> String {
    collapse_cpp_whitespace(
        suffix
            .trim()
            .trim_start_matches("->")
            .trim_start_matches('{')
            .trim_end_matches(';'),
    )
}

pub(crate) fn normalize_cpp_whitespace(value: &str) -> String {
    collapse_cpp_whitespace(value)
}

fn normalize_cpp_type_text(value: &str) -> String {
    collapse_cpp_whitespace(value)
        .replace(", ", ",")
        .replace(" <", "<")
        .replace("< ", "<")
        .replace(" >", ">")
}

fn collapse_cpp_whitespace(value: &str) -> String {
    let mut result = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result.trim().to_string()
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn collect_cpp_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "type_identifier" | "identifier" | "qualified_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}

fn cpp_body_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "declaration_list" | "field_declaration_list" | "enumerator_list"
            )
        })
    })
}

fn cpp_contains_namespace_definition(node: Node<'_>) -> bool {
    if node.kind() == "namespace_definition" {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(cpp_contains_namespace_definition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::LanguageAdapter;
    use crate::analyzer::cpp::adapter::CppAdapter;
    use crate::analyzer::tree_sitter_analyzer::{
        finish_declaration_identity_comparison_probe, start_declaration_identity_comparison_probe,
    };
    use std::fmt::Write;

    #[test]
    fn cpp_alias_and_macro_dedup_comparison_count_is_linear() {
        const DISTINCT_PER_KIND: usize = 64;
        let mut source = String::new();
        for index in 0..DISTINCT_PER_KIND {
            writeln!(source, "typedef int Alias{index};").unwrap();
        }
        writeln!(source, "typedef long Alias0;").unwrap();
        for index in 0..DISTINCT_PER_KIND {
            writeln!(source, "#define MACRO_{index} {index}").unwrap();
        }
        writeln!(source, "#define MACRO_0 duplicate").unwrap();
        source.push_str("void overloaded(int value);\nvoid overloaded(double value);\n");

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let file = ProjectFile::new(std::env::temp_dir(), "dedup.cpp");

        start_declaration_identity_comparison_probe();
        let parsed = CppAdapter.parse_file(&file, &source, &tree);
        let comparisons = finish_declaration_identity_comparison_probe();

        assert_eq!(
            DISTINCT_PER_KIND,
            parsed
                .declarations()
                .iter()
                .filter(|unit| unit.is_class() && unit.short_name().starts_with("Alias"))
                .count(),
            "typedef aliases should retain semantic-identity deduplication"
        );
        assert_eq!(
            DISTINCT_PER_KIND,
            parsed
                .declarations()
                .iter()
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Macro && unit.short_name().starts_with("MACRO_")
                })
                .count(),
            "macros should retain semantic-identity deduplication"
        );
        assert_eq!(
            2,
            parsed
                .declarations()
                .iter()
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Function && unit.short_name() == "overloaded"
                })
                .count(),
            "function overloads must remain distinct"
        );

        let dedup_inputs = DISTINCT_PER_KIND * 2 + 2;
        assert!(
            comparisons <= dedup_inputs * 4,
            "semantic-identity dedup should perform O(inputs) comparisons; got {comparisons} comparisons for {dedup_inputs} alias/macro inputs"
        );
    }
}
