use crate::analyzer::model::StructuredTypeIdentityBuilder;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{
    CallableArity, CodeUnit, CodeUnitType, DispatchExtensibility, ParameterMetadata, ProjectFile,
    SignatureMetadata, StructuredTypeIdentity, StructuredTypeName,
    csharp_constant_pattern_type_candidate, csharp_member_access_type_receiver,
    csharp_type_node_identity, csharp_type_reference_root,
};
use crate::hash::HashSet;
use tree_sitter::{Node, Tree};

use super::imports::csharp_import_info_from_using_directive;

pub(super) fn parse_csharp_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
    collect_csharp_type_identifiers(tree.root_node(), source, &mut parsed.type_identifiers);
    let mut visitor = CSharpVisitor {
        file,
        source,
        parsed: &mut parsed,
    };
    visitor.visit_container(tree.root_node(), "", None);
    parsed
}

#[derive(Clone)]
struct CSharpScope {
    package_name: String,
    lexical_scope: Vec<String>,
    class_unit: Option<CodeUnit>,
}

struct CSharpWork<'tree> {
    node: Node<'tree>,
    scope: CSharpScope,
}

struct CSharpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CSharpVisitor<'a> {
    fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        class_unit: Option<CodeUnit>,
    ) {
        let mut stack = Vec::new();
        self.push_children(
            node,
            CSharpScope {
                package_name: package_name.to_string(),
                lexical_scope: Vec::new(),
                class_unit,
            },
            &mut stack,
        );
        while let Some(work) = stack.pop() {
            self.visit_node(work.node, &work.scope, &mut stack);
        }
    }

    fn push_children<'tree>(
        &self,
        node: Node<'tree>,
        scope: CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        // A file-scoped namespace (`namespace X;`) has no body: its type declarations
        // are following SIBLINGS, not children. Apply its namespace to everything after
        // it so their package_name is populated. Block namespaces keep a body and flow
        // through `queue_namespace`.
        let mut current = scope;
        let mut scoped: Vec<(Node<'tree>, CSharpScope)> = Vec::with_capacity(children.len());
        for child in children {
            if child.kind() == "file_scoped_namespace_declaration" {
                if let Some(namespace_path) = self.namespace_scope_path(child) {
                    let package_name =
                        csharp_join_namespace(&current.package_name, &namespace_path);
                    let mut lexical_scope = current.lexical_scope.clone();
                    lexical_scope.extend(namespace_path);
                    current = CSharpScope {
                        package_name,
                        lexical_scope,
                        class_unit: current.class_unit.clone(),
                    };
                }
                continue;
            }
            scoped.push((child, current.clone()));
        }
        for (child, child_scope) in scoped.into_iter().rev() {
            stack.push(CSharpWork {
                node: child,
                scope: child_scope,
            });
        }
    }

    fn namespace_scope_path(&self, node: Node<'_>) -> Option<Vec<String>> {
        let name_node = node.child_by_field_name("name")?;
        csharp_namespace_path(name_node, self.source)
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        match node.kind() {
            // Block namespaces only; file-scoped namespaces are handled in push_children
            // (their types are following siblings, not body children).
            "namespace_declaration" => self.queue_namespace(node, scope, stack),
            "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "record_struct_declaration" => self.visit_type_declaration(node, scope, stack),
            "method_declaration" => self.visit_method(node, scope),
            "constructor_declaration" => self.visit_constructor(node, scope),
            "property_declaration" => self.visit_property(node, scope),
            "field_declaration" => self.visit_field_declaration(node, scope),
            "enum_member_declaration" => self.visit_enum_member(node, scope),
            "using_directive" => self.visit_using_directive(node),
            _ => {}
        }
    }

    fn visit_using_directive(&mut self, node: Node<'_>) {
        let raw = cs_node_text(node, self.source).trim().to_string();
        if raw.is_empty() {
            return;
        }
        self.parsed.import_statements.push(raw.clone());
        if let Some(info) = csharp_import_info_from_using_directive(node, self.source, raw) {
            self.parsed.imports.push(info);
        }
    }

    fn queue_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some(namespace_path) = self.namespace_scope_path(node) else {
            return;
        };
        let package_name = csharp_join_namespace(&scope.package_name, &namespace_path);
        let mut lexical_scope = scope.lexical_scope.clone();
        lexical_scope.extend(namespace_path);
        if let Some(body) = cs_namespace_body(node) {
            self.push_children(
                body,
                CSharpScope {
                    package_name,
                    lexical_scope,
                    class_unit: scope.class_unit.clone(),
                },
                stack,
            );
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &CSharpScope,
        stack: &mut Vec<CSharpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let arity = node
            .child_by_field_name("type_parameters")
            .or_else(|| first_named_child_of_kind(node, "type_parameter_list"))
            .map_or(0, count_type_parameters);
        let identity_name = if arity == 0 {
            name.to_string()
        } else {
            format!("{name}`{arity}")
        };
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${identity_name}", parent.short_name())
        } else {
            identity_name.clone()
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed.add_raw_supertypes(
            code_unit.clone(),
            extract_csharp_supertypes(node, self.source),
        );
        self.parsed.add_signature_with_metadata(
            code_unit.clone(),
            SignatureMetadata::new(csharp_type_signature(node, self.source), Vec::new())
                .with_type_parameters(csharp_declaration_type_parameters(node, self.source)),
        );

        if let Some(body) = cs_type_body(node) {
            let mut lexical_scope = scope.lexical_scope.clone();
            lexical_scope.push(identity_name);
            self.push_children(
                body,
                CSharpScope {
                    package_name: scope.package_name.clone(),
                    lexical_scope,
                    class_unit: Some(code_unit),
                },
                stack,
            );
        }
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let signature_key = csharp_method_signature_key(node, self.source);
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(signature_key),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_method_skeleton(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            csharp_signature_metadata(signature, node, self.source, &scope.lexical_scope),
        );
    }

    fn visit_constructor(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(csharp_parameter_key(node, self.source)),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_constructor_skeleton(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            csharp_signature_metadata(signature, node, self.source, &scope.lexical_scope),
        );
    }

    fn visit_property(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = csharp_property_signature(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            csharp_dispatch_signature_metadata(signature, node, self.source, &scope.lexical_scope),
        );
    }

    fn visit_field_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(declaration) = node
            .child_by_field_name("declaration")
            .or_else(|| first_named_child_of_kind(node, "variable_declaration"))
        else {
            return;
        };

        let prefix = csharp_field_prefix(node, declaration, self.source);
        let type_node = declaration.child_by_field_name("type");
        let type_text = type_node
            .map(|child| normalize_cs_whitespace(cs_node_text(child, self.source)))
            .unwrap_or_default();
        let return_type_identity = type_node.and_then(|type_node| {
            csharp_structured_type_identity(type_node, self.source, &scope.lexical_scope)
        });
        let declaration_text = normalize_cs_whitespace(cs_node_text(node, self.source));

        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = cs_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                self.source,
                Some(parent.clone()),
                None,
            );
            let signature =
                csharp_field_signature(&prefix, &type_text, &declaration_text, child, self.source);
            self.parsed.add_signature_with_metadata(
                code_unit,
                SignatureMetadata::new(signature, Vec::new())
                    .with_return_type_text((!type_text.is_empty()).then(|| type_text.clone()))
                    .with_return_type_identity(return_type_identity.clone())
                    .with_dispatch_extensibility(DispatchExtensibility::Closed),
            );
        }
    }

    fn visit_enum_member(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        let signature = normalize_cs_whitespace(cs_node_text(node, self.source));
        self.parsed.add_signature_with_metadata(
            code_unit,
            SignatureMetadata::new(signature, Vec::new())
                .with_dispatch_extensibility(DispatchExtensibility::Closed),
        );
    }
}

fn count_type_parameters(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter")
        .count()
}

fn collect_csharp_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "attribute"
            && let Some(name) = node.child_by_field_name("name")
        {
            identifiers.extend(super::csharp_attribute_type_names(name, source));
        }
        if let Some(root) = csharp_type_reference_root(node) {
            let text = csharp_type_node_identity(root, source);
            if !text.is_empty() {
                identifiers.insert(text);
            }
        }
        if let Some(candidate) = csharp_constant_pattern_type_candidate(node) {
            let text = csharp_type_node_identity(candidate, source);
            if !text.is_empty() {
                identifiers.insert(text);
            }
        }
        if let Some(receiver) = csharp_member_access_type_receiver(node) {
            let text = csharp_type_node_identity(receiver, source);
            if !text.is_empty() {
                identifiers.insert(text);
            }
        }
        WalkControl::Continue
    });
}

fn cs_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

fn normalize_cs_whitespace(value: &str) -> String {
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

fn cs_namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| last_named_child(node))
}

fn cs_type_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| first_named_child_of_kind(node, "declaration_list"))
}

fn csharp_type_signature(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{head} {{")
}

fn extract_csharp_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(base_list) = first_named_child_of_kind(node, "base_list") else {
        return Vec::new();
    };
    let mut supertypes = Vec::new();
    let mut cursor = base_list.walk();
    for child in base_list.named_children(&mut cursor) {
        let text = super::csharp_type_node_identity(child, source);
        if !text.is_empty() {
            supertypes.push(text);
        }
    }
    supertypes
}

fn csharp_method_skeleton(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{} {{ … }}", head.trim_end_matches(';').trim())
}

fn csharp_method_signature_key(node: Node<'_>, source: &str) -> String {
    let parameters = csharp_parameter_key(node, source);
    let generic_arity = node
        .child_by_field_name("type_parameters")
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "type_parameter_list")
        })
        .map_or(0, |type_parameters| type_parameters.named_child_count());
    if generic_arity == 0 {
        parameters
    } else {
        format!("`{generic_arity}{parameters}")
    }
}

fn csharp_constructor_skeleton(node: Node<'_>, source: &str) -> String {
    csharp_method_skeleton(node, source)
}

fn csharp_dispatch_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> SignatureMetadata {
    let return_type = csharp_declared_type_node(node);
    SignatureMetadata::new(signature, Vec::new())
        .with_return_type_text(
            return_type
                .map(|return_type| csharp_type_node_identity(return_type, source))
                .filter(|return_type| !return_type.is_empty()),
        )
        .with_return_type_identity(return_type.and_then(|return_type| {
            csharp_structured_type_identity(return_type, source, lexical_scope)
        }))
        .with_dispatch_extensibility(super::csharp_callable_dispatch_extensibility(
            source,
            node,
            super::csharp_has_modifier(source, node, "static"),
        ))
}

fn csharp_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> SignatureMetadata {
    let callable_arity = csharp_callable_arity(node);
    let type_parameters = csharp_method_type_parameters(node, source);
    let return_type = csharp_declared_type_node(node);
    let return_type_text = return_type
        .map(|return_type| csharp_type_node_identity(return_type, source))
        .filter(|return_type| !return_type.is_empty());
    let return_type_identity = return_type.and_then(|return_type| {
        csharp_structured_type_identity(return_type, source, lexical_scope)
    });
    let bare_return_type_parameter =
        csharp_bare_return_type_parameter(node, source, &type_parameters);
    let extension_receiver_type_node = csharp_extension_receiver_type_node(node, source);
    let extension_receiver_type = extension_receiver_type_node
        .map(|type_node| csharp_type_node_identity(type_node, source))
        .filter(|receiver_type| !receiver_type.is_empty());
    let extension_receiver_type_identity = extension_receiver_type_node
        .and_then(|type_node| csharp_structured_type_identity(type_node, source, lexical_scope));
    let extension_receiver_is_unconstrained_type_parameter = extension_receiver_type_node
        .is_some_and(|type_node| {
            let receiver = cs_node_text(type_node, source).trim();
            type_node.kind() == "identifier"
                && type_parameters
                    .iter()
                    .any(|parameter| parameter == receiver)
                && !csharp_method_type_parameter_has_constraints(node, source, receiver)
        });
    let parameter_text = csharp_rendered_parameter_text(node, source);
    let metadata = if let Some(parameters_start) = signature.find(&parameter_text) {
        let parameters_end = parameters_start + parameter_text.len();
        let mut search_start = parameters_start;
        let parameters = csharp_parameter_label_nodes(node)
            .into_iter()
            .filter_map(|label_node| {
                let label = normalize_cs_whitespace(cs_node_text(label_node, source));
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
            .with_type_parameters(type_parameters)
            .with_return_type_text(return_type_text)
            .with_return_type_identity(return_type_identity)
            .with_bare_return_type_parameter(bare_return_type_parameter)
            .with_extension_receiver_type(extension_receiver_type)
            .with_extension_receiver_type_identity(extension_receiver_type_identity)
            .with_extension_receiver_is_unconstrained_type_parameter(
                extension_receiver_is_unconstrained_type_parameter,
            )
    } else {
        SignatureMetadata::new(signature, Vec::new())
            .with_callable_arity(callable_arity)
            .with_type_parameters(type_parameters)
            .with_return_type_text(return_type_text)
            .with_return_type_identity(return_type_identity)
            .with_bare_return_type_parameter(bare_return_type_parameter)
            .with_extension_receiver_type(extension_receiver_type)
            .with_extension_receiver_type_identity(extension_receiver_type_identity)
            .with_extension_receiver_is_unconstrained_type_parameter(
                extension_receiver_is_unconstrained_type_parameter,
            )
    };
    metadata.with_dispatch_extensibility(super::csharp_callable_dispatch_extensibility(
        source,
        node,
        super::csharp_has_modifier(source, node, "static"),
    ))
}

fn csharp_extension_receiver_type_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut parameters_cursor = parameters.walk();
    let first_parameter = parameters
        .named_children(&mut parameters_cursor)
        .find(|child| child.kind() == "parameter")?;
    let mut parameter_cursor = first_parameter.walk();
    let has_this_modifier = first_parameter
        .named_children(&mut parameter_cursor)
        .any(|child| child.kind() == "modifier" && cs_node_text(child, source) == "this");
    if !has_this_modifier {
        return None;
    }
    first_parameter.child_by_field_name("type")
}

fn csharp_declared_type_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("returns")
        .or_else(|| node.child_by_field_name("return_type"))
        .or_else(|| node.child_by_field_name("type"))
}

fn csharp_bare_return_type_parameter(
    node: Node<'_>,
    source: &str,
    type_parameters: &[String],
) -> Option<String> {
    let return_type = node
        .child_by_field_name("returns")
        .or_else(|| node.child_by_field_name("return_type"))?;
    if return_type.kind() != "identifier" {
        return None;
    }
    let return_type = source
        .get(return_type.start_byte()..return_type.end_byte())
        .map(str::trim)
        .filter(|return_type| !return_type.is_empty())?;
    type_parameters
        .iter()
        .any(|parameter| parameter == return_type)
        .then(|| return_type.to_string())
}

fn csharp_method_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(type_parameters) = node.child_by_field_name("type_parameters").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "type_parameter_list")
    }) else {
        return Vec::new();
    };
    let mut cursor = type_parameters.walk();
    type_parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| {
            let name = parameter
                .child_by_field_name("name")
                .or_else(|| parameter.named_child(0))
                .unwrap_or(parameter);
            let text = cs_node_text(name, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        })
        .collect()
}

fn csharp_method_type_parameter_has_constraints(
    node: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter_constraints_clause")
        .any(|clause| {
            let mut clause_cursor = clause.walk();
            clause.named_children(&mut clause_cursor).any(|child| {
                child.kind() == "identifier" && cs_node_text(child, source).trim() == parameter_name
            })
        })
}

fn csharp_declaration_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    csharp_method_type_parameters(node, source)
}

enum CSharpStructuredTypeFrame<'tree> {
    Visit(Node<'tree>),
    WrapReference,
    WrapPointer,
    WrapArray,
    BuildGeneric { argument_count: usize },
}

/// Persist the parser-proven shape of a C# declared type. The arena builder and
/// explicit frame stack keep indexing safe even for adversarially deep type
/// syntax, while the lexical scope preserves the exact nested lookup context
/// needed by bounded consumers.
fn csharp_structured_type_identity(
    node: Node<'_>,
    source: &str,
    lexical_scope: &[String],
) -> Option<StructuredTypeIdentity> {
    let mut frames = vec![CSharpStructuredTypeFrame::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();

    while let Some(frame) = frames.pop() {
        match frame {
            CSharpStructuredTypeFrame::Visit(node) => match node.kind() {
                "type" | "simple_base_type" | "primary_constructor_base_type" => {
                    frames.push(CSharpStructuredTypeFrame::Visit(csharp_type_wrapper_child(
                        node,
                    )?));
                }
                // Nullable reference types retain the same nominal declaration.
                // Value-type nullable members are library-supplied and therefore
                // do not publish a workspace member target through this path.
                "nullable_type" => {
                    frames.push(CSharpStructuredTypeFrame::Visit(csharp_type_wrapper_child(
                        node,
                    )?));
                }
                "ref_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapReference);
                    frames.push(CSharpStructuredTypeFrame::Visit(csharp_type_wrapper_child(
                        node,
                    )?));
                }
                "pointer_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapPointer);
                    frames.push(CSharpStructuredTypeFrame::Visit(csharp_type_wrapper_child(
                        node,
                    )?));
                }
                "array_type" => {
                    frames.push(CSharpStructuredTypeFrame::WrapArray);
                    frames.push(CSharpStructuredTypeFrame::Visit(csharp_type_wrapper_child(
                        node,
                    )?));
                }
                "identifier"
                | "predefined_type"
                | "qualified_name"
                | "alias_qualified_name"
                | "generic_name" => {
                    let (name, arguments) =
                        csharp_structured_named_type(node, source, lexical_scope)?;
                    values.push(builder.named(name)?);
                    if !arguments.is_empty() {
                        frames.push(CSharpStructuredTypeFrame::BuildGeneric {
                            argument_count: arguments.len(),
                        });
                        frames.extend(
                            arguments
                                .into_iter()
                                .rev()
                                .map(CSharpStructuredTypeFrame::Visit),
                        );
                    }
                }
                _ => return None,
            },
            CSharpStructuredTypeFrame::WrapReference => {
                let inner = values.pop()?;
                values.push(builder.reference(inner)?);
            }
            CSharpStructuredTypeFrame::WrapPointer => {
                let inner = values.pop()?;
                values.push(builder.pointer(inner)?);
            }
            CSharpStructuredTypeFrame::WrapArray => {
                let inner = values.pop()?;
                values.push(builder.array(inner)?);
            }
            CSharpStructuredTypeFrame::BuildGeneric { argument_count } => {
                let value_count = argument_count.checked_add(1)?;
                let start = values.len().checked_sub(value_count)?;
                let mut built = values.split_off(start);
                let base = built.remove(0);
                values.push(builder.generic(base, built)?);
            }
        }
    }

    (values.len() == 1)
        .then(|| values.pop())
        .flatten()
        .and_then(|root| builder.finish(root))
}

fn csharp_structured_named_type<'tree>(
    node: Node<'tree>,
    source: &str,
    lexical_scope: &[String],
) -> Option<(StructuredTypeName, Vec<Node<'tree>>)> {
    let mut path = Vec::new();
    let mut arguments = Vec::new();
    let mut absolute = false;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "predefined_type" => {
                path.push(csharp_identifier_text(current, source)?);
            }
            "generic_name" => {
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(0))?;
                let type_arguments = current
                    .child_by_field_name("type_arguments")
                    .or_else(|| first_named_child_of_kind(current, "type_argument_list"))?;
                let mut cursor = type_arguments.walk();
                let generic_arguments = type_arguments
                    .named_children(&mut cursor)
                    .collect::<Vec<_>>();
                let name = csharp_identifier_text(name, source)?;
                path.push(format!("{name}`{}", generic_arguments.len()));
                arguments.extend(generic_arguments);
            }
            "qualified_name" => {
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                stack.push(name);
                stack.push(qualifier);
            }
            "alias_qualified_name" => {
                let alias = current
                    .child_by_field_name("alias")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                let alias = csharp_identifier_text(alias, source)?;
                if alias == "global" {
                    absolute = true;
                } else {
                    path.push(alias);
                }
                stack.push(name);
            }
            _ => return None,
        }
    }
    let name = StructuredTypeName::new(path, lexical_scope.to_vec(), absolute)?;
    Some((name, arguments))
}

fn csharp_type_wrapper_child(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })
}

fn csharp_identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = cs_node_text(node, source).trim();
    let text = text.strip_prefix('@').unwrap_or(text);
    (!text.is_empty()).then(|| text.to_string())
}

fn csharp_namespace_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" => path.push(csharp_identifier_text(current, source)?),
            "qualified_name" => {
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.named_child(0))?;
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
                stack.push(name);
                stack.push(qualifier);
            }
            _ => return None,
        }
    }
    (!path.is_empty()).then_some(path)
}

fn csharp_join_namespace(prefix: &str, path: &[String]) -> String {
    if prefix.is_empty() {
        path.join(".")
    } else if path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}.{}", path.join("."))
    }
}

fn csharp_callable_arity(node: Node<'_>) -> CallableArity {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return CallableArity::exact(0);
    };
    let mut required = 0usize;
    let mut total = 0usize;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if parameter.kind() != "parameter" {
            continue;
        }
        total += 1;
        let mut parameter_cursor = parameter.walk();
        let optional = parameter
            .children(&mut parameter_cursor)
            .any(|child| child.kind() == "=");
        if !optional {
            required += 1;
        }
    }
    let repeated = csharp_parameter_list_has_params(parameters);
    if repeated {
        total += 1;
    }
    CallableArity::new(required, total, repeated)
}

fn csharp_parameter_list_has_params(parameters: Node<'_>) -> bool {
    let mut cursor = parameters.walk();
    parameters
        .children(&mut cursor)
        .any(|child| child.kind() == "params")
}

fn csharp_rendered_parameter_text(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("parameters")
        .map(|parameters| normalize_cs_whitespace(cs_node_text(parameters, source)))
        .unwrap_or_else(|| "()".to_string())
}

fn csharp_parameter_label_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        if let Some(name) = child.child_by_field_name("name") {
            labels.push(name);
            continue;
        }
        let mut param_cursor = child.walk();
        if let Some(name) = child
            .named_children(&mut param_cursor)
            .find(|candidate| candidate.kind() == "identifier")
        {
            labels.push(name);
        }
    }
    if csharp_parameter_list_has_params(parameters)
        && let Some(name) = parameters.child_by_field_name("name")
    {
        labels.push(name);
    }
    labels
}

fn csharp_property_signature(node: Node<'_>, source: &str) -> String {
    normalize_cs_whitespace(cs_node_text(node, source))
}

fn csharp_parameter_key(node: Node<'_>, source: &str) -> String {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return "()".to_string();
    };
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let part = child
            .child_by_field_name("type")
            .map(|type_node| normalize_cs_whitespace(cs_node_text(type_node, source)))
            .unwrap_or_else(|| normalize_cs_whitespace(cs_node_text(child, source)));
        parts.push(part);
    }
    if csharp_parameter_list_has_params(parameters)
        && let Some(type_node) = parameters.child_by_field_name("type")
    {
        parts.push(normalize_cs_whitespace(cs_node_text(type_node, source)));
    }
    format!("({})", parts.join(", "))
}

fn csharp_field_prefix(field_node: Node<'_>, declaration: Node<'_>, source: &str) -> String {
    let field_text = cs_node_text(field_node, source);
    let end = declaration
        .start_byte()
        .saturating_sub(field_node.start_byte());
    let prefix = field_text.get(..end).unwrap_or(field_text);
    let prefix = normalize_cs_whitespace(prefix);
    regex::Regex::new(r"^(?:\[[^\]]+\]\s*)+")
        .ok()
        .map(|regex| regex.replace(&prefix, "").trim().to_string())
        .unwrap_or(prefix)
}

fn csharp_field_signature(
    prefix: &str,
    type_text: &str,
    declaration_text: &str,
    declarator: Node<'_>,
    source: &str,
) -> String {
    let name = declarator
        .child_by_field_name("name")
        .map(|child| cs_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let initializer = declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .and_then(|value| csharp_literal_initializer(value, source));
    let initializer =
        initializer.or_else(|| csharp_literal_initializer_from_text(declaration_text, &name));

    let base = if prefix.is_empty() {
        format!("{type_text} {name}")
    } else {
        format!("{prefix} {type_text} {name}")
    };
    let base = normalize_cs_whitespace(&base);
    if let Some(initializer) = initializer {
        format!("{base} = {initializer};")
    } else {
        format!("{base};")
    }
}

fn csharp_literal_initializer(node: Node<'_>, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    ) {
        return Some(normalize_cs_whitespace(cs_node_text(node, source)));
    }
    None
}

fn csharp_literal_initializer_from_text(declaration_text: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"\b{}\s*=\s*("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[-+]?\d+(?:\.\d+)?|true|false|null)\s*(?:,|;)"#,
        regex::escape(name)
    );
    regex::Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}
