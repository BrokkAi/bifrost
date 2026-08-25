use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentId, SegmentKind, joined_segments, normalize_joined, segment_interner,
};
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, ParameterMetadata, Range, SignatureMetadata, StructuredTypeIdentity,
    StructuredTypeIdentityBuilder, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use tree_sitter::{Node, Point, Tree};

use crate::aliases::{php_file_context_from_tree_at, resolve_php_type_node};

/// Intern one qualified-name segment in the process-global interner.
fn php_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// PHP's `\`-separated namespace path is stored `.`-joined in `package_name`.
const PHP_PACKAGE_SEPARATOR: &str = ".";

/// Build the structured namespace prefix for a PHP declaration.
///
/// `determine_php_package_name` (below) already turns the namespace's `\`-
/// separated AST text into a `.`-joined string (`replace('\\', ".")`) before it
/// ever becomes `package_name`. Each component becomes one
/// [`SegmentKind::Package`] segment: `Package`-`Package` renders with `.` by
/// default, matching this convention exactly (unlike Go's `/`-joined import
/// path, which needs the `Path` kind).
///
/// [`joined_segments`] is the split half of the shared empty-component
/// decision; `php_namespace_package_name` applies [`normalize_joined`], its
/// join half, to the string it stores. Making one decision in one place is what
/// keeps the two spellings from disagreeing when malformed source puts a
/// literal `.` where a PHP identifier cannot have one (#2352).
fn php_package_fq(package_name: &str) -> FqName {
    let mut fq = FqName::new();
    for component in joined_segments(package_name, PHP_PACKAGE_SEPARATOR) {
        fq.push(php_segment(component, SegmentKind::Package));
    }
    fq
}

pub fn parse_php_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let package_name = determine_php_package_name(tree.root_node(), source);
    let mut parsed = ParsedFile::new(package_name);
    let package_name = parsed.package_name.clone();
    let mut visitor = PhpVisitor {
        file,
        source,
        parsed: &mut parsed,
    };
    visitor.visit_children(tree.root_node(), &PhpScope::new(package_name, None));
    parsed
}

#[derive(Clone)]
struct PhpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

impl PhpScope {
    fn new(package_name: String, class_unit: Option<CodeUnit>) -> Self {
        Self {
            package_name,
            class_unit,
        }
    }
}

struct PhpContainer<'tree> {
    node: Node<'tree>,
    scope: PhpScope,
}

struct PhpNodeWork<'tree> {
    node: Node<'tree>,
    scope: PhpScope,
}

enum PhpWork<'tree> {
    Container(PhpContainer<'tree>),
    Node(PhpNodeWork<'tree>),
}

fn push_php_child_work<'tree>(node: Node<'tree>, scope: PhpScope, stack: &mut Vec<PhpWork<'tree>>) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(PhpWork::Node(PhpNodeWork {
                node: child,
                scope: scope.clone(),
            }));
        }
    }
}

struct PhpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut ParsedFile,
}

impl<'a> PhpVisitor<'a> {
    fn visit_children(&mut self, node: Node<'_>, scope: &PhpScope) {
        let mut stack = vec![PhpWork::Container(PhpContainer {
            node,
            scope: PhpScope::new(scope.package_name.clone(), scope.class_unit.clone()),
        })];
        while let Some(work) = stack.pop() {
            match work {
                PhpWork::Container(container) => {
                    push_php_child_work(container.node, container.scope, &mut stack);
                }
                PhpWork::Node(work) => {
                    self.visit_node(work.node, &work.scope, &mut stack);
                }
            }
        }
    }

    fn visit_node<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        match node.kind() {
            "namespace_definition" => self.visit_namespace(node, scope, stack),
            "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "enum_declaration" => self.visit_type_declaration(node, scope, stack),
            "function_definition" => self.visit_function(node, scope),
            "method_declaration" => self.visit_method(node, scope),
            "property_declaration" => self.visit_property_declaration(node, scope),
            "const_declaration" => self.visit_const_declaration(node, scope),
            "enum_case" => self.visit_enum_case(node, scope),
            "declaration_list" | "compound_statement" => {
                stack.push(PhpWork::Container(PhpContainer {
                    node,
                    scope: PhpScope::new(scope.package_name.clone(), scope.class_unit.clone()),
                }))
            }
            "anonymous_function" | "arrow_function" => {}
            _ if scope.class_unit.is_none() && node.named_child_count() > 0 => {
                stack.push(PhpWork::Container(PhpContainer {
                    node,
                    scope: PhpScope::new(scope.package_name.clone(), None),
                }))
            }
            _ => {}
        }
    }

    fn visit_namespace<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let package_name = php_namespace_package_name(name_node, self.source);
        let scope = PhpScope::new(package_name, scope.class_unit.clone());
        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if !matches!(child.kind(), "namespace_name" | "name") {
                stack.push(PhpWork::Node(PhpNodeWork {
                    node: child,
                    scope: scope.clone(),
                }));
            }
        }
    }

    fn visit_type_declaration<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &PhpScope,
        stack: &mut Vec<PhpWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name.clone()
        };
        // A nested type (class/interface/trait/enum inside another type) is
        // always `$`-joined in the legacy convention above; `Nested` is the tag whose
        // join IS a literal `$` regardless of the previous segment's kind. A top-level type has no parent and is a
        // plain `Type` hanging off the namespace `Package` chain.
        let fq = match &scope.class_unit {
            Some(parent) => parent
                .fq()
                .clone()
                .with_pushed(php_segment(&name, SegmentKind::Nested)),
            None => php_package_fq(&scope.package_name)
                .with_pushed(php_segment(&name, SegmentKind::Type)),
        };
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed
            .add_signature(code_unit.clone(), php_type_signature(node, self.source));
        self.parsed
            .set_raw_supertypes(code_unit.clone(), extract_php_supertypes(node, self.source));

        if let Some(body) = php_class_body(node) {
            stack.push(PhpWork::Container(PhpContainer {
                node: body,
                scope: PhpScope::new(scope.package_name.clone(), Some(code_unit)),
            }));
        }
    }

    fn visit_function(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}.{}", parent.short_name(), name)
        } else {
            name.clone()
        };
        let fq = match &scope.class_unit {
            Some(parent) => parent
                .fq()
                .clone()
                .with_pushed(php_segment(&name, SegmentKind::Member)),
            None => php_package_fq(&scope.package_name)
                .with_pushed(php_segment(&name, SegmentKind::Member)),
        };
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            short_name,
            fq,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        let signature = php_function_signature(node, self.source);
        self.parsed.add_signature_with_metadata(
            code_unit,
            php_signature_metadata(signature, node, self.source),
        );
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &PhpScope) {
        self.visit_function(node, scope);
        self.visit_promoted_parameters(node, scope);
    }

    fn visit_property_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let modifiers = php_property_prefix(node, self.source);
        let type_prefix = node
            .child_by_field_name("type")
            .map(|type_node| format!("{} ", php_node_text(type_node, self.source).trim()))
            .unwrap_or_default();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "property_element" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let raw_name = php_node_text(name_node, self.source).trim().to_string();
            if raw_name.is_empty() {
                continue;
            }
            let stripped_name = raw_name.trim_start_matches('$');
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), stripped_name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(php_segment(stripped_name, SegmentKind::Member)),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = child
                .child_by_field_name("default_value")
                .filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{modifiers}{type_prefix}{raw_name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{modifiers}{type_prefix}{raw_name};")
            };
            self.parsed.add_signature_with_metadata(
                code_unit,
                SignatureMetadata::new(signature, Vec::new())
                    .with_return_type_text(php_declared_type_text(node, self.source))
                    .with_return_type_identity(php_declared_type_identity(node, self.source)),
            );
        }
    }

    fn visit_const_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let prefix = php_const_prefix(node, self.source);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "const_element" {
                continue;
            }
            let Some(name_node) = php_find_named_descendant(child, "name") else {
                continue;
            };
            let name = php_node_text(name_node, self.source).trim().to_string();
            if name.is_empty() {
                continue;
            }
            let short_name = if let Some(parent) = &scope.class_unit {
                format!("{}.{}", parent.short_name(), name)
            } else {
                format!("_module_.{name}")
            };
            // Mirrors `short_name`: a class constant extends its owning type's
            // `fq`; a free (module-level) constant gets the same synthetic
            // `_module_` scope marker Go uses for package-level `var`/`const`
            // (see `GO_MODULE_SCOPE_SEGMENT` in `src/analyzer/go/mod.rs` and the
            // matching Decision Log entry) — a `Package` segment, since it is a
            // module-scope marker rather than a real type or member.
            let fq = match &scope.class_unit {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(php_segment(&name, SegmentKind::Member)),
                None => php_package_fq(&scope.package_name)
                    .with_pushed(php_segment("_module_", SegmentKind::Package))
                    .with_pushed(php_segment(&name, SegmentKind::Member)),
            };
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                short_name,
                fq,
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                scope.class_unit.clone(),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = php_const_value(child).filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{prefix}{name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{prefix}{name};")
            };
            self.parsed.add_signature(code_unit, signature);
        }
    }

    fn visit_enum_case(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            parent
                .fq()
                .clone()
                .with_pushed(php_segment(&name, SegmentKind::Member)),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed.add_signature(
            code_unit,
            normalize_php_snippet(&php_node_text(node, self.source)),
        );
    }

    fn visit_promoted_parameters(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(parameters) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            if parameter.kind() != "property_promotion_parameter" {
                continue;
            }
            let Some(name_node) = parameter.child_by_field_name("name") else {
                continue;
            };
            let raw_name = php_node_text(name_node, self.source).trim().to_string();
            if raw_name.is_empty() {
                continue;
            }
            let stripped_name = raw_name.trim_start_matches('$');
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), stripped_name),
                parent
                    .fq()
                    .clone()
                    .with_pushed(php_segment(stripped_name, SegmentKind::Member)),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                parameter,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(parameter, self.source));
            let signature = format!(
                "{};",
                normalize_php_snippet(&php_node_text(parameter, self.source)).trim_end_matches(',')
            );
            self.parsed.add_signature_with_metadata(
                code_unit,
                SignatureMetadata::new(signature, Vec::new())
                    .with_return_type_text(php_declared_type_text(parameter, self.source))
                    .with_return_type_identity(php_declared_type_identity(parameter, self.source)),
            );
        }
    }
}

fn determine_php_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            return php_namespace_package_name(name_node, source);
        }
    }
    String::new()
}

/// The `.`-joined package path a `namespace_definition` declares. A leading
/// `\` in the name text is tree-sitter recovering a namespace-RELATIVE name
/// reference (`namespace\Foo::CLASS;`) as a namespace definition: the marker
/// is an anonymous child token of the name node, so drop that token's range
/// rather than stripping text. Keeping it turned the package into `.Foo`
/// while the FqName bridge drops empty components, desyncing the
/// package/short boundary assert for every unit in the file (phan's
/// tests/files/src/0019_noop.php, #2413).
///
/// The `\` -> `.` mapping then goes through [`normalize_joined`], the same
/// decision about empty components that [`php_package_fq`] makes when it splits
/// this string back apart. A PHP identifier cannot contain a literal `.`, so a
/// well-formed namespace passes through untouched; malformed source can put one
/// there anyway. PHP_CodeSniffer's `namespace MyStandard\.hidden;` fixture --
/// which documents its own parse error -- mapped to `MyStandard..hidden`, whose
/// empty middle component the fq dropped and the stored package kept (#2352).
fn php_namespace_package_name(name_node: Node<'_>, source: &str) -> String {
    let start = name_node
        .child(0)
        .filter(|child| !child.is_named() && child.kind() == "\\")
        .map_or(name_node.start_byte(), |marker| marker.end_byte());
    let dotted = source
        .get(start..name_node.end_byte())
        .expect("namespace name node covers one source range")
        .replace('\\', PHP_PACKAGE_SEPARATOR);
    normalize_joined(&dotted, PHP_PACKAGE_SEPARATOR).into_owned()
}

fn php_class_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
    })
}

fn php_type_signature(node: Node<'_>, source: &str) -> String {
    let declaration_text = php_raw_text_with_attributes(node, source);
    let trimmed = normalize_php_snippet(&declaration_text);
    let Some((head, _)) = trimmed.split_once('{') else {
        return trimmed.to_string();
    };
    format!("{} {{", head.trim_end())
}

fn extract_php_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "base_clause" | "class_interface_clause") {
            collect_php_supertype_nodes(child, source, &mut raw);
        }
    }
    if node.kind() == "class_declaration"
        && let Some(body) = php_class_body(node)
    {
        let mut body_cursor = body.walk();
        for child in body.named_children(&mut body_cursor) {
            if child.kind() == "use_declaration" {
                collect_php_supertype_nodes(child, source, &mut raw);
            }
        }
    }
    raw
}

fn collect_php_supertype_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "name" | "namespace_name" | "qualified_name" | "fully_qualified_name"
        ) {
            let text = php_node_text(current, source);
            let text = text.trim();
            if !text.is_empty() {
                raw.push(text.to_string());
            }
            continue;
        }

        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn php_function_signature(node: Node<'_>, source: &str) -> String {
    let declaration_range = php_declaration_range(node, source);
    if let Some(body) = node.child_by_field_name("body") {
        let header =
            normalize_php_snippet(&source[declaration_range.start_byte..body.start_byte()]);
        format!("{header} {{ ... }}")
    } else {
        php_text_with_attributes(node, source).trim().to_string()
    }
}

fn php_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameter_text = normalize_php_snippet(&php_node_text(parameters_node, source));
    let Some(parameters_start) = signature.find(&parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new());
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = php_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = normalize_php_snippet(&php_node_text(label_node, source));
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
        .with_return_type_text(php_declared_type_text(node, source))
        .with_return_type_identity(php_declared_type_identity(node, source))
}

fn php_declared_type_text(node: Node<'_>, source: &str) -> Option<String> {
    php_declared_type_node(node)
        .map(|type_node| php_node_text(type_node, source).trim().to_string())
        .filter(|text| !text.is_empty())
}

/// Persist the one nominal PHP type named by this declaration as a canonical,
/// absolute component path. Alias and namespace resolution happen while the
/// parser tree is present, so readers of this nominal case never reconstruct
/// PHP type syntax from signature text.
fn php_declared_type_identity(node: Node<'_>, source: &str) -> Option<StructuredTypeIdentity> {
    let type_node = php_declared_type_node(node)?;
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let context = php_file_context_from_tree_at(root, source, node.start_byte(), || true)?;
    let resolved = resolve_php_type_node(type_node, source, &context, || true)?;
    let path = joined_segments(&resolved, PHP_PACKAGE_SEPARATOR)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let name = StructuredTypeName::new(path, Vec::new(), true)?;
    let mut builder = StructuredTypeIdentityBuilder::default();
    let root = builder.named(name)?;
    builder.finish(root)
}

pub fn php_declared_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let field_name = match node.kind() {
        "function_definition" | "method_declaration" => "return_type",
        "property_declaration" | "property_promotion_parameter" => "type",
        _ => return None,
    };
    node.child_by_field_name(field_name)
}

fn php_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "simple_parameter"
                | "optional_parameter"
                | "variadic_parameter"
                | "property_promotion_parameter"
        ) && let Some(name_node) = child.child_by_field_name("name")
        {
            labels.push(name_node);
        }
    }
    labels
}

fn php_property_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    }
}

fn php_const_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    parts.push("const".to_string());
    format!("{} ", parts.join(" "))
}

fn php_attribute_lines(node: Node<'_>, source: &str) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        attributes.push(php_node_text(prev, source).trim().to_string());
        current = prev;
    }
    attributes.reverse();
    attributes
}

fn php_text_with_attributes(node: Node<'_>, source: &str) -> String {
    normalize_php_snippet(&php_raw_text_with_attributes(node, source))
}

fn php_raw_text_with_attributes(node: Node<'_>, source: &str) -> String {
    let range = php_declaration_range(node, source);
    source[range.start_byte..range.end_byte].to_string()
}

fn php_declaration_range(node: Node<'_>, source: &str) -> Range {
    let mut start_byte = node.start_byte();
    let mut start_point = node.start_position();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        start_byte = prev.start_byte();
        start_point = prev.start_position();
        current = prev;
    }
    php_range(
        start_byte,
        start_point,
        node.end_byte(),
        node.end_position(),
    )
}

fn php_is_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer"
            | "float"
            | "string"
            | "encapsed_string"
            | "string_value"
            | "boolean"
            | "boolean_literal"
            | "null"
            | "null_literal"
    )
}

fn php_node_text(node: Node<'_>, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

fn php_const_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("value").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() != "name")
            .find(|child| child.kind() != "comment")
    })
}

fn php_find_named_descendant<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn normalize_php_snippet(snippet: &str) -> String {
    snippet
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn php_range(start_byte: usize, start: Point, end_byte: usize, end: Point) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: start.row + 1,
        end_line: end.row + 1,
    }
}
