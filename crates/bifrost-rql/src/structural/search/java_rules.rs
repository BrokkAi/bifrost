// Closed Java structural relations used by the CodeQL parity lane.
//
// These relations select declaration and identifier nodes from the Java AST,
// then join source fields to the shared `SignatureMetadata` rows. Names are
// classified only after the AST has selected a declaration name; no source
// text scan is used to locate syntax.
//
// Javadoc relations parse the selected leading block comment and join its
// structured tag facts to the corresponding Java declaration.

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::query::JavaRule;
use brokk_bifrost_core::analyzer::model::SignatureMetadata;
use brokk_bifrost_core::analyzer::structural::resolution::{
    DeclaredVisibility, MemberFamilyOutcome, MethodFamilyRelation,
};
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
use brokk_bifrost_jvm::java::javadoc::{
    JavadocBlockFacts, JavadocTagKind, parse_block_comment, preceding_javadoc_comment,
};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

use super::field_metadata::{field_sites, FieldSite};
use super::language_rules::LanguageRuleMatches;

const KNOWN_CHECKED_JDK_TYPES: &[&str] = &[
    "ClassNotFoundException",
    "CloneNotSupportedException",
    "DataFormatException",
    "ExecutionException",
    "FileNotFoundException",
    "GeneralSecurityException",
    "IllegalAccessException",
    "InstantiationException",
    "InterruptedException",
    "IOException",
    "InvocationTargetException",
    "MalformedURLException",
    "NoSuchFieldException",
    "NoSuchMethodException",
    "ParseException",
    "ReflectiveOperationException",
    "SQLException",
    "TimeoutException",
    "URISyntaxException",
    "UnsupportedEncodingException",
    "UnknownHostException",
];

const KNOWN_UNCHECKED_TYPES: &[&str] = &[
    "ArithmeticException",
    "ArrayIndexOutOfBoundsException",
    "ArrayStoreException",
    "Error",
    "AssertionError",
    "BootstrapMethodError",
    "ClassCastException",
    "ClassCircularityError",
    "ExceptionInInitializerError",
    "IllegalArgumentException",
    "IllegalMonitorStateException",
    "IllegalStateException",
    "IncompatibleClassChangeError",
    "IndexOutOfBoundsException",
    "InternalError",
    "LinkageError",
    "NoClassDefFoundError",
    "NoSuchFieldError",
    "NoSuchMethodError",
    "NullPointerException",
    "OutOfMemoryError",
    "RuntimeException",
    "SecurityException",
    "StackOverflowError",
    "ThreadDeath",
    "UnknownError",
    "UnsatisfiedLinkError",
    "UnsupportedOperationException",
    "VerifyError",
    "VirtualMachineError",
    "WrongMethodTypeException",
];


/// Return the exact structural spans selected by one closed Java relation.
pub(super) fn matches_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    rule: JavaRule,
) -> LanguageRuleMatches {
    if language_for_file(file) != Language::Java {
        return LanguageRuleMatches::default();
    }
    let Some(tree) = parse_tree_for_language(file, Language::Java, source) else {
        return LanguageRuleMatches::default();
    };
    let fields = field_sites(analyzer, file);
    let mut ranges = match rule {
        JavaRule::NonFinalImmutableField => {
            non_final_immutable_fields(&tree, source, &fields)
        }
        JavaRule::NonPrivateField => non_private_fields(&tree, source, &fields),
        JavaRule::MisnamedConstant => misnamed_constants(&tree, source, &fields),
        JavaRule::MisnamedVariable => misnamed_variables(&tree, source, &fields),
        JavaRule::UnderscoreIdentifier => named_declarations(&tree, source, "_"),
        JavaRule::EnumIdentifier => named_declarations(&tree, source, "enum"),
        JavaRule::ConstructorTypo => constructor_typos(&tree, source),
        JavaRule::RawConstructorInvocation => {
            raw_constructor_invocations(analyzer, file, source, &tree)
        }
        JavaRule::RawReturnType => raw_return_types(analyzer, file, source, &tree),
        JavaRule::RawVariable => raw_variables(analyzer, file, source, &tree),
        JavaRule::TypeBoundExtendsFinal => type_bounds_extending_final(analyzer, file, source, &tree),
        JavaRule::TypeVariableHidesType => type_variables_hiding_types(analyzer, file, source, &tree),
        JavaRule::InconsistentJavadocThrows
        | JavaRule::UnknownJavadocParameter
        | JavaRule::UndocumentedException
        | JavaRule::UndocumentedFunction
        | JavaRule::UndocumentedParameter
        | JavaRule::UndocumentedReturnValue
        | JavaRule::UndocumentedType => javadoc_matches(analyzer, file, source, &tree, rule),
    };
    ranges.sort_unstable();
    ranges.dedup();
    LanguageRuleMatches::from_ranges(ranges)
}

fn javadoc_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    rule: JavaRule,
) -> Vec<Range> {
    let sites = declaration_sites(analyzer, file);
    let source: Arc<str> = Arc::from(source.to_owned());
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        match rule {
            JavaRule::UndocumentedType if is_type_declaration(node) => {
                if undocumented_type(analyzer, &sites, node, &source) {
                    ranges.push(node_range(node));
                }
            }
            JavaRule::UnknownJavadocParameter if is_type_declaration(node) => {
                if unknown_type_parameter_tag(&sites, node, &source) {
                    ranges.push(node_range(node));
                }
            }
            JavaRule::UndocumentedParameter if is_parameter(node) => {
                if undocumented_parameter(analyzer, &sites, node, &source) {
                    ranges.push(node_range(node));
                }
            }
            JavaRule::UnknownJavadocParameter
            | JavaRule::UndocumentedException
            | JavaRule::UndocumentedFunction
            | JavaRule::UndocumentedReturnValue
            | JavaRule::InconsistentJavadocThrows
                if is_callable(node)
                    && callable_rule_matches(analyzer, &sites, node, &source, rule) =>
            {
                ranges.push(node_range(node));
            }
            _ => {}
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

#[derive(Clone)]
struct JavaFieldSite<'tree> {
    name: Node<'tree>,
    owner: Node<'tree>,
    metadata: SignatureMetadata,
    enum_constant: bool,
}
fn java_field_sites<'tree>(
    tree: &'tree Tree,
    metadata_sites: &[FieldSite],
) -> Vec<JavaFieldSite<'tree>> {
    let mut fields = Vec::new();
    for node in descendants(tree.root_node()) {
        match node.kind() {
            "field_declaration" | "constant_declaration" => {
                for declarator in named_children(node)
                    .into_iter()
                    .filter(|child| child.kind() == "variable_declarator")
                {
                    let Some(name) = declarator.child_by_field_name("name") else {
                        continue;
                    };
                    let Some(owner) = enclosing_type(declarator) else {
                        continue;
                    };
                    let Some(metadata) = metadata_for_node(metadata_sites, declarator)
                        .or_else(|| metadata_for_node(metadata_sites, node))
                    else {
                        continue;
                    };
                    fields.push(JavaFieldSite {
                        name,
                        owner,
                        metadata,
                        enum_constant: false,
                    });
                }
            }
            "enum_constant" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                let Some(owner) = enclosing_type(node) else {
                    continue;
                };
                let Some(metadata) = metadata_for_node(metadata_sites, node) else {
                    continue;
                };
                fields.push(JavaFieldSite {
                    name,
                    owner,
                    metadata,
                    enum_constant: true,
                });
            }
            _ => {}
        }
    }
    fields
}

fn metadata_for_node(metadata_sites: &[FieldSite], node: Node<'_>) -> Option<SignatureMetadata> {
    metadata_sites
        .iter()
        .find(|site| {
            site.range.start_byte == node.start_byte() && site.range.end_byte == node.end_byte()
        })
        .map(|site| site.metadata.clone())
}

fn non_final_immutable_fields(
    tree: &Tree,
    source: &str,
    metadata_sites: &[FieldSite],
) -> Vec<Range> {
    java_field_sites(tree, metadata_sites)
        .into_iter()
        .filter(|field| !field.enum_constant)
        .filter(|field| !field.metadata.field_is_final())
        .filter(|field| is_immutable_type(&field.metadata))
        .filter(|field| writes_are_initialization_only(field, tree.root_node(), source))
        .map(|field| node_range(field.name))
        .collect()
}

fn non_private_fields(
    tree: &Tree,
    source: &str,
    metadata_sites: &[FieldSite],
) -> Vec<Range> {
    java_field_sites(tree, metadata_sites)
        .into_iter()
        .filter(|field| !field.enum_constant)
        .filter(|field| {
            field.metadata.callable_declared_visibility() != Some(DeclaredVisibility::Private)
        })
        .filter(|field| {
            !(field.metadata.field_is_static() && field.metadata.field_is_final())
        })
        .filter(|field| !has_external_access(field, tree.root_node(), source))
        .map(|field| node_range(field.name))
        .collect()
}

fn misnamed_constants(
    tree: &Tree,
    source: &str,
    metadata_sites: &[FieldSite],
) -> Vec<Range> {
    java_field_sites(tree, metadata_sites)
        .into_iter()
        .filter(|field| field.metadata.field_is_static() && field.metadata.field_is_final())
        .filter(|field| is_immutable_type(&field.metadata))
        .filter(|field| node_text(source, field.name) != Some("serialVersionUID"))
        .filter(|field| {
            node_text(source, field.name).is_some_and(|name| {
                name.chars().any(|character| character.is_ascii_lowercase())
            })
        })
        .map(|field| node_range(field.name))
        .collect()
}

fn misnamed_variables(
    tree: &Tree,
    source: &str,
    metadata_sites: &[FieldSite],
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for field in java_field_sites(tree, metadata_sites) {
        if field.metadata.field_is_static() && field.metadata.field_is_final() {
            continue;
        }
        if starts_uppercase(source, field.name) {
            ranges.push(node_range(field.name));
        }
    }
    for node in descendants(tree.root_node()) {
        let name = match node.kind() {
            "formal_parameter"
            | "spread_parameter"
            | "catch_formal_parameter"
            | "resource"
            | "type_pattern" => node.child_by_field_name("name"),
            "variable_declarator"
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "local_variable_declaration") =>
            {
                node.child_by_field_name("name")
            }
            _ => None,
        };
        if let Some(name) = name
            && starts_uppercase(source, name)
        {
            ranges.push(node_range(name));
        }
    }
    ranges
}

fn named_declarations(tree: &Tree, source: &str, wanted: &str) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        if let Some(name) = declaration_name(node).or_else(|| recovered_method_name(node))
            && node_text(source, name) == Some(wanted)
        {
            ranges.push(node_range(name));
        }
    }
    for package in descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "package_declaration")
    {
        for node in descendants(package).into_iter().filter(|node| {
            matches!(node.kind(), "identifier" | "type_identifier")
        }) {
            if node_text(source, node) == Some(wanted) {
                ranges.push(node_range(node));
            }
        }
    }
    ranges
}

fn constructor_typos(tree: &Tree, source: &str) -> Vec<Range> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "method_declaration")
        .filter(|method| {
            let Some(name) = method.child_by_field_name("name") else {
                return false;
            };
            let Some(owner) = enclosing_type(*method) else {
                return false;
            };
            let Some(owner_name) = owner.child_by_field_name("name") else {
                return false;
            };
            node_text(source, name) == node_text(source, owner_name)
        })
        .map(node_range)
        .collect()
}

fn declaration_name(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    let is_declaration_head = matches!(
        parent.kind(),
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration"
            | "enum_constant"
            | "type_parameter"
            | "formal_parameter"
            | "spread_parameter"
            | "catch_formal_parameter"
            | "resource"
            | "variable_declarator"
    );
    is_declaration_head
        .then(|| parent.child_by_field_name("name"))
        .flatten()
        .filter(|name| name.id() == node.id())
}

/// tree-sitter-java recovers a pre-Java-9 underscore method as an `ERROR`
/// containing its return type and `underscore_pattern`, followed by the body
/// block as the next class-body child. Preserve that grammar-backed relation
/// so the declaration rule can still select the method name.
fn recovered_method_name(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "underscore_pattern" {
        return None;
    }
    let error = node.parent()?;
    if error.kind() != "ERROR" {
        return None;
    }
    let class_body = error.parent()?;
    if class_body.kind() != "class_body" {
        return None;
    }
    let children = named_children(class_body);
    let error_index = children.iter().position(|child| child.id() == error.id())?;
    let next = children.get(error_index.saturating_add(1))?;
    (next.kind() == "block").then_some(node)
}

fn is_immutable_type(metadata: &SignatureMetadata) -> bool {
    let Some(type_text) = metadata.return_type_text() else {
        return false;
    };
    matches!(
        type_text.trim(),
        "boolean"
            | "byte"
            | "char"
            | "double"
            | "float"
            | "int"
            | "long"
            | "short"
            | "void"
            | "Boolean"
            | "Byte"
            | "Character"
            | "Double"
            | "Float"
            | "Integer"
            | "Long"
            | "Short"
            | "Void"
            | "String"
            | "java.lang.Boolean"
            | "java.lang.Byte"
            | "java.lang.Character"
            | "java.lang.Double"
            | "java.lang.Float"
            | "java.lang.Integer"
            | "java.lang.Long"
            | "java.lang.Short"
            | "java.lang.Void"
            | "java.lang.String"
    )
}

fn writes_are_initialization_only(
    field: &JavaFieldSite<'_>,
    root: Node<'_>,
    source: &str,
) -> bool {
    let Some(field_name) = node_text(source, field.name) else {
        return false;
    };
    for node in descendants(root) {
        let target = match node.kind() {
            "assignment_expression" => node.child_by_field_name("left"),
            "update_expression" => node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("operand")),
            _ => None,
        };
        let Some(target) = target else {
            continue;
        };
        let Some(target_name) = assignment_target_name(target) else {
            continue;
        };
        if node_text(source, target_name) != Some(field_name) {
            continue;
        }
        if !is_initialization_context(node, field.owner) {
            return false;
        }
    }
    true
}

fn is_initialization_context(node: Node<'_>, owner: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if enclosing_type(ancestor).is_some_and(|candidate| candidate.id() != owner.id()) {
            return false;
        }
        match ancestor.kind() {
            "constructor_declaration" | "compact_constructor_declaration" | "static_initializer" => {
                return true;
            }
            "lambda_expression" | "method_declaration" => return false,
            "block" if ancestor
                .parent()
                .is_some_and(|parent| parent.kind() == "class_body") => return true,
            _ => {}
        }
        current = ancestor.parent();
    }
    false
}

fn has_external_access(field: &JavaFieldSite<'_>, root: Node<'_>, source: &str) -> bool {
    let Some(field_name) = node_text(source, field.name) else {
        return true;
    };
    for node in descendants(root) {
        if node.kind() != "identifier"
            || node.id() == field.name.id()
            || node_text(source, node) != Some(field_name)
        {
            continue;
        }
        if declaration_name(node).is_some() {
            continue;
        }
        if enclosing_type(node).is_some_and(|owner| owner.id() != field.owner.id()) {
            return true;
        }
    }
    false
}

fn assignment_target_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "field_access" => node.child_by_field_name("field"),
        "parenthesized_expression" => node
            .child_by_field_name("expression")
            .and_then(assignment_target_name),
        _ => None,
    }
}

fn starts_uppercase(source: &str, node: Node<'_>) -> bool {
    node_text(source, node).is_some_and(|name| {
        name.chars()
            .next()
            .is_some_and(|character| character.is_ascii_uppercase())
    })
}

fn enclosing_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn raw_constructor_invocations(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> Vec<Range> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "object_creation_expression")
        .filter_map(|node| {
            let ty = node.child_by_field_name("type")?;
            let named = raw_named_type(ty)?;
            is_generic_declaration(analyzer, file, source, tree, named)
                .then(|| node_range(node))
        })
        .collect()
}

fn raw_return_types(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> Vec<Range> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "method_declaration")
        .filter_map(|method| {
            let ty = method.child_by_field_name("type")?;
            let named = raw_named_type(ty)?;
            is_generic_declaration(analyzer, file, source, tree, named)
                .then(|| node_range(method))
        })
        .collect()
}

fn raw_variables(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        match node.kind() {
            "formal_parameter" | "spread_parameter" => {
                let Some(ty) = node.child_by_field_name("type") else {
                    continue;
                };
                let Some(named) = raw_named_type(ty) else {
                    continue;
                };
                if is_generic_declaration(analyzer, file, source, tree, named) {
                    ranges.push(node_range(node));
                }
            }
            "field_declaration" | "local_variable_declaration" => {
                let Some(ty) = node.child_by_field_name("type") else {
                    continue;
                };
                let Some(named) = raw_named_type(ty) else {
                    continue;
                };
                if !is_generic_declaration(analyzer, file, source, tree, named) {
                    continue;
                }
                // Java's normalized structural surface currently emits a
                // variable declarator as an assignment only when it has an
                // initializer.  Keep the language relation exact to that
                // surface; uninitialized fields/locals remain unrepresented
                // until a declaration fact is added to the shared vocabulary.
                for declarator in direct_variable_declarators(node) {
                    if declarator.child_by_field_name("value").is_some() {
                        ranges.push(node_range(declarator));
                    }
                }
            }
            _ => {}
        }
    }
    ranges
}

fn type_bounds_extending_final(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        if node.kind() == "type_parameter" {
            for bound in type_parameter_bounds(node) {
                if bound_is_final(analyzer, file, source, tree, bound) {
                    ranges.push(node_range(node));
                }
            }
        } else if node.kind() == "wildcard" || node.kind() == "wildcard_type" {
            if !has_extends_operator(node) {
                continue;
            }
            let Some(bound) = node
                .child_by_field_name("bound")
                .or_else(|| named_children(node).into_iter().next())
            else {
                continue;
            };
            if bound_is_final(analyzer, file, source, tree, bound) {
                ranges.push(node_range(node));
            }
        }
    }
    ranges
}

fn type_variables_hiding_types(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> Vec<Range> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "type_parameter")
        .filter_map(|parameter| {
            let name_node = parameter_name_node(parameter)?;
            let visible = resolve_type_declaration(analyzer, file, source, tree, name_node);
            matches!(visible, TypeResolution::Known(_)).then(|| node_range(parameter))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeResolution {
    Known(TypeDeclaration),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypeDeclaration {
    arity: Option<usize>,
    finality: Option<bool>,
}

fn is_generic_declaration(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    type_node: Node<'_>,
) -> bool {
    matches!(
        resolve_type_declaration(analyzer, file, source, tree, type_node),
        TypeResolution::Known(TypeDeclaration { arity: Some(arity), .. }) if arity > 0
    )
}

fn bound_is_final(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    bound: Node<'_>,
) -> bool {
    let Some(bound) = nominal_type_node(bound) else {
        return false;
    };
    matches!(
        resolve_type_declaration(analyzer, file, source, tree, bound),
        TypeResolution::Known(TypeDeclaration { finality: Some(true), .. })
    )
}

fn resolve_type_declaration(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    type_node: Node<'_>,
) -> TypeResolution {
    let Some(type_node) = nominal_type_node(type_node) else {
        return TypeResolution::Unknown;
    };
    let Some(components) = type_name_components(type_node, source) else {
        return TypeResolution::Unknown;
    };
    if components.is_empty() {
        return TypeResolution::Unknown;
    }

    let source_candidates = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| unit.is_class())
        .filter(|unit| unit_name_matches(unit, &components))
        .collect::<Vec<_>>();
    if source_candidates.len() > 1 {
        return TypeResolution::Unknown;
    }
    if let Some(unit) = source_candidates.first() {
        return source_declaration_fact(analyzer, file, tree, source, unit);
    }

    let mut qualified_names = imported_type_names(tree, source)
        .into_iter()
        .filter(|(simple, _)| components.len() == 1 && simple == &components[0])
        .map(|(_, qualified)| qualified)
        .collect::<Vec<_>>();
    if components.len() > 1 {
        qualified_names.push(components.join("."));
    } else {
        let package = package_name(tree, source);
        if !package.is_empty() {
            qualified_names.push(format!("{package}.{}", components[0]));
        }
        qualified_names.push(format!("java.lang.{}", components[0]));
    }
    qualified_names.sort();
    qualified_names.dedup();

    let mut resolved = Vec::new();
    for qualified in qualified_names {
        let definitions = analyzer
            .definitions(&qualified)
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        if definitions.len() > 1 {
            return TypeResolution::Unknown;
        }
        if let Some(unit) = definitions.first() {
            resolved.push(source_declaration_fact(analyzer, file, tree, source, unit));
            continue;
        }
        if let Some(models) = analyzer.active_semantic_models() {
            let matches = models.types_named(&qualified);
            if matches.records.len() == 1 {
                let record = matches.records[0].record;
                resolved.push(TypeResolution::Known(TypeDeclaration {
                    arity: Some(record.type_parameters.len()),
                    // The Java model's `is_sealed` field is the existing
                    // declaration finality bit: Java artifact producers set
                    // it for final or sealed declarations.  A sealed-only
                    // declaration is conservatively treated as unresolved by
                    // the final-bound rule below unless it is also final in
                    // source; this field remains useful for JDK final types.
                    finality: Some(record.is_sealed),
                }));
            }
        }
    }
    match resolved.as_slice() {
        [TypeResolution::Known(fact)] => TypeResolution::Known(*fact),
        _ => TypeResolution::Unknown,
    }
}

fn source_declaration_fact(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
    unit: &brokk_bifrost_core::analyzer::CodeUnit,
) -> TypeResolution {
    let metadata = analyzer.signature_metadata(unit);
    let metadata = metadata.first().filter(|entry| entry.type_parameters_recorded());
    let declaration_nodes = descendants(tree.root_node())
        .into_iter()
        .filter(|node| is_type_declaration_node(*node))
        .collect::<Vec<_>>();
    let ranges = analyzer.ranges_of(unit);
    let declaration_node = declaration_nodes
        .iter()
        .copied()
        .find(|node| ranges.iter().any(|range| *range == node_range(*node)))
        .or_else(|| {
            (unit.source() == file).then(|| {
                let named = declaration_nodes
                    .iter()
                    .copied()
                    .filter(|node| {
                        node.child_by_field_name("name")
                            .and_then(|name| java_owned_text(name, source))
                            .is_some_and(|name| name == unit.terminal_name())
                    })
                    .collect::<Vec<_>>();
                (named.len() == 1).then(|| named[0])
            })?
        });
    let arity = metadata
        .map(|entry| entry.type_parameters().len())
        .or_else(|| declaration_node.map(|node| declared_type_parameter_count(node)));
    let finality = declaration_node.map(|node| declaration_is_final(node, source));
    TypeResolution::Known(TypeDeclaration { arity, finality })
}

fn raw_named_type(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "generic_type" => None,
        "array_type" => node
            .child_by_field_name("element")
            .and_then(raw_named_type),
        "annotated_type" => last_named_child(node).and_then(raw_named_type),
        "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier" => {
            Some(node)
        }
        _ => None,
    }
}

fn nominal_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "generic_type" => node.child_by_field_name("type"),
        "array_type" => node
            .child_by_field_name("element")
            .and_then(nominal_type_node),
        "annotated_type" => last_named_child(node).and_then(nominal_type_node),
        "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier" => {
            Some(node)
        }
        _ => None,
    }
}

fn type_name_components(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    match node.kind() {
        "identifier" | "type_identifier" => Some(vec![java_owned_text(node, source)?]),
        "scoped_identifier" | "scoped_type_identifier" => {
            let mut parts = Vec::new();
            let mut current = Some(node);
            let mut stack = Vec::new();
            while let Some(next) = current {
                if matches!(next.kind(), "identifier" | "type_identifier") {
                    stack.push(java_owned_text(next, source)?);
                    break;
                }
                let children = named_children(next);
                let name = children
                    .iter()
                    .rev()
                    .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
                    .copied();
                let scope = children
                    .iter()
                    .find(|child| {
                        matches!(
                            child.kind(),
                            "scoped_identifier" | "scoped_type_identifier"
                        )
                    })
                    .copied();
                if let Some(name) = name {
                    stack.push(java_owned_text(name, source)?);
                }
                current = scope;
            }
            stack.reverse();
            parts.extend(stack);
            (!parts.is_empty()).then_some(parts)
        }
        _ => None,
    }
}

fn unit_name_matches(unit: &brokk_bifrost_core::analyzer::CodeUnit, components: &[String]) -> bool {
    let segments = unit.fq_segment_texts();
    segments.ends_with(components)
}

fn imported_type_names(tree: &Tree, source: &str) -> Vec<(String, String)> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "import_declaration")
        .filter_map(|node| {
            if descendants(node)
                .into_iter()
                .any(|child| child.kind() == "static" || child.kind() == "asterisk")
            {
                return None;
            }
            let path = named_children(node).into_iter().find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "scoped_identifier" | "scoped_type_identifier"
                )
            })?;
            let parts = type_name_components(path, source)?;
            let simple = parts.last()?.clone();
            Some((simple, parts.join(".")))
        })
        .collect()
}

fn package_name(tree: &Tree, source: &str) -> String {
    descendants(tree.root_node())
        .into_iter()
        .find(|node| node.kind() == "package_declaration")
        .and_then(|node| {
            named_children(node).into_iter().find_map(|child| {
                type_name_components(child, source).map(|parts| parts.join("."))
            })
        })
        .unwrap_or_default()
}

fn type_parameter_bounds(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| child.kind() == "type_bound")
        .map_or_else(Vec::new, named_children)
}

fn has_extends_operator(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == "extends")
}

fn parameter_name_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| child.kind() == "type_identifier")
    })
}

fn direct_variable_declarators(node: Node<'_>) -> Vec<Node<'_>> {
    descendants(node)
        .into_iter()
        .filter(|candidate| candidate.kind() == "variable_declarator")
        .filter(|candidate| {
            let mut current = candidate.parent();
            while let Some(parent) = current {
                if parent.id() == node.id() {
                    return true;
                }
                if matches!(parent.kind(), "field_declaration" | "local_variable_declaration") {
                    return false;
                }
                current = parent.parent();
            }
            false
        })
        .collect()
}

fn is_type_declaration_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

fn declared_type_parameter_count(node: Node<'_>) -> usize {
    node.child_by_field_name("type_parameters")
        .map_or(0, |parameters| {
            named_children(parameters)
                .into_iter()
                .filter(|child| child.kind() == "type_parameter")
                .count()
        })
}

fn declaration_is_final(node: Node<'_>, source: &str) -> bool {
    if matches!(node.kind(), "enum_declaration" | "record_declaration") {
        return true;
    }
    let modifiers = node.child_by_field_name("modifiers").or_else(|| {
        named_children(node)
            .into_iter()
            .find(|child| child.kind() == "modifiers")
    });
    modifiers.is_some_and(|modifiers| {
        let mut cursor = modifiers.walk();
        modifiers.children(&mut cursor).any(|modifier| {
            modifier.kind() == "final"
                || java_owned_text(modifier, source).is_some_and(|text| text == "final")
        })
    })
}


fn java_owned_text(node: Node<'_>, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes()).ok().map(str::to_owned)
}


fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().last()
}


fn node_text<'a>(source: &'a str, node: Node<'_>) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

fn descendants(root: Node<'_>) -> Vec<Node<'_>> {
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        nodes.push(node);
        pending.extend(named_children(node));
    }
    nodes
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}

#[derive(Clone)]
struct DeclarationSite {
    range: Range,
    unit: CodeUnit,
    metadata: Vec<SignatureMetadata>,
}

fn declaration_sites(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<DeclarationSite> {
    let mut sites = Vec::new();
    for unit in analyzer.get_declarations(file) {
        if !(unit.is_class() || unit.is_function()) {
            continue;
        }
        let metadata = analyzer.signature_metadata(&unit);
        for range in analyzer.ranges_of(&unit) {
            sites.push(DeclarationSite {
                range,
                unit: unit.clone(),
                metadata: metadata.clone(),
            });
        }
    }
    sites
}

fn site_for<'a>(sites: &'a [DeclarationSite], node: Node<'_>) -> Option<&'a DeclarationSite> {
    let range = node_range(node);
    sites.iter().find(|site| site.range == range)
}

fn undocumented_type(
    _analyzer: &dyn IAnalyzer,
    sites: &[DeclarationSite],
    node: Node<'_>,
    source: &str,
) -> bool {
    let Some(site) = site_for(sites, node) else {
        return false;
    };
    if !is_public(site) || is_generated(site, node, source) {
        return false;
    }
    match documentation(node, source) {
        None => true,
        Some(facts) if facts.complete => !facts.acceptable_text,
        Some(_) => false,
    }
}

fn callable_rule_matches(
    analyzer: &dyn IAnalyzer,
    sites: &[DeclarationSite],
    callable: Node<'_>,
    source: &str,
    rule: JavaRule,
) -> bool {
    let Some(site) = site_for(sites, callable) else {
        return false;
    };
    if rule != JavaRule::UnknownJavadocParameter
        && !callable_is_eligible(analyzer, site, callable, source)
    {
        return false;
    }
    if rule == JavaRule::UnknownJavadocParameter && site.unit.is_synthetic() {
        return false;
    }
    let Some(documentation) = documentation(callable, source) else {
        return rule == JavaRule::UndocumentedFunction;
    };
    if !documentation.complete {
        return false;
    }
    match rule {
        JavaRule::UndocumentedFunction => !documentation.acceptable_text,
        JavaRule::UnknownJavadocParameter => {
            unknown_parameter_tag(callable, &documentation, source)
        }
        JavaRule::UndocumentedParameter => false,
        JavaRule::UndocumentedReturnValue => {
            is_non_void_method(callable)
                && !documentation.tags.iter().any(|tag| {
                    tag.kind == JavadocTagKind::Return && tag.acceptable
                })
        }
        JavaRule::UndocumentedException => undocumented_exception(
            analyzer,
            site,
            callable,
            &documentation,
            source,
        ),
        JavaRule::InconsistentJavadocThrows => {
            inconsistent_throws(analyzer, site, callable, &documentation, source)
        }
        JavaRule::UndocumentedType => false,
        _ => false,
    }
}

fn undocumented_parameter(
    analyzer: &dyn IAnalyzer,
    sites: &[DeclarationSite],
    parameter: Node<'_>,
    source: &str,
) -> bool {
    let Some(callable) = enclosing_callable(parameter) else {
        return false;
    };
    let Some(site) = site_for(sites, callable) else {
        return false;
    };
    if !callable_is_eligible(analyzer, site, callable, source) {
        return false;
    }
    let Some(documentation) = documentation(callable, source) else {
        return false;
    };
    if !documentation.complete {
        return false;
    }
    let Some(name) = parameter_name(parameter, source) else {
        return false;
    };
    !documentation.tags.iter().any(|tag| {
        tag.kind == JavadocTagKind::Param
            && tag.name.as_deref() == Some(name.as_str())
            && tag.acceptable
    })
}

fn unknown_parameter_tag(
    callable: Node<'_>,
    documentation: &JavadocBlockFacts,
    source: &str,
) -> bool {
    let actual_parameters = parameter_names(callable, source);
    let type_parameters = type_parameter_names(callable, source);
    documentation.tags.iter().any(|tag| {
        if tag.kind != JavadocTagKind::Param {
            return false;
        }
        let Some(name) = tag.name.as_deref() else {
            return true;
        };
        !actual_parameters.iter().any(|actual| actual == name)
            && !type_parameters.iter().any(|actual| actual == name)
    })
}

fn unknown_type_parameter_tag(
    sites: &[DeclarationSite],
    declaration: Node<'_>,
    source: &str,
) -> bool {
    let Some(site) = site_for(sites, declaration) else {
        return false;
    };
    if site.unit.is_synthetic() {
        return false;
    }
    let Some(documentation) = documentation(declaration, source) else {
        return false;
    };
    if !documentation.complete {
        return false;
    }
    let mut valid = type_parameter_names(declaration, source);
    if declaration.kind() == "record_declaration" {
        valid.extend(parameter_names_from_field(declaration, source));
    }
    documentation.tags.iter().any(|tag| {
        if tag.kind != JavadocTagKind::Param {
            return false;
        }
        let Some(name) = tag.name.as_deref() else {
            return true;
        };
        !valid.iter().any(|actual| actual == name)
    })
}

fn undocumented_exception(
    analyzer: &dyn IAnalyzer,
    site: &DeclarationSite,
    callable: Node<'_>,
    documentation: &JavadocBlockFacts,
    source: &str,
) -> bool {
    let declared = declared_throws(callable, source);
    if declared.is_empty() {
        return false;
    }
    for (type_node, name) in declared {
        let status = exception_status(analyzer, site.unit.source(), source, type_node, &name);
        if status == ExceptionStatus::Unknown {
            return false;
        }
        if status == ExceptionStatus::Checked
            && !documentation.tags.iter().any(|tag| {
                tag.kind == JavadocTagKind::Throws
                    && tag.terminal_name.as_deref() == type_terminal(&name)
                    && tag.acceptable
            })
        {
            return true;
        }
    }
    false
}

fn inconsistent_throws(
    analyzer: &dyn IAnalyzer,
    site: &DeclarationSite,
    callable: Node<'_>,
    documentation: &JavadocBlockFacts,
    source: &str,
) -> bool {
    let declared = declared_throws(callable, source);
    let mut statuses = Vec::new();
    for (type_node, name) in &declared {
        let status = exception_status(analyzer, site.unit.source(), source, *type_node, name);
        if status == ExceptionStatus::Unknown {
            return false;
        }
        statuses.push((name.as_str(), status));
    }
    documentation.tags.iter().any(|tag| {
        if tag.kind != JavadocTagKind::Throws {
            return false;
        }
        let Some(tag_name) = tag.terminal_name.as_deref() else {
            return false;
        };
        if known_unchecked(tag_name) {
            return false;
        }
        if !known_checked(tag_name) && !statuses.iter().any(|(_, status)| *status == ExceptionStatus::Checked) {
            return false;
        }
        !statuses
            .iter()
            .any(|(declared_name, status)| {
                *status == ExceptionStatus::Checked
                    && type_names_possible(declared_name, tag_name)
            })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExceptionStatus {
    Checked,
    Unchecked,
    Unknown,
}

fn exception_status(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    name: &str,
) -> ExceptionStatus {
    let Some(terminal) = type_terminal(name) else {
        return ExceptionStatus::Unknown;
    };
    if known_unchecked(terminal) {
        return ExceptionStatus::Unchecked;
    }
    if known_checked(terminal) {
        return ExceptionStatus::Checked;
    }

    let source: Arc<str> = Arc::from(source.to_owned());
    let Some(outcome) = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(type_node.start_byte()),
            end_byte: Some(type_node.end_byte()),
        }],
        file.clone(),
        Arc::clone(&source),
    )
    .into_iter()
    .next()
    else {
        return ExceptionStatus::Unknown;
    };
    if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.len() != 1 {
        return ExceptionStatus::Unknown;
    }
    let class = &outcome.definitions[0];
    if !class.is_class() {
        return ExceptionStatus::Unknown;
    }
    if known_unchecked(class.terminal_name()) {
        return ExceptionStatus::Unchecked;
    }
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        return ExceptionStatus::Unknown;
    };
    let ancestors = provider.get_ancestors(class);
    if ancestors
        .iter()
        .any(|ancestor| known_unchecked(ancestor.terminal_name()))
    {
        ExceptionStatus::Unchecked
    } else if ancestors
        .iter()
        .any(|ancestor| matches!(ancestor.terminal_name(), "Exception" | "Throwable"))
    {
        ExceptionStatus::Checked
    } else {
        ExceptionStatus::Unknown
    }
}

fn known_checked(name: &str) -> bool {
    name == "Exception" || name == "Throwable" || KNOWN_CHECKED_JDK_TYPES.contains(&name)
}

fn known_unchecked(name: &str) -> bool {
    KNOWN_UNCHECKED_TYPES.contains(&name)
}

fn type_names_possible(declared: &str, tagged: &str) -> bool {
    declared == tagged || declared == "Exception" || declared == "Throwable"
}

fn type_terminal(name: &str) -> Option<&str> {
    name.rsplit('.').next().filter(|name| !name.is_empty())
}

fn callable_is_eligible(
    analyzer: &dyn IAnalyzer,
    site: &DeclarationSite,
    callable: Node<'_>,
    source: &str,
) -> bool {
    if !is_public(site) || is_generated(site, callable, source) {
        return false;
    }
    if is_getter_or_setter(callable, source) {
        return false;
    }
    let Some(provider) = analyzer.member_family_provider() else {
        return false;
    };
    let family = provider.member_family(&site.unit, None);
    if !matches!(
        family.outcome,
        MemberFamilyOutcome::Proven | MemberFamilyOutcome::NoFamily
    ) {
        return false;
    }
    !family.edges.iter().any(|edge| {
        matches!(
            edge.relation,
            MethodFamilyRelation::Overrides | MethodFamilyRelation::Implements
        )
    })
}

fn is_public(site: &DeclarationSite) -> bool {
    !site.metadata.is_empty()
        && site.metadata.iter().all(|metadata| {
            metadata.callable_declared_visibility() == Some(DeclaredVisibility::Public)
        })
}

fn is_generated(site: &DeclarationSite, node: Node<'_>, source: &str) -> bool {
    site.unit.is_synthetic() || descendants(node).into_iter().any(|candidate| {
        candidate.kind() == "annotation"
            && candidate
                .child_by_field_name("name")
                .and_then(|name| source.get(name.byte_range()))
                .is_some_and(|name| {
                    matches!(
                        name.trim(),
                        "Generated"
                            | "javax.annotation.Generated"
                            | "javax.annotation.processing.Generated"
                            | "lombok.Generated"
                    )
                })
    })
}

fn is_getter_or_setter(callable: Node<'_>, source: &str) -> bool {
    let Some(name) = callable
        .child_by_field_name("name")
        .and_then(|name| source.get(name.byte_range()))
    else {
        return false;
    };
    let parameters = parameter_names(callable, source);
    let returns_void = callable
        .child_by_field_name("type")
        .is_some_and(|return_type| return_type.kind() == "void_type");
    let getter = (name.strip_prefix("get").is_some_and(valid_accessor_suffix)
        || name.strip_prefix("is").is_some_and(valid_accessor_suffix))
        && parameters.is_empty()
        && !returns_void;
    let setter = name.strip_prefix("set").is_some_and(valid_accessor_suffix)
        && parameters.len() == 1
        && returns_void;
    getter || setter
}

fn valid_accessor_suffix(suffix: &str) -> bool {
    suffix.chars().next().is_some_and(char::is_uppercase)
}

fn documentation(node: Node<'_>, source: &str) -> Option<JavadocBlockFacts> {
    let comment = preceding_javadoc_comment(node, source)?;
    parse_block_comment(comment, source)
}

fn is_non_void_method(node: Node<'_>) -> bool {
    node.kind() == "method_declaration"
        && node
            .child_by_field_name("type")
            .is_some_and(|return_type| return_type.kind() != "void_type")
}

fn declared_throws<'tree>(
    callable: Node<'tree>,
    source: &str,
) -> Vec<(Node<'tree>, String)> {
    let mut result = Vec::new();
    let mut cursor = callable.walk();
    for child in callable.named_children(&mut cursor) {
        if child.kind() != "throws" {
            continue;
        }
        let mut types = child.walk();
        for type_node in child.named_children(&mut types) {
            if let Some(name) = java_type_name(type_node, source) {
                result.push((type_node, name));
            }
        }
    }
    result
}

fn java_type_name(node: Node<'_>, source: &str) -> Option<String> {
    java_type_name_components(node, source)
        .and_then(|components| components.last().cloned())
}

fn parameter_names(callable: Node<'_>, source: &str) -> Vec<String> {
    parameter_nodes(callable)
        .into_iter()
        .filter_map(|parameter| parameter_name(parameter, source))
        .collect()
}

fn parameter_names_from_field(declaration: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = declaration.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| matches!(parameter.kind(), "formal_parameter" | "spread_parameter"))
        .filter_map(|parameter| parameter_name(parameter, source))
        .collect()
}

fn parameter_name(parameter: Node<'_>, source: &str) -> Option<String> {
    parameter
        .child_by_field_name("name")
        .and_then(|name| source.get(name.byte_range()))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn parameter_nodes(callable: Node<'_>) -> Vec<Node<'_>> {
    let parameters = callable.child_by_field_name("parameters").or_else(|| {
        (callable.kind() == "compact_constructor_declaration")
            .then(|| callable.parent()?.parent()?.child_by_field_name("parameters"))
            .flatten()
    });
    parameters
        .into_iter()
        .flat_map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter(|parameter| matches!(parameter.kind(), "formal_parameter" | "spread_parameter"))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn type_parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| {
            parameter
                .child_by_field_name("name")
                .or_else(|| parameter.named_child(0))
                .and_then(|name| source.get(name.byte_range()))
                .map(|name| format!("<{}>", name.trim()))
        })
        .collect()
}

fn enclosing_callable(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if is_callable(parent) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn is_callable(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
    )
}

fn is_parameter(node: Node<'_>) -> bool {
    matches!(node.kind(), "formal_parameter" | "spread_parameter")
}

fn is_type_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_jvm::java::declarations::parse_tree;

    #[test]
    fn java_tree_exposes_javadoc_as_the_preceding_block_comment() {
        let source = "/** Explains the type. */\npublic class Sample {\n    /** Explains the method. */\n    public String value() { return \"x\"; }\n}";
        let tree = parse_tree(source).expect("Java grammar");
        let class = descendants(tree.root_node())
            .into_iter()
            .find(|node| node.kind() == "class_declaration")
            .expect("class");
        let method = descendants(tree.root_node())
            .into_iter()
            .find(|node| node.kind() == "method_declaration")
            .expect("method");
        assert!(preceding_javadoc_comment(class, source).is_some());
        assert!(preceding_javadoc_comment(method, source).is_some());
        assert!(documentation(method, source).is_some_and(|facts| facts.complete));
    }
}
