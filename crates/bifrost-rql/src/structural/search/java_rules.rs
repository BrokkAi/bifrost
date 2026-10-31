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
    DeclaredVisibility, MethodFamilyRelation,
};
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
use brokk_bifrost_jvm::java::javadoc::{
    JavadocBlockFacts, JavadocTagKind, parse_block_comment, preceding_javadoc_comment,
};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

use super::field_metadata::{FieldSite, field_sites};
use super::language_rules::{LanguageRuleMatch, LanguageRuleMatches, UndecidedSite};

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
    let mut undecided = Vec::new();
    if matches!(
        rule,
        JavaRule::InconsistentJavadocThrows
            | JavaRule::UnknownJavadocParameter
            | JavaRule::UndocumentedException
            | JavaRule::UndocumentedFunction
            | JavaRule::UndocumentedParameter
            | JavaRule::UndocumentedReturnValue
            | JavaRule::UndocumentedType
    ) {
        return LanguageRuleMatches::decided(
            javadoc_matches(analyzer, file, source, &tree, rule, &mut undecided),
            undecided,
            Language::Java.config_label(),
            rule.label(),
            file,
        );
    }
    let ranges = match rule {
        JavaRule::NonFinalImmutableField => non_final_immutable_fields(&tree, source, &fields),
        JavaRule::NonPrivateField => non_private_fields(&tree, source, &fields),
        JavaRule::MisnamedConstant => misnamed_constants(&tree, source, &fields),
        JavaRule::MisnamedVariable => misnamed_variables(&tree, source, &fields),
        JavaRule::UnderscoreIdentifier => named_declarations(&tree, source, "_"),
        JavaRule::EnumIdentifier => named_declarations(&tree, source, "enum"),
        JavaRule::ConstructorTypo => constructor_typos(&tree, source),
        JavaRule::RawConstructorInvocation => {
            raw_constructor_invocations(analyzer, file, source, &tree, &mut undecided)
        }
        JavaRule::RawReturnType => raw_return_types(analyzer, file, source, &tree, &mut undecided),
        JavaRule::RawVariable => raw_variables(analyzer, file, source, &tree, &mut undecided),
        JavaRule::TypeBoundExtendsFinal => {
            type_bounds_extending_final(analyzer, file, source, &tree, &mut undecided)
        }
        JavaRule::TypeVariableHidesType => {
            type_variables_hiding_types(analyzer, file, source, &tree, &mut undecided)
        }
        _ => unreachable!("Java Javadoc rules returned above"),
    };
    LanguageRuleMatches::decided(
        ranges.into_iter().map(LanguageRuleMatch::from).collect(),
        undecided,
        Language::Java.config_label(),
        rule.label(),
        file,
    )
}

/// Whether a Java relation holds at one site. `Undecided` carries the reason
/// the analyzer could not answer, which becomes an incomplete diagnostic
/// instead of a clean negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Holds,
    Fails,
    Undecided(&'static str),
}

impl Decision {
    fn from_bool(holds: bool) -> Self {
        if holds { Self::Holds } else { Self::Fails }
    }

    /// Both relations must hold; `next` is consulted only when `self` does
    /// not already fail.
    fn and(self, next: impl FnOnce() -> Self) -> Self {
        match self {
            Self::Fails => Self::Fails,
            Self::Holds => next(),
            Self::Undecided(reason) => match next() {
                Self::Fails => Self::Fails,
                Self::Holds | Self::Undecided(_) => Self::Undecided(reason),
            },
        }
    }
}

fn record_decision(
    decision: Decision,
    range: Range,
    ranges: &mut Vec<Range>,
    undecided: &mut Vec<UndecidedSite>,
) {
    match decision {
        Decision::Holds => ranges.push(range),
        Decision::Fails => {}
        Decision::Undecided(reason) => undecided.push(UndecidedSite::at(range, reason)),
    }
}

fn javadoc_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    rule: JavaRule,
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<LanguageRuleMatch> {
    let sites = declaration_sites(analyzer, file);
    let source: Arc<str> = Arc::from(source.to_owned());
    let mut ranges = Vec::new();
    let mut tag_matches = Vec::new();
    for node in descendants(tree.root_node()) {
        match rule {
            JavaRule::UndocumentedType if is_type_declaration(node) => {
                if undocumented_type(analyzer, &sites, node, &source) {
                    tag_matches.push(LanguageRuleMatch::from(node_range(node)));
                }
            }
            JavaRule::UnknownJavadocParameter if is_type_declaration(node) => {
                tag_matches.extend(
                    unknown_type_parameter_tag(&sites, node, &source)
                        .into_iter()
                        .map(|report| LanguageRuleMatch {
                            select: node_range(node),
                            report,
                        }),
                );
            }
            JavaRule::UndocumentedParameter if is_parameter(node) => record_decision(
                undocumented_parameter(analyzer, &sites, node, &source),
                node_range(node),
                &mut ranges,
                undecided,
            ),
            JavaRule::UnknownJavadocParameter
            | JavaRule::UndocumentedException
            | JavaRule::UndocumentedFunction
            | JavaRule::UndocumentedReturnValue
            | JavaRule::InconsistentJavadocThrows
                if is_callable(node) =>
            {
                let select = node_range(node);
                match rule {
                    JavaRule::UnknownJavadocParameter => {
                        tag_matches.extend(
                            callable_unknown_parameter_tags(&sites, node, &source)
                                .into_iter()
                                .map(|report| LanguageRuleMatch { select, report }),
                        );
                    }
                    JavaRule::InconsistentJavadocThrows => {
                        let reports = callable_inconsistent_throws(
                            analyzer, &sites, node, &source, undecided,
                        );
                        tag_matches.extend(
                            reports
                                .into_iter()
                                .map(|report| LanguageRuleMatch { select, report }),
                        );
                    }
                    _ => record_decision(
                        callable_rule_matches(analyzer, &sites, node, &source, rule),
                        select,
                        &mut ranges,
                        undecided,
                    ),
                }
            }
            _ => {}
        }
    }
    tag_matches.extend(ranges.into_iter().map(LanguageRuleMatch::from));
    tag_matches
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

fn non_private_fields(tree: &Tree, source: &str, metadata_sites: &[FieldSite]) -> Vec<Range> {
    java_field_sites(tree, metadata_sites)
        .into_iter()
        .filter(|field| !field.enum_constant)
        .filter(|field| {
            field.metadata.callable_declared_visibility() != Some(DeclaredVisibility::Private)
        })
        .filter(|field| !(field.metadata.field_is_static() && field.metadata.field_is_final()))
        .filter(|field| !has_external_access(field, tree.root_node(), source))
        .map(|field| node_range(field.name))
        .collect()
}

fn misnamed_constants(tree: &Tree, source: &str, metadata_sites: &[FieldSite]) -> Vec<Range> {
    java_field_sites(tree, metadata_sites)
        .into_iter()
        .filter(|field| field.metadata.field_is_static() && field.metadata.field_is_final())
        .filter(|field| is_immutable_type(&field.metadata))
        .filter(|field| node_text(source, field.name) != Some("serialVersionUID"))
        .filter(|field| {
            node_text(source, field.name)
                .is_some_and(|name| name.chars().any(|character| character.is_ascii_lowercase()))
        })
        .map(|field| node_range(field.name))
        .collect()
}

fn misnamed_variables(tree: &Tree, source: &str, metadata_sites: &[FieldSite]) -> Vec<Range> {
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
        for node in descendants(package)
            .into_iter()
            .filter(|node| matches!(node.kind(), "identifier" | "type_identifier"))
        {
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

fn writes_are_initialization_only(field: &JavaFieldSite<'_>, root: Node<'_>, source: &str) -> bool {
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
            "constructor_declaration"
            | "compact_constructor_declaration"
            | "static_initializer" => {
                return true;
            }
            "lambda_expression" | "method_declaration" => return false,
            "block"
                if ancestor
                    .parent()
                    .is_some_and(|parent| parent.kind() == "class_body") =>
            {
                return true;
            }
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
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        if node.kind() != "object_creation_expression" {
            continue;
        }
        let Some(named) = node.child_by_field_name("type").and_then(raw_named_type) else {
            continue;
        };
        record_decision(
            is_generic_declaration(analyzer, file, source, tree, named),
            node_range(node),
            &mut ranges,
            undecided,
        );
    }
    ranges
}

fn raw_return_types(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for method in descendants(tree.root_node()) {
        if method.kind() != "method_declaration" {
            continue;
        }
        let Some(named) = method.child_by_field_name("type").and_then(raw_named_type) else {
            continue;
        };
        record_decision(
            is_generic_declaration(analyzer, file, source, tree, named),
            node_range(method),
            &mut ranges,
            undecided,
        );
    }
    ranges
}

fn raw_variables(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        match node.kind() {
            "formal_parameter" | "spread_parameter" => {
                let Some(named) = node.child_by_field_name("type").and_then(raw_named_type) else {
                    continue;
                };
                record_decision(
                    is_generic_declaration(analyzer, file, source, tree, named),
                    node_range(node),
                    &mut ranges,
                    undecided,
                );
            }
            "field_declaration" | "local_variable_declaration" => {
                let Some(named) = node.child_by_field_name("type").and_then(raw_named_type) else {
                    continue;
                };
                // Java's normalized structural surface currently emits a
                // variable declarator as an assignment only when it has an
                // initializer.  Keep the language relation exact to that
                // surface; uninitialized fields/locals remain unrepresented
                // until a declaration fact is added to the shared vocabulary.
                let declarators = direct_variable_declarators(node)
                    .into_iter()
                    .filter(|declarator| declarator.child_by_field_name("value").is_some())
                    .collect::<Vec<_>>();
                if declarators.is_empty() {
                    continue;
                }
                let decision = is_generic_declaration(analyzer, file, source, tree, named);
                for declarator in declarators {
                    record_decision(decision, node_range(declarator), &mut ranges, undecided);
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
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for node in descendants(tree.root_node()) {
        if node.kind() == "type_parameter" {
            for bound in type_parameter_bounds(node) {
                record_decision(
                    bound_is_final(analyzer, file, source, tree, bound),
                    node_range(node),
                    &mut ranges,
                    undecided,
                );
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
            record_decision(
                bound_is_final(analyzer, file, source, tree, bound),
                node_range(node),
                &mut ranges,
                undecided,
            );
        }
    }
    ranges
}

fn type_variables_hiding_types(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let mut ranges = Vec::new();
    for parameter in descendants(tree.root_node()) {
        if parameter.kind() != "type_parameter" {
            continue;
        }
        let Some(name_node) = parameter_name_node(parameter) else {
            continue;
        };
        let decision = match resolve_type_declaration(analyzer, file, source, tree, name_node) {
            // An import that names the type proves it is visible even when
            // its declaration is not indexed.
            TypeResolution::Known(_) | TypeResolution::NotIndexed(_) => Decision::Holds,
            TypeResolution::Absent => Decision::Fails,
            TypeResolution::Unknown(reason) => Decision::Undecided(reason),
        };
        record_decision(decision, node_range(parameter), &mut ranges, undecided);
    }
    ranges
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeResolution {
    Known(TypeDeclaration),
    /// An import or a qualified name names the type, but nothing indexed
    /// declares it.
    NotIndexed(&'static str),
    /// Every scope that can declare the name was searched and none does.
    Absent,
    Unknown(&'static str),
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
) -> Decision {
    if names_type_variable_in_scope(type_node, source) {
        return Decision::Fails;
    }
    match resolve_type_declaration(analyzer, file, source, tree, type_node) {
        TypeResolution::Known(TypeDeclaration {
            arity: Some(arity), ..
        }) => Decision::from_bool(arity > 0),
        TypeResolution::Known(TypeDeclaration { arity: None, .. }) => {
            Decision::Undecided("the type parameters of the declared type are not recorded")
        }
        TypeResolution::Absent => Decision::Undecided("no declaration of the type is visible"),
        TypeResolution::NotIndexed(reason) | TypeResolution::Unknown(reason) => {
            Decision::Undecided(reason)
        }
    }
}

fn bound_is_final(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    bound: Node<'_>,
) -> Decision {
    let Some(bound) = nominal_type_node(bound) else {
        return Decision::Fails;
    };
    if names_type_variable_in_scope(bound, source) {
        return Decision::Fails;
    }
    match resolve_type_declaration(analyzer, file, source, tree, bound) {
        TypeResolution::Known(TypeDeclaration {
            finality: Some(finality),
            ..
        }) => Decision::from_bool(finality),
        TypeResolution::Known(TypeDeclaration { finality: None, .. }) => {
            Decision::Undecided("the finality of the bound type is not recorded")
        }
        TypeResolution::Absent => {
            Decision::Undecided("no declaration of the bound type is visible")
        }
        TypeResolution::NotIndexed(reason) | TypeResolution::Unknown(reason) => {
            Decision::Undecided(reason)
        }
    }
}

/// Whether a simple type name refers to a type parameter declared by an
/// enclosing type or callable. Such a name is a type variable, never a raw or
/// final class type, so it needs no declaration lookup.
fn names_type_variable_in_scope(type_node: Node<'_>, source: &str) -> bool {
    if !matches!(type_node.kind(), "type_identifier" | "identifier") {
        return false;
    }
    let Some(name) = node_text(source, type_node) else {
        return false;
    };
    let mut current = type_node.parent();
    while let Some(ancestor) = current {
        let declares_name = named_children(ancestor)
            .into_iter()
            .filter(|child| child.kind() == "type_parameters")
            .flat_map(named_children)
            .filter(|parameter| parameter.kind() == "type_parameter")
            .filter_map(parameter_name_node)
            .any(|parameter| node_text(source, parameter) == Some(name));
        if declares_name {
            return true;
        }
        current = ancestor.parent();
    }
    false
}

/// Resolve a written Java type name to its declaration by the JLS scope
/// order: declarations in this file, single-type imports, the package, then
/// on-demand imports together with `java.lang`.
fn resolve_type_declaration(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    type_node: Node<'_>,
) -> TypeResolution {
    let Some(type_node) = nominal_type_node(type_node) else {
        return TypeResolution::Unknown("the type has no nominal name");
    };
    let Some(components) =
        type_name_components(type_node, source).filter(|parts| !parts.is_empty())
    else {
        return TypeResolution::Unknown("the type name has no identifier components");
    };

    let source_candidates = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| unit.is_class())
        .filter(|unit| unit_name_matches(unit, &components))
        .collect::<Vec<_>>();
    match source_candidates.as_slice() {
        [] => {}
        [unit] => {
            return TypeResolution::Known(source_declaration_fact(
                analyzer, file, tree, source, unit,
            ));
        }
        _ => {
            return TypeResolution::Unknown(
                "more than one declaration in the file matches the type",
            );
        }
    }

    if components.len() > 1 {
        return match lookup_qualified_type(analyzer, file, tree, source, &components.join(".")) {
            TypeResolution::Absent => {
                TypeResolution::NotIndexed("the qualified type is not indexed")
            }
            resolved => resolved,
        };
    }
    let name = &components[0];
    let imports = java_imports(tree, source);
    let single_type = imports
        .iter()
        .filter(|import| !import.on_demand && import.components.last() == Some(name))
        .map(|import| import.components.join("."))
        .collect::<Vec<_>>();
    if !single_type.is_empty() {
        return match lookup_type_group(analyzer, file, tree, source, &single_type) {
            TypeResolution::Absent => {
                TypeResolution::NotIndexed("the imported type is not indexed")
            }
            resolved => resolved,
        };
    }
    let package = package_name(tree, source);
    let same_package = if package.is_empty() {
        name.clone()
    } else {
        format!("{package}.{name}")
    };
    match lookup_qualified_type(analyzer, file, tree, source, &same_package) {
        TypeResolution::Absent => {}
        resolved => return resolved,
    }
    let mut implicit = imports
        .iter()
        .filter(|import| import.on_demand && !import.is_static)
        .map(|import| format!("{}.{name}", import.components.join(".")))
        .collect::<Vec<_>>();
    implicit.push(format!("java.lang.{name}"));
    match lookup_type_group(analyzer, file, tree, source, &implicit) {
        TypeResolution::Absent if imports.iter().any(|import| import.on_demand) => {
            TypeResolution::Unknown("an on-demand import may declare the type")
        }
        TypeResolution::Absent if !java_lang_indexed(analyzer, file, tree, source) => {
            TypeResolution::Unknown("java.lang is not indexed, so it may declare the type")
        }
        resolved => resolved,
    }
}

/// Resolve names that share one scope level: more than one hit is an
/// ambiguity, not a choice.
fn lookup_type_group(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
    qualified_names: &[String],
) -> TypeResolution {
    let mut found = Vec::new();
    for qualified in qualified_names {
        match lookup_qualified_type(analyzer, file, tree, source, qualified) {
            TypeResolution::Known(fact) => found.push(fact),
            TypeResolution::Absent => {}
            unresolved @ (TypeResolution::NotIndexed(_) | TypeResolution::Unknown(_)) => {
                return unresolved;
            }
        }
    }
    match found.as_slice() {
        [] => TypeResolution::Absent,
        [fact] => TypeResolution::Known(*fact),
        _ => TypeResolution::Unknown("more than one visible declaration matches the type"),
    }
}

fn lookup_qualified_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
    qualified: &str,
) -> TypeResolution {
    let definitions = analyzer
        .definitions(qualified)
        .filter(|unit| unit.is_class())
        .collect::<Vec<_>>();
    match definitions.as_slice() {
        [] => {}
        [unit] => {
            return TypeResolution::Known(source_declaration_fact(
                analyzer, file, tree, source, unit,
            ));
        }
        _ => return TypeResolution::Unknown("more than one indexed declaration matches the type"),
    }
    let Some(models) = analyzer.active_semantic_models() else {
        return TypeResolution::Absent;
    };
    match models.types_named(qualified).records.as_slice() {
        [] => TypeResolution::Absent,
        [matched] => TypeResolution::Known(TypeDeclaration {
            arity: Some(matched.record.type_parameters.len()),
            // The Java model's `is_sealed` field is the existing
            // declaration finality bit: Java artifact producers set
            // it for final or sealed declarations.  A sealed-only
            // declaration is conservatively treated as unresolved by
            // the final-bound rule below unless it is also final in
            // source; this field remains useful for JDK final types.
            finality: Some(matched.record.is_sealed),
        }),
        _ => TypeResolution::Unknown("more than one semantic-model type matches the type"),
    }
}

/// Whether a lookup in `java.lang` can answer: without an indexed JDK or a
/// semantic model for it, a name absent elsewhere may still be a `java.lang`
/// type.
fn java_lang_indexed(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
) -> bool {
    matches!(
        lookup_qualified_type(analyzer, file, tree, source, "java.lang.Object"),
        TypeResolution::Known(_)
    )
}

/// Facts about a class declaration, read from its declaring file's syntax
/// tree, which is `tree` when the class is declared in `file`.
fn source_declaration_fact(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    tree: &Tree,
    source: &str,
    unit: &CodeUnit,
) -> TypeDeclaration {
    let metadata_arity = analyzer
        .signature_metadata(unit)
        .first()
        .filter(|entry| entry.type_parameters_recorded())
        .map(|entry| entry.type_parameters().len());
    let ranges = analyzer.ranges_of(unit);
    if unit.source() == file {
        return declaration_fact_in_tree(tree, source, unit, &ranges, metadata_arity);
    }
    let declaring = unit.source();
    let declaring_source = (language_for_file(declaring) == Language::Java)
        .then(|| analyzer.indexed_source(declaring))
        .flatten();
    let declaring_tree = declaring_source.as_deref().and_then(|declaring_source| {
        parse_tree_for_language(declaring, Language::Java, declaring_source)
    });
    match (declaring_source.as_deref(), declaring_tree.as_ref()) {
        (Some(declaring_source), Some(declaring_tree)) => declaration_fact_in_tree(
            declaring_tree,
            declaring_source,
            unit,
            &ranges,
            metadata_arity,
        ),
        _ => TypeDeclaration {
            arity: metadata_arity,
            finality: None,
        },
    }
}

fn declaration_fact_in_tree(
    tree: &Tree,
    source: &str,
    unit: &CodeUnit,
    ranges: &[Range],
    metadata_arity: Option<usize>,
) -> TypeDeclaration {
    let declaration_nodes = descendants(tree.root_node())
        .into_iter()
        .filter(|node| is_type_declaration_node(*node))
        .collect::<Vec<_>>();
    let declaration_node = declaration_nodes
        .iter()
        .copied()
        .find(|node| ranges.iter().any(|range| *range == node_range(*node)))
        .or_else(|| {
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
        });
    let arity = metadata_arity.or_else(|| declaration_node.map(declared_type_parameter_count));
    let finality = declaration_node.map(|node| declaration_is_final(node, source));
    TypeDeclaration { arity, finality }
}

fn raw_named_type(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "generic_type" => None,
        "array_type" => node.child_by_field_name("element").and_then(raw_named_type),
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
                        matches!(child.kind(), "scoped_identifier" | "scoped_type_identifier")
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

struct JavaImport {
    components: Vec<String>,
    is_static: bool,
    on_demand: bool,
}

fn java_imports(tree: &Tree, source: &str) -> Vec<JavaImport> {
    descendants(tree.root_node())
        .into_iter()
        .filter(|node| node.kind() == "import_declaration")
        .filter_map(|node| {
            let mut cursor = node.walk();
            let tokens = node.children(&mut cursor).collect::<Vec<_>>();
            let path = tokens.iter().copied().find(|child| {
                matches!(
                    child.kind(),
                    "identifier"
                        | "type_identifier"
                        | "scoped_identifier"
                        | "scoped_type_identifier"
                )
            })?;
            Some(JavaImport {
                components: type_name_components(path, source)?,
                is_static: tokens.iter().any(|child| child.kind() == "static"),
                on_demand: tokens.iter().any(|child| child.kind() == "asterisk"),
            })
        })
        .collect()
}

fn package_name(tree: &Tree, source: &str) -> String {
    descendants(tree.root_node())
        .into_iter()
        .find(|node| node.kind() == "package_declaration")
        .and_then(|node| {
            named_children(node)
                .into_iter()
                .find_map(|child| type_name_components(child, source).map(|parts| parts.join(".")))
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
    node.children(&mut cursor)
        .any(|child| child.kind() == "extends")
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
                if matches!(
                    parent.kind(),
                    "field_declaration" | "local_variable_declaration"
                ) {
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
) -> Decision {
    let Some(site) = site_for(sites, callable) else {
        return Decision::Fails;
    };
    let documented = match documentation(callable, source) {
        None => Decision::from_bool(rule == JavaRule::UndocumentedFunction),
        Some(documentation) if !documentation.complete => Decision::Fails,
        Some(documentation) => match rule {
            JavaRule::UndocumentedFunction => Decision::from_bool(!documentation.acceptable_text),
            JavaRule::UndocumentedReturnValue => Decision::from_bool(
                is_non_void_method(callable)
                    && !documentation
                        .tags
                        .iter()
                        .any(|tag| tag.kind == JavadocTagKind::Return && tag.acceptable),
            ),
            JavaRule::UndocumentedException => {
                undocumented_exception(analyzer, site, callable, &documentation, source)
            }
            _ => Decision::Fails,
        },
    };
    // Eligibility asks for the method family, which can be unproven; consult
    // it only for a callable whose documentation would otherwise match.
    documented.and(|| callable_is_eligible(analyzer, site, callable, source))
}

fn undocumented_parameter(
    analyzer: &dyn IAnalyzer,
    sites: &[DeclarationSite],
    parameter: Node<'_>,
    source: &str,
) -> Decision {
    let Some(callable) = enclosing_callable(parameter) else {
        return Decision::Fails;
    };
    let Some(site) = site_for(sites, callable) else {
        return Decision::Fails;
    };
    let Some(documentation) = documentation(callable, source) else {
        return Decision::Fails;
    };
    if !documentation.complete {
        return Decision::Fails;
    }
    let Some(name) = parameter_name(parameter, source) else {
        return Decision::Fails;
    };
    Decision::from_bool(!documentation.tags.iter().any(|tag| {
        tag.kind == JavadocTagKind::Param
            && tag.name.as_deref() == Some(name.as_str())
            && tag.acceptable
    }))
    .and(|| callable_is_eligible(analyzer, site, callable, source))
}

fn callable_unknown_parameter_tags(
    sites: &[DeclarationSite],
    callable: Node<'_>,
    source: &str,
) -> Vec<Range> {
    let Some(site) = site_for(sites, callable) else {
        return Vec::new();
    };
    if site.unit.is_synthetic() {
        return Vec::new();
    }
    let Some(documentation) = documentation(callable, source) else {
        return Vec::new();
    };
    if !documentation.complete {
        return Vec::new();
    }
    let actual_parameters = parameter_names(callable, source);
    let type_parameters = type_parameter_names(callable, source);
    documentation
        .tags
        .iter()
        .filter(|tag| {
            tag.kind == JavadocTagKind::Param
                && tag.name.as_deref().is_none_or(|name| {
                    !actual_parameters.iter().any(|actual| actual == name)
                        && !type_parameters.iter().any(|actual| actual == name)
                })
        })
        .map(|tag| javadoc_tag_range(callable, source, tag))
        .collect()
}

fn unknown_type_parameter_tag(
    sites: &[DeclarationSite],
    declaration: Node<'_>,
    source: &str,
) -> Vec<Range> {
    let Some(site) = site_for(sites, declaration) else {
        return Vec::new();
    };
    if site.unit.is_synthetic() {
        return Vec::new();
    }
    let Some(documentation) = documentation(declaration, source) else {
        return Vec::new();
    };
    if !documentation.complete {
        return Vec::new();
    }
    let mut valid = type_parameter_names(declaration, source);
    if declaration.kind() == "record_declaration" {
        valid.extend(parameter_names_from_field(declaration, source));
    }
    documentation
        .tags
        .iter()
        .filter(|tag| {
            tag.kind == JavadocTagKind::Param
                && tag
                    .name
                    .as_deref()
                    .is_none_or(|name| !valid.iter().any(|actual| actual == name))
        })
        .map(|tag| javadoc_tag_range(declaration, source, tag))
        .collect()
}

fn javadoc_tag_range(
    declaration: Node<'_>,
    source: &str,
    tag: &brokk_bifrost_jvm::java::javadoc::JavadocTagFact,
) -> Range {
    let comment = preceding_javadoc_comment(declaration, source)
        .expect("documentation tags belong to a preceding Javadoc comment");
    let offset = comment.start_byte();
    let start_byte = offset + tag.start_byte;
    let end_byte = offset + tag.end_byte;
    let line_at = |offset: usize| {
        comment.start_position().row + 1 + source[comment.start_byte()..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
    };
    Range {
        start_byte,
        end_byte,
        start_line: line_at(start_byte),
        end_line: line_at(end_byte),
    }
}

fn undocumented_exception(
    analyzer: &dyn IAnalyzer,
    site: &DeclarationSite,
    callable: Node<'_>,
    documentation: &JavadocBlockFacts,
    source: &str,
) -> Decision {
    let mut unclassified = false;
    for (type_node, name) in declared_throws(callable, source) {
        let documented = documentation.tags.iter().any(|tag| {
            tag.kind == JavadocTagKind::Throws
                && tag.terminal_name.as_deref() == type_terminal(&name)
                && tag.acceptable
        });
        if documented {
            continue;
        }
        match exception_status(analyzer, site.unit.source(), source, type_node, &name) {
            ExceptionStatus::Checked => return Decision::Holds,
            ExceptionStatus::Unchecked => {}
            ExceptionStatus::Unknown => unclassified = true,
        }
    }
    if unclassified {
        Decision::Undecided(
            "an undocumented declared exception is not classified as checked or unchecked",
        )
    } else {
        Decision::Fails
    }
}

fn callable_inconsistent_throws(
    analyzer: &dyn IAnalyzer,
    sites: &[DeclarationSite],
    callable: Node<'_>,
    source: &str,
    undecided: &mut Vec<UndecidedSite>,
) -> Vec<Range> {
    let Some(site) = site_for(sites, callable) else {
        return Vec::new();
    };
    let Some(documentation) = documentation(callable, source) else {
        return Vec::new();
    };
    if !documentation.complete {
        return Vec::new();
    }
    let mut unresolved = None;
    let reported = inconsistent_throws(
        analyzer,
        site,
        callable,
        &documentation,
        source,
        &mut unresolved,
    );
    if reported.is_empty() && unresolved.is_none() {
        return Vec::new();
    }
    match callable_is_eligible(analyzer, site, callable, source) {
        Decision::Holds => {
            if let Some(reason) = unresolved {
                undecided.push(UndecidedSite::at(node_range(callable), reason));
            }
            reported
        }
        Decision::Fails => Vec::new(),
        Decision::Undecided(reason) => {
            undecided.push(UndecidedSite::at(
                node_range(callable),
                unresolved.unwrap_or(reason),
            ));
            Vec::new()
        }
    }
}

fn inconsistent_throws(
    analyzer: &dyn IAnalyzer,
    site: &DeclarationSite,
    callable: Node<'_>,
    documentation: &JavadocBlockFacts,
    source: &str,
    undecided: &mut Option<&'static str>,
) -> Vec<Range> {
    let declared = declared_throws(callable, source);
    let statuses = declared
        .iter()
        .map(|(type_node, name)| {
            let status = exception_status(analyzer, site.unit.source(), source, *type_node, name);
            (name.as_str(), status)
        })
        .collect::<Vec<_>>();
    let declares_checked = statuses
        .iter()
        .any(|(_, status)| *status == ExceptionStatus::Checked);
    let declares_unclassified = statuses
        .iter()
        .any(|(_, status)| *status == ExceptionStatus::Unknown);
    let mut reported = Vec::new();
    for tag in &documentation.tags {
        if tag.kind != JavadocTagKind::Throws {
            continue;
        }
        let Some(tag_name) = tag.terminal_name.as_deref() else {
            continue;
        };
        if known_unchecked(tag_name) {
            continue;
        }
        if !known_checked(tag_name) && !declares_checked {
            // The tagged type is neither a known JDK type nor comparable to
            // a declared checked exception, so its own classification
            // decides the relation and nothing here supplies it.
            undecided
                .get_or_insert("a documented exception is not classified as checked or unchecked");
            continue;
        }
        let consistent = statuses.iter().any(|(declared_name, status)| {
            *status == ExceptionStatus::Checked && type_names_possible(declared_name, tag_name)
        });
        if consistent {
            continue;
        }
        if declares_unclassified {
            undecided
                .get_or_insert("a declared exception is not classified as checked or unchecked");
            continue;
        }
        reported.push(javadoc_tag_range(callable, source, tag));
    }
    reported
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
    .next() else {
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
    let answer = provider.get_ancestors(class);
    if !answer.is_complete() {
        return ExceptionStatus::Unknown;
    }
    let ancestors = answer.definite();
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
) -> Decision {
    if !is_public(site) || is_generated(site, callable, source) {
        return Decision::Fails;
    }
    if is_getter_or_setter(callable, source) {
        return Decision::Fails;
    }
    let Some(provider) = analyzer.member_family_provider() else {
        return Decision::Undecided("no method-family provider can rule out an override");
    };
    let family = provider.member_family(&site.unit, None);
    if !family.ancestors.is_proven() {
        return Decision::Undecided(
            "the method family is not proven, so an override is not ruled out",
        );
    }
    Decision::from_bool(!family.edges.iter().any(|edge| {
        matches!(
            edge.relation,
            MethodFamilyRelation::Overrides | MethodFamilyRelation::Implements
        )
    }))
}

fn is_public(site: &DeclarationSite) -> bool {
    !site.metadata.is_empty()
        && site.metadata.iter().all(|metadata| {
            metadata.callable_declared_visibility() == Some(DeclaredVisibility::Public)
        })
}

fn is_generated(site: &DeclarationSite, node: Node<'_>, source: &str) -> bool {
    site.unit.is_synthetic()
        || descendants(node).into_iter().any(|candidate| {
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

fn declared_throws<'tree>(callable: Node<'tree>, source: &str) -> Vec<(Node<'tree>, String)> {
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
    java_type_name_components(node, source).and_then(|components| components.last().cloned())
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
        .or_else(|| {
            (parameter.kind() == "spread_parameter")
                .then(|| {
                    named_children(parameter)
                        .into_iter()
                        .find(|child| child.kind() == "variable_declarator")
                        .and_then(|declarator| declarator.child_by_field_name("name"))
                })
                .flatten()
        })
        .and_then(|name| source.get(name.byte_range()))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn parameter_nodes(callable: Node<'_>) -> Vec<Node<'_>> {
    let parameters = callable.child_by_field_name("parameters").or_else(|| {
        (callable.kind() == "compact_constructor_declaration")
            .then(|| {
                callable
                    .parent()?
                    .parent()?
                    .child_by_field_name("parameters")
            })
            .flatten()
    });
    parameters
        .into_iter()
        .flat_map(|parameters| {
            let mut cursor = parameters.walk();
            parameters
                .named_children(&mut cursor)
                .filter(|parameter| {
                    matches!(parameter.kind(), "formal_parameter" | "spread_parameter")
                })
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
