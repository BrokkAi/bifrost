//! Java structural spec for `query_code`.
//!
//! This maps tree-sitter-java node types to Bifrost's normalized structural
//! vocabulary and extracts role edges from AST fields.

use super::string_literal::decoded_string_literal_value;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_decorators_under, attach_positional_argument_roles, attach_role_with_derived_name,
    attach_terminal_callee, field_name_in_parent, first_named_child, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    chain_name_child, linear_chain_tokens, qualified_path_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_CALLABLE_APPLICABILITY,
    HoistingClass, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseIndex, CallResultUseOpenReason, CallResultUseSite,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{
    ImplicitScopeBinder, RoleSink, StructuralSpec,
};
use brokk_bifrost_core::analyzer::tree_walk::last_named_child;
use brokk_bifrost_core::analyzer::tree_walk::named_children_iter;
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified-name chains of the Java grammar, paired with the
/// field that names each link's own segment.
const JAVA_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("scoped_identifier", Some("name")),
    ("scoped_type_identifier", None),
];

#[derive(Debug, Default)]
pub struct JavaStructuralSpec;

pub static JAVA_STRUCTURAL_SPEC: JavaStructuralSpec = JavaStructuralSpec;

/// Whether Java syntax directly discards an invocation's normal result.
///
/// The caller must pass the call node from the prepared tree for the exact
/// source snapshot it is analyzing. An invocation used by an argument,
/// initializer, return, or condition is consumed, even if the enclosing
/// expression is later discarded. Recovered syntax and method references do
/// not establish a result-use fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaCallResultUse {
    Discarded,
    /// Another syntax context. It may consume the result or discard it by a
    /// separate construct; this proof makes no claim beyond the recognized
    /// expression-statement and `for` initializer/update shapes.
    OtherContext,
}

/// Why an exact structural call cannot prove its result-use role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaCallResultUseOpen {
    MissingCall,
    AmbiguousCall,
    UnclassifiedSyntax,
}

/// One exact AST call span in a prepared Java source snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JavaCallResultUseSite {
    start_byte: usize,
    end_byte: usize,
    result_use: Option<JavaCallResultUse>,
}

/// Index every invocation once. Callers must build this from the prepared tree
/// for the same immutable source snapshot as their structural/semantic rows.
pub struct JavaCallResultUseIndex {
    sites: Vec<JavaCallResultUseSite>,
}

impl JavaCallResultUseIndex {
    pub fn new(root: Node<'_>) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "method_invocation" | "object_creation_expression" | "method_reference"
            ) {
                sites.push(JavaCallResultUseSite {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    result_use: java_call_result_use(node),
                });
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        sites.sort_unstable_by_key(|site| (site.start_byte, site.end_byte));
        Self { sites }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<JavaCallResultUse, JavaCallResultUseOpen> {
        let key = (start_byte, end_byte);
        let start = self
            .sites
            .partition_point(|site| (site.start_byte, site.end_byte) < key);
        let end = self
            .sites
            .partition_point(|site| (site.start_byte, site.end_byte) <= key);
        match &self.sites[start..end] {
            [] => Err(JavaCallResultUseOpen::MissingCall),
            [site] => site
                .result_use
                .ok_or(JavaCallResultUseOpen::UnclassifiedSyntax),
            _ => Err(JavaCallResultUseOpen::AmbiguousCall),
        }
    }
}

/// The shared result-use adapter for Java. The legacy index above remains
/// available to Java's lambda/result-conversion analysis, while RQL consumes
/// this language-neutral index for the exact call-result-use relation.
#[derive(Debug, Clone)]
pub struct JavaCallResultUseRelationIndex {
    inner: CallResultUseIndex,
}

impl JavaCallResultUseRelationIndex {
    pub fn new(root: Node<'_>) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "method_invocation" | "object_creation_expression" | "method_reference"
            ) {
                sites.push(java_call_result_use_site(node));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        Self {
            inner: CallResultUseIndex::new(sites),
        }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        self.inner.at_span(start_byte, end_byte)
    }
}

/// Convert Java's established syntax result into the shared relation without
/// changing the legacy Java-facing enum used by typed lambda analysis.
pub fn java_call_result_use_site(call: Node<'_>) -> CallResultUseSite {
    let result_use = match java_call_result_use(call) {
        Some(JavaCallResultUse::Discarded) => CallResultUse::Discarded,
        Some(JavaCallResultUse::OtherContext) => CallResultUse::Consumed,
        None => CallResultUse::Open(CallResultUseOpenReason::UnclassifiedSyntax),
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), result_use)
}

pub fn java_call_result_use(call: Node<'_>) -> Option<JavaCallResultUse> {
    if !matches!(
        call.kind(),
        "method_invocation" | "object_creation_expression"
    ) || call.has_error()
    {
        return None;
    }
    let mut expression = call;
    while let Some(parent) = expression.parent() {
        if parent.has_error() {
            return None;
        }
        // An expression lambda may adapt the same invocation to either a
        // value-returning or void functional method. Syntax alone cannot
        // establish whether that adapter discards the result.
        if parent.kind() == "lambda_expression" {
            return None;
        }
        if parent.kind() == "parenthesized_expression"
            && parent.named_child_count() == 1
            && parent
                .named_child(0)
                .is_some_and(|child| child.id() == expression.id())
        {
            expression = parent;
            continue;
        }
        return Some(
            if parent.kind() == "expression_statement"
                && parent.named_child_count() == 1
                && parent
                    .named_child(0)
                    .is_some_and(|child| child.id() == expression.id())
                && !java_switch_rule_value_expression_statement(parent)
                || parent.kind() == "for_statement"
                    && matches!(
                        field_name_in_parent(parent, expression),
                        Some("init" | "update")
                    )
            {
                JavaCallResultUse::Discarded
            } else {
                JavaCallResultUse::OtherContext
            },
        );
    }
    None
}

/// A switch rule's expression statement can produce the enclosing switch
/// expression's value. It is not a discarded statement result in that role.
pub fn java_switch_rule_value_expression_statement(node: Node<'_>) -> bool {
    if !node
        .parent()
        .is_some_and(|parent| parent.kind() == "switch_rule")
    {
        return false;
    }
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "switch_expression" {
            return current
                .parent()
                .is_some_and(|parent| !java_parent_statement_body(parent, current));
        }
        ancestor = current.parent();
    }
    false
}

pub fn java_parent_statement_body(parent: Node<'_>, node: Node<'_>) -> bool {
    match parent.kind() {
        "block" | "constructor_body" | "program" | "switch_block_statement_group" => true,
        "if_statement" => ["consequence", "alternative"].into_iter().any(|field| {
            parent
                .child_by_field_name(field)
                .is_some_and(|child| child.id() == node.id())
        }),
        "while_statement"
        | "do_statement"
        | "for_statement"
        | "enhanced_for_statement"
        | "switch_rule" => parent
            .child_by_field_name("body")
            .is_some_and(|body| body.id() == node.id()),
        "labeled_statement" => {
            let mut cursor = parent.walk();
            parent
                .named_children(&mut cursor)
                .any(|child| child.id() == node.id() && child.kind() != "identifier")
        }
        _ => false,
    }
}

pub const JAVA_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("binary_expression", NormalizedKind::BinaryExpression),
    ("ternary_expression", NormalizedKind::If),
    ("switch_expression", NormalizedKind::Switch),
    ("switch_label", NormalizedKind::Case),
    ("switch_rule", NormalizedKind::Case),
    ("labeled_statement", NormalizedKind::Label),
    ("break_statement", NormalizedKind::Break),
    ("continue_statement", NormalizedKind::Continue),
    ("cast_expression", NormalizedKind::Cast),
    ("instanceof_expression", NormalizedKind::InstanceOf),
    ("array_access", NormalizedKind::Subscript),
    ("array_creation_expression", NormalizedKind::ArrayCreation),
    ("unary_expression", NormalizedKind::UnaryExpression),
    ("synchronized_statement", NormalizedKind::Lock),
    ("line_comment", NormalizedKind::Comment),
    ("block_comment", NormalizedKind::Comment),
    ("method_invocation", NormalizedKind::Call),
    ("method_reference", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    // The implicit `close` of a try-with-resources statement runs at the
    // construct's own exit, so the statement is the source fact the
    // resource-lifecycle selector names for that release.
    (
        "try_with_resources_statement",
        NormalizedKind::ResourceRelease,
    ),
    ("field_access", NormalizedKind::FieldAccess),
    ("method_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    (
        "compact_constructor_declaration",
        NormalizedKind::Constructor,
    ),
    ("lambda_expression", NormalizedKind::Lambda),
    ("formal_parameter", NormalizedKind::Parameter),
    ("spread_parameter", NormalizedKind::Parameter),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("annotation_type_declaration", NormalizedKind::Class),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("import_declaration", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    // tree-sitter-java recovers the pre-Java-9 underscore spelling as a
    // named pattern node. Keep it in the identifier fact domain so language
    // rules can distinguish its declaration role from ordinary uses.
    ("underscore_pattern", NormalizedKind::Identifier),
    ("type_identifier", NormalizedKind::Identifier),
    ("scoped_identifier", NormalizedKind::Identifier),
    ("scoped_type_identifier", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("decimal_integer_literal", NormalizedKind::NumericLiteral),
    ("hex_integer_literal", NormalizedKind::NumericLiteral),
    ("octal_integer_literal", NormalizedKind::NumericLiteral),
    ("binary_integer_literal", NormalizedKind::NumericLiteral),
    (
        "decimal_floating_point_literal",
        NormalizedKind::NumericLiteral,
    ),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::Loop),
    ("enhanced_for_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
    // Java scopes statements with `block`; `switch_block` is the statement
    // list of a switch, and both are separate nodes from the callable, class,
    // and loop declarations that already become facts.
    ("array_initializer", NormalizedKind::CollectionLiteral),
    ("block", NormalizedKind::Block),
    ("switch_block", NormalizedKind::Block),
    ("annotation", NormalizedKind::Decorator),
    ("marker_annotation", NormalizedKind::Decorator),
];

pub fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" | "this" | "super" => return Some(current),
            "scoped_identifier" | "scoped_type_identifier" => {
                current = current
                    .child_by_field_name("name")
                    .or_else(|| last_named_child(current))?;
            }
            "generic_type" => {
                current = current
                    .child_by_field_name("type")
                    .or_else(|| first_named_child(current))?;
            }
            "field_access" => current = current.child_by_field_name("field")?,
            "method_invocation" => current = current.child_by_field_name("name")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "annotation" | "marker_annotation" => current = current.child_by_field_name("name")?,
            _ => return None,
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    attach_decorators_under(
        sink,
        declaration,
        "modifiers",
        &["annotation", "marker_annotation"],
        expression_name_node,
    );
}

static JAVA_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

/// The declaration heads whose `name` field is the declared symbol itself.
const JAVA_DECLARATION_HEADS: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
    "method_declaration",
    "constructor_declaration",
    "compact_constructor_declaration",
    "annotation_type_element_declaration",
    "enum_constant",
    "type_parameter",
];

/// The binding forms whose `name` field introduces a fresh local binding.
const JAVA_BINDER_HEADS: &[&str] = &[
    "formal_parameter",
    "spread_parameter",
    "catch_formal_parameter",
    "resource",
    "variable_declarator",
    "enhanced_for_statement",
];

/// Classify one Java identifier token by its AST position.
///
/// Compound `scoped_identifier`/`scoped_type_identifier` nodes are *not*
/// classified: an occurrence is a token, so the chain contributes its segments
/// (`PathSegment`) and its tail (the role the whole chain plays in context),
/// never a third row spanning both.
fn java_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if !matches!(
        node.kind(),
        "identifier" | "type_identifier" | "underscore_pattern"
    ) {
        return None;
    }

    if crate::type_parameters::is_name(node, brokk_bifrost_core::analyzer::Language::Java) {
        return Some(OccurrenceRole::DeclarationName);
    }

    // Climb out of any qualified-name chain this token terminates. A token in
    // a `scope` position is a path segment however deep the chain runs. Which
    // child spells the chain node's own segment comes from `JAVA_PATH_CHAIN`,
    // the same table `qualified_path_root` and `path_segment_tokens` read:
    // `scoped_identifier` names it in a field, `scoped_type_identifier` has no
    // fields at all and spells it positionally as the last named child, so a
    // field lookup there is false for the tail as well as for the scope and
    // would classify a whole qualified type as path segments (#1644).
    let mut anchor = node;
    let mut parent = anchor.parent()?;
    while let Some(&(_, name_field)) = JAVA_PATH_CHAIN
        .iter()
        .find(|(kind, _)| *kind == parent.kind())
    {
        if chain_name_child(parent, name_field).map(|name| name.id()) != Some(anchor.id()) {
            return Some(OccurrenceRole::PathSegment);
        }
        anchor = parent;
        parent = anchor.parent()?;
    }

    let field = field_name_in_parent(parent, anchor);
    let parent_kind = parent.kind();
    let role = match parent_kind {
        "import_declaration" => OccurrenceRole::ImportTarget,
        "package_declaration" => OccurrenceRole::DeclarationName,
        "annotation" | "marker_annotation" if field == Some("name") => OccurrenceRole::TypeOperand,
        "element_value_pair" if field == Some("key") => OccurrenceRole::LabelOrKey,
        "labeled_statement" | "break_statement" | "continue_statement" => {
            OccurrenceRole::LabelOrKey
        }
        "method_invocation" => match field {
            Some("name") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "field_access" => match field {
            Some("field") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "object_creation_expression" if field == Some("type") => OccurrenceRole::TypeOperand,
        _ if field == Some("name") && JAVA_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        _ if field == Some("name") && JAVA_BINDER_HEADS.contains(&parent_kind) => {
            OccurrenceRole::Binder
        }
        // `(a, b) -> ...` binds through `inferred_parameters`, and `a -> ...`
        // binds through the lambda's own `parameters` field.
        "inferred_parameters" => OccurrenceRole::Binder,
        "lambda_expression" if field == Some("parameters") => OccurrenceRole::Binder,
        // Every remaining `type_identifier` position in Java is a type operand
        // (extends/implements clauses, generic arguments, casts, throws,
        // annotated types); every remaining `identifier` is a value read.
        _ if node.kind() == "type_identifier"
            || matches!(anchor.kind(), "type_identifier" | "scoped_type_identifier") =>
        {
            OccurrenceRole::TypeOperand
        }
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// The binding one Java binder token introduces, and the interval it is in
/// effect over.
///
/// Java has five binder shapes and they differ only in that interval:
///
/// - A formal or lambda parameter is in effect over its whole callable, which
///   is exactly the declaring scope, so it is `ScopeWide`. This is what makes a
///   parameter reachable from inside the body block even though the parameter
///   list sits outside that block's byte range.
/// - A local is in effect from the end of its declaration statement to the end
///   of its block (`SourceOrder`), which is why a read above the declaration
///   reaches nothing.
/// - A `catch` parameter is in effect over the catch clause's body, and a
///   try-with-resources resource over the try block — both `DeclaredHead`,
///   because the interval is a named sub-range of the declaring scope rather
///   than a suffix of it.
/// - An enhanced-for variable is in effect over the statement in its `body`
///   field. The iterable expression is outside that interval, so it cannot
///   resolve to the variable being declared.
pub(super) fn java_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "formal_parameter"
                | "spread_parameter"
                | "receiver_parameter"
                | "inferred_parameters"
                | "lambda_expression"
                | "catch_formal_parameter"
                | "resource"
                | "variable_declarator"
                | "enhanced_for_statement"
                | "type_pattern"
        )
    })?;
    // A varargs name sits inside a variable_declarator, but it introduces a
    // parameter just like a name directly inside a formal_parameter.
    let form = form
        .parent()
        .filter(|parent| parent.kind() == "spread_parameter")
        .unwrap_or(form);
    match form.kind() {
        "formal_parameter"
        | "spread_parameter"
        | "receiver_parameter"
        | "inferred_parameters"
        | "lambda_expression" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "catch_formal_parameter" => {
            let clause = nearest_ancestor(form, |kind| kind == "catch_clause")?;
            let body = clause.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "resource" => {
            let statement = nearest_ancestor(form, |kind| kind == "try_with_resources_statement")?;
            let body = statement.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "enhanced_for_statement" => {
            let body = form.child_by_field_name("body")?;
            // A recovered header or body cannot establish this binder's interval.
            if form.has_error() || binder.is_missing() || body.is_missing() {
                return None;
            }
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "type_pattern" => {
            // `if (o instanceof String s)` binds `s` for the guarded branch.
            // The grammar does not mark that branch, so the honest interval is
            // the enclosing condition's statement, which the pattern's nearest
            // statement ancestor states exactly.
            let statement = nearest_ancestor(form, |kind| {
                matches!(kind, "if_statement" | "while_statement" | "do_statement")
            })?;
            Some(BindingActivation {
                kind: BindingKind::PatternBinder,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(statement),
            })
        }
        _ => {
            // A local declarator: in effect from the end of the statement that
            // declares it. A `for` init declaration ends before the condition,
            // so the loop's own header sees the variable.
            let declaration =
                nearest_ancestor(form, |kind| kind == "local_variable_declaration").unwrap_or(form);
            Some(BindingActivation {
                kind: BindingKind::Local,
                hoisting: HoistingClass::SourceOrder,
                activation: Range {
                    start_byte: declaration.end_byte(),
                    end_byte: scope.end_byte,
                    start_line: declaration.end_position().row + 1,
                    end_line: scope.end_line,
                },
            })
        }
    }
}

impl StructuralSpec for JavaStructuralSpec {
    fn language(&self) -> Language {
        Language::Java
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value_may_be_absent(&self, node: Node<'_>, source: &str) -> bool {
        // The shared decoder also abstains on unsupported escapes and UTF-16
        // surrogate values that cannot be represented as a Rust string.
        node.kind() == "string_literal" && decoded_string_literal_value(node, source).is_none()
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        decoded_string_literal_value(node, source)
    }

    fn declaration_attributes(
        &self,
        node: Node<'_>,
        _source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes> {
        let type_kind = match node.kind() {
            "class_declaration" => Some("class"),
            "interface_declaration" => Some("interface"),
            "enum_declaration" => Some("enum"),
            "record_declaration" => Some("record"),
            "annotation_type_declaration" => Some("annotation"),
            _ => None,
        };
        let owner = match node.kind() {
            "variable_declarator" => node.parent()?,
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "formal_parameter"
            | "spread_parameter" => node,
            _ if type_kind.is_some() => node,
            _ => return None,
        };
        Some(
            brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes {
                modifiers: super::declarations::java_modifier_keywords(owner)
                    .map(str::to_owned)
                    .collect(),
                type_kind: type_kind.map(str::to_owned),
            },
        )
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &brokk_bifrost_core::analyzer::structural::callable::CallSiteContext,
    ) -> NormalizedKind {
        if node.kind() == "variable_declarator" && node.child_by_field_name("value").is_none() {
            return NormalizedKind::Declaration;
        }
        if kind == NormalizedKind::BinaryExpression
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(operator.kind(), "==" | "!=" | "<" | ">" | "<=" | ">=")
                })
        {
            NormalizedKind::Comparison
        } else {
            kind
        }
    }

    fn statement_fact_syntax(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::statement_facts::producer::StatementFactSyntax>
    {
        Some(self)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        JAVA_KIND_TABLE
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_kind_from_table(
            kind,
            &[
                NormalizedKind::SyntaxError,
                NormalizedKind::Comparison,
                NormalizedKind::Declaration,
                NormalizedKind::RegexPattern,
                NormalizedKind::RegexSequence,
                NormalizedKind::RegexGroup,
                NormalizedKind::RegexAlternation,
                NormalizedKind::RegexCharacterClass,
                NormalizedKind::RegexCharacterRange,
                NormalizedKind::RegexQuantifier,
                NormalizedKind::RegexAnchor,
                NormalizedKind::RegexEscape,
                NormalizedKind::RegexLiteral,
                NormalizedKind::RegexWildcard,
                NormalizedKind::RegexRiskHostname,
                NormalizedKind::RegexRiskRange,
                NormalizedKind::RegexRiskBadTag,
                NormalizedKind::RegexRiskExponential,
                NormalizedKind::RegexIncomplete,
                NormalizedKind::RegexRiskBackspaceEscape,
                NormalizedKind::RegexRiskDuplicateClassCharacter,
                NormalizedKind::RegexRiskUnmatchableCaret,
                NormalizedKind::RegexRiskUnmatchableDollar,
                NormalizedKind::RegexRiskIncompleteSpecialGroup,
                NormalizedKind::RegexRiskPolynomial,
            ],
            self.kind_table(),
        )
    }

    fn embedded_leaf_facts(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        source: &str,
        _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Vec<brokk_bifrost_core::analyzer::structural::spec::EmbeddedLeafFact> {
        // An enclosing top-level type contains every lexical constant source
        // used by its calls, including constants outside the call expression.
        if kind == NormalizedKind::Class && node.parent().is_some_and(|p| p.kind() == "program") {
            super::regex::file_facts(node, source)
        } else {
            Vec::new()
        }
    }

    // A valueless variable_declarator is not filtered here: should_extract
    // sees the table kind (Assignment) before refine_kind runs, and
    // refine_kind records that declarator as a Declaration.
    fn should_extract(&self, node: Node<'_>, _kind: NormalizedKind) -> bool {
        node.kind() != "switch_label"
            || !node
                .parent()
                .is_some_and(|parent| parent.kind() == "switch_rule")
    }

    fn generator_construct(
        &self,
        node: Node<'_>,
        _kind: NormalizedKind,
        _source: &str,
    ) -> Option<&'static str> {
        match node.kind() {
            "method_reference" => Some("java_method_reference"),
            "object_creation_expression" => Some("java_object_creation"),
            _ => None,
        }
    }

    fn supports_role(&self, role: Role) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_role_without_kwarg(role)
    }

    /// Java spells its non-ordinary call shapes as distinct grammar nodes, so
    /// the classification is a node-type reading with no source-text work:
    /// `new T(x)` is an `object_creation_expression` and `T::f` a
    /// `method_reference`, which names a callable without applying it
    /// (#1478). `this(x)`/`super(x)` stay unclassified because
    /// `explicit_constructor_invocation` is not in this adapter's kind table,
    /// so those sites are not call facts at all.
    fn call_site_facts(
        &self,
        node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        match node.kind() {
            "object_creation_expression" => Some(CallSiteFacts::of_kind(CallKind::Constructor)),
            "method_reference" => Some(CallSiteFacts::of_kind(CallKind::MethodValue)),
            _ => None,
        }
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &JAVA_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_CALLABLE_APPLICABILITY
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // Java has no export, re-export, partial, or header/body construct;
        // its indirections are imports and nested owners.
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn implicit_scope_binders<'tree>(
        &self,
        scope_node: Node<'tree>,
    ) -> Option<Vec<ImplicitScopeBinder<'tree>>> {
        if scope_node.kind() != "compact_constructor_declaration" {
            return Some(Vec::new());
        }
        // JLS 8.10.4.2: the compact constructor inherits the record header's
        // component parameters.
        let record = scope_node.parent()?.parent()?;
        if record.kind() != "record_declaration" {
            return None;
        }
        let components =
            super::declarations::java_record_components(record.child_by_field_name("parameters")?)
                .ok()?;
        Some(
            components
                .into_iter()
                .map(|component| ImplicitScopeBinder {
                    name: component.name,
                })
                .collect(),
        )
    }

    fn type_parameter_owner<'tree>(&self, name: Node<'tree>) -> Option<Node<'tree>> {
        crate::type_parameters::owner(name, brokk_bifrost_core::analyzer::Language::Java)
    }

    fn type_parameter_scope_barrier(&self, owner: Node<'_>) -> bool {
        crate::type_parameters::barrier(owner, brokk_bifrost_core::analyzer::Language::Java)
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        java_binding_activation(binder, scope)
    }

    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        qualified_path_chain_root(token, JAVA_PATH_CHAIN)
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        linear_chain_tokens(root, JAVA_PATH_CHAIN, &[])
    }

    fn segment_generic_arity(&self, token: Node<'_>) -> Option<u32> {
        spelled_generic_arity(token, JAVA_PATH_CHAIN, &["generic_type"])
    }

    fn indirection_relation(
        &self,
        token: Node<'_>,
        _source: &str,
        _surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        nearest_ancestor(token, |kind| kind == "import_declaration").map(|_| RouteHopKind::Import)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = java_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        use brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles;
        let fields: &[(Role, &str)] = match kind {
            NormalizedKind::BinaryExpression | NormalizedKind::Comparison => &[
                (Role::Left, "left"),
                (Role::Right, "right"),
                (Role::Operator, "operator"),
            ],
            NormalizedKind::Assignment => &[(Role::Operator, "operator")],
            NormalizedKind::If => &[
                (Role::Test, "condition"),
                (Role::Consequence, "consequence"),
                (Role::Alternative, "alternative"),
            ],
            NormalizedKind::Switch => &[(Role::Test, "condition"), (Role::Body, "body")],
            NormalizedKind::Cast => &[(Role::Type, "type"), (Role::Value, "value")],
            NormalizedKind::InstanceOf => &[
                (Role::Operand, "left"),
                (Role::Type, "right"),
                (Role::Binding, "name"),
                (Role::Binding, "pattern"),
            ],
            NormalizedKind::Subscript => &[(Role::Object, "array"), (Role::Indices, "index")],
            NormalizedKind::ArrayCreation => &[
                (Role::Type, "type"),
                (Role::Dimensions, "dimensions"),
                (Role::Value, "value"),
            ],
            NormalizedKind::UnaryExpression => {
                &[(Role::Operator, "operator"), (Role::Operand, "operand")]
            }
            NormalizedKind::Lock => &[(Role::Body, "body")],
            _ => &[],
        };
        attach_field_roles(sink, node, fields, expression_name_node);
        match kind {
            NormalizedKind::Lock => {
                if let Some(value) = named_children_iter(node)
                    .find(|child| child.kind() == "parenthesized_expression")
                {
                    attach_role_with_derived_name(
                        sink,
                        Role::Value,
                        brokk_bifrost_core::analyzer::tree_walk::expression_target_node(value),
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Label | NormalizedKind::Break | NormalizedKind::Continue => {
                for child in named_children_iter(node) {
                    if child.kind() == "identifier" {
                        sink.role_named(Role::Label, child, child);
                    } else if !child.is_extra() {
                        sink.role(Role::Body, child);
                    }
                }
            }
            NormalizedKind::Case => {
                for child in named_children_iter(node).filter(|child| !child.is_extra()) {
                    if node.kind() == "switch_rule" && child.kind() == "switch_label" {
                        for test in named_children_iter(child).filter(|test| !test.is_extra()) {
                            sink.role(Role::Test, test);
                        }
                    } else if node.kind() == "switch_rule" {
                        sink.role(Role::Body, child);
                    } else {
                        sink.role(Role::Test, child);
                    }
                }
            }
            _ => {}
        }
        match kind {
            NormalizedKind::Call => {
                match node.kind() {
                    "method_invocation" => {
                        if let Some(name) = node.child_by_field_name("name") {
                            attach_terminal_callee(sink, name, Some(name));
                        }
                        if let Some(object) = node.child_by_field_name("object") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Receiver,
                                object,
                                expression_name_node,
                            );
                        }
                    }
                    "object_creation_expression" => {
                        if let Some(type_node) = node.child_by_field_name("type") {
                            attach_role_with_derived_name(
                                sink,
                                Role::Callee,
                                type_node,
                                expression_name_node,
                            );
                            if let Some(name) = expression_name_node(type_node) {
                                sink.set_name(name);
                            }
                        }
                    }
                    "method_reference" => {
                        let mut cursor = node.walk();
                        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                        if let Some((member, receivers)) = children.split_last()
                            && let Some(receiver) = receivers.last()
                        {
                            attach_terminal_callee(sink, *member, Some(*member));
                            attach_role_with_derived_name(
                                sink,
                                Role::Receiver,
                                *receiver,
                                expression_name_node,
                            );
                        }
                    }
                    _ => {}
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_positional_argument_roles(sink, arguments, expression_name_node);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(field) = node.child_by_field_name("field") {
                    sink.set_name(field);
                    sink.role_named(Role::Field, field, field);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Declaration
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Parameter => {
                let name = if node.kind() == "spread_parameter" {
                    super::declarations::spread_parameter_name(node)
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(name) = name {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.set_name(name);
                        sink.role_named(Role::Left, name, name);
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(
                        child.kind(),
                        "identifier" | "scoped_identifier" | "field_access"
                    ) {
                        sink.role_named(Role::Module, child, child);
                        break;
                    }
                }
            }
            NormalizedKind::Identifier => match node.kind() {
                "scoped_identifier" | "scoped_type_identifier" => {
                    if let Some(name) = node
                        .child_by_field_name("name")
                        .or_else(|| last_named_child(node))
                    {
                        sink.set_name(name);
                    }
                }
                _ => sink.set_name(node),
            },
            NormalizedKind::Decorator => {
                if let Some(name) = expression_name_node(node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::Lambda => {
                attach_decorators(sink, node);
            }
            NormalizedKind::ForLoop => {
                if let Some(value) = node.child_by_field_name("value") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Iterable,
                        value,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::CollectionLiteral => {
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if matches!(child.kind(), "line_comment" | "block_comment") {
                        continue;
                    }
                    attach_role_with_derived_name(sink, Role::Element, child, expression_name_node);
                }
            }
            _ => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
        }
    }
}

/// The identifier introduced by one Java pattern node, without inferring its scope.
pub fn java_pattern_binding_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "instanceof_expression" => node.child_by_field_name("name"),
        "type_pattern" | "record_pattern_component" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "identifier")
        }
        _ => None,
    }
}

/// Reverse the existing pattern inventory hook for lexical identity lookup.
pub fn java_pattern_binding_declaration(name: Node<'_>) -> Option<Node<'_>> {
    let pattern = name.parent()?;
    (java_pattern_binding_name(pattern) == Some(name)).then_some(pattern)
}

/// A switch arm is a separate declaration space; conditions in a loop cannot
/// leak bindings to another iteration or beyond that loop without a flow proof.
pub fn java_pattern_scope(kind: &str) -> bool {
    matches!(
        kind,
        "variable_declarator"
            | "switch_rule"
            | "switch_block_statement_group"
            | "lambda_expression"
            | "while_statement"
            | "do_statement"
            | "for_statement"
    )
}

/// Initializers and loop conditions can require a visibility proof beyond
/// their own syntax node; switch arms and lambdas confine their bindings.
pub fn java_pattern_bindings_may_escape_scope(kind: &str) -> bool {
    matches!(
        kind,
        "variable_declarator" | "while_statement" | "do_statement" | "for_statement"
    )
}

fn java_contains(outer: Node<'_>, inner: Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// The instanceof test owning a binding, including record components whose
/// lexical identities exist even though extraction can remain unsupported.
pub fn java_pattern_instanceof(mut pattern: Node<'_>) -> Option<Node<'_>> {
    loop {
        match pattern.kind() {
            "instanceof_expression" => return Some(pattern),
            "record_pattern_component"
            | "record_pattern_body"
            | "record_pattern"
            | "pattern"
            | "type_pattern" => pattern = pattern.parent()?,
            _ => return None,
        }
    }
}

/// A deliberately bounded Java abrupt-completion proof. Finally, break,
/// continue and loop reasoning require more than a syntactic last statement.
fn java_pattern_guard_is_abrupt(statement: Node<'_>) -> Option<bool> {
    let mut pending = vec![statement];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "return_statement" | "throw_statement" => {}
            "block" => {
                let mut cursor = node.walk();
                let Some(last) = node
                    .named_children(&mut cursor)
                    .filter(|child| !child.is_extra())
                    .last()
                else {
                    return Some(false);
                };
                pending.push(last);
            }
            "if_statement" => {
                let (Some(yes), Some(no)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return None;
                };
                pending.extend([yes, no]);
            }
            "expression_statement" | "local_variable_declaration" | "empty_statement" => {
                return Some(false);
            }
            _ => return None,
        }
    }
    Some(true)
}

/// Java's definitely-matched visibility rules (JLS 6.3), using structured
/// control syntax. Unproved alternatives never acquire a binding by byte order.
pub fn java_pattern_binding_visible(pattern: Node<'_>, focus: Node<'_>) -> Option<bool> {
    if pattern.has_error() || focus.start_byte() < pattern.end_byte() {
        return Some(false);
    }
    let test = java_pattern_instanceof(pattern);
    if test.is_none() {
        // Switch patterns bind only in their selected arm, including its guard.
        let mut owner = pattern.parent();
        while let Some(node) = owner {
            if matches!(node.kind(), "switch_rule" | "switch_block_statement_group") {
                return Some(java_contains(node, focus));
            }
            if matches!(
                node.kind(),
                "block" | "lambda_expression" | "method_declaration"
            ) {
                return Some(false);
            }
            owner = node.parent();
        }
        return Some(false);
    }
    let test = test.expect("instanceof case");
    let proves = |condition, outcome| {
        if !java_contains(condition, test) {
            return false;
        }
        let mut node = test;
        let mut required = true;
        while node != condition {
            let Some(parent) = node.parent() else {
                return false;
            };
            match parent.kind() {
                "parenthesized_expression" => {}
                "unary_expression"
                    if parent
                        .child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == "!") =>
                {
                    required = !required
                }
                "binary_expression" => {
                    match parent.child_by_field_name("operator").map(|op| op.kind()) {
                        Some("&&") if required => {}
                        Some("||") if !required => {}
                        _ => return false,
                    }
                }
                _ => return false,
            }
            node = parent;
        }
        required == outcome
    };
    let mut ancestor = focus.parent();
    while let Some(node) = ancestor {
        if let Some(left) = node.child_by_field_name("left")
            && node.kind() == "binary_expression"
            && node
                .child_by_field_name("right")
                .is_some_and(|right| java_contains(right, focus))
        {
            match node.child_by_field_name("operator").map(|op| op.kind()) {
                Some("&&") if proves(left, true) => return Some(true),
                Some("||") if proves(left, false) => return Some(true),
                _ => {}
            }
        }
        if let Some(condition) = node.child_by_field_name("condition") {
            for (field, outcome) in [
                ("consequence", true),
                ("alternative", false),
                ("body", true),
                ("update", true),
            ] {
                if matches!(
                    node.kind(),
                    "if_statement" | "ternary_expression" | "while_statement" | "for_statement"
                ) && node
                    .child_by_field_name(field)
                    .is_some_and(|arm| java_contains(arm, focus))
                    && proves(condition, outcome)
                {
                    return Some(true);
                }
            }
        }
        ancestor = node.parent();
    }
    // A negated loop condition may bind a pattern after normal loop exit,
    // but break/label/finally paths require a flow proof we do not have here.
    let mut owner = test.parent();
    while let Some(node) = owner {
        if matches!(
            node.kind(),
            "while_statement" | "do_statement" | "for_statement"
        ) && node.end_byte() <= focus.start_byte()
            && node
                .parent()
                .is_some_and(|block| block.kind() == "block" && java_contains(block, focus))
            && node
                .child_by_field_name("condition")
                .is_some_and(|condition| proves(condition, false))
        {
            return None;
        }
        if matches!(
            node.kind(),
            "block" | "lambda_expression" | "method_declaration"
        ) {
            break;
        }
        owner = node.parent();
    }
    // An abrupt opposite arm admits the matched binding after the if, in the
    // same enclosing block. This also covers references inside later lambdas.
    let mut unproven = false;
    let mut ancestor = test.parent();
    while let Some(node) = ancestor {
        if node.kind() == "if_statement"
            && node.end_byte() <= focus.start_byte()
            && node
                .parent()
                .is_some_and(|block| block.kind() == "block" && java_contains(block, focus))
            && let Some(condition) = node.child_by_field_name("condition")
        {
            for (field, remaining) in [("consequence", false), ("alternative", true)] {
                if proves(condition, remaining)
                    && let Some(arm) = node.child_by_field_name(field)
                {
                    match java_pattern_guard_is_abrupt(arm) {
                        Some(true) => return Some(true),
                        None => unproven = true,
                        Some(false) => {}
                    }
                }
            }
        }
        if matches!(
            node.kind(),
            "block" | "lambda_expression" | "method_declaration"
        ) {
            break;
        }
        ancestor = node.parent();
    }
    if unproven { None } else { Some(false) }
}

/// The text one plain Java string literal denotes.
///
/// Text blocks, escape sequences, string-template interpolations, and
/// recovered shapes return `None`: each of them denotes a value that differs
/// from any single source span. The returned slice is always the exact
/// `string_fragment` AST span (or empty for `""`), never text recovered by
/// delimiter scanning.
pub fn java_plain_string_literal<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    if node.kind() != "string_literal" || node.has_error() {
        return None;
    }
    // A text block opens with the `"""` token; only `"` opens a plain literal.
    if node.child(0)?.kind() != "\"" {
        return None;
    }
    let mut fragment = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_fragment" if fragment.is_none() => fragment = Some(child),
            _ => return None,
        }
    }
    match fragment {
        Some(fragment) => fragment.utf8_text(source.as_bytes()).ok(),
        None => Some(""),
    }
}

#[cfg(test)]
mod plain_string_literal_tests {
    use super::java_plain_string_literal;
    use tree_sitter::Parser;

    fn literals(source: &str) -> Vec<Option<String>> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let mut found = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "string_literal" {
                found.push(java_plain_string_literal(node, source).map(str::to_owned));
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        found
    }

    #[test]
    fn only_plain_literals_denote_their_fragment() {
        let source = "class C { void f() {\n\
            g(\"db.url\");\n\
            g(\"\");\n\
            g(\"db\\turl\");\n\
            g(\"\"\"\n    db.url\n    \"\"\");\n\
        } }";
        assert_eq!(
            literals(source),
            vec![Some("db.url".to_owned()), Some(String::new()), None, None,]
        );
    }

    #[test]
    fn recovered_and_nonliteral_nodes_do_not_denote_plain_strings() {
        for source in [
            "\"db.url",
            "\"",
            "class C { String s = \"db.url; }",
            "class C { String s = \"db.url\n; }",
        ] {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_java::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            // Unterminated quotes recover as ERROR rather than string_literal
            // in 0.23.5. Pin this grammar fact before testing the adapter.
            assert!(tree.root_node().has_error());
            let mut stack = vec![tree.root_node()];
            let mut errors = 0;
            while let Some(node) = stack.pop() {
                if node.is_error() {
                    errors += 1;
                }
                assert_ne!(
                    node.kind(),
                    "string_literal",
                    "{}",
                    tree.root_node().to_sexp()
                );
                assert_eq!(java_plain_string_literal(node, source), None);
                for index in 0..node.named_child_count() {
                    stack.push(node.named_child(index).unwrap());
                }
            }
            assert!(errors > 0, "recovery was exercised");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "d5886539d3ef: quicksilver round 5 survivor review: raw newlines accepted as plain Java strings"
    )]
    #[ignore = "finds real bug: released Java grammar accepts raw newlines in string fragments"]
    fn raw_newline_is_not_a_java_string_literal() {
        // JLS 3.10.5 forbids a raw line terminator in an ordinary string.
        assert_eq!(literals("class C { String s = \"db.url\n\"; }"), vec![None]);
    }
}

#[cfg(test)]
mod result_use_tests {
    use super::{
        JavaCallResultUse, JavaCallResultUseIndex, JavaCallResultUseOpen,
        JavaCallResultUseRelationIndex, java_call_result_use,
    };
    use brokk_bifrost_core::analyzer::structural::result_use::CallResultUse;
    use tree_sitter::{Node, Parser};

    #[test]
    fn direct_java_statement_discards_only_its_own_call_result() {
        let source = "class C {\n\
            String trim(String s) {\n\
                s.trim();\n\
                sink(s.trim());\n\
                String result = s.trim();\n\
                if (s.isEmpty()) {}\n\
                return s.trim();\n\
            }\n\
            void sink(String s) {}\n\
        }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_invocation" {
                calls.push((node.start_position().row, java_call_result_use(node)));
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        assert_eq!(
            calls,
            vec![
                (2, Some(JavaCallResultUse::Discarded)),
                (3, Some(JavaCallResultUse::Discarded)),
                (3, Some(JavaCallResultUse::OtherContext)),
                (4, Some(JavaCallResultUse::OtherContext)),
                (5, Some(JavaCallResultUse::OtherContext)),
                (6, Some(JavaCallResultUse::OtherContext)),
            ]
        );
    }

    #[test]
    fn shared_java_relation_preserves_exact_legacy_classification() {
        let source =
            "class C { void f(String s) { s.trim(); sink(s.trim()); } void sink(String s) {} }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let index = JavaCallResultUseRelationIndex::new(tree.root_node());
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_invocation" {
                let site = index
                    .at_span(node.start_byte(), node.end_byte())
                    .expect("exact shared Java call site");
                calls.push(site.default_use());
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], CallResultUse::Discarded);
        assert_eq!(calls[1], CallResultUse::Discarded);
        assert_eq!(calls[2], CallResultUse::Consumed);
    }

    #[test]
    fn method_reference_and_recovered_invocation_are_open() {
        fn first<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if node.kind() == kind {
                    return Some(node);
                }
                for index in (0..node.named_child_count()).rev() {
                    stack.push(node.named_child(index).expect("named child exists"));
                }
            }
            None
        }
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let reference = parser
            .parse("class C { void f() { Runnable r = this::f; } }", None)
            .expect("Java tree");
        let node = first(reference.root_node(), "method_reference").expect("method reference");
        assert_eq!(java_call_result_use(node), None);
        assert_eq!(
            JavaCallResultUseIndex::new(reference.root_node())
                .at_span(node.start_byte(), node.end_byte()),
            Err(JavaCallResultUseOpen::UnclassifiedSyntax)
        );
        let recovered = parser
            .parse("class C { void f() { call(1, ); } }", None)
            .expect("recovered Java tree");
        let node = first(recovered.root_node(), "method_invocation")
            .expect("recovered invocation remains a syntax node");
        assert_eq!(java_call_result_use(node), None);
        assert_eq!(
            JavaCallResultUseIndex::new(recovered.root_node())
                .at_span(node.start_byte(), node.end_byte()),
            Err(JavaCallResultUseOpen::UnclassifiedSyntax)
        );
    }

    #[test]
    fn constructor_result_is_discarded_only_at_direct_statement_site() {
        let source =
            "class C { void f() { new C(); C c = new C(); sink(new C()); } void sink(C c) {} }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let mut uses = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "object_creation_expression" {
                uses.push(java_call_result_use(node));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        assert_eq!(
            uses,
            vec![
                Some(JavaCallResultUse::Discarded),
                Some(JavaCallResultUse::OtherContext),
                Some(JavaCallResultUse::OtherContext),
            ]
        );
        let index = JavaCallResultUseIndex::new(tree.root_node());
        let sites = &index.sites;
        assert_eq!(sites.len(), 4, "three constructors and one outer sink call");
        assert_eq!(sites[0].result_use, Some(JavaCallResultUse::Discarded));
        assert_eq!(
            index.at_span(sites[0].start_byte, sites[0].end_byte),
            Ok(JavaCallResultUse::Discarded)
        );
        assert_eq!(
            index.at_span(source.len(), source.len()),
            Err(JavaCallResultUseOpen::MissingCall)
        );
        assert!(sites.windows(2).all(|pair| {
            (pair[0].start_byte, pair[0].end_byte) <= (pair[1].start_byte, pair[1].end_byte)
        }));
    }

    #[test]
    fn switch_expression_rule_consumes_its_call_value() {
        let source =
            "class C { String f(String s) { return switch (s) { default -> s.trim(); }; } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let sites = JavaCallResultUseIndex::new(tree.root_node()).sites;
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].result_use, Some(JavaCallResultUse::OtherContext));
    }

    #[test]
    fn for_initializer_and_update_discard_direct_call_results() {
        let source = "class C { void f(String s) { \
            for (s.trim(); s.isEmpty(); s.trim(), sink(s.trim())) {} \
        } void sink(String s) {} }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        assert!(!tree.root_node().has_error(), "{tree:?}");
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_invocation" {
                calls.push((
                    &source[node.start_byte()..node.end_byte()],
                    java_call_result_use(node),
                ));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        assert_eq!(
            calls,
            vec![
                ("s.trim()", Some(JavaCallResultUse::Discarded)),
                ("s.isEmpty()", Some(JavaCallResultUse::OtherContext)),
                ("s.trim()", Some(JavaCallResultUse::Discarded)),
                ("sink(s.trim())", Some(JavaCallResultUse::Discarded)),
                ("s.trim()", Some(JavaCallResultUse::OtherContext)),
            ]
        );
    }

    #[test]
    fn expression_lambda_needs_a_functional_return_contract() {
        let source = "class C { void f(String s) { Runnable discard = () -> s.trim(); java.util.function.Supplier<String> keep = () -> s.trim(); } }";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar");
        let tree = parser.parse(source, None).expect("Java tree");
        let index = JavaCallResultUseIndex::new(tree.root_node());
        assert_eq!(index.sites.len(), 2);
        assert!(index.sites.iter().all(|site| site.result_use.is_none()));
    }
}

impl brokk_bifrost_core::analyzer::statement_facts::producer::StatementFactSyntax
    for JavaStructuralSpec
{
    fn supports_kind(
        &self,
        kind: brokk_bifrost_core::analyzer::statement_facts::StatementFactKind,
    ) -> bool {
        use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
        !matches!(
            kind,
            StatementFactKind::NestedIfStatements | StatementFactKind::MisleadingIndentation
        )
    }

    fn roles<'tree>(&self, node: Node<'tree>, role: Role) -> Vec<Node<'tree>> {
        let field = match role {
            Role::Test if matches!(node.kind(), "switch_label" | "switch_rule") => {
                let label = if node.kind() == "switch_label" {
                    Some(node)
                } else {
                    named_children_iter(node).find(|child| child.kind() == "switch_label")
                };
                let Some(label) = label else {
                    return Vec::new();
                };
                // A combined `case null, default` covers every enum constant.
                // Default arms contribute no finite set of enum tests.
                if label
                    .children(&mut label.walk())
                    .any(|child| child.kind() == "default")
                {
                    return Vec::new();
                }
                return named_children_iter(label)
                    .filter(|child| !child.is_extra())
                    .collect();
            }
            Role::Test => "condition",
            Role::Consequence => "consequence",
            Role::Alternative => "alternative",
            Role::Body => "body",
            Role::Operator => "operator",
            Role::Left => "left",
            Role::Right => "right",
            Role::Label if node.kind() == "labeled_statement" => {
                return named_children_iter(node)
                    .find(|child| child.kind() == "identifier")
                    .into_iter()
                    .collect();
            }
            _ => return Vec::new(),
        };
        node.child_by_field_name(field).into_iter().collect()
    }

    fn loop_variable(&self, node: Node<'_>, source: &str) -> Option<String> {
        let name = if node.kind() == "enhanced_for_statement" {
            node.child_by_field_name("name")?
        } else if node.kind() == "for_statement" {
            let init = node.child_by_field_name("init")?;
            match init.kind() {
                "local_variable_declaration" => named_children_iter(init)
                    .find(|child| child.kind() == "variable_declarator")?
                    .child_by_field_name("name")?,
                "assignment_expression" => init.child_by_field_name("left")?,
                _ => return None,
            }
        } else {
            return None;
        };
        (name.kind() == "identifier")
            .then(|| name.utf8_text(source.as_bytes()).ok().map(str::to_owned))
            .flatten()
    }

    fn is_counted_loop(&self, node: Node<'_>) -> bool {
        node.kind() == "for_statement"
    }
    fn loop_initializers<'tree>(&self, node: Node<'tree>) -> Vec<Node<'tree>> {
        let mut cursor = node.walk();
        node.children_by_field_name("init", &mut cursor)
            .filter(|child| child.is_named() && !child.is_extra())
            .collect()
    }

    // Java's enum operand is resolved by the analyzer's shared lexical binding
    // engine. A grammar-only spec cannot invent that binding proof.
    fn switch_enum<'tree>(&self, _node: Node<'tree>, _source: &str) -> Option<Node<'tree>> {
        None
    }

    fn enumeration(
        &self,
        node: Node<'_>,
        source: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::statement_facts::EnumFact,
        Vec<brokk_bifrost_core::analyzer::statement_facts::EnumeratorFact>,
    )> {
        use brokk_bifrost_core::analyzer::statement_facts::{EnumFact, EnumeratorFact};
        if node.kind() != "enum_declaration" {
            return None;
        }
        let range = node_range(node);
        let name = node
            .child_by_field_name("name")
            .and_then(|name| name.utf8_text(source.as_bytes()).ok())
            .map(str::to_owned);
        let enumerators = node
            .child_by_field_name("body")
            .map(|body| {
                named_children_iter(body)
                    .filter(|child| child.kind() == "enum_constant")
                    .filter_map(|constant| {
                        let name = constant
                            .child_by_field_name("name")?
                            .utf8_text(source.as_bytes())
                            .ok()?
                            .to_owned();
                        Some(EnumeratorFact {
                            range: node_range(constant),
                            enum_range: range,
                            name,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some((EnumFact { range, name }, enumerators))
    }
    fn name<'tree>(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        expression_name_node(node)
    }
}
