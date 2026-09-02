//! Python structural spec: maps tree-sitter-python node types onto the
//! normalized kind vocabulary and extracts role edges from AST fields.
//! See `src/analyzer/structural/spec.rs` for the contract and
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the design.

use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, nearest_ancestor, node_range,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, PYTHON_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, default_occurrence_namespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT, HoistingClass,
    LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedLeafFact, RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

use crate::syntax::{
    expression_name_node, python_deferred_annotation_identifier_ranges,
    python_keyword_argument_label, python_node_is_in_annotation,
};

#[derive(Debug, Default)]
pub struct PythonStructuralSpec;

pub static PYTHON_STRUCTURAL_SPEC: PythonStructuralSpec = PythonStructuralSpec;

/// Grammar node-type → normalized kind. Every name here must exist in the
/// tree-sitter-python grammar; `tests::python_kind_table_matches_grammar`
/// asserts that, so a grammar bump that renames a node fails loudly.
pub const PYTHON_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call", NormalizedKind::Call),
    ("attribute", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda", NormalizedKind::Lambda),
    ("class_definition", NormalizedKind::Class),
    ("assignment", NormalizedKind::Assignment),
    ("import_statement", NormalizedKind::Import),
    ("import_from_statement", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("concatenated_string", NormalizedKind::StringLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("none", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("raise_statement", NormalizedKind::Throw),
    ("except_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::ForLoop),
    ("list", NormalizedKind::CollectionLiteral),
    ("set", NormalizedKind::CollectionLiteral),
    ("dictionary", NormalizedKind::CollectionLiteral),
    ("tuple", NormalizedKind::CollectionLiteral),
    ("while_statement", NormalizedKind::WhileLoop),
    // Python's indented suite. The module node is deliberately absent: a file
    // scope is not a statement list nested inside another one, and making the
    // root a fact in one language only would give Python a scope shape no
    // other adapter has.
    ("block", NormalizedKind::Block),
    ("decorator", NormalizedKind::Decorator),
];

/// Attach `decorators` edges for a definition wrapped in Python's
/// `decorated_definition` node (which itself is not normalized).
fn attach_decorators(sink: &mut RoleSink<'_>, definition: Node<'_>) {
    let Some(parent) = definition.parent() else {
        return;
    };
    if parent.kind() != "decorated_definition" {
        return;
    }
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
}

static PYTHON_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

/// Whether a `dotted_name` names an imported module rather than an ordinary
/// attribute chain, which decides whether its tail is an import target.
///
/// `relative_import` is the wrapper the grammar puts around the module name of
/// `from .impl import x`. It is the same import target as the `pkg.impl` of
/// `from pkg.impl import x`, so it passes through like the other wrappers.
fn python_dotted_name_is_import(dotted_name: Node<'_>) -> bool {
    let mut current = dotted_name;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                return true;
            }
            "aliased_import" | "dotted_name" | "relative_import" => current = parent,
            _ => return false,
        }
    }
}

/// Classify one Python identifier token by its AST position.
///
/// Python has no separate type-identifier node, so annotation operands are
/// recognized by their enclosing `type` node — the same field the parser uses
/// to separate `def f(x: T)`'s binder from its annotation.
fn python_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "identifier" {
        return None;
    }
    let parent = node.parent()?;
    let field = field_name_in_parent(parent, node);
    let role = match parent.kind() {
        "function_definition" | "class_definition" if field == Some("name") => {
            OccurrenceRole::DeclarationName
        }
        // Every annotation, return type and type-alias operand is wrapped in a
        // `type` node; `generic_type`/`type_parameter` nest inside one.
        "type" | "generic_type" | "type_parameter" | "constrained_type" | "union_type" => {
            OccurrenceRole::TypeOperand
        }
        "parameters"
        | "lambda_parameters"
        | "typed_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "tuple_pattern"
        | "list_pattern"
        | "pattern_list"
        | "as_pattern_target" => OccurrenceRole::Binder,
        "default_parameter" | "typed_default_parameter" if field == Some("name") => {
            OccurrenceRole::Binder
        }
        "for_statement" | "for_in_clause" if field == Some("left") => OccurrenceRole::Binder,
        "keyword_argument" if python_keyword_argument_label(node) => OccurrenceRole::LabelOrKey,
        "attribute" => match field {
            Some("attribute") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "aliased_import" if field == Some("alias") => OccurrenceRole::ImportAlias,
        "import_from_statement" if field == Some("name") => OccurrenceRole::ImportTarget,
        "dotted_name" => {
            let is_tail =
                parent.named_child(parent.named_child_count().saturating_sub(1)) == Some(node);
            match (is_tail, python_dotted_name_is_import(parent)) {
                (true, true) => OccurrenceRole::ImportTarget,
                (true, false) => OccurrenceRole::ValueReference,
                (false, _) => OccurrenceRole::PathSegment,
            }
        }
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// Whether a `def` declares a method, that is, whether the suite it sits in
/// belongs to a `class_definition`.
///
/// This reads the parse tree rather than the nearest enclosing normalized kind
/// because the suite between a class and its methods is itself a normalized
/// node now (`NormalizedKind::Block`, issue #1474). Walking the concrete
/// ancestors is also the more direct statement of the rule: a nested `def`
/// inside a method reaches its enclosing `function_definition` first and stays
/// a function.
fn python_definition_is_method(definition: Node<'_>) -> bool {
    let mut current = definition;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "class_definition" => return true,
            // The suite that holds the members, and the wrapper a decorated
            // definition sits in, are pass-through on the way to the owner.
            "block" | "decorated_definition" => current = parent,
            _ => return false,
        }
    }
    false
}

/// The binding one Python binder token introduces, and the interval it is in
/// effect over.
///
/// Python's function locals are scope-categorical rather than positional: a
/// name assigned anywhere in a function body is a local of that function for
/// the whole body, which is why a read above the assignment is an
/// `UnboundLocalError` rather than a read of an outer name. That is exactly
/// `ScopeWide`. The one positional exception is a comprehension target, which
/// lives in the comprehension's own implicit scope; the same exception
/// `analyzer::python::bindings` records as `PythonComprehensionBinding`.
fn python_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    // A binder outside every form below is an ordinary assignment target --
    // the members of a module-level or block-level `a, b = ...` pattern list,
    // for example -- and Python's scope-categorical rule makes it a local of
    // its declaring scope for the whole scope. Answering `None` here made the
    // whole file's lexical environment incomplete as soon as one such binder
    // existed (scripts/test-cost/greedy.py's `s, k = heapq.heappop(heap)` at
    // module scope), which failed every code-smells gate that derived it.
    let Some(form) = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "parameters"
                | "lambda_parameters"
                | "for_statement"
                | "for_in_clause"
                | "as_pattern"
                | "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
                | "function_definition"
        )
    }) else {
        return Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        });
    };
    match form.kind() {
        "parameters" | "lambda_parameters" | "function_definition" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "for_in_clause" => {
            // A comprehension clause binds only inside the comprehension.
            let comprehension = nearest_ancestor(form, |kind| {
                matches!(
                    kind,
                    "list_comprehension"
                        | "set_comprehension"
                        | "dictionary_comprehension"
                        | "generator_expression"
                )
            })?;
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(comprehension),
            })
        }
        "for_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "as_pattern" => Some(BindingActivation {
            kind: BindingKind::PatternBinder,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        _ => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
    }
}

/// The text one plain string literal denotes, or `None` when the literal is
/// not plain: an f-string interpolation, an escape sequence this reader does
/// not decode, or an implicit concatenation. `None` is never an empty name --
/// it is "this value is computed", which makes the whole surface unreadable.
fn python_plain_string_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "string" {
        return None;
    }
    let mut cursor = node.walk();
    let mut content = None;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" | "string_end" => {}
            "string_content" if content.is_none() && child.named_child_count() == 0 => {
                content = Some(child);
            }
            _ => return None,
        }
    }
    // A literal with no content run is the empty string.
    Some(content.map_or("", |child| node_source_text(child, source)))
}

/// Whether every member of a curated surface was read from the parse tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadableSurface {
    Yes,
    No,
}

/// Collect the members of an `__all__` value into `names`, reporting whether
/// every member was readable. Only a list or tuple display of plain string
/// literals is; anything else is a value the source computes.
fn python_collect_all_members(
    value: Node<'_>,
    source: &str,
    names: &mut HashSet<String>,
) -> ReadableSurface {
    if !matches!(value.kind(), "list" | "tuple") {
        return ReadableSurface::No;
    }
    let mut cursor = value.walk();
    for element in value.named_children(&mut cursor) {
        match python_plain_string_text(element, source) {
            Some(text) => {
                names.insert(text.to_owned());
            }
            None => return ReadableSurface::No,
        }
    }
    ReadableSurface::Yes
}

/// The names a Python module curates as its public surface: the value of its
/// module-level `__all__`.
///
/// Only the module's own statements are read. An `__all__` inside a function
/// is a local rather than the module's surface, and a name the module binds
/// conditionally is still bound by the statement this reader already sees.
/// A statement that assigns, extends, or mutates `__all__` with anything but a
/// list or tuple of plain string literals makes the surface unreadable: the
/// members are then unknown, and no import is classified from them.
fn python_curated_export_surface(root: Node<'_>, source: &str) -> CuratedExportSurface {
    let names_all = |node: Option<Node<'_>>| {
        node.is_some_and(|node| {
            node.kind() == "identifier" && node_source_text(node, source) == "__all__"
        })
    };
    let mut names: HashSet<String> = HashSet::default();
    let mut stated = false;
    let mut readable = ReadableSurface::Yes;
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.kind() != "expression_statement" {
            continue;
        }
        let mut inner = statement.walk();
        for expression in statement.named_children(&mut inner) {
            match expression.kind() {
                "assignment" | "augmented_assignment" => {
                    if !names_all(expression.child_by_field_name("left")) {
                        continue;
                    }
                    stated = true;
                    // An annotation without a value (`__all__: list[str]`)
                    // binds nothing, so it states no members either way.
                    let Some(value) = expression.child_by_field_name("right") else {
                        continue;
                    };
                    // `+=` extends the surface; every other augmentation is a
                    // value this reader does not compute.
                    let extends = expression.kind() == "assignment"
                        || expression
                            .child_by_field_name("operator")
                            .is_some_and(|operator| operator.kind() == "+=");
                    if !extends
                        || python_collect_all_members(value, source, &mut names)
                            == ReadableSurface::No
                    {
                        readable = ReadableSurface::No;
                    }
                }
                // `__all__.extend(other)` and its siblings rewrite the surface
                // from a value the reader cannot see.
                "call" => {
                    let Some(function) = expression.child_by_field_name("function") else {
                        continue;
                    };
                    if function.kind() == "attribute"
                        && names_all(function.child_by_field_name("object"))
                    {
                        stated = true;
                        readable = ReadableSurface::No;
                    }
                }
                _ => {}
            }
        }
    }
    match (stated, readable) {
        (false, _) => CuratedExportSurface::Absent,
        (true, ReadableSurface::Yes) => CuratedExportSurface::Listed(names),
        (true, ReadableSurface::No) => CuratedExportSurface::Unreadable,
    }
}

/// Which indirection relation one Python import token participates in.
///
/// Python's grammar names no re-export, so the relation follows the explicit
/// re-export rules the typing ecosystem already enforces (PEP 484 stub
/// semantics, applied by pyright and mypy in strict mode), which makes this
/// relation agree with what a type checker calls public:
///
/// 1. A name on the module's `__all__` is a re-export of whatever binding the
///    module gives that name.
/// 2. The redundant-alias forms `from x import y as y` and `import x as x`
///    are re-exports.
/// 3. `from x import *` is one star hop that forwards the public surface of
///    `x`; the expansion is the import machinery's work, not this producer's,
///    so the hop is recorded on the module reference and nothing is
///    enumerated here.
/// 4. Every other import is an ordinary import, including a plain
///    `from .impl import helper` in a package `__init__.py` that states no
///    `__all__`. The facade convention alone does not make a name public, and
///    a consumer that wants every name a facade imports already has the
///    import relation.
///
/// `None` is the answer for a name whose membership only an unreadable
/// `__all__` could settle; the file's relations then report incomplete rather
/// than guessing either way.
fn python_indirection_relation(
    token: Node<'_>,
    source: &str,
    surface: &CuratedExportSurface,
) -> Option<RouteHopKind> {
    let statement = nearest_ancestor(token, |kind| {
        matches!(
            kind,
            "import_statement" | "import_from_statement" | "future_import_statement"
        )
    })?;
    // The statement's own child that holds this token: a `module_name` field,
    // or one `name` field of the import list.
    let mut clause = token;
    while let Some(parent) = clause.parent() {
        if parent.id() == statement.id() {
            break;
        }
        clause = parent;
    }

    if field_name_in_parent(statement, clause) == Some("module_name") {
        // `from x import a` binds `a`, not `x`, so the module reference
        // forwards nothing -- unless the import is the star form, whose one
        // hop forwards the whole surface of `x`.
        let mut cursor = statement.walk();
        let star = statement
            .children(&mut cursor)
            .any(|child| child.kind() == "wildcard_import");
        return Some(if star {
            RouteHopKind::ReExport
        } else {
            RouteHopKind::Import
        });
    }

    let bound = match clause.kind() {
        "aliased_import" => {
            let name = clause.child_by_field_name("name")?;
            let alias = clause.child_by_field_name("alias")?;
            if node_source_text(name, source) == node_source_text(alias, source) {
                return Some(RouteHopKind::ReExport);
            }
            alias
        }
        // `import a.b.c` binds the top package `a`; `from m import a` binds
        // the single-segment name the import list spells.
        "dotted_name" if statement.kind() == "import_statement" => clause.named_child(0)?,
        "dotted_name" => clause,
        _ => return None,
    };
    match surface.lists(node_source_text(bound, source)) {
        Some(true) => Some(RouteHopKind::ReExport),
        Some(false) => Some(RouteHopKind::Import),
        None => None,
    }
}

impl StructuralSpec for PythonStructuralSpec {
    fn language(&self) -> Language {
        Language::Python
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `import x as y` is an alias, and `python_indirection_relation`
        // states which imports re-export (issue #1649).
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Alias)
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::ReExport)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    /// Python's one qualified-path chain is `dotted_name`, which is flat
    /// rather than left-nested: its named children are the segments in order.
    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if token.kind() != "identifier" {
            return None;
        }
        token
            .parent()
            .filter(|parent| parent.kind() == "dotted_name")
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        if root.kind() != "dotted_name" {
            return Vec::new();
        }
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .collect()
    }

    fn curated_export_surface(&self, root: Node<'_>, source: &str) -> CuratedExportSurface {
        python_curated_export_surface(root, source)
    }

    fn indirection_relation(
        &self,
        token: Node<'_>,
        source: &str,
        surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        python_indirection_relation(token, source, surface)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PYTHON_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Function && python_definition_is_method(node) {
            NormalizedKind::Method
        } else {
            kind
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        kind != NormalizedKind::Assignment || node.child_by_field_name("right").is_some()
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        kind == NormalizedKind::Method
            || self
                .kind_table()
                .iter()
                .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &PYTHON_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &PYTHON_MATERIALIZATION_SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        python_binding_activation(binder, scope)
    }

    /// Python only classifies a scope segment inside a `dotted_name`, and every
    /// non-tail segment of a dotted name is a module.
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        match role {
            OccurrenceRole::PathSegment => Some(Namespace::Module),
            _ => default_occurrence_namespace(role, declares),
        }
    }

    fn embedded_leaf_facts(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<EmbeddedLeafFact> {
        if kind != NormalizedKind::StringLiteral
            || node.kind() != "string"
            || !python_node_is_in_annotation(node)
        {
            return Vec::new();
        }

        python_deferred_annotation_identifier_ranges(node, source, cancellation)
            .unwrap_or_default()
            .into_iter()
            .map(|range| EmbeddedLeafFact {
                kind: NormalizedKind::Identifier,
                range,
                occurrence_role: OccurrenceRole::TypeOperand,
            })
            .collect()
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = python_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    // A call's own name is its callee's, so
                    // { "kind": "call", "name": "eval" } reads naturally.
                    attach_terminal_callee(sink, function, expression_name_node(function));
                    if function.kind() == "attribute"
                        && let Some(object) = function.child_by_field_name("object")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            object,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    for index in 0..arguments.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(argument) = arguments.named_child(index) else {
                            continue;
                        };
                        match argument.kind() {
                            "comment" => {}
                            "keyword_argument" => {
                                if let (Some(keyword), Some(value)) = (
                                    argument.child_by_field_name("name"),
                                    argument.child_by_field_name("value"),
                                ) {
                                    sink.kwarg(keyword, value);
                                }
                            }
                            _ => attach_argument_role_with_derived_name(
                                sink,
                                argument,
                                expression_name_node,
                            ),
                        }
                    }
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(attribute) = node.child_by_field_name("attribute") {
                    sink.set_name(attribute);
                    sink.role_named(Role::Field, attribute, attribute);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => {
                if let Some(left) = node.child_by_field_name("left") {
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
            }
            NormalizedKind::Import => match node.kind() {
                "import_from_statement" => {
                    if let Some(module) = node.child_by_field_name("module_name") {
                        sink.role_named(Role::Module, module, module);
                    }
                }
                _ => {
                    for index in 0..node.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(child) = node.named_child(index) else {
                            continue;
                        };
                        match child.kind() {
                            "dotted_name" => sink.role_named(Role::Module, child, child),
                            "aliased_import" => {
                                if let Some(name) = child.child_by_field_name("name") {
                                    sink.role_named(Role::Module, name, name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            },
            NormalizedKind::Identifier => sink.set_name(node),
            NormalizedKind::Decorator => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
                    sink.set_name(name);
                }
            }
            NormalizedKind::ForLoop => {
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Iterable,
                        right,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::CollectionLiteral => {
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if child.kind() == "comment" {
                        continue;
                    }
                    attach_role_with_derived_name(sink, Role::Element, child, expression_name_node);
                }
            }
            _ => {}
        }
    }
}
