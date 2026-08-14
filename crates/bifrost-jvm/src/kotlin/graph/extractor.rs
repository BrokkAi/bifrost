//! Forward per-file scan for the Kotlin query path.
//!
//! Walks one Kotlin file top to bottom looking for references to a single target
//! ([`super::resolver::TargetSpec`]), recording each one it can prove. The walk is
//! iterative (`walk_tree_iterative`) rather than recursive, per the repository's
//! stack-safety rule for graph tree walks, and it descends with a
//! `LocalInferenceEngine` so a binding's type is already known by the time a
//! reference below it is reached.
//!
//! There is one arm per [`TargetKind`]: a written type, a constructor call, a
//! function reference (a call, a callable reference, or a declaration that
//! overrides it), and a property reference (a member access, a bare name, an
//! enum entry, or the left-hand side of a write). Each arm records only what it
//! can prove; a reference whose receiver type could not be established goes to
//! the unproven channel rather than being guessed into the proven set or dropped.

use super::KotlinGraphSource;
use crate::kotlin::graph::hits;
use crate::kotlin::graph::resolver::{
    KotlinNameResolver, KotlinResolutionCtx, ReceiverTargetMatch, TargetKind, TargetSpec,
    kotlin_callable_arities, member_unit, receiver_is_same_owner, receiver_matches_target,
    receiver_type_fq_name,
};
use crate::kotlin::syntax::{
    kotlin_binding_type_text, kotlin_call_arity, kotlin_call_with_callee, kotlin_callee,
    kotlin_class_literal_type, kotlin_dotted_navigation_segments, kotlin_import_header_segments,
    kotlin_is_declaration_name, kotlin_is_expression_kind, kotlin_is_navigation_kind,
    kotlin_named_argument_label, kotlin_navigation_member, kotlin_navigation_receiver,
    kotlin_user_type_segments,
};
use brokk_bifrost_core::analyzer::tree_walk::{
    TreeWalkAction, first_named_child_of_kind, named_children, walk_tree_iterative,
};
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::text_utils::compute_line_starts;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

/// Node kinds that open a Kotlin binding scope.
///
/// `class_body` is listed separately from the rest by callers that need to know
/// where the class scope began (a bare property reference is shadowed by a local
/// only when the local is declared inside the same class scope), so it stays in
/// this list and is also tested for directly.
const SCOPE_NODES: &[&str] = &[
    "class_body",
    "function_declaration",
    "function_body",
    "anonymous_initializer",
    "lambda_literal",
    "control_structure_body",
    "when_entry",
    "for_statement",
    "catch_block",
    "secondary_constructor",
];

pub struct ScanState<'a> {
    pub max_usages: usize,
    pub hits: &'a mut BTreeSet<UsageHit>,
    pub unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub raw_match_count: &'a mut usize,
    pub limit_exceeded: &'a mut bool,
}

pub struct ScanCtx<'a> {
    pub graph: &'a KotlinGraphSource<'a>,
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub line_starts: &'a [usize],
    pub spec: &'a TargetSpec,
    pub names: &'a KotlinNameResolver<'a>,
    pub hits: &'a mut BTreeSet<UsageHit>,
    pub unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub raw_match_count: &'a mut usize,
    pub max_usages: usize,
    pub limit_exceeded: &'a mut bool,
    pub enclosing_cache: HashMap<(usize, usize), hits::EnclosingContext>,
    /// Value bindings visible at the node being visited, and what type each one
    /// has when the scan could establish it.
    ///
    /// Separate from the type-parameter stack because Kotlin has separate
    /// namespaces for types and values; see [`TypeParameterScopes`].
    pub bindings: LocalInferenceEngine<String>,
    /// Whether a receiver of a given type reaches the target. Asked once per
    /// distinct receiver type rather than once per reference.
    pub receiver_match_cache: HashMap<String, ReceiverTargetMatch>,
    /// The type each declaration declares, resolved in its own file's scope.
    /// A chain expression asks this of the same callee once per link.
    pub declared_type_cache: HashMap<String, Option<String>>,
    /// Scope depth at which the innermost enclosing class body was entered, so a
    /// bare property reference can tell a local that shadows it from a local
    /// declared outside the class entirely.
    pub class_scope_depths: Vec<usize>,
    /// Which scope kinds each open frame opened, so the walk's exit callback
    /// unwinds exactly what its matching enter pushed.
    pending_exits: Vec<ScopeExit>,
}

struct ScopeExit {
    values: bool,
    class_scope: bool,
    type_parameters: bool,
}

/// The query path's half of the shared receiver-typing contract.
///
/// Everything the resolver asks for is already here; the only method with real
/// content is [`KotlinResolutionCtx::enclosing_owner_fq_names`], which a query
/// answers through `IAnalyzer::enclosing_code_unit` because it has to attribute
/// each hit to a caller anyway. The inverted builder answers the same question
/// from the `ClassRangeIndex` it already holds.
impl KotlinResolutionCtx for ScanCtx<'_> {
    fn graph(&self) -> &KotlinGraphSource<'_> {
        self.graph
    }

    fn source(&self) -> &str {
        self.source
    }

    fn bindings(&self) -> &LocalInferenceEngine<String> {
        &self.bindings
    }

    fn resolve_type_fqn(&self, spelled: &str, byte: usize) -> Option<String> {
        self.names.resolve_type_fqn(spelled, byte)
    }

    fn resolve_callable_fqn(&self, spelled: &str, byte: usize) -> Option<String> {
        self.names.resolve_callable_fqn(spelled, byte)
    }

    fn enclosing_owner_fq_names(&mut self, node: Node<'_>) -> Vec<String> {
        let mut owners = Vec::new();
        let mut current = hits::enclosing_context(node, self).enclosing;
        while let Some(unit) = current {
            if unit.is_class() {
                owners.push(unit.fq_name());
            }
            current = self.graph.index.parent_of(&unit);
        }
        owners
    }

    fn declared_type_cache(&mut self) -> &mut HashMap<String, Option<String>> {
        &mut self.declared_type_cache
    }
}

pub fn scan_file(
    graph: &KotlinGraphSource<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let Some(source) = graph
        .index
        .indexed_source(file)
        .or_else(|| graph.index.project().read_source(file).ok())
    else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&crate::kotlin::language::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let line_starts = compute_line_starts(&source);
    let names = KotlinNameResolver::new(graph, file, tree.root_node(), &source);
    let mut type_parameters: TypeParameterScopes = Vec::new();
    let mut ctx = ScanCtx {
        graph,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        names: &names,
        hits: state.hits,
        unproven_hits: state.unproven_hits,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
        bindings: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        receiver_match_cache: HashMap::default(),
        declared_type_cache: HashMap::default(),
        class_scope_depths: Vec::new(),
        pending_exits: Vec::new(),
    };
    walk(tree.root_node(), &mut ctx, &mut type_parameters);
}

/// Type-parameter names in scope, innermost frame last.
///
/// Tracked *separately* from the value bindings in [`ScanCtx`] because Kotlin
/// has separate namespaces for types and values. `val Base = 1` shadows the
/// class `Base` where a value is expected (`Base.length` reads the string's
/// property) but not where a type is expected (`val x: Base` is still the
/// class); `class Box<Base>` does exactly the reverse. Collapsing the two into
/// the single shadow map the one-namespace languages use would make each wrong
/// in the other's positions.
type TypeParameterScopes = Vec<Vec<String>>;

fn type_parameter_in_scope(scopes: &TypeParameterScopes, name: &str) -> bool {
    scopes
        .iter()
        .any(|frame| frame.iter().any(|declared| declared == name))
}

fn walk(root: Node<'_>, ctx: &mut ScanCtx<'_>, type_parameters: &mut TypeParameterScopes) {
    let mut state = (ctx, type_parameters);
    walk_tree_iterative(
        root,
        &mut state,
        |node, (ctx, type_parameters)| {
            if *ctx.limit_exceeded {
                return TreeWalkAction::Stop;
            }
            let enters_value_scope = SCOPE_NODES.contains(&node.kind());
            let enters_class_scope = enters_value_scope && node.kind() == "class_body";
            let declared_type_parameters = type_parameter_names(node, ctx.source);
            let enters_type_scope = !declared_type_parameters.is_empty();
            if enters_value_scope {
                ctx.bindings.enter_scope();
                if enters_class_scope {
                    // Remembered so a bare property reference can tell a local
                    // that shadows it from one declared outside the class.
                    ctx.class_scope_depths.push(ctx.bindings.scope_depth());
                }
            }
            if enters_type_scope {
                type_parameters.push(declared_type_parameters);
            }
            seed_value_declarations(node, ctx);
            record_reference(node, ctx, type_parameters);

            if enters_value_scope || enters_type_scope {
                // The exit callback cannot see which of the three it is
                // unwinding, so it is recorded on the frame itself.
                ctx.pending_exits.push(ScopeExit {
                    values: enters_value_scope,
                    class_scope: enters_class_scope,
                    type_parameters: enters_type_scope,
                });
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |(ctx, type_parameters)| {
            let Some(exit) = ctx.pending_exits.pop() else {
                return;
            };
            if exit.values {
                ctx.bindings.exit_scope();
            }
            if exit.class_scope {
                ctx.class_scope_depths.pop();
            }
            if exit.type_parameters {
                type_parameters.pop();
            }
        },
    );
}

/// The type parameters `node` declares, if it declares any.
///
/// Read from the `type_parameters` child rather than from a field, because the
/// grammar names no field for it. Both `class Box<T>` and `fun <T> f()` carry it.
fn type_parameter_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = first_named_child_of_kind(node, "type_parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter(|child| child.kind() == "type_parameter")
        .filter_map(|parameter| first_named_child_of_kind(parameter, "type_identifier"))
        .map(|name| node_text(name, source))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Record what each value declaration introduces: its type when the scan can
/// establish one, otherwise a *shadow* — a binding of unknown type.
///
/// Both halves matter. The type is what receiver typing reads, so `val b: Base`
/// makes `b.greet()` a proven call. The shadow is what keeps a local from being
/// misread as the class it hides: a local `val Registry = "text"` shadows the
/// object `Registry` in value positions, so a later `Registry.length` is not a
/// reference to the object.
fn seed_value_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "variable_declaration" | "parameter" | "class_parameter" | "parameter_with_optional_type"
    ) {
        return;
    }
    let Some(name_node) = first_named_child_of_kind(node, "simple_identifier") else {
        return;
    };
    let name = node_text(name_node, ctx.source).to_string();
    if name.is_empty() {
        return;
    }
    match binding_type_fq_name(node, ctx) {
        Some(fqn) => ctx.bindings.seed_symbol(name, fqn),
        None => ctx.bindings.declare_shadow(name),
    }
}

/// The type a binding has: the type it writes, or the type its initializer
/// proves.
fn binding_type_fq_name(binding: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<String> {
    if let Some(spelled) = kotlin_binding_type_text(binding, ctx.source)
        && let Some(fqn) = ctx.names.resolve_type_fqn(&spelled, binding.start_byte())
    {
        return Some(fqn);
    }
    // A `variable_declaration` holds only the name and the written type; the
    // initializer is its sibling under the enclosing `property_declaration`.
    let owner = if binding.kind() == "variable_declaration" {
        binding.parent()?
    } else {
        binding
    };
    let initializer = named_children(owner)
        .into_iter()
        .rev()
        .find(|child| kotlin_is_expression_kind(child.kind()))?;
    receiver_type_fq_name(initializer, ctx, 0)
}

fn record_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>, types: &TypeParameterScopes) {
    match ctx.spec.kind {
        TargetKind::Type => record_type_reference(node, ctx, types),
        TargetKind::Constructor => record_constructor_reference(node, ctx),
        TargetKind::Function => record_function_reference(node, ctx),
        TargetKind::Property => record_property_reference(node, ctx),
    }
}

// ---------------------------------------------------------------------------
// Callables
// ---------------------------------------------------------------------------

/// Record a reference to a constructor: `Base(1)`, a fully-qualified
/// `lib.Base(1)`, or a superclass constructor call in a supertype list.
///
/// A Kotlin class with no primary-constructor parameters has no constructor unit
/// at all, so a constructor target always takes at least one parameter and
/// `Base()` on such a class names the *class*, not a constructor.
fn record_constructor_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let (callee, arity) = match node.kind() {
        // `class D : Base(1)` calls the superclass constructor. The same token
        // is also a type reference, which a type query reports separately.
        "constructor_invocation" => {
            let Some(callee) = kotlin_callee(node) else {
                return;
            };
            (callee, kotlin_call_arity(node))
        }
        "call_expression" => {
            let Some(callee) = kotlin_callee(node) else {
                return;
            };
            (callee, kotlin_call_arity(node))
        }
        _ => return,
    };
    if !ctx.spec.accepts_arity(arity) {
        return;
    }
    let Some(owner) = ctx.spec.owner.as_ref().map(CodeUnit::fq_name) else {
        return;
    };
    let Some((token, spelled)) = constructed_type_spelling(callee, ctx) else {
        return;
    };
    if ctx
        .names
        .resolve_type_fqn(&spelled, token.start_byte())
        .is_some_and(|resolved| resolved == owner)
    {
        hits::push_hit(token, ctx);
    }
}

/// The token and spelled name of the type a callee constructs, for the shapes a
/// constructor call can take.
fn constructed_type_spelling<'tree>(
    callee: Node<'tree>,
    ctx: &ScanCtx<'_>,
) -> Option<(Node<'tree>, String)> {
    match callee.kind() {
        "simple_identifier" => {
            let name = node_text(callee, ctx.source);
            (!name.is_empty() && !ctx.bindings.is_shadowed(name))
                .then(|| (callee, name.to_string()))
        }
        // `: Base(1)` in a supertype list spells its callee as a `user_type`.
        "user_type" => {
            let segments = kotlin_user_type_segments(callee);
            let last = segments.last().copied()?;
            let spelled = segments
                .iter()
                .map(|segment| node_text(*segment, ctx.source))
                .collect::<Vec<_>>()
                .join(".");
            (!spelled.is_empty()).then_some((last, spelled))
        }
        // `lib.Base(1)`.
        kind if kotlin_is_navigation_kind(kind) => {
            let member = kotlin_navigation_member(callee)?;
            let spelled = dotted_navigation_spelling(callee, ctx)?;
            Some((member, spelled))
        }
        _ => None,
    }
}

/// The dotted name a navigation spells, when every link of it is a plain name.
fn dotted_navigation_spelling(navigation: Node<'_>, ctx: &ScanCtx<'_>) -> Option<String> {
    let segments = kotlin_dotted_navigation_segments(navigation)?;
    let names: Vec<&str> = segments
        .iter()
        .map(|segment| node_text(*segment, ctx.source))
        .collect();
    (!names.iter().any(|name| name.is_empty())).then(|| names.join("."))
}

/// Record a reference to a function: a call, a callable reference, or a
/// declaration that overrides it.
fn record_function_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "call_expression" => record_call(node, ctx),
        "function_declaration" => record_override_declaration(node, ctx),
        // `::topLevel` names a callable without applying it, so no arity is
        // proven and the reference is judged on the name alone.
        "callable_reference" => record_callable_reference(node, ctx),
        // `String::length` and a plain `receiver.member` read as a value both
        // parse as a navigation. One that is a call's callee is handled by the
        // call arm, so only the non-call ones land here.
        kind if kotlin_is_navigation_kind(kind) && kotlin_call_with_callee(node).is_none() => {
            record_member_access(node, ctx, None)
        }
        _ => {}
    }
}

/// Record a call whose callee names the target.
fn record_call(call: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(callee) = kotlin_callee(call) else {
        return;
    };
    let arity = kotlin_call_arity(call);
    match callee.kind() {
        kind if kotlin_is_navigation_kind(kind) => record_member_access(callee, ctx, Some(arity)),
        "simple_identifier" => {
            if node_text(callee, ctx.source) != ctx.spec.member_name
                || kotlin_is_declaration_name(callee)
                || !ctx.spec.accepts_arity(arity)
            {
                return;
            }
            record_bare_reference(callee, ctx, Some(arity));
        }
        _ => {}
    }
}

/// Record `receiver.member`, typed through the receiver.
fn record_member_access(navigation: Node<'_>, ctx: &mut ScanCtx<'_>, arity: Option<usize>) {
    let Some(member) = kotlin_navigation_member(navigation) else {
        return;
    };
    if node_text(member, ctx.source) != ctx.spec.member_name {
        return;
    }
    if arity.is_some_and(|arity| !ctx.spec.accepts_arity(arity)) {
        return;
    }
    let Some(receiver) = kotlin_navigation_receiver(navigation) else {
        return;
    };
    match receiver_matches_target(receiver, ctx) {
        ReceiverTargetMatch::Matched if receiver_is_same_owner(receiver, ctx) => {
            hits::push_self_receiver_hit(member, ctx)
        }
        ReceiverTargetMatch::Matched => hits::push_hit(member, ctx),
        // The receiver's type could not be established — a lambda parameter, an
        // inferred local, a smart cast. The reference stays visible in the
        // unproven channel rather than being guessed into the proven set or
        // dropped.
        ReceiverTargetMatch::Unresolved => hits::push_unproven_hit(member, ctx),
        // Proof the reference names a *different* declaration.
        ReceiverTargetMatch::Incompatible => {}
    }
}

/// Record a bare (receiver-less) reference to the target: an implicit-`this`
/// member, a top-level declaration of the file's own package, or an imported one.
fn record_bare_reference(token: Node<'_>, ctx: &mut ScanCtx<'_>, arity: Option<usize>) {
    // A top-level target has no receiver at all: the bare name either resolves
    // to it through the file's scope or does not.
    if ctx.spec.owner.is_none() {
        if ctx
            .names
            .resolve_callable_fqn(&ctx.spec.member_name, token.start_byte())
            .is_some_and(|resolved| resolved == ctx.spec.fq_name)
        {
            hits::push_hit(token, ctx);
        }
        return;
    }

    // A member named without a receiver is an implicit-`this` reference, which
    // is same-owner under the uniform #1014 policy — but only when the name
    // really does resolve to the target from here.
    let owners = ctx.enclosing_owner_fq_names(token);
    for owner in &owners {
        if let Some(found) = member_unit(owner, &ctx.spec.member_name, arity, ctx) {
            if found.fq_name() == ctx.spec.fq_name {
                hits::push_self_receiver_hit(token, ctx);
            }
            // The nearest enclosing owner that declares the name is the one the
            // reference binds to; a further-out one cannot also answer it.
            return;
        }
    }
    // Not reachable through any enclosing scope: an import may still bring it in.
    if ctx
        .names
        .resolve_callable_fqn(&ctx.spec.member_name, token.start_byte())
        .is_some_and(|resolved| resolved == ctx.spec.fq_name)
    {
        hits::push_hit(token, ctx);
    }
}

/// Record `::name`, a callable reference.
fn record_callable_reference(reference: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = named_children(reference)
        .into_iter()
        .find(|child| child.kind() == "simple_identifier")
    else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    record_bare_reference(name_node, ctx, None);
}

/// Record a declaration that *overrides* the target as a reference to it.
///
/// An override is a reference in the sense a user asking "who uses this?" means:
/// renaming the target must rename the override too, and a base declaration
/// reached only through its overrides is not dead.
fn record_override_declaration(declaration: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = first_named_child_of_kind(declaration, "simple_identifier") else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    let Some(declared) = ctx
        .graph
        .index
        .enclosing_code_unit(ctx.file, &node_range(name_node, ctx))
    else {
        return;
    };
    if declared.fq_name() == ctx.spec.fq_name {
        // The target's own declaration site is not a usage of itself.
        return;
    }
    let Some(owner) = ctx.graph.index.parent_of(&declared) else {
        return;
    };
    if !ctx
        .spec
        .declaration_owner_fq_names
        .contains(&owner.fq_name())
    {
        return;
    }
    // An override must be callable the same way the target is. A declaration
    // that shares only the name is a different member that happens to collide,
    // not an override — Kotlin would not accept it as one either. A declaration
    // with no recorded arity is admitted: missing metadata is an absence of
    // evidence, not evidence of a mismatch.
    let arities = kotlin_callable_arities(ctx.graph, &declared);
    if arities.is_empty()
        || arities
            .iter()
            .any(|arity| ctx.spec.accepts_arity(arity.total()))
    {
        hits::push_override_declaration_hit(name_node, ctx);
    }
}

fn node_range(node: Node<'_>, ctx: &ScanCtx<'_>) -> brokk_bifrost_core::analyzer::Range {
    brokk_bifrost_core::analyzer::Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: brokk_bifrost_core::text_utils::find_line_index_for_offset(
            ctx.line_starts,
            node.start_byte(),
        ),
        end_line: brokk_bifrost_core::text_utils::find_line_index_for_offset(
            ctx.line_starts,
            node.end_byte(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Record a reference to a property, a `val`/`var` constructor parameter, or an
/// enum entry. A read and a write name the same declaration, because the index
/// records one `Field` unit for a property even with custom accessors.
fn record_property_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        // Both a read (`navigation_expression`) and the left-hand side of a
        // write (`directly_assignable_expression`) name the same declaration:
        // the index records one `Field` unit for a property even with custom
        // accessors.
        kind if kotlin_is_navigation_kind(kind) => record_member_access(node, ctx, None),
        "simple_identifier" => record_bare_property_reference(node, ctx),
        _ => {}
    }
}

/// Record a bare property name: `count` rather than `this.count`.
///
/// A property reference and a local of the same name are spelled identically, so
/// the local scopes decide. A local declared *inside* the class body shadows the
/// property; one declared outside it does not reach the property at all.
fn record_bare_property_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node_text(node, ctx.source) != ctx.spec.member_name || kotlin_is_declaration_name(node) {
        return;
    }
    // A navigation's member is reached through the navigation arm, with its
    // receiver; recording it here as well would report it twice and without
    // proof.
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "navigation_suffix")
    {
        return;
    }
    // A named argument's label names a parameter, not a property.
    if node
        .parent()
        .filter(|parent| parent.kind() == "value_argument")
        .is_some_and(|parent| kotlin_named_argument_label(parent, node))
    {
        return;
    }
    let shadowed = match ctx.class_scope_depths.last() {
        Some(depth) => ctx
            .bindings
            .is_shadowed_at_or_below_scope(*depth, &ctx.spec.member_name),
        None => ctx.bindings.is_shadowed(&ctx.spec.member_name),
    };
    if shadowed {
        return;
    }
    record_bare_reference(node, ctx, None);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

fn record_type_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>, types: &TypeParameterScopes) {
    match node.kind() {
        "import_header" => record_import_reference(node, ctx),
        "user_type" => record_user_type_reference(node, ctx, types),
        "simple_identifier" => record_qualifier_reference(node, ctx),
        "call_expression" => record_constructed_type_reference(node, ctx),
        // `C::class`. The bare form is the only thing a `callable_reference` can
        // be that names a type.
        "callable_reference" => record_class_literal_reference(node, ctx, types),
        // `lib.D::class`. A navigation that is not a class literal names a
        // member, which a type query does not report.
        kind if kotlin_is_navigation_kind(kind) => record_class_literal_reference(node, ctx, types),
        _ => {}
    }
}

/// Record `C::class` or `lib.D::class` — a class literal, which names the type in
/// Kotlin's *type* namespace exactly as a written type does.
///
/// Kotlin spells a bound literal (`x::class`, the runtime class of a value) the
/// same way, and the grammar cannot tell the two apart: both are one name to the
/// left of `::class`. The separator is the value namespace — a binding of that
/// name in scope proves the receiver is a value, and a value's runtime class
/// names no declaration the query could report.
fn record_class_literal_reference(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    types: &TypeParameterScopes,
) {
    let Some(literal) = kotlin_class_literal_type(node) else {
        return;
    };
    let segments = match literal.kind() {
        // A bare name, aliased to `type_identifier` by the callable-reference
        // form and left a `simple_identifier` by the navigation one.
        "type_identifier" | "simple_identifier" => vec![literal],
        kind if kotlin_is_navigation_kind(kind) => {
            let Some(segments) = kotlin_dotted_navigation_segments(literal) else {
                return;
            };
            segments
        }
        // `f()::class` names the runtime class of a call's result.
        _ => return,
    };
    let Some(leading) = segments.first() else {
        return;
    };
    // Only the leading segment can be shadowed: `lib` of `lib.D::class` is a
    // qualifier, and a value binding can never supply one.
    if ctx.bindings.is_shadowed(node_text(*leading, ctx.source)) {
        return;
    }
    record_type_name_segments(&segments, ctx, types);
}

/// Record the type named by a constructor call written without a type
/// annotation: the `Base` of `val b = Base()`.
///
/// Kotlin spells a constructor call exactly like a function call, so the token
/// is a bare `simple_identifier` rather than a `user_type` — the arm above never
/// sees it, and the qualifier arm below only fires for a navigation *receiver*.
/// Without this, the most common way to mention a class in Kotlin (`Base()` on
/// its own) is invisible to "who uses this class?".
fn record_constructed_type_reference(call: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(callee) = kotlin_callee(call) else {
        return;
    };
    if callee.kind() != "simple_identifier" || kotlin_is_declaration_name(callee) {
        return;
    }
    let name = node_text(callee, ctx.source);
    // A local of the same name is a value, not the class it hides.
    if name.is_empty() || name != ctx.spec.member_name || ctx.bindings.is_shadowed(name) {
        return;
    }
    if ctx
        .names
        .resolve_type_fqn(name, callee.start_byte())
        .is_some_and(|resolved| resolved == ctx.spec.fq_name)
    {
        hits::push_hit(callee, ctx);
    }
}

/// Record a reference to the target inside `import a.b.C`, `import a.b.C as D`,
/// or `import a.b.*`.
///
/// Only the segment that resolves to the target is recorded, and only when it is
/// the *last* segment of the path: `import lib.Base.Nested` references `Nested`,
/// and reporting `Base` as well would double-count one import. An alias records
/// at the alias token instead, because that is the name a reader would rename.
fn record_import_reference(header: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let segments = kotlin_import_header_segments(header);
    let Some(last) = segments.last().copied() else {
        return;
    };
    let path = segments
        .iter()
        .map(|segment| node_text(*segment, ctx.source))
        .collect::<Vec<_>>()
        .join(".");
    if path != ctx.spec.fq_name {
        return;
    }
    let token = first_named_child_of_kind(header, "import_alias")
        .and_then(|alias| first_named_child_of_kind(alias, "type_identifier"))
        .unwrap_or(last);
    hits::push_import_hit(token, ctx);
}

/// Record a reference to the target in a written type such as `val b: lib.Base`,
/// `class D : Base()`, or `List<Base>`.
///
/// A dotted type name is one `user_type` with one `type_identifier` per segment,
/// so each *prefix* is resolved in turn and the segment whose prefix resolves to
/// the target is the one recorded. That is what makes focusing `Outer` in
/// `Outer.Inner` a reference to `Outer` and focusing `Inner` a reference to
/// `Outer.Inner`, rather than attributing both to the outer name.
fn record_user_type_reference(
    user_type: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    types: &TypeParameterScopes,
) {
    // A nested `user_type` is reached through its parent's segment walk, so
    // visiting it again would record the same token twice. Generic arguments are
    // not nested `user_type`s of their owner (they sit inside `type_arguments`),
    // so they are still visited in their own right.
    if user_type
        .parent()
        .is_some_and(|parent| parent.kind() == "user_type")
    {
        return;
    }

    record_type_name_segments(&kotlin_user_type_segments(user_type), ctx, types);
}

/// Record the one segment of a dotted type name whose prefix resolves to the
/// target, and stop there: `Outer.Inner` names `Outer` at its own token and
/// `Outer.Inner` at `Inner`'s, so one spelling is never attributed twice.
fn record_type_name_segments(
    segments: &[Node<'_>],
    ctx: &mut ScanCtx<'_>,
    types: &TypeParameterScopes,
) {
    let mut spelling = String::new();
    for (index, segment) in segments.iter().enumerate() {
        let name = node_text(*segment, ctx.source);
        if name.is_empty() {
            return;
        }
        // A generic parameter shadows a class of the same name for the whole
        // declaration that introduced it: inside `class Box<Base>`, every `Base`
        // is the parameter. Only the *leading* segment can be shadowed -- a
        // parameter is a single name, so it can never be the `Inner` of
        // `Outer.Inner`.
        if index == 0 && type_parameter_in_scope(types, name) {
            return;
        }
        if !spelling.is_empty() {
            spelling.push('.');
        }
        spelling.push_str(name);
        if ctx
            .names
            .resolve_type_fqn(&spelling, segment.start_byte())
            .is_some_and(|resolved| resolved == ctx.spec.fq_name)
        {
            hits::push_hit(*segment, ctx);
            return;
        }
    }
}

/// Record a reference to the target used as a *qualifier*: the receiver of a
/// member access that names a type rather than a value, as in `Base.helper()` or
/// `Color.RED`.
///
/// This is the one place a bare `simple_identifier` can name a type, so it is
/// guarded three ways: the identifier must actually be a navigation receiver, it
/// must not be a declaration's own name, and it must not be shadowed by a local
/// binding — `val Base = 1; Base.length` is a property access on a string, not a
/// reference to the class.
fn record_qualifier_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if kotlin_is_declaration_name(node) {
        return;
    }
    let name = node_text(node, ctx.source);
    if name.is_empty() || name != ctx.spec.member_name || ctx.bindings.is_shadowed(name) {
        return;
    }
    let Some(navigation) = node
        .parent()
        .filter(|parent| parent.kind() == "navigation_expression")
    else {
        return;
    };
    if kotlin_navigation_receiver(navigation).is_none_or(|receiver| receiver.id() != node.id()) {
        return;
    }
    if ctx
        .names
        .resolve_type_fqn(name, node.start_byte())
        .is_some_and(|resolved| resolved == ctx.spec.fq_name)
    {
        hits::push_hit(node, ctx);
    }
}
