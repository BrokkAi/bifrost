//! Whole-workspace inverted edge builder for Kotlin.
//!
//! The query path in [`super::extractor`] asks "does this reference name *the*
//! target?"; this asks the same question inverted — "what does this reference
//! name?" — once per file, so `usage_graph`, `callers`, `callees`, relevance
//! ranking, and dead-code detection do not have to run the query path once per
//! declaration.
//!
//! The two directions share their whole resolution backbone through
//! [`KotlinResolutionCtx`]: receiver typing, member lookup order (own members,
//! then the companion, then ancestors breadth-first), the name-resolution
//! ladder, and the published facts of issue #1345 all have one implementation.
//! What differs is only the two lexical questions a whole-workspace pass can
//! answer more cheaply — which class encloses a byte, and which declaration
//! encloses a reference — and those are the methods this module implements
//! against the per-file [`ClassRangeIndex`] the driver already builds.
//!
//! Kotlin node fqns are dotted and package-qualified (`lib.Base`,
//! `lib.Base.greet`), the same space Java and Scala resolve into, which is what
//! makes the `Jvm` realm's three builders merge into one node set without
//! double counting: each scans only files of its own language.
//!
//! Three shapes are recorded:
//!
//! - a written type (`val b: lib.Base`, `class D : Base()`, `List<Base>`, an
//!   `import`, a static/companion/object qualifier) resolves to the type's fqn,
//!   one edge per *semantic segment* so `Outer.Inner` records both;
//! - a call resolves through its receiver's type to the declaration the call
//!   binds to — which may be an ancestor's, or the companion's, so the edge
//!   lands on the real declaration rather than on a name that does not exist;
//! - a property read or write resolves the same way, to the one `Field` unit
//!   Kotlin indexes for a property.
//!
//! A receiver whose type could not be established records *unproven* inbound
//! rather than nothing, so a declaration reachable only through unresolvable
//! receivers reads as inconclusive to the dead-code detector instead of dead.
//! Same-owner calls (implicit `this`, explicit `this`, own-type/companion
//! qualifier) route through [`route_same_owner`] into that same unproven
//! channel, which is the uniform #1014 facet B / #1138 policy: a private helper
//! called only from its own class is never a proven inbound edge, and never
//! confidently dead either.

use super::KotlinGraphSource;
use super::resolver::{
    KotlinNameResolver, KotlinResolutionCtx, bare_callable_unit, kotlin_callable_arities,
    member_unit, receiver_is_same_owner, receiver_type_fq_name, type_unit, visible_extension_unit,
};
use crate::kotlin::syntax::{
    kotlin_binding_type_text, kotlin_call_arity, kotlin_call_with_callee, kotlin_callee,
    kotlin_class_literal_type, kotlin_dotted_navigation_segments, kotlin_import_header_segments,
    kotlin_is_declaration_name, kotlin_is_expression_kind, kotlin_is_navigation_kind,
    kotlin_named_argument_label, kotlin_navigation_member, kotlin_navigation_receiver,
    kotlin_user_type_segments,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::tree_walk::{
    TreeWalkAction, first_named_child_of_kind, named_children, walk_tree_iterative,
};
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::inverted_edges::{
    ClassRangeIndex, FileEdgeScanInput, PerFileEdges, classify_reference_node,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine,
};
use brokk_bifrost_core::analyzer::usages::same_owner::route_same_owner;
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

/// Node kinds that open a Kotlin binding scope.
///
/// Kept identical to the query path's list: a binding visible to one path and
/// not the other would make find-references and `usage_graph` disagree about
/// what a name means, which is the drift the shared resolver exists to prevent.
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

/// Resolve every reference one already-parsed Kotlin file spells.
///
/// The whole-workspace fan-out that calls this stays in
/// `brokk-bifrost-analysis`: both per-file indexes it feeds in have a
/// `FileState` fast path, and `FileState` is analysis-crate-private (Ruby's
/// `forward_owner_relation_facts` precedent -- decode on that side, hand the
/// decoded facts across).
pub fn scan_file(
    graph: &KotlinGraphSource<'_>,
    file: &ProjectFile,
    input: &FileEdgeScanInput<'_>,
    class_ranges: ClassRangeIndex,
) -> PerFileEdges {
    let names = KotlinNameResolver::new(graph, file, input.root(), input.source);
    let mut scan = KotlinEdgeScan {
        graph,
        source: input.source,
        names: &names,
        class_ranges,
        bindings: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        declared_type_cache: HashMap::default(),
        owner_chain_cache: HashMap::default(),
        input,
        edges: PerFileEdges::default(),
    };
    walk(input.root(), &mut scan);
    scan.edges
}

struct KotlinEdgeScan<'a> {
    graph: &'a KotlinGraphSource<'a>,
    source: &'a str,
    names: &'a KotlinNameResolver<'a>,
    class_ranges: ClassRangeIndex,
    bindings: LocalInferenceEngine<String>,
    declared_type_cache: HashMap<String, Option<String>>,
    /// Owner chains by the fqn of the innermost enclosing class, so the walk
    /// pays for `parent_of` once per class rather than once per reference.
    owner_chain_cache: HashMap<String, Vec<String>>,
    input: &'a FileEdgeScanInput<'a>,
    edges: PerFileEdges,
}

impl KotlinResolutionCtx for KotlinEdgeScan<'_> {
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

    /// Answered from the per-file class-span index rather than from
    /// `CodeUnitIndex::enclosing_code_unit`, because a whole-workspace pass already
    /// built the index and would otherwise pay for the same answer twice per
    /// reference.
    fn enclosing_owner_fq_names(&mut self, node: Node<'_>) -> Vec<String> {
        let Some(innermost) = self.class_ranges.enclosing_unit(node.start_byte()).cloned() else {
            return Vec::new();
        };
        let key = innermost.fq_name();
        if let Some(cached) = self.owner_chain_cache.get(&key) {
            return cached.clone();
        }
        let mut owners = Vec::new();
        let mut current = Some(innermost);
        while let Some(unit) = current {
            if unit.is_class() {
                owners.push(unit.fq_name());
            }
            current = self.graph.index.parent_of(&unit);
        }
        self.owner_chain_cache.insert(key, owners.clone());
        owners
    }

    fn declared_type_cache(&mut self) -> &mut HashMap<String, Option<String>> {
        &mut self.declared_type_cache
    }
}

impl KotlinEdgeScan<'_> {
    fn record(&mut self, callee: String, node: Node<'_>) {
        self.edges.record_kind(
            self.input,
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_unproven(&mut self, name: &str, node: Node<'_>) {
        self.edges
            .record_unproven_name(self.input, name, node.start_byte(), node.end_byte());
    }
}

fn walk(root: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    walk_tree_iterative(
        root,
        scan,
        |node, scan| {
            let enters_scope = SCOPE_NODES.contains(&node.kind());
            if enters_scope {
                scan.bindings.enter_scope();
            }
            seed_value_declarations(node, scan);
            record_reference(node, scan);
            if enters_scope {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |scan| scan.bindings.exit_scope(),
    );
}

/// Record what each value declaration introduces: its type when the scan can
/// establish one, otherwise a *shadow* — a binding of unknown type that keeps a
/// local from being misread as the class it hides.
fn seed_value_declarations(node: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    if !matches!(
        node.kind(),
        "variable_declaration" | "parameter" | "class_parameter" | "parameter_with_optional_type"
    ) {
        return;
    }
    let Some(name_node) = first_named_child_of_kind(node, "simple_identifier") else {
        return;
    };
    let name = node_text(name_node, scan.source).to_string();
    if name.is_empty() {
        return;
    }
    match binding_type_fq_name(node, scan) {
        Some(fqn) => scan.bindings.seed_symbol(name, fqn),
        None => scan.bindings.declare_shadow(name),
    }
}

fn binding_type_fq_name(binding: Node<'_>, scan: &mut KotlinEdgeScan<'_>) -> Option<String> {
    if let Some(spelled) = kotlin_binding_type_text(binding, scan.source)
        && let Some(fqn) = scan.names.resolve_type_fqn(&spelled, binding.start_byte())
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
    receiver_type_fq_name(initializer, scan, 0)
}

fn record_reference(node: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    match node.kind() {
        "import_header" => record_import(node, scan),
        "user_type" => record_user_type(node, scan),
        // A superclass constructor call in a supertype list; its `user_type`
        // child records the type itself.
        "constructor_invocation" => record_constructor_invocation(node, scan),
        "call_expression" => record_call(node, scan),
        // `C::class` names a type; `::name` and `C::name` name a callable.
        "callable_reference" => match kotlin_class_literal_type(node) {
            Some(literal) => record_class_literal(literal, scan),
            None => record_callable_reference(node, scan),
        },
        "simple_identifier" => record_bare_identifier(node, scan),
        // A property read (`navigation_expression`) and the left-hand side of a
        // write (`directly_assignable_expression`) have the identical shape and
        // name the one `Field` unit Kotlin indexes for a property. One that is a
        // call's callee is handled by the call arm.
        kind if kotlin_is_navigation_kind(kind) && kotlin_call_with_callee(node).is_none() => {
            // `lib.D::class` is the qualified class literal, not a member access.
            match kotlin_class_literal_type(node) {
                Some(literal) => record_class_literal(literal, scan),
                None => record_member_access(node, scan, None),
            }
        }
        _ => {}
    }
}

/// Record `C::class` or `lib.D::class` — a class literal, which names the type in
/// Kotlin's *type* namespace exactly as a written type does.
///
/// Kotlin spells a bound literal (`x::class`, the runtime class of a value) the
/// same way, and the grammar cannot tell the two apart. The separator is the
/// value namespace: a binding of the leading name proves the receiver is a value,
/// and a value's runtime class names no declaration this pass could edge to.
fn record_class_literal(literal: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
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
    if scan.bindings.is_shadowed(node_text(*leading, scan.source)) {
        return;
    }
    record_type_name_segments(&segments, scan);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Record `import a.b.C` / `import a.b.C as D` at the last path segment.
///
/// A star import names a package, not a declaration, so it records nothing.
fn record_import(header: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    let segments = kotlin_import_header_segments(header);
    let Some(last) = segments.last().copied() else {
        return;
    };
    let path = segments
        .iter()
        .map(|segment| node_text(*segment, scan.source))
        .collect::<Vec<_>>()
        .join(".");
    if path.is_empty() || !scan.input.is_node(&path) {
        return;
    }
    scan.record(path, last);
}

/// Record a written type, one edge per semantic segment.
///
/// A dotted Kotlin type name is a *single* `user_type` with one `type_identifier`
/// per segment, so each prefix is resolved in turn: `Outer.Inner` records
/// `Outer` at its own token and `Outer.Inner` at `Inner`'s, which is what makes
/// an outer type's usage count include the nested references that named it.
fn record_user_type(user_type: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    // A nested `user_type` is reached through its parent's segment walk. Generic
    // arguments sit inside `type_arguments`, not directly under their owner, so
    // they are still visited in their own right.
    if user_type
        .parent()
        .is_some_and(|parent| parent.kind() == "user_type")
    {
        return;
    }
    record_type_name_segments(&kotlin_user_type_segments(user_type), scan);
}

/// Record one edge per resolving prefix of a dotted type name, so an outer type's
/// usage count includes the nested references that named it.
fn record_type_name_segments(segments: &[Node<'_>], scan: &mut KotlinEdgeScan<'_>) {
    let mut spelling = String::new();
    for segment in segments {
        let name = node_text(*segment, scan.source);
        if name.is_empty() {
            return;
        }
        if !spelling.is_empty() {
            spelling.push('.');
        }
        spelling.push_str(name);
        if let Some(resolved) = scan.names.resolve_type_fqn(&spelling, segment.start_byte()) {
            scan.record(resolved, *segment);
        }
    }
}

/// Record `class D : Base(1)` — a reference to the superclass and, when the
/// class declares one, to its constructor.
fn record_constructor_invocation(node: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    let Some(callee) = kotlin_callee(node) else {
        return;
    };
    let Some(owner_fqn) = resolve_constructed_type(callee, scan) else {
        return;
    };
    record_constructor_of(&owner_fqn, callee, node, kotlin_call_arity(node), scan);
}

/// The fqn of the type a callee constructs, for the shapes a constructor call
/// takes: a bare name, a `user_type` in a supertype list, or a dotted
/// navigation.
fn resolve_constructed_type(callee: Node<'_>, scan: &mut KotlinEdgeScan<'_>) -> Option<String> {
    match callee.kind() {
        "simple_identifier" => {
            let name = node_text(callee, scan.source).to_string();
            if name.is_empty() || scan.bindings.is_shadowed(&name) {
                return None;
            }
            scan.names.resolve_type_fqn(&name, callee.start_byte())
        }
        "user_type" => {
            let segments = kotlin_user_type_segments(callee);
            let spelled = segments
                .iter()
                .map(|segment| node_text(*segment, scan.source))
                .collect::<Vec<_>>()
                .join(".");
            (!spelled.is_empty())
                .then(|| scan.names.resolve_type_fqn(&spelled, callee.start_byte()))
                .flatten()
        }
        kind if kotlin_is_navigation_kind(kind) => {
            let spelled = dotted_navigation_spelling(callee, scan)?;
            scan.names.resolve_type_fqn(&spelled, callee.start_byte())
        }
        _ => None,
    }
}

/// Record a construction of `owner_fqn`: the class itself, and — when the class
/// declares one that accepts `arity` — its constructor.
///
/// The class reference is the load-bearing half. A Kotlin class with no
/// primary-constructor parameters has no constructor unit at all, so `Base()`
/// names only the class; and a Kotlin constructor is indexed as a *synthetic*
/// unit, which the workspace catalog excludes, so for most workspaces the class
/// edge is the only one a consumer can see.
fn record_constructor_of(
    owner_fqn: &str,
    type_node: Node<'_>,
    reference: Node<'_>,
    arity: usize,
    scan: &mut KotlinEdgeScan<'_>,
) {
    scan.record(owner_fqn.to_string(), type_node);
    let Some(identifier) = owner_fqn.rsplit('.').next() else {
        return;
    };
    let constructor_fqn = format!("{owner_fqn}.{identifier}");
    let declared = scan
        .graph
        .with_definitions(|definitions| definitions.fqn(&constructor_fqn))
        .iter()
        .any(|candidate| {
            candidate.is_function()
                && kotlin_callable_arities(scan.graph, candidate)
                    .iter()
                    .any(|recorded| recorded.accepts(arity))
        });
    if declared {
        scan.record(constructor_fqn, reference);
    }
}

/// The dotted name a navigation spells, when every link of it is a plain name.
fn dotted_navigation_spelling(navigation: Node<'_>, scan: &KotlinEdgeScan<'_>) -> Option<String> {
    let segments = kotlin_dotted_navigation_segments(navigation)?;
    let names: Vec<&str> = segments
        .iter()
        .map(|segment| node_text(*segment, scan.source))
        .collect();
    (!names.iter().any(|name| name.is_empty())).then(|| names.join("."))
}

/// Record a bare `simple_identifier` that names a *type* used as a qualifier:
/// the receiver of a member access, as in `Base.helper()` or `Color.RED`.
///
/// This is the one place a bare identifier can name a type, so it is guarded
/// three ways: it must actually be a navigation receiver, it must not be a
/// declaration's own name, and it must not be shadowed by a local — `val Base =
/// 1; Base.length` is a property access on a string, not a reference to a class.
fn record_bare_identifier(node: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    if kotlin_is_declaration_name(node) {
        return;
    }
    let name = node_text(node, scan.source).to_string();
    if name.is_empty() || scan.bindings.is_shadowed(&name) {
        return;
    }
    let Some(navigation) = node
        .parent()
        .filter(|parent| kotlin_is_navigation_kind(parent.kind()))
    else {
        return;
    };
    if kotlin_navigation_receiver(navigation).is_none_or(|receiver| receiver.id() != node.id()) {
        return;
    }
    if let Some(resolved) = scan.names.resolve_type_fqn(&name, node.start_byte()) {
        scan.record(resolved, node);
    }
}

// ---------------------------------------------------------------------------
// Calls and members
// ---------------------------------------------------------------------------

fn record_call(call: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    let Some(callee) = kotlin_callee(call) else {
        return;
    };
    let arity = kotlin_call_arity(call);
    match callee.kind() {
        kind if kotlin_is_navigation_kind(kind) => {
            // `lib.Base(1)` is a fully-qualified construction, not a member call.
            if let Some(owner_fqn) = dotted_navigation_spelling(callee, scan)
                .and_then(|spelled| scan.names.resolve_type_fqn(&spelled, callee.start_byte()))
                .filter(|fqn| type_unit(scan.graph, fqn).is_some())
            {
                let type_node = kotlin_navigation_member(callee).unwrap_or(callee);
                record_constructor_of(&owner_fqn, type_node, call, arity, scan);
                return;
            }
            record_member_access(callee, scan, Some(arity));
        }
        "simple_identifier" => {
            if kotlin_is_declaration_name(callee) {
                return;
            }
            let name = node_text(callee, scan.source).to_string();
            if name.is_empty() {
                return;
            }
            // `Base(1)` constructs a `Base`; a constructor call and a function
            // call are spelled identically, so the type reading is tried first.
            if !scan.bindings.is_shadowed(&name)
                && let Some(owner_fqn) = scan.names.resolve_type_fqn(&name, callee.start_byte())
                && type_unit(scan.graph, &owner_fqn).is_some()
            {
                record_constructor_of(&owner_fqn, callee, call, arity, scan);
                return;
            }
            record_bare_callable(callee, &name, Some(arity), scan);
        }
        _ => {}
    }
}

/// Record `::name`, a callable reference. No arity is applied, so the reference
/// is judged on the name alone.
fn record_callable_reference(reference: Node<'_>, scan: &mut KotlinEdgeScan<'_>) {
    let Some(name_node) = named_children(reference)
        .into_iter()
        .find(|child| child.kind() == "simple_identifier")
    else {
        return;
    };
    let name = node_text(name_node, scan.source).to_string();
    if name.is_empty() {
        return;
    }
    record_bare_callable(name_node, &name, None, scan);
}

/// Record a receiver-less reference: an implicit-`this` member, a top-level
/// declaration of the file's own package, or one an import brings in.
fn record_bare_callable(
    token: Node<'_>,
    name: &str,
    arity: Option<usize>,
    scan: &mut KotlinEdgeScan<'_>,
) {
    // A member named without a receiver is an implicit-`this` reference, which
    // is same-owner under the uniform #1014 policy. The *nearest* enclosing
    // owner that declares the name is the one the reference binds to; a
    // further-out one cannot also answer it.
    let owners = scan.enclosing_owner_fq_names(token);
    for owner in &owners {
        if let Some(found) = member_unit(owner, name, arity, scan) {
            let fqn = found.fq_name();
            route_same_owner(
                scan,
                true,
                |scan| {
                    scan.edges.record_unproven(
                        scan.input,
                        fqn,
                        token.start_byte(),
                        token.end_byte(),
                    )
                },
                |scan| scan.record_unproven(name, token),
            );
            return;
        }
    }
    let unit = match arity {
        Some(arity) => bare_callable_unit(name, arity, token, scan),
        None => scan
            .resolve_callable_fqn(name, token.start_byte())
            .and_then(|fqn| {
                scan.graph
                    .with_definitions(|definitions| definitions.fqn(&fqn))
                    .iter()
                    .find(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
                    .cloned()
            }),
    };
    match unit {
        Some(unit) => scan.record(unit.fq_name(), token),
        None => scan.record_unproven(name, token),
    }
}

/// Record `receiver.member`, typed through the receiver.
///
/// The edge lands on the declaration the call *binds to*, which may be an
/// ancestor's or the companion's rather than one spelled `Receiver.member` —
/// `member_unit` is the same lookup the query path uses, so the two cannot
/// disagree about which declaration a call means.
fn record_member_access(navigation: Node<'_>, scan: &mut KotlinEdgeScan<'_>, arity: Option<usize>) {
    let Some(member) = kotlin_navigation_member(navigation) else {
        return;
    };
    let name = node_text(member, scan.source).to_string();
    if name.is_empty() {
        return;
    }
    // A named argument's label names a parameter, not a member.
    if member
        .parent()
        .filter(|parent| parent.kind() == "value_argument")
        .is_some_and(|parent| kotlin_named_argument_label(parent, member))
    {
        return;
    }
    let Some(receiver) = kotlin_navigation_receiver(navigation) else {
        return;
    };
    // Same-owner (`this.m()`, `Owner.m()` from inside `Owner`, and the companion
    // access that spells) is recorded as unproven inbound rather than dropped:
    // a member reachable only through same-owner references is inconclusive for
    // dead code, never confidently dead.
    let same_owner = receiver_is_same_owner(receiver, scan);
    let owner_fqn = receiver_type_fq_name(receiver, scan, 0);
    let resolved = owner_fqn
        .as_ref()
        .and_then(|owner| member_unit(owner, &name, arity, scan))
        .map(|unit| unit.fq_name())
        // A nested type reached through its owner's name (`Outer.Inner`) is a
        // type, not a member: the reference names the nested declaration.
        .or_else(|| {
            let nested = format!("{}.{}", owner_fqn.as_ref()?, name);
            type_unit(scan.graph, &nested).map(|unit| unit.fq_name())
        })
        // An extension is declared outside the type it extends, so it is reached
        // through the receiver's type but never found among its members.
        .or_else(|| {
            let owner = owner_fqn.as_ref()?;
            visible_extension_unit(&name, owner, member.start_byte(), scan)
                .map(|unit| unit.fq_name())
        });
    route_same_owner(
        scan,
        same_owner,
        |scan| match &resolved {
            Some(fqn) => scan.edges.record_unproven(
                scan.input,
                fqn.clone(),
                member.start_byte(),
                member.end_byte(),
            ),
            None => scan.record_unproven(&name, member),
        },
        |scan| match &resolved {
            Some(fqn) => scan.record(fqn.clone(), member),
            // The receiver's type could not be established — a lambda parameter,
            // an inferred local, a smart cast. The site stays visible in the
            // unproven channel rather than being guessed into a proven edge.
            None => scan.record_unproven(&name, member),
        },
    );
}
