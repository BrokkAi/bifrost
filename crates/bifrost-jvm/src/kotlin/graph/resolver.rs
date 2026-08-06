//! What a Kotlin usage query is looking for, and how a spelled name becomes a
//! declaration while looking for it.
//!
//! Two things live here. [`TargetSpec`] is the question — which declaration are
//! we finding references to — derived once per query and read by every scan.
//! [`KotlinNameResolver`] is the answer side: it turns a name as *spelled* in
//! Kotlin source into the fully-qualified name it denotes at a given position,
//! through Kotlin's real precedence ladder.
//!
//! The ladder itself is not reimplemented here. `crate::kotlin::types`
//! owns it as `resolve_kotlin_type_name`, parameterised over a "does this
//! fully-qualified name exist" predicate. This module supplies a predicate backed
//! by `IAnalyzer::global_usage_definition_index`, which under `MultiAnalyzer`
//! merges the declarations of every language in the workspace. That is what lets
//! a Kotlin file resolve a Java type declared next door, and it is why the
//! predicate is not `KotlinAnalyzer::source_type_exists`: the Kotlin-only lookup
//! would silently drop every cross-language answer.

use super::KotlinGraphSource;
use super::extractor::ScanCtx;
use crate::kotlin::declarations::kotlin_package_name;
use crate::kotlin::syntax::{
    kotlin_call_arity, kotlin_callee, kotlin_is_navigation_kind, kotlin_navigation_member,
    kotlin_navigation_receiver, kotlin_type_spelling, kotlin_unwrap_receiver,
};
use crate::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};
use brokk_bifrost_core::analyzer::model::{CallableArity, ImportInfo, SignatureMetadata};
use brokk_bifrost_core::analyzer::tree_walk::named_children;
use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::cell::RefCell;
use tree_sitter::Node;

/// How many levels of ancestor scope a name lookup inherits.
///
/// Matches `MAX_INHERITED_SCOPE_DEPTH` in `crate::kotlin::types` and
/// the same constant in the #1238 definition resolver, so navigation and usages
/// see the same scope for the same position.
const MAX_INHERITED_SCOPE_DEPTH: usize = 4;

/// What kind of declaration a query is finding references to.
///
/// Kotlin properties are one kind rather than two: `declarations.rs` indexes a
/// property as a single `Field` unit even when it declares a custom `get()`/
/// `set()`, so `obj.value` and `obj.value = 1` name the same declaration and
/// modelling accessors separately would invent identities the index does not
/// have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Type,
    Constructor,
    Function,
    Property,
}

/// How a receiver's type relates to the target a query is looking for.
///
/// The three outcomes carry three different amounts of knowledge, and keeping
/// them apart is what stops "we don't know" from collapsing into "yes" or "no":
/// `Matched` is proof the reference names the target, `Incompatible` is proof it
/// names something *else*, and `Unresolved` is the absence of either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverTargetMatch {
    Matched,
    Incompatible,
    Unresolved,
}

pub struct TargetSpec {
    /// The declaration the query names.
    pub target: CodeUnit,
    pub kind: TargetKind,
    /// The target's own fully-qualified name.
    ///
    /// For a type query this is what a spelled name must resolve to. For a
    /// top-level callable or property it is what a bare name must resolve to,
    /// because a top-level declaration is named through the file's own scope
    /// rather than through a receiver.
    pub fq_name: String,
    /// The declaration that owns `target`; the target itself when it is a type.
    ///
    /// `None` for a top-level Kotlin callable or property, which Kotlin declares
    /// directly in a package with no enclosing declaration at all.
    pub owner: Option<CodeUnit>,
    /// Fully-qualified names a *receiver* may denote for a reference to name
    /// this target.
    ///
    /// Usually just the declaring owner. Two Kotlin shapes widen it: an
    /// extension is reached through the type it extends rather than through the
    /// file that declares it, and a companion's members are reached through the
    /// enclosing class's own name (`Base.of()`, not only `Base.Companion.of()`).
    pub receiver_owner_fq_names: HashSet<String>,
    /// Owners whose declaration of the same member name counts as an override of
    /// the target, so the *declaration* is reported as a reference to what it
    /// overrides.
    pub declaration_owner_fq_names: HashSet<String>,
    /// The name a reference must spell.
    pub member_name: String,
    /// Arities the target accepts, or `None` for a non-callable.
    ///
    /// A set rather than one value because Kotlin overloads collapse into a
    /// single indexed identity carrying several signatures, so "the target's
    /// arity" is genuinely plural.
    pub callable_arities: Option<HashSet<CallableArity>>,
}

impl TargetSpec {
    pub fn from_targets(graph: &KotlinGraphSource<'_>, targets: &[CodeUnit]) -> Option<Self> {
        // Kotlin overloads collapse into one indexed identity: two functions
        // with the same fully-qualified name become a single `CodeUnit` carrying
        // several signatures. So the overload set a caller passes describes one
        // declaration, and the first entry is enough to identify it — but a
        // caller may still pass several distinct units (duplicate source copies
        // of one fully-qualified name), and every one of their arities counts.
        let mut spec = Self::from_target(graph, targets.first()?)?;
        if let Some(arities) = spec.callable_arities.as_mut() {
            for extra in targets.iter().skip(1) {
                if extra.fq_name() == spec.fq_name {
                    arities.extend(kotlin_callable_arities(graph, extra));
                }
            }
        }
        Some(spec)
    }

    pub fn from_target(graph: &KotlinGraphSource<'_>, target: &CodeUnit) -> Option<Self> {
        let fq_name = target.fq_name();
        if target.is_class() || is_kotlin_type_alias(graph, target) {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                receiver_owner_fq_names: [fq_name.clone()].into_iter().collect(),
                declaration_owner_fq_names: [fq_name.clone()].into_iter().collect(),
                member_name: target.identifier().to_string(),
                callable_arities: None,
                fq_name,
            });
        }

        // A Kotlin top-level function or property has no enclosing declaration.
        // That is not a gap in the index — the language really does declare it
        // straight into a package — so it is modelled as an owner-less target
        // named through the file's scope, not refused as an unsupported shape.
        let owner = graph.index.parent_of(target);
        let kind = if target.is_field() {
            TargetKind::Property
        } else if owner
            .as_ref()
            .is_some_and(|owner| target.identifier() == owner.identifier())
        {
            // Kotlin constructors are indexed as synthetic `Owner.Owner`
            // callables, so sharing the owner's spelling is what identifies one.
            TargetKind::Constructor
        } else {
            TargetKind::Function
        };

        let mut receiver_owner_fq_names: HashSet<String> = HashSet::default();
        let mut declaration_owner_fq_names: HashSet<String> = HashSet::default();
        if let Some(owner) = owner.as_ref() {
            receiver_owner_fq_names.insert(owner.fq_name());
            declaration_owner_fq_names.insert(owner.fq_name());
            // A companion's members answer to the enclosing class's own name:
            // `Base.of()` and `Base.Companion.of()` are the same call. The
            // enclosing class is therefore a legitimate receiver for them.
            if let Some(host) = companion_host_of(graph, owner) {
                receiver_owner_fq_names.insert(host);
            }
        }
        // An extension is reached through the type it extends, never through the
        // file or class that happens to declare it. Reading the receiver from
        // the published signature metadata (issue #1345) is a structured check;
        // the spelling is resolved in the *declaring* file's scope, because a
        // spelled type means whatever the file that wrote it says it means.
        if let Some(extended) = extension_receiver_fq_name(graph, target) {
            receiver_owner_fq_names.insert(extended);
        }
        if kind == TargetKind::Function
            && let (Some(owner), Some(provider)) = (owner.as_ref(), graph.hierarchy)
        {
            // A subclass that redeclares the member overrides it, and an
            // ancestor that declares it is what the target overrides. Both are
            // realm-aware, so a Java subclass overriding a Kotlin `open fun` is
            // included.
            for relative in provider
                .get_descendants(owner)
                .into_iter()
                .chain(provider.get_ancestors(owner))
            {
                if owner_declares_member(graph, &relative.fq_name(), target.identifier(), None) {
                    declaration_owner_fq_names.insert(relative.fq_name());
                }
            }
        }

        Some(Self {
            kind,
            callable_arities: (kind != TargetKind::Property)
                .then(|| kotlin_callable_arities(graph, target)),
            target: target.clone(),
            owner,
            receiver_owner_fq_names,
            declaration_owner_fq_names,
            member_name: target.identifier().to_string(),
            fq_name,
        })
    }

    /// Whether a call passing `arity` arguments can be a call of this target.
    ///
    /// A callable with no recorded arity accepts anything: missing metadata is
    /// an absence of evidence, and using it to reject a candidate would turn a
    /// gap in indexing into a confident wrong answer.
    pub fn accepts_arity(&self, arity: usize) -> bool {
        self.callable_arities
            .as_ref()
            .is_none_or(|arities| arities.is_empty() || arities.iter().any(|a| a.accepts(arity)))
    }
}

/// Every arity `unit`'s recorded signatures accept.
///
/// Collected over *all* of `signature_metadata`, not just the first: Kotlin
/// overloads share one `CodeUnit`, so a single identity legitimately carries
/// several signatures and rejecting a call on the first one's arity would miss
/// every other overload.
pub fn kotlin_callable_arities(
    graph: &KotlinGraphSource<'_>,
    unit: &CodeUnit,
) -> HashSet<CallableArity> {
    graph
        .index
        .signature_metadata(unit)
        .iter()
        .filter_map(SignatureMetadata::callable_arity)
        .collect()
}

/// Whether `unit` is a Kotlin `companion object`.
///
/// Read from the published `SignatureMetadata` marker rather than from the
/// declaring file's syntax. Companion-ness is not derivable from the identity —
/// a companion and an ordinary nested `object` are both nested classes, and the
/// `Companion` default name is a name-resolution rule a source file may
/// override — so before milestone 3 this question cost one *parse* of the
/// declaring file. That was bounded for a query (one target, asked once) but not
/// for the whole-workspace edge builder, which asks it per callee owner. The
/// Kotlin declaration walk now publishes it, at the cost of one signature-blob
/// field, and the epoch salt carries `kotlin-companion-object-marker-2026-07` so
/// a warm workspace re-indexes rather than reading every companion as an
/// ordinary object.
pub fn is_companion_object(graph: &KotlinGraphSource<'_>, unit: &CodeUnit) -> bool {
    unit.is_class()
        && graph
            .index
            .signature_metadata(unit)
            .iter()
            .any(SignatureMetadata::is_companion_object)
}

/// The class a companion object is declared inside, or `None` when `unit` is not
/// a companion.
fn companion_host_of(graph: &KotlinGraphSource<'_>, unit: &CodeUnit) -> Option<String> {
    is_companion_object(graph, unit)
        .then(|| graph.index.parent_of(unit))
        .flatten()
        .map(|host| host.fq_name())
}

/// The fully-qualified name of the type `unit` extends, when `unit` is a Kotlin
/// extension.
pub fn extension_receiver_fq_name(
    graph: &KotlinGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<String> {
    let spelled = graph
        .index
        .signature_metadata(unit)
        .into_iter()
        .find_map(|entry| entry.extension_receiver_type().map(str::to_string))?;
    let byte = graph.index.ranges(unit).into_iter().min()?.start_byte;
    KotlinNameResolver::for_declaration(graph, unit).resolve_type_fqn(&spelled, byte)
}

// ---------------------------------------------------------------------------
// Receiver typing: what type is the thing on the left of the dot?
// ---------------------------------------------------------------------------

/// How far a receiver chain (`a.b().c().d()`) is followed before the scan gives
/// up and reports the reference as unproven.
///
/// Shared with Java rather than restated, so the two JVM languages report the
/// same budget when a chain exhausts it.
use crate::java::graph::return_type::METHOD_RECEIVER_CHAIN_LIMIT;

/// How many ancestors deep a member lookup walks before giving up.
const MAX_MEMBER_HIERARCHY_DEPTH: usize = 8;

/// What Kotlin receiver typing needs from whichever usage path is driving it.
///
/// `usages/traits.rs` requires the query path and the edge path to share one
/// resolver, and this trait is where that sharing is real rather than asserted:
/// everything below it — how a receiver is typed, which member a name binds to,
/// what a declaration declares — has exactly one implementation, used by
/// [`super::extractor::ScanCtx`] when answering "who uses *this* declaration?"
/// and by [`super::inverted`]'s scan when answering "what does this reference
/// name?". Only the two questions differ; the machinery does not.
///
/// The two paths do differ in how they answer the *lexical* questions, which is
/// why those are methods rather than fields. A query resolves a reference's
/// enclosing declaration through `IAnalyzer::enclosing_code_unit`, because it
/// has to attribute the hit to a caller anyway; the whole-workspace builder
/// already holds a per-file `ClassRangeIndex` and would pay for the same answer
/// twice by asking the graph again.
pub trait KotlinResolutionCtx {
    fn graph(&self) -> &KotlinGraphSource<'_>;

    /// The source text of the file being scanned.
    fn source(&self) -> &str;

    /// Value bindings visible at the node being visited.
    fn bindings(&self) -> &LocalInferenceEngine<String>;

    /// The fully-qualified name the *type* `spelled` denotes at `byte`.
    fn resolve_type_fqn(&self, spelled: &str, byte: usize) -> Option<String>;

    /// The fully-qualified name the receiver-less *callable or property*
    /// `spelled` denotes at `byte`.
    fn resolve_callable_fqn(&self, spelled: &str, byte: usize) -> Option<String>;

    /// Fully-qualified names of the class-like declarations lexically enclosing
    /// `node`, innermost first.
    fn enclosing_owner_fq_names(&mut self, node: Node<'_>) -> Vec<String>;

    /// The type each declaration declares, memoized for the duration of one file
    /// scan: a chain expression asks the same question of the same callee once
    /// per link.
    fn declared_type_cache(&mut self) -> &mut HashMap<String, Option<String>>;
}

/// Whether a reference through `receiver` names the target.
pub fn receiver_matches_target(receiver: Node<'_>, ctx: &mut ScanCtx<'_>) -> ReceiverTargetMatch {
    match receiver_type_fq_name(receiver, ctx, 0) {
        Some(fqn) => receiver_type_matches_target(&fqn, ctx),
        None => ReceiverTargetMatch::Unresolved,
    }
}

/// Whether a receiver *known* to have type `receiver_fqn` reaches the target.
///
/// The three outcomes are all load-bearing. A receiver whose own type declares a
/// same-named member is `Incompatible` — the call names that declaration, not
/// this one, which is what keeps an override's call sites off the base
/// declaration's usage list. A receiver that inherits the member from the
/// target's owner, with nothing in between redeclaring it, is `Matched`.
/// Anything the hierarchy cannot decide stays `Unresolved` and becomes an
/// unproven hit rather than silence.
pub fn receiver_type_matches_target(
    receiver_fqn: &str,
    ctx: &mut ScanCtx<'_>,
) -> ReceiverTargetMatch {
    if let Some(cached) = ctx.receiver_match_cache.get(receiver_fqn) {
        return *cached;
    }
    let resolved = receiver_type_matches_target_uncached(receiver_fqn, ctx);
    ctx.receiver_match_cache
        .insert(receiver_fqn.to_string(), resolved);
    resolved
}

fn receiver_type_matches_target_uncached(
    receiver_fqn: &str,
    ctx: &ScanCtx<'_>,
) -> ReceiverTargetMatch {
    if ctx.spec.receiver_owner_fq_names.contains(receiver_fqn) {
        return ReceiverTargetMatch::Matched;
    }
    // A type target is named by its own name, never through a receiver of some
    // other type, so there is nothing for the hierarchy to widen.
    if ctx.spec.kind == TargetKind::Type {
        return ReceiverTargetMatch::Incompatible;
    }
    let Some(owner) = ctx.spec.owner.as_ref() else {
        // A top-level declaration has no receiver; a reference through one names
        // something else.
        return ReceiverTargetMatch::Incompatible;
    };
    let (Some(provider), Some(receiver_unit)) =
        (ctx.graph.hierarchy, type_unit(ctx.graph, receiver_fqn))
    else {
        return ReceiverTargetMatch::Unresolved;
    };

    // The receiver's own type declares this member: the reference names *that*
    // declaration. Proof of a different identity, not absence of proof.
    // Overloads collapse into one indexed identity, so "this owner declares a
    // member of this name" is the strongest honest statement available here;
    // gating on an arity would make one overload's shape speak for all of them.
    if owner_declares_member(ctx.graph, receiver_fqn, &ctx.spec.member_name, None) {
        return ReceiverTargetMatch::Incompatible;
    }

    // Walk up the hierarchy breadth-first. The first level that declares the
    // member is the one a call binds to, so reaching the target's owner before
    // anything else declares it is proof; reaching a *different* declarer first
    // is proof of the opposite.
    let mut frontier = vec![receiver_unit];
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
        let mut next = Vec::new();
        let mut declaring_at_this_level = Vec::new();
        for unit in &frontier {
            for ancestor in provider.get_direct_ancestors(unit) {
                let fqn = ancestor.fq_name();
                if seen.contains(&fqn) {
                    continue;
                }
                seen.push(fqn.clone());
                if owner_declares_member(ctx.graph, &fqn, &ctx.spec.member_name, None) {
                    declaring_at_this_level.push(fqn);
                } else {
                    next.push(ancestor);
                }
            }
        }
        if !declaring_at_this_level.is_empty() {
            return if declaring_at_this_level.len() == 1
                && declaring_at_this_level[0] == owner.fq_name()
            {
                ReceiverTargetMatch::Matched
            } else if declaring_at_this_level
                .iter()
                .any(|fqn| *fqn == owner.fq_name())
            {
                // Several supertypes at the same distance declare it and one of
                // them is the target's owner: the language picks one and this
                // scan cannot say which.
                ReceiverTargetMatch::Unresolved
            } else {
                ReceiverTargetMatch::Incompatible
            };
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    ReceiverTargetMatch::Incompatible
}

/// Whether a *matched* receiver is a same-owner receiver: the current instance
/// (`this`) or the own type itself (`Owner.member` from inside `Owner`, which is
/// how a companion member is reached).
///
/// `super` is not same-owner, and neither is a call through another variable
/// that merely happens to have the same type. That is the uniform cross-language
/// policy of #1014 facet B, enforced here so "is this Kotlin declaration dead?"
/// means what it means for the Java neighbours in the same workspace.
pub fn receiver_is_same_owner(receiver: Node<'_>, ctx: &mut impl KotlinResolutionCtx) -> bool {
    let receiver = kotlin_unwrap_receiver(receiver);
    match receiver.kind() {
        "this_expression" => true,
        "super_expression" => false,
        "simple_identifier" => {
            let name = node_text(receiver, ctx.source()).to_string();
            // A value binding of the owner's type is a different object, so it
            // stays external even though its type matches.
            if name.is_empty() || ctx.bindings().is_shadowed(&name) {
                return false;
            }
            let Some(fqn) = ctx.resolve_type_fqn(&name, receiver.start_byte()) else {
                return false;
            };
            ctx.enclosing_owner_fq_names(receiver).contains(&fqn)
        }
        _ => false,
    }
}

/// The fully-qualified name of the type the expression `node` evaluates to.
pub fn receiver_type_fq_name(
    node: Node<'_>,
    ctx: &mut impl KotlinResolutionCtx,
    depth: usize,
) -> Option<String> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        // Budget exhausted: report nothing rather than guess. The caller turns
        // that into an unproven hit, so the site stays visible.
        return None;
    }
    let node = kotlin_unwrap_receiver(node);
    match node.kind() {
        "this_expression" => this_receiver_fq_name(node, ctx),
        "super_expression" => {
            let owner = ctx.enclosing_owner_fq_names(node).into_iter().next()?;
            let unit = type_unit(ctx.graph(), &owner)?;
            ctx.graph()
                .hierarchy?
                .get_direct_ancestors(&unit)
                .first()
                .map(CodeUnit::fq_name)
        }
        "simple_identifier" => {
            let name = node_text(node, ctx.source()).to_string();
            if name.is_empty() {
                return None;
            }
            if let Some(bound) = ctx.bindings().resolve_symbol(&name).as_precise()
                && bound.len() == 1
            {
                return bound.iter().next().cloned();
            }
            if ctx.bindings().is_shadowed(&name) {
                // A binding is in scope but its type is not known — a lambda
                // parameter, an inferred local, a smart cast. Deliberately not
                // resolved as a type name: doing so would read a local as the
                // class it shadows.
                return None;
            }
            ctx.resolve_type_fqn(&name, node.start_byte())
        }
        "call_expression" => call_result_type_fq_name(node, ctx, depth),
        kind if kotlin_is_navigation_kind(kind) => {
            let member = kotlin_navigation_member(node)?;
            let member_name = node_text(member, ctx.source()).to_string();
            let receiver = kotlin_navigation_receiver(node)?;
            // A dotted qualifier (`lib.Base`) is a type name, not a member
            // access on a value, so it is tried as a whole first.
            if let Some(fqn) = navigation_type_fq_name(node, ctx) {
                return Some(fqn);
            }
            let receiver_fqn = receiver_type_fq_name(receiver, ctx, depth + 1)?;
            member_declared_type(&receiver_fqn, &member_name, None, ctx)
        }
        "as_expression" => named_children(node)
            .into_iter()
            .find_map(|child| kotlin_type_spelling(child, ctx.source()))
            .and_then(|spelled| ctx.resolve_type_fqn(&spelled, node.start_byte())),
        _ => None,
    }
}

/// The type `this` denotes at `node`, honouring a `this@Outer` label.
fn this_receiver_fq_name(node: Node<'_>, ctx: &mut impl KotlinResolutionCtx) -> Option<String> {
    let owners = ctx.enclosing_owner_fq_names(node);
    let label = node_text(node, ctx.source())
        .strip_prefix("this@")
        .map(str::to_string);
    match label {
        // `this@Outer` selects the enclosing owner spelled `Outer`, which is why
        // the label is compared against the owner chain rather than resolved as
        // a free type name: it names a *scope*, not any visible type.
        Some(label) => owners.into_iter().find(|fqn| {
            fqn.rsplit('.')
                .next()
                .is_some_and(|terminal| terminal == label)
        }),
        None => owners.into_iter().next(),
    }
}

/// The whole of a dotted qualifier (`lib.Base` in `lib.Base.of()`) read as a type
/// name.
fn navigation_type_fq_name(
    navigation: Node<'_>,
    ctx: &mut impl KotlinResolutionCtx,
) -> Option<String> {
    let mut segments = Vec::new();
    let mut current = navigation;
    loop {
        let member = kotlin_navigation_member(current)?;
        segments.push(node_text(member, ctx.source()).to_string());
        let receiver = kotlin_navigation_receiver(current)?;
        match receiver.kind() {
            kind if kotlin_is_navigation_kind(kind) => current = receiver,
            "simple_identifier" => {
                segments.push(node_text(receiver, ctx.source()).to_string());
                break;
            }
            _ => return None,
        }
    }
    segments.reverse();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    ctx.resolve_type_fqn(&segments.join("."), navigation.start_byte())
}

/// The type a call evaluates to: the constructed type for a constructor call,
/// otherwise the callee's declared return type.
fn call_result_type_fq_name(
    call: Node<'_>,
    ctx: &mut impl KotlinResolutionCtx,
    depth: usize,
) -> Option<String> {
    let callee = kotlin_callee(call)?;
    let arity = kotlin_call_arity(call);
    match callee.kind() {
        "simple_identifier" => {
            let name = node_text(callee, ctx.source()).to_string();
            if name.is_empty() {
                return None;
            }
            // `Base()` constructs a `Base`. Tried first because a constructor
            // call and a function call are spelled identically.
            if !ctx.bindings().is_shadowed(&name)
                && let Some(fqn) = ctx.resolve_type_fqn(&name, callee.start_byte())
            {
                return Some(fqn);
            }
            let unit = bare_callable_unit(&name, arity, callee, ctx)?;
            declared_type_of(&unit, ctx)
        }
        kind if kotlin_is_navigation_kind(kind) => {
            let member = kotlin_navigation_member(callee)?;
            let member_name = node_text(member, ctx.source()).to_string();
            let receiver = kotlin_navigation_receiver(callee)?;
            // `lib.Base()` — a fully-qualified constructor call.
            if let Some(fqn) = navigation_type_fq_name(callee, ctx) {
                return Some(fqn);
            }
            let receiver_fqn = receiver_type_fq_name(receiver, ctx, depth + 1)?;
            member_declared_type(&receiver_fqn, &member_name, Some(arity), ctx)
        }
        _ => None,
    }
}

/// The declaration a bare call names: a member of an enclosing owner (or what it
/// inherits), then a top-level callable of the file's own package, then one an
/// import brings in.
pub fn bare_callable_unit(
    name: &str,
    arity: usize,
    node: Node<'_>,
    ctx: &mut impl KotlinResolutionCtx,
) -> Option<CodeUnit> {
    for owner in ctx.enclosing_owner_fq_names(node) {
        if let Some(unit) = member_unit(&owner, name, Some(arity), ctx) {
            return Some(unit);
        }
    }
    let fqn = ctx.resolve_callable_fqn(name, node.start_byte())?;
    ctx.graph().with_definitions(|definitions| {
        definitions
            .fqn(&fqn)
            .iter()
            .find(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
            .cloned()
    })
}

/// The member declaration `member_name` names on a receiver of type
/// `owner_fqn`, searching the owner, its companion, and its ancestors.
pub fn member_unit(
    owner_fqn: &str,
    member_name: &str,
    arity: Option<usize>,
    ctx: &mut impl KotlinResolutionCtx,
) -> Option<CodeUnit> {
    let graph = ctx.graph();
    if let Some(unit) = declared_member_unit(graph, owner_fqn, member_name, arity) {
        return Some(unit);
    }
    let owner_unit = type_unit(graph, owner_fqn)?;
    // A companion's members answer to the enclosing class's name.
    for child in graph.with_definitions(|definitions| definitions.fqn_direct_children(owner_fqn)) {
        if child.is_class()
            && is_companion_object(graph, &child)
            && let Some(unit) = declared_member_unit(graph, &child.fq_name(), member_name, arity)
        {
            return Some(unit);
        }
    }
    let provider = graph.hierarchy?;
    let mut frontier = vec![owner_unit];
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
        let mut next = Vec::new();
        for unit in &frontier {
            for ancestor in provider.get_direct_ancestors(unit) {
                let fqn = ancestor.fq_name();
                if seen.contains(&fqn) {
                    continue;
                }
                seen.push(fqn.clone());
                if let Some(found) = declared_member_unit(graph, &fqn, member_name, arity) {
                    return Some(found);
                }
                next.push(ancestor);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    None
}

fn declared_member_unit(
    graph: &KotlinGraphSource<'_>,
    owner_fqn: &str,
    member_name: &str,
    arity: Option<usize>,
) -> Option<CodeUnit> {
    graph
        .with_definitions(|definitions| definitions.fqn(&format!("{owner_fqn}.{member_name}")))
        .iter()
        .find(|unit| {
            !unit.is_synthetic()
                && (unit.is_function() || unit.is_field())
                && arity.is_none_or(|arity| {
                    if !unit.is_function() {
                        return true;
                    }
                    let arities = kotlin_callable_arities(graph, unit);
                    arities.is_empty() || arities.iter().any(|recorded| recorded.accepts(arity))
                })
        })
        .cloned()
}

/// The extension declaration `member_name` names on a receiver of type
/// `owner_fqn`, when one is visible at `byte`.
///
/// An extension is *not* a member of the type it extends: the index records it
/// where it is written, as a top-level callable of its own file's package or as
/// a member of the class that declares it. So `member_unit` cannot find it, and
/// the visibility rule that does is the one for any receiver-less name — the
/// declaring file's package, or an import that names it — which is exactly what
/// [`KotlinResolutionCtx::resolve_callable_fqn`] answers.
///
/// The receiver type must match the extended type *exactly*, not merely conform
/// to it. That is deliberately the same bar the query path applies through
/// `TargetSpec::receiver_owner_fq_names`: if one direction accepted a subtype
/// receiver and the other did not, `scan_usages` and `usage_graph` would
/// disagree about whether a call is a usage of the extension.
pub fn visible_extension_unit(
    member_name: &str,
    owner_fqn: &str,
    byte: usize,
    ctx: &mut impl KotlinResolutionCtx,
) -> Option<CodeUnit> {
    let fqn = ctx.resolve_callable_fqn(member_name, byte)?;
    let graph = ctx.graph();
    let unit = graph
        .with_definitions(|definitions| definitions.fqn(&fqn))
        .iter()
        .find(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
        .cloned()?;
    (extension_receiver_fq_name(graph, &unit)? == owner_fqn).then_some(unit)
}

/// The declared type of the member `member_name` on a receiver of type
/// `owner_fqn`.
fn member_declared_type(
    owner_fqn: &str,
    member_name: &str,
    arity: Option<usize>,
    ctx: &mut impl KotlinResolutionCtx,
) -> Option<String> {
    // A nested type reached through its owner's name (`Outer.Inner`) is a type,
    // not a member with a type.
    let nested = format!("{owner_fqn}.{member_name}");
    if type_unit(ctx.graph(), &nested).is_some() {
        return Some(nested);
    }
    let unit = member_unit(owner_fqn, member_name, arity, ctx)?;
    declared_type_of(&unit, ctx)
}

/// The fully-qualified name of the type `unit` declares, from the published
/// signature metadata (issue #1345) resolved in the file that wrote it.
///
/// Cached per declaration for the duration of one file scan: a chain expression
/// asks the same question of the same callee once per link.
pub fn declared_type_of(unit: &CodeUnit, ctx: &mut impl KotlinResolutionCtx) -> Option<String> {
    let key = unit.fq_name();
    if let Some(cached) = ctx.declared_type_cache().get(&key) {
        return cached.clone();
    }
    let resolved = declared_type_of_uncached(unit, ctx.graph());
    ctx.declared_type_cache().insert(key, resolved.clone());
    resolved
}

fn declared_type_of_uncached(unit: &CodeUnit, graph: &KotlinGraphSource<'_>) -> Option<String> {
    // An enum entry writes no type: it is an instance of its own enum.
    if unit.is_field()
        && let Some(parent) = graph.index.parent_of(unit)
        && parent.is_class()
        && graph.index.signature_metadata(unit).is_empty()
    {
        return Some(parent.fq_name());
    }
    let spelled = graph
        .index
        .signature_metadata(unit)
        .into_iter()
        .find_map(|entry| entry.return_type_text().map(str::to_string))?;
    let byte = graph.index.ranges(unit).into_iter().min()?.start_byte;
    KotlinNameResolver::for_declaration(graph, unit).resolve_type_fqn(&spelled, byte)
}

/// The workspace type declaration named `fqn`, if there is one.
pub fn type_unit(graph: &KotlinGraphSource<'_>, fqn: &str) -> Option<CodeUnit> {
    graph
        .with_definitions(|definitions| definitions.fqn(fqn))
        .iter()
        .find(|unit| !unit.is_synthetic() && unit.fq_name() == fqn && unit.is_class())
        .cloned()
}

/// Whether `owner_fqn` declares a member spelled `member_name`, optionally one
/// that accepts a call of `arity`.
pub fn owner_declares_member(
    graph: &KotlinGraphSource<'_>,
    owner_fqn: &str,
    member_name: &str,
    arity: Option<usize>,
) -> bool {
    graph
        .with_definitions(|definitions| definitions.fqn(&format!("{owner_fqn}.{member_name}")))
        .iter()
        .any(|unit| {
            !unit.is_synthetic()
                && (unit.is_function() || unit.is_field())
                && arity.is_none_or(|arity| {
                    if !unit.is_function() {
                        return true;
                    }
                    let arities = kotlin_callable_arities(graph, unit);
                    arities.is_empty() || arities.iter().any(|recorded| recorded.accepts(arity))
                })
        })
}

/// Whether `unit` is a Kotlin `typealias`.
///
/// `declarations.rs` indexes a type alias as a `Field` `CodeUnit` and records the
/// alias-ness separately, so `is_class()` is false for one. That makes the flag
/// load-bearing here twice over: an alias is *referenced* in type positions
/// (`val v: Parent`), so a query for one is a type query, and a spelled name can
/// *resolve* to one, so the name ladder has to count it as an existing type.
/// Without this, a query for an alias would fall into the property arm and be
/// answered by receiver typing, which an alias never has.
fn is_kotlin_type_alias(graph: &KotlinGraphSource<'_>, unit: &CodeUnit) -> bool {
    unit.is_field()
        && graph
            .type_alias
            .is_some_and(|provider| provider.is_type_alias(unit))
}

/// The file-level half of a Kotlin name scope: what the file declares itself to
/// be in, and what it imported.
struct KotlinFileFacts {
    package_name: String,
    imports: Vec<ImportInfo>,
}

/// Turns spelled Kotlin names into fully-qualified names, for one file scan.
///
/// Holds the per-file facts the ladder needs and caches the enclosing-scope
/// lookup, which is otherwise repeated for every reference in the file.
pub struct KotlinNameResolver<'a> {
    graph: &'a KotlinGraphSource<'a>,
    file: &'a ProjectFile,
    facts: KotlinFileFacts,
    /// Scope owners by the byte offset asked about. A file scan asks this once
    /// per reference and the answer only changes when the enclosing declaration
    /// changes, so without the cache a large file re-walks the owner chain
    /// hundreds of times.
    owners_at: RefCell<Vec<(usize, Vec<String>)>>,
}

impl<'a> KotlinNameResolver<'a> {
    pub fn new(
        graph: &'a KotlinGraphSource<'a>,
        file: &'a ProjectFile,
        root: tree_sitter::Node<'_>,
        source: &str,
    ) -> Self {
        Self {
            graph,
            file,
            facts: KotlinFileFacts {
                // Read from the syntax tree rather than from an indexed
                // declaration: a file whose declarations were dropped by parse
                // recovery still has a package header, and the same-package tier
                // of the ladder needs it.
                package_name: kotlin_package_name(root, source),
                imports: graph
                    .imports
                    .map(|provider| provider.import_info_of(file))
                    .unwrap_or_default(),
            },
            owners_at: RefCell::new(Vec::new()),
        }
    }

    /// A resolver for the file that declared `unit`, built without parsing it.
    ///
    /// The package comes from the declaration's own identity and the imports
    /// from the import index, so resolving a *published* fact — an extension's
    /// receiver, a callee's return type — in the scope of the file that wrote it
    /// costs no parse. That is what makes issue #1345's published facts a
    /// saving rather than a reordering.
    pub fn for_declaration(graph: &'a KotlinGraphSource<'a>, unit: &'a CodeUnit) -> Self {
        Self {
            graph,
            file: unit.source(),
            facts: KotlinFileFacts {
                package_name: unit.package_name().to_string(),
                imports: graph
                    .imports
                    .map(|provider| provider.import_info_of(unit.source()))
                    .unwrap_or_default(),
            },
            owners_at: RefCell::new(Vec::new()),
        }
    }

    /// The fully-qualified name the type `spelled` at `byte` denotes.
    ///
    /// Answers with the *name*, not a declaration, because in the JVM realm the
    /// name is the identity. Two source files declaring `lib.Base` — a vendored
    /// copy, or the same package built by two modules — are one classpath entry
    /// and therefore one usage-graph node, so a reference to `Base` is a
    /// reference to both. Returning a single `CodeUnit` here would have to either
    /// pick one arbitrarily or fail closed, and failing closed would report zero
    /// usages for every duplicated type in a monorepo. Java's usage graph reports
    /// both copies for exactly this reason.
    pub fn resolve_type_fqn(&self, spelled: &str, byte: usize) -> Option<String> {
        self.resolve_type_name(spelled, byte).resolved()
    }

    /// The fully-qualified name the *callable or property* `spelled` at `byte`
    /// denotes when it is named without a receiver.
    ///
    /// Kotlin has separate namespaces for types and values, so this cannot share
    /// the type ladder's existence predicate: `val Base = 1` alongside
    /// `class Base` means "does a type named `Base` exist here" and "does a
    /// value named `Base` exist here" have different answers, and answering a
    /// value question with the type predicate would resolve a bare call to a
    /// class. The *ladder* is the same — Kotlin's precedence rules do not change
    /// between namespaces — so only the predicate differs.
    pub fn resolve_callable_fqn(&self, spelled: &str, byte: usize) -> Option<String> {
        let owners = self.scope_owners_at(byte);
        let scope = KotlinNameScope {
            package_name: &self.facts.package_name,
            imports: &self.facts.imports,
            scope_owners: owners,
        };
        resolve_kotlin_type_name(spelled, &scope, |candidate| self.callable_exists(candidate))
            .resolved()
    }

    /// Whether any language in the workspace indexes a callable or property
    /// named `fqn`.
    ///
    /// Synthetic units are excluded: Kotlin's primary constructors are synthetic
    /// `Owner.Owner` callables, and a bare name never reaches one — a
    /// constructor is named through its type.
    fn callable_exists(&self, fqn: &str) -> bool {
        self.graph
            .with_definitions(|definitions| definitions.fqn(fqn))
            .iter()
            .any(|unit| {
                !unit.is_synthetic()
                    && unit.fq_name() == fqn
                    && (unit.is_function() || unit.is_field())
            })
    }

    pub fn resolve_type_name(&self, spelled: &str, byte: usize) -> KotlinTypeName {
        let owners = self.scope_owners_at(byte);
        let scope = KotlinNameScope {
            package_name: &self.facts.package_name,
            imports: &self.facts.imports,
            scope_owners: owners,
        };
        resolve_kotlin_type_name(spelled, &scope, |candidate| self.type_exists(candidate))
    }

    /// Whether any language in the workspace indexes a type named `fqn`.
    ///
    /// Kotlin type aliases count: a spelled name can resolve to one, and a
    /// reference through an alias is a reference to the alias. Synthetic units do
    /// not: Kotlin's primary constructors are synthetic `Owner.Owner` callables,
    /// and no type reference names one.
    fn type_exists(&self, fqn: &str) -> bool {
        self.graph
            .with_definitions(|definitions| definitions.fqn(fqn))
            .iter()
            .any(|unit| {
                !unit.is_synthetic()
                    && unit.fq_name() == fqn
                    && (unit.is_class() || is_kotlin_type_alias(self.graph, unit))
            })
    }

    /// Fully-qualified names of the declarations enclosing `byte`, innermost
    /// first, plus the scopes they inherit.
    fn scope_owners_at(&self, byte: usize) -> Vec<String> {
        if let Some((_, owners)) = self
            .owners_at
            .borrow()
            .iter()
            .find(|(cached, _)| *cached == byte)
        {
            return owners.clone();
        }
        let owners = self.compute_scope_owners_at(byte);
        self.owners_at.borrow_mut().push((byte, owners.clone()));
        owners
    }

    fn compute_scope_owners_at(&self, byte: usize) -> Vec<String> {
        let Some(enclosing) = self.graph.index.enclosing_code_unit(
            self.file,
            &Range {
                start_byte: byte,
                end_byte: byte.saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        ) else {
            return Vec::new();
        };
        let mut owners = Vec::new();
        let mut lexical = Vec::new();
        let mut current = Some(enclosing);
        while let Some(unit) = current {
            let fqn = unit.fq_name();
            if !owners.contains(&fqn) {
                owners.push(fqn.clone());
                lexical.push(unit.clone());
            }
            current = self.graph.index.parent_of(&unit);
        }

        // A class can name a type its superclass declares, so what the lexical
        // owners inherit is part of the scope too. Depth-capped because a cyclic
        // or malformed hierarchy would otherwise make one name lookup unbounded.
        let Some(provider) = self.graph.hierarchy else {
            return owners;
        };
        let mut frontier = lexical;
        for _ in 0..MAX_INHERITED_SCOPE_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in provider.get_direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if !owners.contains(&fqn) {
                        owners.push(fqn);
                        next.push(ancestor);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        owners
    }
}
