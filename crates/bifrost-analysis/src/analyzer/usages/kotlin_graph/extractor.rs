//! Forward per-file scan for the Kotlin query path.
//!
//! Walks one Kotlin file top to bottom looking for references to a single target
//! ([`super::resolver::TargetSpec`]), recording each one it can prove. The walk is
//! iterative (`walk_tree_iterative`) rather than recursive, per the repository's
//! stack-safety rule for analyzer tree walks, and it descends with a
//! `LocalInferenceEngine` so a binding's type is already known by the time a
//! reference below it is reached.
//!
//! Milestone 1 of issue #1239 implements the `TargetKind::Type` arm: references
//! to a Kotlin class, interface, object, enum, or type alias. The callable and
//! property arms arrive in milestone 2, and until then they record nothing, which
//! the strategy surfaces as an explicit unsupported-shape diagnostic rather than
//! an empty success.

use crate::analyzer::kotlin::syntax::{
    kotlin_import_header_segments, kotlin_is_declaration_name, kotlin_navigation_receiver,
    kotlin_user_type_segments,
};
use crate::analyzer::tree_walk::{TreeWalkAction, first_named_child_of_kind, walk_tree_iterative};
use crate::analyzer::usages::common::node_text;
use crate::analyzer::usages::kotlin_graph::hits;
use crate::analyzer::usages::kotlin_graph::resolver::{KotlinNameResolver, TargetKind, TargetSpec};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
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

pub(super) struct ScanState<'a> {
    pub(super) max_usages: usize,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) limit_exceeded: &'a mut bool,
}

pub(super) struct ScanCtx<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) spec: &'a TargetSpec,
    pub(super) names: &'a KotlinNameResolver<'a>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) raw_match_count: &'a mut usize,
    pub(super) max_usages: usize,
    pub(super) limit_exceeded: &'a mut bool,
    pub(super) enclosing_cache: HashMap<(usize, usize), hits::EnclosingContext>,
}

pub(super) fn scan_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let Some(source) = analyzer
        .indexed_source(file)
        .or_else(|| analyzer.project().read_source(file).ok())
    else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let line_starts = compute_line_starts(&source);
    let names = KotlinNameResolver::new(analyzer, file, tree.root_node(), &source);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut ctx = ScanCtx {
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        names: &names,
        hits: state.hits,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    walk(tree.root_node(), &mut ctx, &mut bindings);
}

fn walk(root: Node<'_>, ctx: &mut ScanCtx<'_>, bindings: &mut LocalInferenceEngine<String>) {
    let mut state = (ctx, bindings);
    walk_tree_iterative(
        root,
        &mut state,
        |node, (ctx, bindings)| {
            if *ctx.limit_exceeded {
                return TreeWalkAction::Stop;
            }
            let enters_scope = SCOPE_NODES.contains(&node.kind());
            if enters_scope {
                bindings.enter_scope();
            }
            seed_declarations(node, ctx, bindings);
            record_reference(node, ctx, bindings);
            if enters_scope {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |(_, bindings)| bindings.exit_scope(),
    );
}

/// Record every name a declaration introduces as a *shadow*: a value binding of
/// unknown type.
///
/// For a type query that is all that is needed, and it is needed: a local
/// `val Base = 1` shadows the type `Base`, so a later bare `Base` is not a
/// reference to the class. Milestone 2 extends this to record the binding's
/// resolved type, which is what receiver typing needs.
fn seed_declarations(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let name_node = match node.kind() {
        "variable_declaration"
        | "parameter"
        | "class_parameter"
        | "parameter_with_optional_type" => first_named_child_of_kind(node, "simple_identifier"),
        _ => return,
    };
    let Some(name_node) = name_node else {
        return;
    };
    let name = node_text(name_node, ctx.source);
    if !name.is_empty() {
        bindings.declare_shadow(name.to_string());
    }
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match ctx.spec.kind {
        TargetKind::Type => record_type_reference(node, ctx, bindings),
        // Milestone 2 of issue #1239. The strategy refuses these target kinds up
        // front with an explicit diagnostic, so this arm is unreachable rather
        // than silently empty.
        TargetKind::Constructor | TargetKind::Function | TargetKind::Property => {}
    }
}

fn record_type_reference(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        "import_header" => record_import_reference(node, ctx),
        "user_type" => record_user_type_reference(node, ctx),
        "simple_identifier" => record_qualifier_reference(node, ctx, bindings),
        _ => {}
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
    if path != ctx.spec.owner.fq_name() {
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
fn record_user_type_reference(user_type: Node<'_>, ctx: &mut ScanCtx<'_>) {
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

    let segments = kotlin_user_type_segments(user_type);
    let mut spelling = String::new();
    for segment in segments {
        let name = node_text(segment, ctx.source);
        if name.is_empty() {
            return;
        }
        if !spelling.is_empty() {
            spelling.push('.');
        }
        spelling.push_str(name);
        if ctx
            .names
            .resolve_type(&spelling, segment.start_byte())
            .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
        {
            hits::push_hit(segment, ctx);
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
fn record_qualifier_reference(
    node: Node<'_>,
    ctx: &mut ScanCtx<'_>,
    bindings: &LocalInferenceEngine<String>,
) {
    if kotlin_is_declaration_name(node) {
        return;
    }
    let name = node_text(node, ctx.source);
    if name.is_empty() || name != ctx.spec.owner.identifier() || bindings.is_shadowed(name) {
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
        .resolve_type(name, node.start_byte())
        .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
    {
        hits::push_hit(node, ctx);
    }
}
