//! Whole-workspace inverted edge builder for Python.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Python node fqns are dotted module
//! paths (`pkg.util.format_value`, `app.helper`), so a reference resolves through
//! the file's import binder:
//!
//! - a `from pkg.util import f` binding resolves a bare `f` to `pkg.util.f`;
//! - an `import pkg.util as u` binding resolves `u.f` to `pkg.util.f`;
//! - a same-file/same-module name resolves to that declaration's fqn.
//!
//! Parameters and local assignments shadow same-named imports and module-level
//! declarations (Python scopes are function-wide), matching the forward scan's
//! shadow handling so a local named like an import does not produce a false edge.
//! A typed receiver — a `recv: Foo` parameter or a `recv = Foo()` local —
//! resolves `recv.method` to `Foo.method` via the forward scan's shared receiver
//! typing ([`collect_scope_facts`] + [`resolve_receiver_type`]).

use super::extractor::{
    collect_assigned_identifiers, collect_scope_facts, enclosing_scope_facts,
    is_declaration_identifier, slice,
};
use super::resolver::resolve_receiver_type;
use crate::analyzer::PythonAnalyzer;
use crate::analyzer::usages::inverted_edges::{
    EdgeCollector, UsageEdges, build_edges, parse_and_collect,
};
use crate::analyzer::usages::local_inference::LocalBindingsSnapshot;
use crate::analyzer::usages::model::ImportKind;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Build the whole Python `caller -> callee` edge set in a single inverted pass.
pub(super) fn build_python_edges<F>(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = py.get_analyzed_files().into_iter().collect();
    let language = tree_sitter_python::LANGUAGE.into();
    build_edges(&files, keep_file, |file| {
        // Parse on demand and drop the tree when this closure returns, so live trees
        // are bounded by the worker count rather than the workspace size (#200).
        // Resolution reaches no other file's tree: the import binder, same-file
        // declarations, and the receiver-type facts are all derived from this file
        // plus the analyzer's own (tree-free) caches.
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let source = parsed.source.as_str();

            // Per-file resolution context from the import binder. A namespace
            // binding's module_specifier is either the full fqn (for
            // `from m import f`) or the module prefix (for `import m as u`); the
            // node-membership check downstream disambiguates which applies.
            let binder = py.import_binder_of(file);
            let mut named: HashMap<String, String> = HashMap::default();
            let mut namespace: HashMap<String, String> = HashMap::default();
            for (local, binding) in &binder.bindings {
                match binding.kind {
                    ImportKind::Named => {
                        if let Some(imported) = &binding.imported_name {
                            named.insert(
                                local.clone(),
                                format!("{}.{}", binding.module_specifier, imported),
                            );
                        }
                    }
                    ImportKind::Namespace => {
                        namespace.insert(local.clone(), binding.module_specifier.clone());
                    }
                    ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
                }
            }
            let same_file: HashMap<String, String> = analyzer
                .declarations(file)
                .map(|unit| (unit.identifier().to_string(), unit.fq_name()))
                .collect();

            // Per-function receiver-type facts (typed params + `x = Foo()`),
            // computed by the same routine the forward scan uses, so a typed
            // `recv.method` resolves to the receiver's class fqn.
            let scope_facts = collect_scope_facts(analyzer, file, "");

            let mut ctx = PyScan {
                analyzer,
                file,
                source,
                named,
                namespace,
                same_file,
                scope_facts: &scope_facts,
                collector,
            };
            scan_tree(parsed.tree.root_node(), &mut ctx);
        })
    })
}

struct PyScan<'a, 'b> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, String>,
    scope_facts: &'a HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    collector: &'a mut EdgeCollector<'b>,
}

impl PyScan<'_, '_> {
    /// The callee fqn a bare name refers to: a named import, a namespace import of
    /// a symbol (module_specifier is the full fqn), or a same-file declaration.
    fn bare_callee(&self, text: &str) -> Option<String> {
        if let Some(fqn) = self.named.get(text) {
            return Some(fqn.clone());
        }
        if let Some(fqn) = self.namespace.get(text) {
            return Some(fqn.clone());
        }
        if let Some(fqn) = self.same_file.get(text) {
            return Some(fqn.clone());
        }
        None
    }

    /// The class fqn `receiver` is typed as within the given scope `facts` — a
    /// typed parameter or a `recv = Class()` local — so `recv.method` resolves to
    /// `Class.method`. Reuses the forward scan's receiver typing.
    fn receiver_type_fqn(
        &self,
        facts: &LocalBindingsSnapshot<String>,
        receiver: &str,
    ) -> Option<String> {
        let resolution = facts.resolution_for(receiver);
        let type_name = resolution
            .as_precise()
            .and_then(|targets| targets.iter().next())?;
        // `target_self_file = false`: resolve only via this file's imports and its
        // own declarations. The forward path's workspace-wide first-match fallback
        // is gated on matching a known target owner; the inverted builder has no
        // target to validate against, so enabling it would let an unimported,
        // non-local type name bind to an unrelated same-named class elsewhere.
        resolve_receiver_type(self.analyzer, self.file, type_name, false).map(|unit| unit.fq_name())
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn scan_tree(root: Node<'_>, ctx: &mut PyScan<'_, '_>) {
    // A stack of in-scope local names, one frame per enclosing function. A name
    // bound in any frame shadows a same-named import/declaration.
    let mut shadows: Vec<HashSet<String>> = Vec::new();
    walk(root, ctx, &mut shadows, None);
}

fn walk<'a>(
    node: Node<'_>,
    ctx: &mut PyScan<'a, '_>,
    shadows: &mut Vec<HashSet<String>>,
    facts: Option<&'a LocalBindingsSnapshot<String>>,
) {
    let mut stack = vec![WalkFrame::Enter { node, facts }];
    while let Some(frame) = stack.pop() {
        match frame {
            WalkFrame::Enter { node, facts } => match node.kind() {
                "import_statement" | "import_from_statement" => {}
                // A function (or lambda) opens a scope; its parameters and the names it
                // assigns are local throughout it, so collect them up front. Resolve the
                // scope's receiver-type facts once here and thread them down.
                "function_definition" | "lambda" => {
                    shadows.push(collect_function_locals(node, ctx.source));
                    let scope_facts =
                        enclosing_scope_facts(ctx.analyzer, ctx.file, ctx.scope_facts, node)
                            .or(facts);
                    stack.push(WalkFrame::ExitScope);
                    push_children(node, scope_facts, &mut stack);
                }
                // A class body is not a function scope: code at the class-body level has
                // no enclosing-function facts. Methods inside re-resolve their own facts.
                "class_definition" => push_children(node, None, &mut stack),
                "identifier" => {
                    handle_identifier(node, ctx, shadows);
                    push_children(node, facts, &mut stack);
                }
                "attribute" => {
                    handle_attribute(node, ctx, shadows, facts);
                    push_children(node, facts, &mut stack);
                }
                _ => push_children(node, facts, &mut stack),
            },
            WalkFrame::ExitScope => {
                shadows.pop();
            }
        }
    }
}

enum WalkFrame<'tree, 'facts> {
    Enter {
        node: Node<'tree>,
        facts: Option<&'facts LocalBindingsSnapshot<String>>,
    },
    ExitScope,
}

fn push_children<'tree, 'facts>(
    node: Node<'tree>,
    facts: Option<&'facts LocalBindingsSnapshot<String>>,
    stack: &mut Vec<WalkFrame<'tree, 'facts>>,
) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push(WalkFrame::Enter { node: child, facts });
        }
    }
}

fn is_shadowed(shadows: &[HashSet<String>], name: &str) -> bool {
    shadows.iter().any(|scope| scope.contains(name))
}

fn handle_identifier(node: Node<'_>, ctx: &mut PyScan<'_, '_>, shadows: &[HashSet<String>]) {
    // The object of an `attribute` is handled by handle_attribute.
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute")
    {
        return;
    }
    if is_declaration_identifier(node) {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || is_shadowed(shadows, text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_attribute<'a>(
    node: Node<'_>,
    ctx: &mut PyScan<'a, '_>,
    shadows: &[HashSet<String>],
    facts: Option<&'a LocalBindingsSnapshot<String>>,
) {
    let (Some(object), Some(attribute)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("attribute"),
    ) else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let attribute_text = slice(attribute, ctx.source);
    if object_text.is_empty() || attribute_text.is_empty() {
        return;
    }
    // `module.symbol` where the object is a namespace import: the callee is the
    // module prefix plus the accessed attribute. A local of the same name as the
    // module shadows the import.
    if !is_shadowed(shadows, object_text)
        && let Some(module) = ctx.namespace.get(object_text)
    {
        ctx.record(format!("{module}.{attribute_text}"), attribute);
        return;
    }

    // `recv.method` where recv is a typed local/parameter: resolve to the
    // receiver's class fqn. The node-membership check downstream drops it unless
    // `Class.method` is a real node, so an untyped or mistyped receiver is inert.
    if let Some(facts) = facts
        && let Some(type_fqn) = ctx.receiver_type_fqn(facts, object_text)
    {
        ctx.record(format!("{type_fqn}.{attribute_text}"), attribute);
    }
}

/// The local names a function binds: its parameters plus every name it assigns.
/// Python scoping is function-wide, so a name assigned anywhere in the body is
/// local throughout; nested function/class scopes are skipped (they get their
/// own frame), but the names they bind in *this* scope are kept.
fn collect_function_locals(func: Node<'_>, source: &str) -> HashSet<String> {
    let mut locals = HashSet::default();
    if let Some(params) = func.child_by_field_name("parameters") {
        collect_parameter_names(params, source, &mut locals);
    }
    if let Some(body) = func.child_by_field_name("body") {
        collect_bound_targets(body, source, &mut locals);
    }
    locals
}

fn collect_parameter_names(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let name = match child.kind() {
            "identifier" => Some(child),
            // typed / default / splat parameters carry the binding either in a
            // `name` field or as their first identifier child.
            _ => child
                .child_by_field_name("name")
                .or_else(|| child.named_child(0).filter(|n| n.kind() == "identifier")),
        };
        if let Some(name) = name {
            let text = slice(name, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
        }
    }
}

/// Collect names bound by assignment within a scope, without descending into
/// nested function/class scopes (only the nested definition's own name is bound
/// here).
fn collect_bound_targets(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = slice(name, source).trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
                continue;
            }
            "lambda" => continue,
            "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                if let Some(left) = node.child_by_field_name("left") {
                    collect_assigned_identifiers(left, source, out);
                }
            }
            "named_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    collect_assigned_identifiers(name, source, out);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}
