//! Bounded syntax evidence for Python process-input keyed reads.
//!
//! CPython publishes the process environment as `os.environ` and the launch
//! argument vector as `sys.argv`. Both are module attributes, so the read's
//! identity is the import binder plus the lexical scope, never the spelling of
//! the root name. This module reports what the syntax proves; the reviewed
//! runtime model in `brokk-bifrost-analysis` owns what the read *means*, and
//! the executable semantics own the load it joins.
//!
//! Every pass is iterative and bounded. An exhausted budget reports an
//! incomplete result rather than a clean one.

use brokk_bifrost_core::analyzer::Range;
use tree_sitter::Node;

use crate::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution,
    python_direct_scope_bindings_bounded, python_name_resolution_at,
};
use crate::imports::python_import_bindings_from_tree;
use crate::syntax::python_plain_string_literal;

/// The reviewed process-input containers this syntax pass looks for.
///
/// The pair bounds the traversal so an ordinary subscript never becomes a
/// fact. It is not an identity claim: a read is reported only after the import
/// binder proves its root names the standard-library module, and only the
/// activated runtime model decides whether the container is attacker
/// controlled.
const PROCESS_INPUT_CONTAINERS: [(&str, &str); 2] = [("os", "environ"), ("sys", "argv")];

/// A statically nameable Python access key.
///
/// Dynamic and unsupported forms are retained as facts so a caller preserves
/// an incomplete answer instead of silently dropping the access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PythonRuntimeAccessKey {
    /// A plain string-literal subscript, such as `os.environ["HOME"]`.
    Property(String),
    /// A non-negative integer-literal subscript, such as `sys.argv[1]`.
    Index(u128),
    /// The subscript is computed, so the read names no static key.
    Dynamic,
    /// The subscript is a slice, a tuple, or another shape whose value is not
    /// one modeled element.
    Unsupported,
}

/// How the root identifier of one access path resolves at its use site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeRootResolution {
    /// The module scope binds the root exactly once, through an import of the
    /// named standard-library module, and no enclosing function rebinds it.
    ImportedModule,
    /// A parameter, local, or other binding covers the root at the use site,
    /// so this occurrence is not the module attribute.
    LexicallyBound,
    /// The binder evidence is insufficient to decide the root.
    Unknown,
}

/// What this module proves about writes to the reviewed container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeMutationEvidence {
    NoKnownWrite,
    KnownWrite,
    KnownWriteAndUnknownEffects,
    UnknownEffects,
}

/// Whether anything that can run before one read could replace the container
/// or intercept the access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeAccessorCoverage {
    NoKnownAccessorEffects,
    UnknownAccessorEffects,
}

/// The execution context one read belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeExecutionContext {
    Module,
    DeferredFunction(Range),
}

/// Why one occurrence of the reviewed path is not a plain keyed read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PythonRuntimeWriteTarget {
    /// The container itself is assigned or deleted (`sys.argv = [...]`).
    Container,
    /// One key of the container is assigned or deleted.
    Key,
    /// The container value reaches a position this pass cannot follow: a
    /// method receiver, a call argument, an alias, or a return.
    ContainerEscape,
    /// The module object itself reaches such a position, so an unseen writer
    /// can replace any of its attributes.
    ModuleEscape,
}

/// One occurrence of a reviewed path that is not a plain keyed read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonRuntimeWrite {
    /// The absolute module the import binder proved for the root.
    pub root_name: String,
    /// The reviewed container this write can reach, when the occurrence names
    /// one. A module escape reaches every container of its module.
    pub container: Option<String>,
    pub range: Range,
    pub target: PythonRuntimeWriteTarget,
}

/// One keyed read of a reviewed process-input container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonRuntimeRead {
    /// The root identifier as written. Evidence, never an identity claim.
    pub binding_name: String,
    /// The absolute module the import binder proved for the root.
    pub root_name: String,
    pub container: String,
    pub access: PythonRuntimeAccessKey,
    /// The whole subscript expression, where the executable load sits.
    pub range: Range,
    pub root_range: Range,
    /// The `os.environ` attribute node. This is both the container load and
    /// the structural seed an RQL field-access query addresses, because a
    /// Python subscript read is anchored on the base of its access chain.
    pub container_range: Range,
    pub candidate_anchor: Range,
    pub key_range: Range,
    pub lexical_resolution: PythonRuntimeRootResolution,
    pub mutation: PythonRuntimeMutationEvidence,
    pub execution: PythonRuntimeExecutionContext,
    /// Accessor and effect coverage scoped to this read's own execution
    /// context and ordered against it. A call that cannot run before the read
    /// does not poison it.
    pub accessor: PythonRuntimeAccessorCoverage,
}

/// Everything one bounded pass over one Python module proves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonRuntimeReadFacts {
    pub reads: Vec<PythonRuntimeRead>,
    pub writes: Vec<PythonRuntimeWrite>,
    /// Number of AST nodes inspected across the bounded passes.
    pub visited_nodes: usize,
    /// False only when a bounded traversal could not visit the full tree.
    /// Dynamic keys, writes, and unknown effects stay represented in rows.
    pub complete: bool,
}

/// Shared node budget for the bounded passes.
#[derive(Debug)]
struct PythonRuntimeBudget {
    remaining: usize,
    exhausted: bool,
    visited_nodes: usize,
}

impl PythonRuntimeBudget {
    /// The node bound keeps a large tree with few matching facts from making
    /// extraction unbounded. The multiplier mirrors the JavaScript pass.
    fn for_facts(max_facts: usize) -> Self {
        Self {
            remaining: max_facts.saturating_mul(64).max(4096),
            exhausted: false,
            visited_nodes: 0,
        }
    }

    fn visit(&mut self) -> bool {
        if self.remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.remaining -= 1;
        self.visited_nodes += 1;
        true
    }
}

/// One import binding that covers a byte offset.
struct ModuleBinding {
    local_name: String,
    /// The top-level package the local name binds.
    root_module: String,
    scope_start_byte: usize,
    scope_end_byte: usize,
    function_scoped: bool,
}

/// Report the reviewed process-input keyed reads and the writes that bound
/// their pristine-input claim.
///
/// `max_facts` bounds emitted rows; the derived node bound stops the pass on a
/// tree large enough to make either traversal unbounded.
pub fn extract_python_runtime_reads(
    root: Node<'_>,
    source: &str,
    max_facts: usize,
) -> PythonRuntimeReadFacts {
    let mut budget = PythonRuntimeBudget::for_facts(max_facts);
    let bindings = module_bindings(root, source);
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            break;
        }
        if node.kind() == "attribute"
            && reads.len() + writes.len() < max_facts
            && let Some(path) = reviewed_attribute_path(node, source)
        {
            let resolution = root_resolution(
                path.root,
                &path.root_module,
                &bindings,
                root,
                source,
                &mut budget,
            );
            if resolution == PythonRuntimeRootResolution::ImportedModule {
                classify_container_occurrence(
                    node,
                    &path,
                    source,
                    root,
                    &mut budget,
                    &mut reads,
                    &mut writes,
                );
            }
        }
        if node.kind() == "identifier"
            && writes.len() + reads.len() < max_facts
            && let Some(module) =
                escaping_module_identifier(node, &bindings, root, source, &mut budget)
        {
            writes.push(PythonRuntimeWrite {
                root_name: module,
                container: None,
                range: node_source_range(node),
                target: PythonRuntimeWriteTarget::ModuleEscape,
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    // A write anywhere in this module refutes the pristine-input claim of
    // every read of the same container, wherever the read is written.
    for read in &mut reads {
        let known_write = writes.iter().any(|write| {
            write.root_name == read.root_name
                && write
                    .container
                    .as_ref()
                    .is_none_or(|container| *container == read.container)
        });
        read.mutation = match (known_write, read.accessor) {
            (false, PythonRuntimeAccessorCoverage::NoKnownAccessorEffects) => {
                PythonRuntimeMutationEvidence::NoKnownWrite
            }
            (false, PythonRuntimeAccessorCoverage::UnknownAccessorEffects) => {
                PythonRuntimeMutationEvidence::UnknownEffects
            }
            (true, PythonRuntimeAccessorCoverage::NoKnownAccessorEffects) => {
                PythonRuntimeMutationEvidence::KnownWrite
            }
            (true, PythonRuntimeAccessorCoverage::UnknownAccessorEffects) => {
                PythonRuntimeMutationEvidence::KnownWriteAndUnknownEffects
            }
        };
    }
    reads.sort_by_key(|read| read.range.start_byte);
    writes.sort_by_key(|write| write.range.start_byte);
    PythonRuntimeReadFacts {
        complete: !budget.exhausted && reads.len() + writes.len() < max_facts,
        visited_nodes: budget.visited_nodes,
        reads,
        writes,
    }
}

/// The structural node that represents one reviewed keyed read.
///
/// A Python subscript expression has no structural fact of its own, so the
/// read is addressed by the base of its access chain: the
/// `<module>.<container>` attribute. This is the same seed the extractor
/// publishes as `candidate_anchor`, so a query and the executable load agree
/// on one identity. A node that is not a reviewed keyed read has no seed.
pub fn python_runtime_keyed_access_seed<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    if node.kind() != "subscript" {
        return None;
    }
    let base = node.child_by_field_name("value")?;
    if base.kind() != "attribute" {
        return None;
    }
    let attribute = base.child_by_field_name("attribute")?;
    let object = base.child_by_field_name("object")?;
    if object.kind() != "identifier" || attribute.kind() != "identifier" {
        return None;
    }
    Some(base)
}

/// One reviewed `<module>.<container>` attribute occurrence.
struct ReviewedPath<'tree> {
    root: Node<'tree>,
    root_module: String,
    container: String,
}

/// Recognize `<identifier>.<container>` for one reviewed pair. Deeper paths
/// (`pkg.os.environ`) have a non-identifier object and are not this module.
fn reviewed_attribute_path<'tree>(node: Node<'tree>, source: &str) -> Option<ReviewedPath<'tree>> {
    let object = node.child_by_field_name("object")?;
    let attribute = node.child_by_field_name("attribute")?;
    if object.kind() != "identifier" || attribute.kind() != "identifier" {
        return None;
    }
    let container = node_text(attribute, source);
    let (root_module, _) = PROCESS_INPUT_CONTAINERS
        .iter()
        .find(|(_, reviewed)| *reviewed == container)?;
    Some(ReviewedPath {
        root: object,
        root_module: (*root_module).to_owned(),
        container: container.to_owned(),
    })
}

/// Decide whether one reviewed container occurrence is a keyed read, a write,
/// or an escape, and record the matching row.
fn classify_container_occurrence<'tree>(
    attribute: Node<'tree>,
    path: &ReviewedPath<'tree>,
    source: &str,
    module_root: Node<'tree>,
    budget: &mut PythonRuntimeBudget,
    reads: &mut Vec<PythonRuntimeRead>,
    writes: &mut Vec<PythonRuntimeWrite>,
) {
    let write = |target| PythonRuntimeWrite {
        root_name: path.root_module.clone(),
        container: Some(path.container.clone()),
        range: node_source_range(attribute),
        target,
    };
    let Some(parent) = attribute.parent() else {
        writes.push(write(PythonRuntimeWriteTarget::ContainerEscape));
        return;
    };
    if parent.kind() != "subscript"
        || parent
            .child_by_field_name("value")
            .is_none_or(|value| value.id() != attribute.id())
    {
        // Every other position -- a method receiver such as
        // `os.environ.update(...)`, an argument, an alias, an assignment
        // target, a `del` -- can replace or observe the container, so the
        // pristine-input claim of every read of it is refuted.
        writes.push(write(if is_binding_target(attribute) {
            PythonRuntimeWriteTarget::Container
        } else {
            PythonRuntimeWriteTarget::ContainerEscape
        }));
        return;
    }
    if is_binding_target(parent) {
        writes.push(write(PythonRuntimeWriteTarget::Key));
        return;
    }
    let Some(subscript) = parent.child_by_field_name("subscript") else {
        writes.push(write(PythonRuntimeWriteTarget::ContainerEscape));
        return;
    };
    let access = access_key(subscript, source);
    let read_range = node_source_range(parent);
    let execution = match enclosing_execution_context(attribute) {
        Some(function) => {
            PythonRuntimeExecutionContext::DeferredFunction(node_source_range(function))
        }
        None => PythonRuntimeExecutionContext::Module,
    };
    let accessor = execution_context_accessor_coverage(attribute, module_root, read_range, budget);
    reads.push(PythonRuntimeRead {
        binding_name: node_text(path.root, source).to_owned(),
        root_name: path.root_module.clone(),
        container: path.container.clone(),
        access,
        range: read_range,
        root_range: node_source_range(path.root),
        container_range: node_source_range(attribute),
        candidate_anchor: node_source_range(attribute),
        key_range: node_source_range(subscript),
        lexical_resolution: PythonRuntimeRootResolution::ImportedModule,
        // Replaced by the module-wide join once every write is known.
        mutation: PythonRuntimeMutationEvidence::UnknownEffects,
        execution,
        accessor,
    });
}

/// The static key one subscript names.
fn access_key(subscript: Node<'_>, source: &str) -> PythonRuntimeAccessKey {
    if let Some(literal) = python_plain_string_literal(subscript, source) {
        return PythonRuntimeAccessKey::Property(literal.to_owned());
    }
    match subscript.kind() {
        "integer" => node_text(subscript, source)
            .parse::<u128>()
            .map_or(PythonRuntimeAccessKey::Unsupported, |index| {
                PythonRuntimeAccessKey::Index(index)
            }),
        "slice" | "tuple" | "list_splat" => PythonRuntimeAccessKey::Unsupported,
        "string" | "concatenated_string" => PythonRuntimeAccessKey::Unsupported,
        _ => PythonRuntimeAccessKey::Dynamic,
    }
}

/// Whether this node is written rather than read: an assignment target, an
/// augmented-assignment target, a `del` operand, or a `for` target.
fn is_binding_target(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                return parent
                    .child_by_field_name("left")
                    .is_some_and(|left| left.id() == current.id());
            }
            "delete_statement" => return true,
            "pattern_list" | "tuple_pattern" | "list_pattern" | "list_splat_pattern" => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

/// The innermost function or lambda whose body executes this node, or `None`
/// for a node in module execution order.
fn enclosing_execution_context<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| covers(body, current))
        {
            return Some(parent);
        }
        current = parent;
    }
    None
}

/// Whether anything that can run before `read_range` inside this read's own
/// execution context could replace the container or intercept the access.
///
/// Every call is treated as such a hazard. Python has no syntax that proves a
/// callee cannot reach `os.environ`, so a call the read cannot be ordered
/// after leaves the read typed incomplete rather than clean.
fn execution_context_accessor_coverage(
    attribute: Node<'_>,
    module_root: Node<'_>,
    read_range: Range,
    budget: &mut PythonRuntimeBudget,
) -> PythonRuntimeAccessorCoverage {
    let scope = enclosing_execution_context(attribute)
        .and_then(|function| function.child_by_field_name("body"))
        .unwrap_or(module_root);
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return PythonRuntimeAccessorCoverage::UnknownAccessorEffects;
        }
        if matches!(node.kind(), "function_definition" | "lambda") {
            // A nested body is a separate execution context. Its header still
            // runs here, so only the body is skipped.
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor).filter(|child| {
                Some(child.id()) != node.child_by_field_name("body").map(|body| body.id())
            }));
            continue;
        }
        if node.kind() == "call" && can_precede(node_source_range(node), read_range, node) {
            return PythonRuntimeAccessorCoverage::UnknownAccessorEffects;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    PythonRuntimeAccessorCoverage::NoKnownAccessorEffects
}

/// Whether `hazard` can execute before a read at `read_range`.
///
/// Source order decides within one straight-line context. A hazard inside a
/// loop that also contains the read can run before it on a later iteration,
/// so the loop is checked structurally rather than by position alone.
fn can_precede(hazard: Range, read_range: Range, hazard_node: Node<'_>) -> bool {
    if hazard.start_byte < read_range.start_byte {
        return true;
    }
    let mut current = hazard_node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "for_statement" | "while_statement")
            && parent.start_byte() <= read_range.start_byte
            && read_range.end_byte <= parent.end_byte()
        {
            return true;
        }
        current = parent;
    }
    false
}

/// The module whose object escapes at this identifier, when one does.
///
/// A module object is shared process-wide, so any position other than the
/// object of an attribute access can carry it to a writer this pass cannot
/// see. Its own import statement is the binder, not a use.
fn escaping_module_identifier(
    node: Node<'_>,
    bindings: &[ModuleBinding],
    module_root: Node<'_>,
    source: &str,
    budget: &mut PythonRuntimeBudget,
) -> Option<String> {
    let name = node_text(node, source);
    let module = binding_root_module(node, name, bindings)?;
    // A parameter or local that happens to spell the module name is not the
    // module object, so it cannot carry it anywhere. The same three facts that
    // decide a read decide this.
    if root_resolution(node, &module, bindings, module_root, source, budget)
        != PythonRuntimeRootResolution::ImportedModule
    {
        return None;
    }
    let parent = node.parent()?;
    if parent.kind() == "attribute"
        && parent
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == node.id())
    {
        return None;
    }
    if matches!(
        parent.kind(),
        "import_statement" | "import_from_statement" | "aliased_import" | "dotted_name"
    ) {
        return None;
    }
    Some(module)
}

/// The top-level module one in-scope import binding gives `name`, when every
/// in-scope binding of the name agrees on it.
fn binding_root_module(
    reference: Node<'_>,
    name: &str,
    bindings: &[ModuleBinding],
) -> Option<String> {
    let offset = reference.start_byte();
    let mut module = None;
    for binding in bindings {
        if binding.local_name != name
            || offset < binding.scope_start_byte
            || offset > binding.scope_end_byte
        {
            continue;
        }
        match &module {
            None => module = Some(binding.root_module.clone()),
            Some(existing) if *existing == binding.root_module => {}
            Some(_) => return None,
        }
    }
    module.filter(|module| {
        PROCESS_INPUT_CONTAINERS
            .iter()
            .any(|(reviewed, _)| reviewed == module)
    })
}

/// Resolve the root identifier of one reviewed path.
///
/// Three independent structured facts have to agree before an occurrence is
/// the module attribute: no enclosing function binds the name, the module
/// scope binds it through imports alone, and every in-scope import binding
/// names the same reviewed package.
fn root_resolution(
    root: Node<'_>,
    expected_module: &str,
    bindings: &[ModuleBinding],
    module_root: Node<'_>,
    source: &str,
    budget: &mut PythonRuntimeBudget,
) -> PythonRuntimeRootResolution {
    let name = node_text(root, source);
    match python_name_resolution_at(name, root, source) {
        PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => {
            // A function-scoped import binds the name locally and still names
            // the module. This pass does not carry that proof, so the root
            // stays undecided rather than conclusively excluded.
            return if bindings
                .iter()
                .any(|binding| binding.local_name == name && binding.function_scoped)
            {
                PythonRuntimeRootResolution::Unknown
            } else {
                PythonRuntimeRootResolution::LexicallyBound
            };
        }
        PythonLexicalNameResolution::Global | PythonLexicalNameResolution::Unbound => {}
    }
    match module_scope_binds_name_through_imports(module_root, name, source, budget) {
        Some(true) => {}
        Some(false) => return PythonRuntimeRootResolution::LexicallyBound,
        None => return PythonRuntimeRootResolution::Unknown,
    }
    match binding_root_module(root, name, bindings) {
        Some(module) if module == expected_module => PythonRuntimeRootResolution::ImportedModule,
        Some(_) => PythonRuntimeRootResolution::LexicallyBound,
        None => PythonRuntimeRootResolution::Unknown,
    }
}

/// Whether the module scope binds `name`, and binds it through imports alone.
///
/// `Some(false)` says something other than an import binds the name, so the
/// occurrence is not the module object. `None` says the bounded walk could not
/// decide, which is not an exclusion.
fn module_scope_binds_name_through_imports(
    module_root: Node<'_>,
    name: &str,
    source: &str,
    budget: &mut PythonRuntimeBudget,
) -> Option<bool> {
    let mut imported = false;
    let mut stack = vec![module_root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return None;
        }
        for binding in python_direct_scope_bindings_bounded(node, source, || budget.visit())? {
            if node_text(binding.declaration, source) != name {
                continue;
            }
            match binding.kind {
                PythonDirectScopeBindingKind::Import => imported = true,
                _ => return Some(false),
            }
        }
        // A nested callable or class body is a separate scope; its header
        // still executes here.
        let excluded_body = matches!(
            node.kind(),
            "class_definition" | "function_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        stack.extend(
            node.named_children(&mut cursor)
                .filter(|child| Some(child.id()) != excluded_body),
        );
    }
    Some(imported)
}

/// The import bindings of this module that can name a reviewed module, with
/// every name the module scope binds more than once removed.
///
/// `import os` and `import os.path` both bind the package `os`, so they agree.
/// A later `os = ...`, a `def os`, or a `from x import os` does not, and the
/// name then names no proven module.
fn module_bindings(root: Node<'_>, source: &str) -> Vec<ModuleBinding> {
    let mut bindings = Vec::new();
    for binding in python_import_bindings_from_tree(root, source) {
        let Some(root_module) = binding.qualified_name.split('.').next() else {
            continue;
        };
        if !PROCESS_INPUT_CONTAINERS
            .iter()
            .any(|(reviewed, _)| *reviewed == root_module)
        {
            continue;
        }
        // A `from os import environ` binds the member, not the module object.
        if binding.qualified_name != root_module && binding.consumed_attributes == 0 {
            continue;
        }
        bindings.push(ModuleBinding {
            local_name: binding.local_name.clone(),
            root_module: root_module.to_owned(),
            scope_start_byte: binding.scope_start_byte,
            scope_end_byte: binding.scope_end_byte,
            function_scoped: binding.is_function_scoped(),
        });
    }
    bindings
}

fn covers(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn node_source_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes())
        .expect("a tree-sitter node range is valid UTF-8 source")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(source: &str) -> PythonRuntimeReadFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        extract_python_runtime_reads(tree.root_node(), source, 64)
    }

    /// The DataFlowBench template-1 positive shape.
    #[test]
    fn imported_module_environment_subscript_is_a_pristine_keyed_read() {
        let source = "import os\n\n\ndef run():\n    command = os.environ[\"DFB\"]\n    os.system(command)\n";
        let facts = facts(source);
        assert!(facts.complete, "{facts:#?}");
        let [read] = facts.reads.as_slice() else {
            panic!("exactly one keyed read: {facts:#?}");
        };
        assert_eq!(read.root_name, "os");
        assert_eq!(read.container, "environ");
        assert_eq!(
            read.access,
            PythonRuntimeAccessKey::Property("DFB".to_owned())
        );
        assert_eq!(
            read.lexical_resolution,
            PythonRuntimeRootResolution::ImportedModule
        );
        assert_eq!(read.mutation, PythonRuntimeMutationEvidence::NoKnownWrite);
        assert_eq!(
            read.accessor,
            PythonRuntimeAccessorCoverage::NoKnownAccessorEffects,
            "the only call runs after the read"
        );
        assert!(facts.writes.is_empty(), "{facts:#?}");
        // The structural seed is the container attribute, which is what an
        // RQL field-access query addresses.
        assert_eq!(
            &source[read.candidate_anchor.start_byte..read.candidate_anchor.end_byte],
            "os.environ"
        );
        assert_eq!(
            &source[read.range.start_byte..read.range.end_byte],
            "os.environ[\"DFB\"]"
        );
    }

    #[test]
    fn imported_module_argv_index_is_a_keyed_read() {
        let facts = facts("import sys\n\n\ndef run():\n    return sys.argv[1]\n");
        let [read] = facts.reads.as_slice() else {
            panic!("exactly one keyed read: {facts:#?}");
        };
        assert_eq!(read.root_name, "sys");
        assert_eq!(read.container, "argv");
        assert_eq!(read.access, PythonRuntimeAccessKey::Index(1));
    }

    /// A parameter named `os` is not the module, and the syntax proves it
    /// without comparing spellings anywhere else.
    #[test]
    fn a_shadowed_module_name_is_not_a_read() {
        let facts = facts("import os\n\n\ndef run(os):\n    return os.environ[\"DFB\"]\n");
        assert!(facts.reads.is_empty(), "{facts:#?}");
    }

    #[test]
    fn a_local_container_name_is_not_a_read() {
        let facts =
            facts("def run():\n    environ = {\"DFB\": \"x\"}\n    return environ[\"DFB\"]\n");
        assert!(facts.reads.is_empty(), "{facts:#?}");
        assert!(facts.writes.is_empty(), "{facts:#?}");
    }

    #[test]
    fn an_unrelated_module_spelled_os_is_not_a_read() {
        let facts = facts("from mypkg import os\n\n\ndef run():\n    return os.environ[\"DFB\"]\n");
        assert!(facts.reads.is_empty(), "{facts:#?}");
    }

    #[test]
    fn a_dynamic_key_stays_a_read_with_no_static_key() {
        let facts = facts("import os\n\n\ndef run(name):\n    return os.environ[name]\n");
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(read.access, PythonRuntimeAccessKey::Dynamic);
    }

    #[test]
    fn a_container_write_refutes_every_read_of_that_container() {
        let facts = facts(
            "import os\n\n\ndef run():\n    os.environ[\"A\"] = \"1\"\n    return os.environ[\"B\"]\n",
        );
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(read.mutation, PythonRuntimeMutationEvidence::KnownWrite);
        let [write] = facts.writes.as_slice() else {
            panic!("one write: {facts:#?}");
        };
        assert_eq!(write.target, PythonRuntimeWriteTarget::Key);
        assert_eq!(write.container.as_deref(), Some("environ"));
    }

    #[test]
    fn a_container_method_receiver_refutes_the_pristine_claim() {
        let facts = facts(
            "import os\n\n\ndef run():\n    os.environ.update({})\n    return os.environ[\"B\"]\n",
        );
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(
            read.mutation,
            PythonRuntimeMutationEvidence::KnownWriteAndUnknownEffects
        );
    }

    #[test]
    fn a_module_object_escape_refutes_every_container() {
        let facts =
            facts("import os\n\n\ndef run(sink):\n    sink(os)\n    return os.environ[\"B\"]\n");
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(
            read.mutation,
            PythonRuntimeMutationEvidence::KnownWriteAndUnknownEffects
        );
        assert!(
            facts
                .writes
                .iter()
                .any(|write| write.target == PythonRuntimeWriteTarget::ModuleEscape),
            "{facts:#?}"
        );
    }

    #[test]
    fn a_call_before_the_read_leaves_accessor_coverage_open() {
        let facts = facts(
            "import os\n\n\ndef run(prepare):\n    prepare()\n    return os.environ[\"B\"]\n",
        );
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(
            read.accessor,
            PythonRuntimeAccessorCoverage::UnknownAccessorEffects
        );
    }

    /// A call in a sibling function cannot run before this read, so it must
    /// not poison it: a reviewed sink call shares a module with its source.
    #[test]
    fn a_call_in_another_function_does_not_poison_the_read() {
        let source = "import os\n\n\ndef other(prepare):\n    prepare()\n\n\ndef run():\n    return os.environ[\"B\"]\n";
        let facts = facts(source);
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(
            read.accessor,
            PythonRuntimeAccessorCoverage::NoKnownAccessorEffects
        );
    }

    #[test]
    fn a_call_later_in_the_same_loop_can_precede_the_read() {
        let source = "import os\n\n\ndef run(items, prepare):\n    for item in items:\n        value = os.environ[\"B\"]\n        prepare(value)\n";
        let facts = facts(source);
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(
            read.accessor,
            PythonRuntimeAccessorCoverage::UnknownAccessorEffects
        );
    }

    #[test]
    fn an_aliased_import_keeps_the_absolute_module_identity() {
        let facts =
            facts("import os as operating\n\n\ndef run():\n    return operating.environ[\"B\"]\n");
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(read.binding_name, "operating");
        assert_eq!(read.root_name, "os");
    }

    /// `import os` beside `import os.path` binds the same package, which the
    /// DataFlowBench propagator cell spells.
    #[test]
    fn a_submodule_import_agrees_with_its_package_binding() {
        let facts =
            facts("import os\nimport os.path\n\n\ndef run():\n    return os.environ[\"B\"]\n");
        let [read] = facts.reads.as_slice() else {
            panic!("one read: {facts:#?}");
        };
        assert_eq!(read.root_name, "os");
    }

    #[test]
    fn a_module_scope_rebinding_of_the_import_name_is_not_a_read() {
        let facts = facts("import os\n\nos = None\n\n\ndef run():\n    return os.environ[\"B\"]\n");
        assert!(facts.reads.is_empty(), "{facts:#?}");
    }
}

/// Why one Python module's member value may not be the module's own at a call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PythonModuleMemberMutation {
    /// A write-shaped target names the member, or names it dynamically.
    Write(Range),
    /// The module object reaches a position this file-local walk cannot
    /// follow, so an unseen writer can replace any of its members.
    Escape(Range),
    /// The bounded walk did not finish, so this file proves nothing.
    Budget,
}

/// What in this file can replace `module.member`, or `None` when nothing can.
///
/// An imported module object is shared process-wide, and Python permits
/// replacing one of its attributes (`os.system = fake`). A reviewed summary
/// describes the standard-library implementation, not a value written over it,
/// so a consumer that closes a call on that summary must first prove no
/// workspace source can perform the replacement. Two evidence families refuse
/// it, and both fail closed:
///
///  1. A write-shaped target -- an assignment, an augmented assignment, or a
///     `del` -- whose attribute access resolves to the module. A statically
///     named attribute refuses that member; `setattr` and every other dynamic
///     form arrives through the escape rule below.
///  2. Any use of a name bound to the module outside its own import statement
///     and its attribute-object position. An alias, a call argument, a return,
///     or a subscript can carry the shared module object to a writer this walk
///     cannot see, so the proof refuses every member instead of following the
///     value. A read of `sys.modules` is refused for the same reason: it
///     reaches every module object in the process.
///
/// A file that never binds the module proves the absence vacuously. The walk
/// is iterative and bounded; exhausting the bound refuses every member.
pub fn python_module_member_mutation(
    root: Node<'_>,
    source: &str,
    module: &str,
    member: &str,
    max_nodes: usize,
) -> Option<PythonModuleMemberMutation> {
    let mut budget = PythonRuntimeBudget {
        remaining: max_nodes,
        exhausted: false,
        visited_nodes: 0,
    };
    let locals: Vec<String> = python_import_bindings_from_tree(root, source)
        .into_iter()
        .filter(|binding| {
            binding.qualified_name == module
                || binding
                    .qualified_name
                    .split('.')
                    .next()
                    .is_some_and(|root_module| {
                        root_module == module && binding.consumed_attributes > 0
                    })
        })
        .map(|binding| binding.local_name)
        .collect();
    // A file that binds nothing is still walked: `sys.modules` reaches every
    // module object whether or not this file imports the one in question.
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return Some(PythonModuleMemberMutation::Budget);
        }
        if node.kind() == "identifier" {
            let name = node_text(node, source);
            // `sys.modules` reaches every module object in the process, so a
            // read of it refuses every member of every module.
            if name == "sys"
                && node.parent().is_some_and(|parent| {
                    parent.kind() == "attribute"
                        && parent
                            .child_by_field_name("attribute")
                            .is_some_and(|attribute| node_text(attribute, source) == "modules")
                })
            {
                return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
            }
            if locals.iter().any(|local| local == name)
                && !matches!(
                    python_name_resolution_at(name, node, source),
                    PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
                )
                && let Some(mutation) = module_binding_use(node, source, member)
            {
                return Some(mutation);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

/// Classify one occurrence of a name bound to the module object.
fn module_binding_use(
    node: Node<'_>,
    source: &str,
    member: &str,
) -> Option<PythonModuleMemberMutation> {
    let Some(parent) = node.parent() else {
        return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
    };
    if matches!(
        parent.kind(),
        "import_statement" | "import_from_statement" | "aliased_import" | "dotted_name"
    ) {
        return None;
    }
    if parent.kind() != "attribute"
        || parent
            .child_by_field_name("object")
            .is_none_or(|object| object.id() != node.id())
    {
        return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
    }
    let Some(attribute) = parent.child_by_field_name("attribute") else {
        return Some(PythonModuleMemberMutation::Escape(node_source_range(
            parent,
        )));
    };
    if node_text(attribute, source) != member {
        return None;
    }
    is_binding_target(parent).then(|| PythonModuleMemberMutation::Write(node_source_range(parent)))
}

#[cfg(test)]
mod module_member_tests {
    use super::*;

    fn mutation(source: &str, member: &str) -> Option<PythonModuleMemberMutation> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        python_module_member_mutation(tree.root_node(), source, "os", member, 4096)
    }

    #[test]
    fn an_ordinary_call_replaces_nothing() {
        assert_eq!(
            mutation("import os\n\n\ndef run(c):\n    os.system(c)\n", "system"),
            None
        );
    }

    #[test]
    fn a_member_assignment_refuses_that_member() {
        let found = mutation(
            "import os\n\n\ndef patch(fake):\n    os.system = fake\n",
            "system",
        );
        assert!(
            matches!(found, Some(PythonModuleMemberMutation::Write(_))),
            "{found:?}"
        );
        // A write to another member leaves this one alone.
        assert_eq!(
            mutation(
                "import os\n\n\ndef patch(fake):\n    os.getcwd = fake\n",
                "system"
            ),
            None
        );
    }

    #[test]
    fn a_module_object_escape_refuses_every_member() {
        for source in [
            "import os\n\n\ndef leak(sink):\n    sink(os)\n",
            "import os\n\n\nalias = os\n",
            "import os\nimport functools\n\n\ndef patch():\n    setattr(os, \"system\", None)\n",
        ] {
            let found = mutation(source, "system");
            assert!(
                matches!(found, Some(PythonModuleMemberMutation::Escape(_))),
                "{source}: {found:?}"
            );
        }
    }

    #[test]
    fn a_module_table_read_refuses_every_member_even_without_the_import() {
        let found = mutation(
            "import sys\n\n\ndef patch(fake):\n    sys.modules[\"os\"].system = fake\n",
            "system",
        );
        assert!(
            matches!(found, Some(PythonModuleMemberMutation::Escape(_))),
            "{found:?}"
        );
    }

    #[test]
    fn a_file_that_never_binds_the_module_proves_the_absence() {
        assert_eq!(mutation("def run():\n    return 1\n", "system"), None);
    }
}

#[cfg(test)]
mod shadowing_tests {
    use super::*;

    fn facts(source: &str) -> PythonRuntimeReadFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        extract_python_runtime_reads(tree.root_node(), source, 64)
    }

    /// A parameter that spells the module name is not the module object, so it
    /// is not an escape and must not refute another function's pristine read.
    #[test]
    fn a_parameter_spelling_the_module_name_is_not_an_escape() {
        let source = "import os\n\n\ndef read_shadowed(os):\n    return os.environ[\"A\"]\n\n\ndef read_real():\n    return os.environ[\"B\"]\n";
        let facts = facts(source);
        assert!(facts.writes.is_empty(), "{facts:#?}");
        let [read] = facts.reads.as_slice() else {
            panic!("only the unshadowed read is a candidate: {facts:#?}");
        };
        assert_eq!(read.mutation, PythonRuntimeMutationEvidence::NoKnownWrite);
        assert_eq!(
            &source[read.key_range.start_byte..read.key_range.end_byte],
            "\"B\""
        );
    }

    #[test]
    fn a_parameter_spelling_the_module_name_does_not_refuse_a_member() {
        let source =
            "import os\n\n\ndef helper(os):\n    return os\n\n\ndef run(c):\n    os.system(c)\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        assert_eq!(
            python_module_member_mutation(tree.root_node(), source, "os", "system", 4096),
            None
        );
    }
}
