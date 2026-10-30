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
use brokk_bifrost_core::analyzer::semantic_diagnostics::contains_node as covers;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

use crate::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution, PythonLexicalScopeInventory,
    python_direct_scope_bindings_bounded, python_executable_scope_children,
    python_name_resolution_at,
};
use crate::imports::python_import_bindings_from_tree;
use crate::syntax::{python_parameter_name, python_plain_string_literal};

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
    // The grammar repeats the `subscript` field for comma-separated keys;
    // even a trailing comma makes a tuple key rather than a scalar index.
    let mut cursor = parent.walk();
    let access = if parent
        .children(&mut cursor)
        .any(|child| child.kind() == ",")
    {
        PythonRuntimeAccessKey::Unsupported
    } else {
        access_key(subscript, source)
    };
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
        "integer" => crate::structural::PYTHON_STRUCTURAL_SPEC
            .integer_literal_value(subscript, source)
            .and_then(|value| value.decimal)
            .and_then(|decimal| decimal.parse::<u128>().ok())
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
/// when the node is outside a function or lambda body.
pub(crate) fn enclosing_execution_context<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
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
        if node.kind() == "call"
            && python_hazard_can_precede_bounded(node_source_range(node), read_range, node, || {
                budget.visit()
            }) != Some(false)
        {
            return PythonRuntimeAccessorCoverage::UnknownAccessorEffects;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    PythonRuntimeAccessorCoverage::NoKnownAccessorEffects
}

/// Whether `hazard` can execute before a read at `read_range`.
///
/// Source order decides within one straight-line context. A call that ends
/// before the read starts has run before it. A call that encloses the read,
/// such as `os.system(os.environ["K"])`, has not: its callee and arguments are
/// evaluated first, and the call itself runs after the read's value exists.
/// A hazard inside a loop that also contains the read can run before it on a
/// later iteration, so the loop is checked structurally rather than by
/// position alone.
pub(crate) fn python_hazard_can_precede_bounded(
    hazard: Range,
    read_range: Range,
    hazard_node: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    if !scope_step() {
        return None;
    }
    if hazard.end_byte <= read_range.start_byte {
        return Some(true);
    }
    let mut current = hazard_node;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        if matches!(parent.kind(), "for_statement" | "while_statement")
            && parent.start_byte() <= read_range.start_byte
            && read_range.end_byte <= parent.end_byte()
        {
            return Some(true);
        }
        current = parent;
    }
    Some(false)
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
        stack.extend(python_executable_scope_children(node));
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

use brokk_bifrost_core::analyzer::usages::reference_site::node_range as node_source_range;

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::try_node_source_text(node, source)
        .expect("a tree-sitter node range is valid UTF-8 source")
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
///     value. A `sys.modules` read is classified by its structured key;
///     dynamic-key results are possible aliases and use the same alias
///     handling. A table write matters only when its stored value is or may
///     be this module. `sys.modules` passed as the mapping of pytest's
///     `MonkeyPatch.setitem`/`delitem` or of `mock.patch.dict` is that table
///     write, delete, or update; any other callee receiving it is an escape.
///
/// A file that never binds the module proves the absence vacuously. The walk
/// is iterative and bounded; exhausting the bound refuses every member.
pub fn python_module_member_mutation(
    root: Node<'_>,
    source: &str,
    source_module: &str,
    module: &str,
    member: &str,
    max_nodes: usize,
) -> Option<PythonModuleMemberMutation> {
    let mut budget = PythonRuntimeBudget {
        remaining: max_nodes,
        exhausted: false,
        visited_nodes: 0,
    };
    let bindings = python_import_bindings_from_tree(root, source);
    let Some(facts) =
        python_sys_modules_aliases(root, source, source_module, module, &bindings, &mut budget)
    else {
        return Some(PythonModuleMemberMutation::Budget);
    };
    let table_aliases = &facts.aliases;
    let locals: Vec<String> = bindings
        .iter()
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
        .map(|binding| binding.local_name.clone())
        .collect();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return Some(PythonModuleMemberMutation::Budget);
        }
        if node.kind() == "call"
            && python_mock_patch_may_replace_module_member(node, source, &bindings, module, member)
        {
            return Some(PythonModuleMemberMutation::Write(node_source_range(node)));
        }
        if node.kind() == "identifier" {
            let name = node_text(node, source);
            if let Some(table) = python_sys_modules_table(node, source) {
                if python_imported_path(table, source, &bindings)
                    .is_some_and(|path| path == ["sys", "modules"])
                {
                    match python_sys_modules_lookup(
                        table,
                        source,
                        source_module,
                        module,
                        &bindings,
                        &facts,
                        &mut budget,
                    ) {
                        PythonSysModulesLookup::Unrelated => {}
                        PythonSysModulesLookup::Escape(range) => {
                            return Some(PythonModuleMemberMutation::Escape(range));
                        }
                        PythonSysModulesLookup::Target(read) => {
                            if let Some(mutation) =
                                python_sys_modules_read_use(read, source, member, table_aliases)
                            {
                                return Some(mutation);
                            }
                        }
                    }
                } else {
                    return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
                }
            }
            let table_alias = table_aliases.contains(name);
            if table_alias && python_module_table_alias_binding_use(node, source, table_aliases) {
                // A recognized table lookup binding is followed at its uses.
            } else if (table_alias
                || (locals.iter().any(|local| local == name)
                    && !matches!(
                        python_name_resolution_at(name, node, source),
                        PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
                    )))
                && let Some(mutation) =
                    module_binding_use(node, source, &bindings, table_aliases, module, member)
            {
                return Some(mutation);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

enum PythonSysModulesLookup<'tree> {
    Unrelated,
    Target(Node<'tree>),
    Escape(Range),
}

/// Return the `sys.modules` attribute when an identifier is its object.
fn python_sys_modules_table<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let table = node.parent()?;
    (table.kind() == "attribute"
        && table
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == node.id())
        && table
            .child_by_field_name("attribute")
            .is_some_and(|attribute| node_text(attribute, source) == "modules"))
    .then_some(table)
}

fn python_sys_modules_read_table<'tree>(read: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    if read.kind() == "subscript" {
        let table = read.child_by_field_name("value")?;
        return (table.kind() == "attribute"
            && table
                .child_by_field_name("attribute")
                .is_some_and(|attribute| node_text(attribute, source) == "modules"))
        .then_some(table);
    }
    if read.kind() == "call" {
        let function = read.child_by_field_name("function")?;
        if function.kind() != "attribute"
            || function
                .child_by_field_name("attribute")
                .is_none_or(|attribute| {
                    !matches!(node_text(attribute, source), "get" | "pop" | "setdefault")
                })
        {
            return None;
        }
        let table = function.child_by_field_name("object")?;
        return (table.kind() == "attribute"
            && table
                .child_by_field_name("attribute")
                .is_some_and(|attribute| node_text(attribute, source) == "modules"))
        .then_some(table);
    }
    None
}

fn python_sys_modules_lookup<'tree>(
    table: Node<'tree>,
    source: &str,
    source_module: &str,
    module: &str,
    bindings: &[crate::imports::PythonImportBinding],
    facts: &PythonSysModulesFacts<'tree>,
    budget: &mut PythonRuntimeBudget,
) -> PythonSysModulesLookup<'tree> {
    // The registry maps names to module objects; changing one entry does not
    // mutate the referenced module's globals. Only storing or producing this
    // queried module as a value can create another write-through alias.
    let escaped = || PythonSysModulesLookup::Escape(node_source_range(table));
    if python_imported_path(table, source, bindings).is_none_or(|path| path != ["sys", "modules"]) {
        return escaped();
    }
    let Some(parent) = table.parent() else {
        return escaped();
    };
    let proof = PythonSysModulesProofContext {
        source,
        source_module,
        module,
        bindings,
        facts,
    };
    if parent.kind() == "subscript"
        && parent
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == table.id())
    {
        if is_binding_target(parent) {
            if parent
                .parent()
                .is_some_and(|parent| parent.kind() == "delete_statement")
            {
                return PythonSysModulesLookup::Unrelated;
            }
            let Some(value) = parent
                .parent()
                .filter(|assignment| assignment.kind() == "assignment")
                .and_then(|assignment| assignment.child_by_field_name("right"))
            else {
                return escaped();
            };
            return match python_sys_modules_stored_value(
                value,
                &proof,
                budget,
                &mut HashSet::default(),
            ) {
                PythonSysModulesStoredValue::Unrelated => PythonSysModulesLookup::Unrelated,
                PythonSysModulesStoredValue::Target | PythonSysModulesStoredValue::Unknown => {
                    escaped()
                }
            };
        }
        return python_sys_modules_read_identity(
            parent.child_by_field_name("subscript"),
            parent,
            &proof,
            budget,
        );
    }
    if parent.kind() == "attribute"
        && parent
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == table.id())
    {
        let Some(call) = parent.parent().filter(|call| {
            call.kind() == "call"
                && call
                    .child_by_field_name("function")
                    .is_some_and(|function| function.id() == parent.id())
        }) else {
            return escaped();
        };
        let method = parent
            .child_by_field_name("attribute")
            .map(|attribute| node_text(attribute, source));
        match method {
            Some("get" | "pop") => {
                let args = python_sys_modules_arguments(call);
                return python_sys_modules_read_identity(
                    args.first().copied(),
                    call,
                    &proof,
                    budget,
                );
            }
            Some("setdefault") => {
                let args = python_sys_modules_arguments(call);
                let default = args
                    .get(1)
                    .copied()
                    .or_else(|| python_sys_modules_keyword_argument(call, source, "default"));
                if let Some(default) = default
                    && python_sys_modules_stored_value(
                        default,
                        &proof,
                        budget,
                        &mut HashSet::default(),
                    ) != PythonSysModulesStoredValue::Unrelated
                {
                    return escaped();
                }
                return python_sys_modules_read_identity(
                    args.first().copied(),
                    call,
                    &proof,
                    budget,
                );
            }
            Some("update") => {
                let Some(arguments) = call.child_by_field_name("arguments") else {
                    return escaped();
                };
                let mut cursor = arguments.walk();
                for argument in arguments.named_children(&mut cursor) {
                    if python_sys_modules_update_argument(argument, &proof, budget)
                        != PythonSysModulesStoredValue::Unrelated
                    {
                        return escaped();
                    }
                }
                return PythonSysModulesLookup::Unrelated;
            }
            Some("clear" | "keys") => return PythonSysModulesLookup::Unrelated,
            _ => return escaped(),
        }
    }
    if parent.kind() == "argument_list"
        && let Some(call) = parent.parent().filter(|call| call.kind() == "call")
        && python_sys_modules_arguments(call)
            .first()
            .is_some_and(|first| first.id() == table.id())
    {
        // A test helper that edits the mapping it receives is the matching
        // table operation; every other callee may keep or mutate the table.
        match python_test_helper_call(call, source, bindings) {
            Some(PythonTestHelperCall::MonkeyPatchSetItem(receiver))
                if python_monkeypatch_receiver(receiver, &proof) =>
            {
                let value = python_sys_modules_arguments(call)
                    .get(2)
                    .copied()
                    .or_else(|| python_sys_modules_keyword_argument(call, source, "value"));
                return match value.map(|value| {
                    python_sys_modules_stored_value(value, &proof, budget, &mut HashSet::default())
                }) {
                    Some(PythonSysModulesStoredValue::Unrelated) => {
                        PythonSysModulesLookup::Unrelated
                    }
                    _ => escaped(),
                };
            }
            Some(PythonTestHelperCall::MonkeyPatchDelItem(receiver))
                if python_monkeypatch_receiver(receiver, &proof) =>
            {
                return PythonSysModulesLookup::Unrelated;
            }
            Some(PythonTestHelperCall::MockPatchDict) => {
                let Some(arguments) = call.child_by_field_name("arguments") else {
                    return escaped();
                };
                let mut cursor = arguments.walk();
                for argument in arguments.named_children(&mut cursor) {
                    let keyword = (argument.kind() == "keyword_argument")
                        .then(|| argument.child_by_field_name("name"))
                        .flatten()
                        .map(|name| node_text(name, source));
                    let identity = if argument.id() == table.id() || keyword == Some("clear") {
                        PythonSysModulesStoredValue::Unrelated
                    } else if keyword == Some("values") {
                        argument
                            .child_by_field_name("value")
                            .map(|value| {
                                python_sys_modules_update_values(
                                    value,
                                    &proof,
                                    budget,
                                    &mut HashSet::default(),
                                )
                            })
                            .unwrap_or(PythonSysModulesStoredValue::Unknown)
                    } else {
                        python_sys_modules_update_argument(argument, &proof, budget)
                    };
                    if identity != PythonSysModulesStoredValue::Unrelated {
                        return escaped();
                    }
                }
                return PythonSysModulesLookup::Unrelated;
            }
            _ => {}
        }
    }
    escaped()
}

/// One argument of a `dict.update`-shaped call: a keyword stores its value
/// under its name, and a positional argument supplies a mapping of entries.
fn python_sys_modules_update_argument<'tree>(
    argument: Node<'tree>,
    proof: &PythonSysModulesProofContext<'_, 'tree>,
    budget: &mut PythonRuntimeBudget,
) -> PythonSysModulesStoredValue {
    if argument.kind() == "keyword_argument" {
        argument
            .child_by_field_name("value")
            .map(|value| {
                python_sys_modules_stored_value(value, proof, budget, &mut HashSet::default())
            })
            .unwrap_or(PythonSysModulesStoredValue::Unknown)
    } else if matches!(argument.kind(), "dictionary_splat" | "list_splat") {
        PythonSysModulesStoredValue::Unknown
    } else {
        python_sys_modules_update_values(argument, proof, budget, &mut HashSet::default())
    }
}

/// Whether a `setitem`/`delitem` receiver is a pytest `MonkeyPatch`: the
/// `monkeypatch` fixture parameter, a parameter annotated `MonkeyPatch`, or a
/// name whose only binding constructs one. The receiver must be bound once in
/// its function so no other value can reach the call.
fn python_monkeypatch_receiver(
    receiver: Node<'_>,
    proof: &PythonSysModulesProofContext<'_, '_>,
) -> bool {
    let source = proof.source;
    let is_monkeypatch_class = |expression: Option<Node<'_>>| {
        expression
            .and_then(|expression| python_imported_path(expression, source, proof.bindings))
            .is_some_and(|path| path.last().is_some_and(|name| name == "MonkeyPatch"))
    };
    if receiver.kind() != "identifier" {
        return false;
    }
    let name = node_text(receiver, source);
    let scope = python_alias_scope(receiver);
    if scope.kind() != "function_definition"
        || !python_sys_modules_has_one_binding(proof, scope, name)
    {
        return false;
    }
    if let Some(parameters) = scope.child_by_field_name("parameters") {
        let mut cursor = parameters.walk();
        if let Some(parameter) = parameters
            .named_children(&mut cursor)
            .find(|parameter| python_parameter_name(*parameter, source).as_deref() == Some(name))
        {
            return name == "monkeypatch"
                || is_monkeypatch_class(
                    parameter
                        .child_by_field_name("type")
                        .and_then(|annotation| annotation.named_child(0)),
                );
        }
    }
    let key = (scope.start_byte(), scope.end_byte(), name.to_owned());
    proof
        .facts
        .assignments
        .get(&key)
        .is_some_and(|values| match values.as_slice() {
            [value] => {
                value.kind() == "call"
                    && is_monkeypatch_class(value.child_by_field_name("function"))
            }
            _ => false,
        })
}

fn python_sys_modules_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() != "keyword_argument")
        .collect()
}

fn python_sys_modules_keyword_argument<'tree>(
    call: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .find(|argument| {
            argument.kind() == "keyword_argument"
                && argument
                    .child_by_field_name("name")
                    .is_some_and(|key| node_text(key, source) == name)
        })
        .and_then(|argument| argument.child_by_field_name("value"))
}

fn python_sys_modules_read_identity<'tree>(
    key: Option<Node<'tree>>,
    read: Node<'tree>,
    proof: &PythonSysModulesProofContext<'_, 'tree>,
    budget: &mut PythonRuntimeBudget,
) -> PythonSysModulesLookup<'tree> {
    let Some(key) = key else {
        return PythonSysModulesLookup::Escape(node_source_range(read));
    };
    if key.kind() == "identifier" && node_text(key, proof.source) == "__name__" {
        return if proof.source_module == proof.module {
            PythonSysModulesLookup::Target(read)
        } else {
            PythonSysModulesLookup::Unrelated
        };
    }
    let Some(key_value) = crate::decode_python_string_value(key, proof.source).ok() else {
        if python_sys_modules_guard_excludes_module(key, read, proof, budget) {
            return PythonSysModulesLookup::Unrelated;
        }
        return PythonSysModulesLookup::Target(read);
    };
    if key_value == proof.module {
        PythonSysModulesLookup::Target(read)
    } else {
        PythonSysModulesLookup::Unrelated
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PythonGuardTruth {
    True,
    False,
    Unknown,
}

/// Whether a structured dominating condition excludes this module name from
/// a dynamic `sys.modules` read. Unknown expressions retain the possible alias.
fn python_sys_modules_guard_excludes_module(
    key: Node<'_>,
    read: Node<'_>,
    proof: &PythonSysModulesProofContext<'_, '_>,
    budget: &mut PythonRuntimeBudget,
) -> bool {
    if key.kind() != "identifier" {
        return false;
    }
    let key_name = node_text(key, proof.source);
    let mut child = read;
    let mut ancestor = read.parent();
    while let Some(node) = ancestor {
        if !budget.visit() {
            return false;
        }
        if matches!(node.kind(), "if_statement" | "elif_clause")
            && let (Some(condition), Some(consequence)) = (
                node.child_by_field_name("condition"),
                node.child_by_field_name("consequence"),
            )
            && consequence.start_byte() <= read.start_byte()
            && read.end_byte() <= consequence.end_byte()
            && python_sys_modules_key_binding_unchanged(key, condition, read, proof, budget)
            && python_sys_modules_guard_truth(
                condition,
                key_name,
                proof.module,
                proof.source,
                budget,
            ) == PythonGuardTruth::False
        {
            return true;
        }
        if node.kind() == "block"
            && let Some(statement) = python_sys_modules_direct_child_containing(node, child)
            && python_sys_modules_prior_continue_guard_excludes(
                node, statement, key, read, key_name, proof, budget,
            )
        {
            return true;
        }
        child = node;
        ancestor = node.parent();
    }
    false
}

/// Prove that the key has the same local binding in the guard and at the read.
/// The existing per-scope binding inventory used by module-alias propagation
/// counts every write in the lexical scope; this stricter source proof also
/// rejects any write or call on the path from the guard to the read.
fn python_sys_modules_key_binding_unchanged(
    key: Node<'_>,
    guard: Node<'_>,
    read: Node<'_>,
    proof: &PythonSysModulesProofContext<'_, '_>,
    budget: &mut PythonRuntimeBudget,
) -> bool {
    let name = node_text(key, proof.source);
    let guard_reference = python_sys_modules_guard_key_reference(guard, name, proof.source, budget);
    let Some(guard_reference) = guard_reference else {
        return false;
    };
    let scope = python_alias_scope(key);
    let key_resolution = python_name_resolution_at(name, key, proof.source);
    let guard_resolution = python_name_resolution_at(name, guard_reference, proof.source);
    let same_lexical_binding = key_resolution == guard_resolution
        && (key_resolution == PythonLexicalNameResolution::Local
            || (scope.kind() == "module"
                && key_resolution == PythonLexicalNameResolution::Unbound));
    if python_alias_scope(guard_reference).id() != scope.id()
        || python_alias_scope(read).id() != scope.id()
        || !same_lexical_binding
    {
        return false;
    }
    if !python_sys_modules_has_one_binding(proof, scope, name) {
        return false;
    }
    let start = guard.start_byte();
    let guard_end = guard.end_byte();
    let end = read.start_byte();
    let mut stack = vec![scope.child_by_field_name("body").unwrap_or(scope)];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return false;
        }
        if node.start_byte() >= end || node.end_byte() <= start {
            continue;
        }
        if python_direct_scope_bindings_bounded(node, proof.source, || budget.visit()).is_none_or(
            |bindings| {
                bindings.into_iter().any(|binding| {
                    node_text(binding.declaration, proof.source) == name
                        && start <= binding.declaration.start_byte()
                        && binding.declaration.start_byte() < end
                })
            },
        ) {
            return false;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "call")
                && guard_end <= child.start_byte()
                && child.end_byte() < end
            {
                return false;
            }
        }
        stack.extend(python_executable_scope_children(node));
    }
    true
}

fn python_sys_modules_guard_key_reference<'tree>(
    condition: Node<'tree>,
    name: &str,
    source: &str,
    budget: &mut PythonRuntimeBudget,
) -> Option<Node<'tree>> {
    let mut stack = vec![condition];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return None;
        }
        if node.kind() == "identifier" && node_text(node, source) == name {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

fn python_sys_modules_direct_child_containing<'tree>(
    block: Node<'tree>,
    child: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut direct = child;
    while direct
        .parent()
        .is_some_and(|parent| parent.id() != block.id())
    {
        direct = direct.parent()?;
    }
    direct
        .parent()
        .is_some_and(|parent| parent.id() == block.id())
        .then_some(direct)
}

fn python_sys_modules_prior_continue_guard_excludes(
    block: Node<'_>,
    read_statement: Node<'_>,
    key: Node<'_>,
    read: Node<'_>,
    key_name: &str,
    proof: &PythonSysModulesProofContext<'_, '_>,
    budget: &mut PythonRuntimeBudget,
) -> bool {
    let mut cursor = block.walk();
    for statement in block.named_children(&mut cursor) {
        if statement.id() == read_statement.id() {
            break;
        }
        if statement.kind() != "if_statement" {
            continue;
        }
        let Some(condition) = statement.child_by_field_name("condition") else {
            continue;
        };
        if condition.kind() != "not_operator"
            || !python_sys_modules_guard_has_direct_abrupt_consequence(statement)
            || !python_sys_modules_key_binding_unchanged(key, condition, read, proof, budget)
        {
            continue;
        }
        let Some(guard_condition) = condition.named_child(0) else {
            continue;
        };
        if python_sys_modules_guard_truth(
            guard_condition,
            key_name,
            proof.module,
            proof.source,
            budget,
        ) == PythonGuardTruth::False
        {
            return true;
        }
    }
    false
}

fn python_sys_modules_guard_has_direct_abrupt_consequence(statement: Node<'_>) -> bool {
    let Some(consequence) = statement.child_by_field_name("consequence") else {
        return false;
    };
    let mut cursor = consequence.walk();
    let mut statements = consequence.named_children(&mut cursor);
    let Some(only) = statements.next() else {
        return false;
    };
    statements.next().is_none()
        && matches!(
            only.kind(),
            "break_statement" | "continue_statement" | "return_statement" | "raise_statement"
        )
}

fn python_sys_modules_guard_truth(
    condition: Node<'_>,
    key_name: &str,
    module: &str,
    source: &str,
    budget: &mut PythonRuntimeBudget,
) -> PythonGuardTruth {
    let mut pending = vec![(condition, false)];
    let mut results = HashMap::<usize, PythonGuardTruth>::default();
    while let Some((node, visited)) = pending.pop() {
        if !budget.visit() {
            return PythonGuardTruth::Unknown;
        }
        if !visited
            && matches!(
                node.kind(),
                "boolean_operator" | "not_operator" | "parenthesized_expression"
            )
        {
            pending.push((node, true));
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                pending.push((child, false));
            }
            continue;
        }
        let value = match node.kind() {
            "boolean_operator" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return PythonGuardTruth::Unknown;
                };
                let Some(right) = node.child_by_field_name("right") else {
                    return PythonGuardTruth::Unknown;
                };
                let Some(operator) = node.child_by_field_name("operator") else {
                    return PythonGuardTruth::Unknown;
                };
                let (Some(left), Some(right)) = (results.get(&left.id()), results.get(&right.id()))
                else {
                    return PythonGuardTruth::Unknown;
                };
                match node_text(operator, source) {
                    "and" => python_guard_and(*left, *right),
                    "or" => python_guard_or(*left, *right),
                    _ => PythonGuardTruth::Unknown,
                }
            }
            "not_operator" => node
                .named_child(0)
                .and_then(|child| results.get(&child.id()).copied())
                .map(python_guard_not)
                .unwrap_or(PythonGuardTruth::Unknown),
            "parenthesized_expression" => node
                .named_child(0)
                .and_then(|child| results.get(&child.id()).copied())
                .unwrap_or(PythonGuardTruth::Unknown),
            _ => python_sys_modules_guard_atom(node, key_name, module, source),
        };
        results.insert(node.id(), value);
    }
    results
        .get(&condition.id())
        .copied()
        .unwrap_or(PythonGuardTruth::Unknown)
}

fn python_guard_and(left: PythonGuardTruth, right: PythonGuardTruth) -> PythonGuardTruth {
    match (left, right) {
        (PythonGuardTruth::False, _) | (_, PythonGuardTruth::False) => PythonGuardTruth::False,
        (PythonGuardTruth::True, PythonGuardTruth::True) => PythonGuardTruth::True,
        _ => PythonGuardTruth::Unknown,
    }
}

fn python_guard_or(left: PythonGuardTruth, right: PythonGuardTruth) -> PythonGuardTruth {
    match (left, right) {
        (PythonGuardTruth::True, _) | (_, PythonGuardTruth::True) => PythonGuardTruth::True,
        (PythonGuardTruth::False, PythonGuardTruth::False) => PythonGuardTruth::False,
        _ => PythonGuardTruth::Unknown,
    }
}

fn python_guard_not(value: PythonGuardTruth) -> PythonGuardTruth {
    match value {
        PythonGuardTruth::True => PythonGuardTruth::False,
        PythonGuardTruth::False => PythonGuardTruth::True,
        PythonGuardTruth::Unknown => PythonGuardTruth::Unknown,
    }
}

fn python_sys_modules_guard_atom(
    node: Node<'_>,
    key_name: &str,
    module: &str,
    source: &str,
) -> PythonGuardTruth {
    if node.kind() == "comparison_operator" {
        return python_sys_modules_guard_comparison(node, key_name, module, source);
    }
    if node.kind() == "call" {
        return python_sys_modules_guard_string_method(node, key_name, module, source);
    }
    PythonGuardTruth::Unknown
}

fn python_sys_modules_guard_comparison(
    node: Node<'_>,
    key_name: &str,
    module: &str,
    source: &str,
) -> PythonGuardTruth {
    let mut cursor = node.walk();
    let operands = node.named_children(&mut cursor).collect::<Vec<_>>();
    let mut cursor = node.walk();
    let operators = node
        .children_by_field_name("operators", &mut cursor)
        .collect::<Vec<_>>();
    let ([left, right], [operator]) = (operands.as_slice(), operators.as_slice()) else {
        return PythonGuardTruth::Unknown;
    };
    let operator = node_text(*operator, source);
    let key_left = left.kind() == "identifier" && node_text(*left, source) == key_name;
    let key_right = right.kind() == "identifier" && node_text(*right, source) == key_name;
    if key_left || key_right {
        let literal = if key_left {
            crate::decode_python_string_value(*right, source)
        } else {
            crate::decode_python_string_value(*left, source)
        };
        if matches!(operator, "==" | "!=")
            && let Ok(literal) = literal
        {
            let matches = literal == module;
            return python_guard_bool(if operator == "==" { matches } else { !matches });
        }
        if operator == "in" && key_left {
            return python_sys_modules_literal_membership(*right, module, source);
        }
        if operator == "in"
            && key_right
            && let Ok(literal) = literal
        {
            return python_guard_bool(module.contains(&literal));
        }
    }
    PythonGuardTruth::Unknown
}

fn python_sys_modules_literal_membership(
    collection: Node<'_>,
    module: &str,
    source: &str,
) -> PythonGuardTruth {
    if !matches!(collection.kind(), "tuple" | "list" | "set") {
        return PythonGuardTruth::Unknown;
    }
    let mut cursor = collection.walk();
    let mut contains = false;
    for value in collection.named_children(&mut cursor) {
        let Ok(literal) = crate::decode_python_string_value(value, source) else {
            return PythonGuardTruth::Unknown;
        };
        contains |= literal == module;
    }
    python_guard_bool(contains)
}

fn python_sys_modules_guard_string_method(
    call: Node<'_>,
    key_name: &str,
    module: &str,
    source: &str,
) -> PythonGuardTruth {
    let Some(function) = call.child_by_field_name("function") else {
        return PythonGuardTruth::Unknown;
    };
    if function.kind() != "attribute"
        || !function
            .child_by_field_name("object")
            .is_some_and(|object| {
                object.kind() == "identifier" && node_text(object, source) == key_name
            })
    {
        return PythonGuardTruth::Unknown;
    }
    let Some(method) = function
        .child_by_field_name("attribute")
        .map(|name| node_text(name, source))
    else {
        return PythonGuardTruth::Unknown;
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return PythonGuardTruth::Unknown;
    };
    let mut cursor = arguments.walk();
    let mut values = arguments.named_children(&mut cursor);
    let Some(first) = values.next() else {
        return PythonGuardTruth::Unknown;
    };
    if values.next().is_some() || first.kind() == "keyword_argument" {
        return PythonGuardTruth::Unknown;
    }
    let matches = if let Ok(literal) = crate::decode_python_string_value(first, source) {
        match method {
            "startswith" => module.starts_with(&literal),
            "endswith" => module.ends_with(&literal),
            _ => return PythonGuardTruth::Unknown,
        }
    } else if matches!(first.kind(), "tuple" | "list" | "set") {
        let mut cursor = first.walk();
        let mut matched = false;
        for value in first.named_children(&mut cursor) {
            let Ok(literal) = crate::decode_python_string_value(value, source) else {
                return PythonGuardTruth::Unknown;
            };
            matched |= match method {
                "startswith" => module.starts_with(&literal),
                "endswith" => module.ends_with(&literal),
                _ => return PythonGuardTruth::Unknown,
            };
        }
        matched
    } else {
        return PythonGuardTruth::Unknown;
    };
    python_guard_bool(matches)
}

fn python_guard_bool(value: bool) -> PythonGuardTruth {
    if value {
        PythonGuardTruth::True
    } else {
        PythonGuardTruth::False
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PythonSysModulesStoredValue {
    Target,
    Unrelated,
    Unknown,
}

struct PythonSysModulesFacts<'tree> {
    aliases: HashSet<String>,
    assignments: HashMap<(usize, usize, String), Vec<Node<'tree>>>,
    binding_counts: HashMap<(usize, usize, String), usize>,
    classes: Vec<PythonExternalClassAlias>,
}

struct PythonSysModulesProofContext<'a, 'tree> {
    source: &'a str,
    source_module: &'a str,
    module: &'a str,
    bindings: &'a [crate::imports::PythonImportBinding],
    facts: &'a PythonSysModulesFacts<'tree>,
}

fn python_sys_modules_has_one_binding(
    proof: &PythonSysModulesProofContext<'_, '_>,
    scope: Node<'_>,
    name: &str,
) -> bool {
    let count = proof
        .facts
        .binding_counts
        .get(&(scope.start_byte(), scope.end_byte(), name.to_owned()))
        .copied()
        .unwrap_or_default()
        + proof
            .bindings
            .iter()
            .filter(|binding| {
                binding.local_name == name
                    && binding.scope_start_byte == scope.start_byte()
                    && binding.scope_end_byte == scope.end_byte()
            })
            .count();
    count == 1
}

fn python_sys_modules_value_scope<'tree>(node: Node<'tree>, source: &str) -> Node<'tree> {
    let nearest = python_alias_scope(node);
    let name = python_static_path(node, source)
        .and_then(|(root, _)| (root.kind() == "identifier").then_some(node_text(root, source)))
        .unwrap_or_default();
    match python_name_resolution_at(name, node, source) {
        PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => nearest,
        PythonLexicalNameResolution::Global => {
            let mut scope = nearest;
            while scope.kind() != "module" {
                scope = python_alias_scope(scope.parent().expect("lexical scope has a parent"));
            }
            scope
        }
        PythonLexicalNameResolution::Unbound if nearest.kind() == "class_definition" => nearest,
        PythonLexicalNameResolution::Unbound => {
            let mut scope = nearest;
            while scope.kind() != "module" {
                scope = python_alias_scope(scope.parent().expect("lexical scope has a parent"));
            }
            scope
        }
    }
}

fn python_sys_modules_stored_value<'tree>(
    value: Node<'tree>,
    context: &PythonSysModulesProofContext<'_, 'tree>,
    budget: &mut PythonRuntimeBudget,
    seen: &mut HashSet<(usize, usize, String)>,
) -> PythonSysModulesStoredValue {
    let source = context.source;
    let module = context.module;
    let bindings = context.bindings;
    let facts = context.facts;
    if !budget.visit() {
        return PythonSysModulesStoredValue::Unknown;
    }
    if python_sys_modules_table(value, source).is_some() {
        return PythonSysModulesStoredValue::Unknown;
    }
    if let Some(table) = python_sys_modules_read_table(value, source) {
        if python_imported_path(table, source, bindings)
            .is_none_or(|path| path != ["sys", "modules"])
        {
            return PythonSysModulesStoredValue::Unknown;
        }
        return match python_sys_modules_read_identity(
            if value.kind() == "subscript" {
                value.child_by_field_name("subscript")
            } else {
                python_sys_modules_arguments(value).first().copied()
            },
            value,
            context,
            budget,
        ) {
            PythonSysModulesLookup::Target(_) => PythonSysModulesStoredValue::Target,
            PythonSysModulesLookup::Unrelated => PythonSysModulesStoredValue::Unrelated,
            PythonSysModulesLookup::Escape(_) => PythonSysModulesStoredValue::Unknown,
        };
    }
    if matches!(
        value.kind(),
        "string"
            | "concatenated_string"
            | "integer"
            | "float"
            | "true"
            | "false"
            | "none"
            | "list"
            | "tuple"
            | "set"
            | "dictionary"
            | "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression"
    ) {
        return PythonSysModulesStoredValue::Unrelated;
    }
    if let Some(path) = python_imported_path(value, source, bindings) {
        let root_name = python_static_path(value, source)
            .map(|(root, _)| node_text(root, source))
            .unwrap_or_default();
        let scope = python_sys_modules_value_scope(value, source);
        if facts.binding_counts.contains_key(&(
            scope.start_byte(),
            scope.end_byte(),
            root_name.to_owned(),
        )) {
            return PythonSysModulesStoredValue::Unknown;
        }
        return if path.join(".") == module {
            PythonSysModulesStoredValue::Target
        } else {
            PythonSysModulesStoredValue::Unrelated
        };
    }
    if value.kind() == "call" {
        let Some(function) = value.child_by_field_name("function") else {
            return PythonSysModulesStoredValue::Unknown;
        };
        if python_imported_path(function, source, bindings)
            .is_some_and(|path| path == ["types", "ModuleType"])
        {
            return PythonSysModulesStoredValue::Unrelated;
        }
        if let Some((root, path)) = python_static_path(function, source)
            && path.len() == 1
            && python_class_alias_visible_at(node_text(root, source), root, source, &facts.classes)
        {
            return PythonSysModulesStoredValue::Unrelated;
        }
        return PythonSysModulesStoredValue::Unknown;
    }
    let Some((root, path)) = python_static_path(value, source) else {
        return PythonSysModulesStoredValue::Unknown;
    };
    if path.len() == 1 && facts.aliases.contains(node_text(root, source)) {
        return PythonSysModulesStoredValue::Target;
    }
    if path.len() == 1
        && python_class_alias_visible_at(node_text(root, source), root, source, &facts.classes)
    {
        return PythonSysModulesStoredValue::Unrelated;
    }
    let scope = python_sys_modules_value_scope(value, source);
    if scope.kind() == "function_definition"
        && scope
            .child_by_field_name("parameters")
            .is_some_and(|parameters| {
                let mut cursor = parameters.walk();
                parameters
                    .named_children(&mut cursor)
                    .filter_map(|parameter| python_parameter_name(parameter, source))
                    .any(|parameter| parameter == node_text(root, source))
            })
    {
        return PythonSysModulesStoredValue::Unknown;
    }
    if !python_sys_modules_has_one_binding(context, scope, node_text(root, source)) {
        return PythonSysModulesStoredValue::Unknown;
    }
    let key = (scope.start_byte(), scope.end_byte(), path.join("."));
    if !seen.insert(key.clone()) {
        return PythonSysModulesStoredValue::Unknown;
    }
    let Some([assignment]) = facts.assignments.get(&key).map(Vec::as_slice) else {
        return PythonSysModulesStoredValue::Unknown;
    };
    python_sys_modules_stored_value(*assignment, context, budget, seen)
}

fn python_sys_modules_update_values<'tree>(
    mapping: Node<'tree>,
    context: &PythonSysModulesProofContext<'_, 'tree>,
    budget: &mut PythonRuntimeBudget,
    seen: &mut HashSet<(usize, usize, String)>,
) -> PythonSysModulesStoredValue {
    let source = context.source;
    let facts = context.facts;
    if mapping.kind() == "dictionary" {
        let mut cursor = mapping.walk();
        for pair in mapping.named_children(&mut cursor) {
            let Some(value) = pair.child_by_field_name("value") else {
                return PythonSysModulesStoredValue::Unknown;
            };
            let identity = python_sys_modules_stored_value(value, context, budget, seen);
            if identity != PythonSysModulesStoredValue::Unrelated {
                return identity;
            }
        }
        return PythonSysModulesStoredValue::Unrelated;
    }
    let Some((root, path)) = python_static_path(mapping, source) else {
        return PythonSysModulesStoredValue::Unknown;
    };
    let scope = python_sys_modules_value_scope(mapping, source);
    let key = (scope.start_byte(), scope.end_byte(), path.join("."));
    if !seen.insert(key.clone()) {
        return PythonSysModulesStoredValue::Unknown;
    }
    if !python_sys_modules_has_one_binding(context, scope, node_text(root, source)) {
        return PythonSysModulesStoredValue::Unknown;
    }
    let Some([assigned_value]) = facts.assignments.get(&key).map(Vec::as_slice) else {
        return PythonSysModulesStoredValue::Unknown;
    };
    python_sys_modules_update_values(*assigned_value, context, budget, seen)
}

/// Collect aliases of the queried module reached through proven
/// `sys.modules` reads in this file. Only names and alias edges survive the
/// bounded, per-file walk.
fn python_sys_modules_aliases<'tree>(
    root: Node<'tree>,
    source: &str,
    source_module: &str,
    module: &str,
    bindings: &[crate::imports::PythonImportBinding],
    budget: &mut PythonRuntimeBudget,
) -> Option<PythonSysModulesFacts<'tree>> {
    let mut aliases_from = HashMap::<String, Vec<String>>::default();
    let mut assignments = HashMap::<(usize, usize, String), Vec<Node<'_>>>::default();
    let mut binding_counts = HashMap::<(usize, usize, String), usize>::default();
    let mut classes = Vec::new();
    let mut pending_table_aliases = Vec::<(Vec<String>, Option<Node<'_>>, Node<'_>)>::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return None;
        }
        if node.kind() == "class_definition"
            && let Some(name) = node.child_by_field_name("name")
        {
            let scope = python_alias_scope(node);
            classes.push(PythonExternalClassAlias {
                name: node_text(name, source).to_owned(),
                scope_start_byte: scope.start_byte(),
                scope_end_byte: scope.end_byte(),
            });
        }
        for binding in python_direct_scope_bindings_bounded(node, source, || budget.visit())? {
            if binding.kind != PythonDirectScopeBindingKind::Import {
                let scope = python_alias_scope(binding.declaration);
                let key = (
                    scope.start_byte(),
                    scope.end_byte(),
                    node_text(binding.declaration, source).to_owned(),
                );
                *binding_counts.entry(key).or_default() += 1;
            }
        }
        if matches!(node.kind(), "function_definition" | "lambda")
            && let Some(parameters) = node.child_by_field_name("parameters")
        {
            let scope = node;
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if let Some(name) = python_parameter_name(parameter, source) {
                    *binding_counts
                        .entry((scope.start_byte(), scope.end_byte(), name))
                        .or_default() += 1;
                }
            }
        }
        if matches!(node.kind(), "assignment" | "annotated_assignment") {
            let (targets, value) = if node.kind() == "assignment" {
                crate::imports::python_assignment_chain(node)
            } else {
                (
                    node.child_by_field_name("left").into_iter().collect(),
                    node.child_by_field_name("right"),
                )
            };
            if let Some(value) = value {
                for target in targets {
                    if let Some((_, path)) = python_static_path(target, source) {
                        let scope = python_alias_scope(target);
                        let key = (scope.start_byte(), scope.end_byte(), path.join("."));
                        assignments.entry(key).or_default().push(value);
                    }
                }
            }
        }
        if node.kind() == "assignment" {
            let (targets, value) = crate::imports::python_assignment_chain(node);
            if let Some(value) = value
                && !targets.is_empty()
                && targets.iter().all(|target| target.kind() == "identifier")
            {
                let target_names = targets
                    .iter()
                    .map(|target| node_text(*target, source).to_owned())
                    .collect::<Vec<_>>();
                if python_sys_modules_read_table(value, source).is_some_and(|table| {
                    python_imported_path(table, source, bindings)
                        .is_some_and(|path| path == ["sys", "modules"])
                }) {
                    pending_table_aliases.push((
                        target_names,
                        if value.kind() == "subscript" {
                            value.child_by_field_name("subscript")
                        } else {
                            python_sys_modules_arguments(value).first().copied()
                        },
                        value,
                    ));
                } else if value.kind() == "identifier" {
                    aliases_from
                        .entry(node_text(value, source).to_owned())
                        .or_default()
                        .extend(target_names);
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    let mut facts = PythonSysModulesFacts {
        aliases: HashSet::default(),
        assignments,
        binding_counts,
        classes,
    };
    let mut target_aliases = Vec::new();
    {
        let proof = PythonSysModulesProofContext {
            source,
            source_module,
            module,
            bindings,
            facts: &facts,
        };
        for (targets, key, read) in pending_table_aliases {
            if matches!(
                python_sys_modules_read_identity(key, read, &proof, budget),
                PythonSysModulesLookup::Target(_)
            ) {
                target_aliases.extend(targets);
            }
        }
    }
    facts.aliases.extend(target_aliases);

    let mut pending = facts.aliases.iter().cloned().collect::<Vec<_>>();
    while let Some(source_name) = pending.pop() {
        if let Some(targets) = aliases_from.get(&source_name) {
            for target in targets {
                if facts.aliases.insert(target.clone()) {
                    pending.push(target.clone());
                }
            }
        }
    }
    Some(facts)
}

fn python_sys_modules_read_use(
    read: Node<'_>,
    source: &str,
    member: &str,
    aliases: &HashSet<String>,
) -> Option<PythonModuleMemberMutation> {
    let mut expression = read;
    let mut direct_attribute = None;
    while let Some(parent) = expression.parent() {
        if parent.kind() != "attribute"
            || parent
                .child_by_field_name("object")
                .is_none_or(|object| object.id() != expression.id())
        {
            break;
        }
        if direct_attribute.is_none() {
            direct_attribute = Some(parent);
        }
        expression = parent;
    }
    if let Some(attribute) = direct_attribute {
        let name = attribute
            .child_by_field_name("attribute")
            .map(|name| node_text(name, source));
        if name == Some("__dict__") {
            return Some(PythonModuleMemberMutation::Escape(node_source_range(
                attribute,
            )));
        }
        if name == Some(member) && is_binding_target(attribute) {
            return Some(PythonModuleMemberMutation::Write(node_source_range(
                attribute,
            )));
        }
        return None;
    }
    if python_builtin_module_read(expression, source) {
        return None;
    }
    if read.parent().is_some_and(|parent| {
        parent.kind() == "assignment"
            && parent
                .child_by_field_name("right")
                .is_some_and(|right| right.id() == read.id())
            && crate::imports::python_assignment_chain(parent)
                .0
                .iter()
                .all(|target| {
                    target.kind() == "identifier" && aliases.contains(node_text(*target, source))
                })
    }) || read.parent().is_some_and(|parent| {
        parent.kind() == "expression_statement"
            && parent
                .named_child(0)
                .is_some_and(|expression| expression.id() == read.id())
    }) {
        return None;
    }
    Some(PythonModuleMemberMutation::Escape(node_source_range(read)))
}

fn python_builtin_module_read(expression: Node<'_>, source: &str) -> bool {
    let Some(arguments) = expression
        .parent()
        .filter(|node| node.kind() == "argument_list")
    else {
        return false;
    };
    let Some(call) = arguments.parent().filter(|node| node.kind() == "call") else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "identifier"
        || !matches!(node_text(function, source), "getattr" | "hasattr")
        || matches!(
            python_name_resolution_at(node_text(function, source), function, source),
            PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
        )
    {
        return false;
    }
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .find(|argument| argument.kind() != "keyword_argument")
        .is_some_and(|first| first.id() == expression.id())
}

fn python_module_table_alias_binding_use(
    node: Node<'_>,
    source: &str,
    aliases: &HashSet<String>,
) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let name = node_text(node, source);
    if !aliases.contains(name) {
        return false;
    }
    if is_binding_target(node) {
        return true;
    }
    node.parent().is_some_and(|assignment| {
        assignment.kind() == "assignment"
            && assignment
                .child_by_field_name("right")
                .is_some_and(|right| right.id() == node.id())
            && crate::imports::python_assignment_chain(assignment)
                .0
                .iter()
                .all(|target| {
                    target.kind() == "identifier" && aliases.contains(node_text(*target, source))
                })
    })
}

/// Find writes to one imported external class member in this file.
///
/// The class identities are qualified names taken from one exact active model
/// record (including its exact aliases). Import binders turn those identities
/// into local AST paths; source spelling alone never establishes the class.
/// Dynamic `setattr` names are treated as possible replacement writes.
pub fn python_external_class_member_mutation(
    root: Node<'_>,
    source: &str,
    class_identities: &[&str],
    member: &str,
    max_nodes: usize,
) -> Option<PythonModuleMemberMutation> {
    let bindings = python_import_bindings_from_tree(root, source);
    let Some(aliases) =
        python_external_class_aliases(root, source, &bindings, class_identities, max_nodes)
    else {
        return Some(PythonModuleMemberMutation::Budget);
    };
    let mut budget = PythonRuntimeBudget {
        remaining: max_nodes,
        exhausted: false,
        visited_nodes: 0,
    };
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return Some(PythonModuleMemberMutation::Budget);
        }
        if node.kind() == "attribute"
            && node
                .child_by_field_name("attribute")
                .is_some_and(|attribute| node_text(attribute, source) == member)
            && is_binding_target(node)
            && let Some(object) = node.child_by_field_name("object")
            && python_external_class_expression(
                object,
                source,
                &bindings,
                class_identities,
                &aliases,
            )
        {
            return Some(PythonModuleMemberMutation::Write(node_source_range(node)));
        }
        if node.kind() == "call"
            && python_setattr_may_replace_class_member(
                node,
                source,
                &bindings,
                class_identities,
                member,
                &aliases,
            )
        {
            return Some(PythonModuleMemberMutation::Write(node_source_range(node)));
        }
        if node.kind() == "call"
            && python_mock_patch_may_replace_class_member(
                node,
                source,
                &bindings,
                class_identities,
                member,
                &aliases,
            )
        {
            return Some(PythonModuleMemberMutation::Write(node_source_range(node)));
        }
        if node.kind() == "identifier"
            && python_class_alias_visible_at(node_text(node, source), node, source, &aliases)
            && python_class_alias_escapes_at(node, source, &aliases)
        {
            return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

#[derive(Clone)]
struct PythonExternalClassAlias {
    name: String,
    scope_start_byte: usize,
    scope_end_byte: usize,
}

fn python_external_class_aliases(
    root: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    class_identities: &[&str],
    max_nodes: usize,
) -> Option<Vec<PythonExternalClassAlias>> {
    let mut budget = PythonRuntimeBudget {
        remaining: max_nodes,
        exhausted: false,
        visited_nodes: 0,
    };
    let mut assignments = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !budget.visit() {
            return None;
        }
        if matches!(node.kind(), "assignment" | "annotated_assignment")
            && let Some(target) = node.child_by_field_name("left")
            && target.kind() == "identifier"
            && let Some(value) = node.child_by_field_name("right")
        {
            let scope = python_alias_scope(node);
            assignments.push((
                node_text(target, source).to_owned(),
                value,
                scope.start_byte(),
                scope.end_byte(),
            ));
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    let mut aliases = Vec::<PythonExternalClassAlias>::new();
    loop {
        let before = aliases.len();
        for (name, value, scope_start_byte, scope_end_byte) in &assignments {
            if python_external_class_expression(
                *value,
                source,
                bindings,
                class_identities,
                &aliases,
            ) && !aliases.iter().any(|alias| {
                alias.name == *name
                    && alias.scope_start_byte == *scope_start_byte
                    && alias.scope_end_byte == *scope_end_byte
            }) {
                aliases.push(PythonExternalClassAlias {
                    name: name.clone(),
                    scope_start_byte: *scope_start_byte,
                    scope_end_byte: *scope_end_byte,
                });
            }
        }
        if aliases.len() == before {
            return Some(aliases);
        }
    }
}

fn python_alias_scope(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "module" | "class_definition" | "function_definition" | "lambda"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

fn python_external_class_expression(
    expression: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    class_identities: &[&str],
    aliases: &[PythonExternalClassAlias],
) -> bool {
    if python_imported_class_expression(expression, source, bindings, class_identities) {
        return true;
    }
    let Some((root, path)) = python_static_path(expression, source) else {
        return false;
    };
    path.len() == 1 && python_class_alias_visible_at(node_text(root, source), root, source, aliases)
}

fn python_class_alias_visible_at(
    name: &str,
    reference: Node<'_>,
    source: &str,
    aliases: &[PythonExternalClassAlias],
) -> bool {
    if !aliases.iter().any(|alias| alias.name == name) {
        return false;
    }
    let mut current = reference;
    while let Some(scope) = nearest_scope(current) {
        if aliases.iter().any(|alias| {
            alias.name == name
                && alias.scope_start_byte == scope.start_byte()
                && alias.scope_end_byte == scope.end_byte()
        }) {
            return true;
        }
        match scope.kind() {
            "function_definition" | "lambda" => {
                let parameters = scope
                    .child_by_field_name("parameters")
                    .into_iter()
                    .flat_map(|parameters| {
                        let mut cursor = parameters.walk();
                        parameters
                            .named_children(&mut cursor)
                            .filter_map(|parameter| python_parameter_name(parameter, source))
                            .collect::<Vec<_>>()
                    });
                let Some(inventory) =
                    PythonLexicalScopeInventory::collect_bounded(scope, source, parameters, || {
                        true
                    })
                else {
                    return true;
                };
                match inventory.name_resolution_at(name, reference) {
                    PythonLexicalNameResolution::Local => return false,
                    PythonLexicalNameResolution::Global => break,
                    PythonLexicalNameResolution::Nonlocal
                    | PythonLexicalNameResolution::Unbound => {}
                }
            }
            "module" => return false,
            // Class names are not enclosing bindings for method bodies. A
            // class-body alias itself was handled above.
            "class_definition" => {}
            _ => unreachable!("nearest_scope returns only Python lexical scopes"),
        }
        current = scope;
    }
    aliases.iter().any(|alias| {
        alias.name == name
            && alias.scope_start_byte == 0
            && reference.start_byte() < alias.scope_end_byte
    })
}

fn nearest_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "module" | "class_definition" | "function_definition" | "lambda"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn python_class_alias_escapes_at(
    node: Node<'_>,
    source: &str,
    aliases: &[PythonExternalClassAlias],
) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "lambda" | "class_definition" | "module"
        ) {
            return false;
        }
        if parent.kind() == "argument_list"
            && parent.parent().is_some_and(|call| call.kind() == "call")
        {
            return true;
        }
        if matches!(parent.kind(), "return_statement" | "yield") {
            return true;
        }
        if matches!(parent.kind(), "list" | "tuple" | "set" | "dictionary") {
            return true;
        }
        if matches!(parent.kind(), "assignment" | "annotated_assignment")
            && parent.child_by_field_name("right").is_some_and(|right| {
                right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
            })
        {
            let Some(target) = parent.child_by_field_name("left") else {
                return true;
            };
            if target.kind() == "identifier"
                && python_class_alias_visible_at(node_text(target, source), target, source, aliases)
            {
                return false;
            }
            return true;
        }
        current = parent;
    }
    false
}

fn python_setattr_may_replace_class_member(
    call: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    class_identities: &[&str],
    member: &str,
    aliases: &[PythonExternalClassAlias],
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let imported_setattr = python_imported_path(function, source, bindings)
        .is_some_and(|path| path == ["builtins", "setattr"]);
    let builtin_setattr = python_static_path(function, source).is_some_and(|(root, path)| {
        path == ["setattr"]
            && !matches!(
                python_name_resolution_at(node_text(root, source), root, source),
                PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
            )
    });
    if !imported_setattr && !builtin_setattr {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let positional = arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() != "keyword_argument")
        .collect::<Vec<_>>();
    let [object, name, ..] = positional.as_slice() else {
        return false;
    };
    if !python_external_class_expression(*object, source, bindings, class_identities, aliases) {
        return false;
    }
    python_plain_string_literal(*name, source).is_none_or(|name| name == member)
}

fn python_mock_patch_may_replace_class_member(
    call: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    class_identities: &[&str],
    member: &str,
    aliases: &[PythonExternalClassAlias],
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(function_path) = python_imported_path(function, source, bindings) else {
        return false;
    };
    let patch_object = function_path == ["unittest", "mock", "patch", "object"];
    let patch_class_path = function_path == ["unittest", "mock", "patch"];
    if !patch_object && !patch_class_path {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let positional = arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() != "keyword_argument")
        .collect::<Vec<_>>();
    let Some(target) = positional.first().copied() else {
        return false;
    };
    if patch_object {
        let Some(name) = positional.get(1).copied() else {
            return false;
        };
        return python_external_class_expression(
            target,
            source,
            bindings,
            class_identities,
            aliases,
        ) && python_plain_string_literal(name, source).is_none_or(|name| name == member);
    }
    let Some(target_path) = python_plain_string_literal(target, source) else {
        return false;
    };
    class_identities
        .iter()
        .any(|class| target_path == *class || target_path == format!("{class}.{member}"))
}

fn python_imported_path(
    expression: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
) -> Option<Vec<String>> {
    let (root, expression_path) = python_static_path(expression, source)?;
    let root_name = node_text(root, source);
    if matches!(
        python_name_resolution_at(root_name, root, source),
        PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
    ) {
        return None;
    }
    let latest_import = bindings
        .iter()
        .filter(|binding| {
            binding.local_name == root_name
                && binding.start_byte <= root.start_byte()
                && binding.scope_start_byte <= root.start_byte()
                && root.end_byte() <= binding.scope_end_byte
        })
        .map(|binding| binding.start_byte)
        .max()?;
    let binding = bindings.iter().find(|binding| {
        binding.local_name == root_name
            && binding.start_byte == latest_import
            && binding.scope_start_byte <= root.start_byte()
            && root.end_byte() <= binding.scope_end_byte
    })?;
    let qualified_prefix = if binding.consumed_attributes > 0 {
        binding.qualified_name.split('.').next()?
    } else {
        binding.qualified_name.as_str()
    };
    let mut qualified_path = qualified_prefix
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    qualified_path.extend(expression_path.into_iter().skip(1));
    Some(qualified_path)
}

fn python_imported_class_expression(
    expression: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    class_identities: &[&str],
) -> bool {
    let Some(path) = python_imported_path(expression, source, bindings) else {
        return false;
    };
    class_identities.iter().any(|identity| {
        identity
            .split('.')
            .map(str::to_owned)
            .eq(path.iter().cloned())
    })
}

fn python_static_path<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Vec<String>)> {
    let mut current = node;
    let mut attributes = Vec::new();
    loop {
        if current.kind() == "identifier" {
            attributes.reverse();
            let mut path = Vec::with_capacity(attributes.len() + 1);
            path.push(node_text(current, source).to_owned());
            path.extend(attributes);
            return Some((current, path));
        }
        if current.kind() != "attribute" {
            return None;
        }
        let attribute = current.child_by_field_name("attribute")?;
        attributes.push(node_text(attribute, source).to_owned());
        current = current.child_by_field_name("object")?;
    }
}

/// Classify one occurrence of a name bound to the module object.
fn module_binding_use(
    node: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    table_aliases: &HashSet<String>,
    module: &str,
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
    let mut expression = node;
    while let Some(parent) = expression.parent() {
        if parent.kind() != "attribute"
            || parent
                .child_by_field_name("object")
                .is_none_or(|object| object.id() != expression.id())
        {
            break;
        }
        expression = parent;
    }
    if python_builtin_module_read(expression, source) {
        return None;
    }
    let imported_path = python_imported_path(expression, source, bindings);
    let table_alias_path = python_static_path(expression, source).and_then(|(root, suffix)| {
        let root_name = node_text(root, source);
        table_aliases.contains(root_name).then(|| {
            let mut resolved = vec![module.to_owned()];
            resolved.extend(suffix.into_iter().skip(1));
            resolved
        })
    });
    let Some(path) = imported_path.or(table_alias_path) else {
        return Some(PythonModuleMemberMutation::Escape(node_source_range(node)));
    };
    let path = path.join(".");
    let target = format!("{module}.{member}");
    if path == target {
        return is_binding_target(expression)
            .then(|| PythonModuleMemberMutation::Write(node_source_range(expression)));
    }
    if path == format!("{module}.__dict__") || path == module {
        return Some(PythonModuleMemberMutation::Escape(node_source_range(
            expression,
        )));
    }
    if path.starts_with(&format!("{module}.")) {
        None
    } else {
        Some(PythonModuleMemberMutation::Escape(node_source_range(node)))
    }
}

/// A test-helper call whose effect on its arguments is known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PythonTestHelperCall<'tree> {
    /// `unittest.mock.patch(target, ...)`.
    MockPatch,
    /// `unittest.mock.patch.dict(in_dict, values, clear=...)`.
    MockPatchDict,
    /// `<receiver>.setitem(dic, name, value)`, a pytest `MonkeyPatch` method
    /// when the receiver is one.
    MonkeyPatchSetItem(Node<'tree>),
    /// `<receiver>.delitem(dic, name, raising=...)`.
    MonkeyPatchDelItem(Node<'tree>),
}

fn python_test_helper_call<'tree>(
    call: Node<'tree>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
) -> Option<PythonTestHelperCall<'tree>> {
    let function = call.child_by_field_name("function")?;
    if let Some(path) = python_imported_path(function, source, bindings)
        && let Some(patch) = path.windows(2).rposition(|pair| pair == ["mock", "patch"])
    {
        return match &path[patch + 2..] {
            [] => Some(PythonTestHelperCall::MockPatch),
            [method] if method == "dict" => Some(PythonTestHelperCall::MockPatchDict),
            _ => None,
        };
    }
    if function.kind() != "attribute" {
        return None;
    }
    let receiver = function.child_by_field_name("object")?;
    match node_text(function.child_by_field_name("attribute")?, source) {
        "setitem" => Some(PythonTestHelperCall::MonkeyPatchSetItem(receiver)),
        "delitem" => Some(PythonTestHelperCall::MonkeyPatchDelItem(receiver)),
        _ => None,
    }
}

fn python_mock_patch_may_replace_module_member(
    call: Node<'_>,
    source: &str,
    bindings: &[crate::imports::PythonImportBinding],
    module: &str,
    member: &str,
) -> bool {
    if python_test_helper_call(call, source, bindings) != Some(PythonTestHelperCall::MockPatch) {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(target) = arguments.named_children(&mut cursor).next() else {
        return false;
    };
    let expected = format!("{module}.{member}");
    python_plain_string_literal(target, source) == Some(expected.as_str())
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

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: module alias exhaustion certified mutation-free"
    )]
    fn qs6_module_mutation_budget_is_not_absence() {
        let source = "import os\nos.system = fake\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        for budget in [0, 1, 2] {
            assert_eq!(
                python_module_member_mutation(
                    tree.root_node(),
                    source,
                    "test",
                    "os",
                    "system",
                    budget
                ),
                Some(PythonModuleMemberMutation::Budget),
                "budget={budget}"
            );
        }
        assert!(
            python_module_member_mutation(tree.root_node(), source, "test", "os", "system", 4096)
                .is_some()
        );
    }

    // Python's integer grammar admits radix prefixes and digit separators.
    // The u128 representation deliberately refuses larger literal magnitudes.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: runtime indices lost radix and separator literals"
    )]
    fn qs6_runtime_key_shapes() {
        use PythonRuntimeAccessKey::{Dynamic, Index, Property, Unsupported};
        for (key, expected) in [
            ("0", Index(0)),
            ("0x1", Index(1)),
            ("0b1", Index(1)),
            ("0o7", Index(7)),
            ("1_0", Index(10)),
            ("340282366920938463463374607431768211455", Index(u128::MAX)),
            ("340282366920938463463374607431768211456", Unsupported),
            ("1:3", Unsupported),
            ("1, 2", Unsupported),
            ("1,", Unsupported),
            ("(1, 2)", Unsupported),
            ("name", Dynamic),
            ("\"HOME\"", Property("HOME".into())),
        ] {
            let source = format!("import sys\nvalue = sys.argv[{key}]\n");
            let facts = facts(&source);
            assert!(facts.complete, "{facts:?}");
            assert_eq!(facts.reads.len(), 1, "{facts:?}");
            assert_eq!(facts.reads[0].access, expected, "{key}");
        }
    }

    #[test]
    fn qs6_runtime_extraction_bounds() {
        let source = "pass\n".repeat(100);
        let tree = crate::declarations::parse_python_tree(&source).unwrap();
        let empty = extract_python_runtime_reads(tree.root_node(), &source, 1);
        assert!(empty.complete, "{empty:?}");
        assert!(empty.visited_nodes > 64, "{empty:?}");
        let source = "import sys\nx = sys.argv[1]\ny = sys.argv[2]\n";
        let tree = crate::declarations::parse_python_tree(source).unwrap();
        for cap in [0, 1, 2, 3] {
            let facts = extract_python_runtime_reads(tree.root_node(), source, cap);
            assert_eq!(facts.reads.len(), cap.min(2), "{facts:?}");
            assert_eq!(facts.complete, cap > 2, "{facts:?}");
        }
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

#[cfg(test)]
mod module_member_tests {
    use super::*;

    fn mutation(source: &str, member: &str) -> Option<PythonModuleMemberMutation> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        python_module_member_mutation(tree.root_node(), source, "test", "os", member, 4096)
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
    fn a_matching_module_table_read_counts_its_attribute_write() {
        let found = mutation(
            "import sys\n\n\ndef patch(fake):\n    sys.modules[\"os\"].system = fake\n",
            "system",
        );
        assert!(
            matches!(found, Some(PythonModuleMemberMutation::Write(_))),
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
            python_module_member_mutation(tree.root_node(), source, "test", "os", "system", 4096),
            None
        );
    }
}

#[cfg(test)]
mod external_class_mutation_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn mutation(source: &str) -> Option<PythonModuleMemberMutation> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        python_external_class_member_mutation(
            tree.root_node(),
            source,
            &["paramiko.client.SSHClient"],
            "set_missing_host_key_policy",
            4096,
        )
    }

    #[test]
    fn exact_imported_class_member_writes_are_found() {
        for source in [
            "from paramiko.client import SSHClient as Client\n\nClient.set_missing_host_key_policy = fake\n",
            "import paramiko.client as client\n\nclient.SSHClient.set_missing_host_key_policy = fake\n",
            "from paramiko.client import SSHClient as Client\n\nsetattr(Client, 'set_missing_host_key_policy', fake)\n",
            "from paramiko.client import SSHClient as Client\n\nsetattr(Client, name, fake)\n",
        ] {
            assert!(
                matches!(mutation(source), Some(PythonModuleMemberMutation::Write(_))),
                "{source}"
            );
        }
    }

    #[test]
    #[hardwon("#4411: class aliases and mock patch APIs left external method dispatch exact")]
    fn class_aliases_and_mock_patch_apis_refute_method_closure() {
        for source in [
            "from paramiko.client import SSHClient as C\nAlias = C\nAlias.set_missing_host_key_policy = fake\n",
            "from paramiko.client import SSHClient as C\nAlias = C\nsetattr(Alias, 'set_missing_host_key_policy', fake)\n",
            "from unittest import mock\nfrom paramiko.client import SSHClient as C\nmock.patch.object(C, 'set_missing_host_key_policy', fake)\n",
            "from unittest.mock import patch\nfrom paramiko.client import SSHClient as C\npatch.object(C, 'set_missing_host_key_policy', fake)\n",
            "from unittest import mock\nmock.patch('paramiko.client.SSHClient.set_missing_host_key_policy', fake)\n",
        ] {
            assert!(
                matches!(mutation(source), Some(PythonModuleMemberMutation::Write(_))),
                "{source}"
            );
        }
    }

    #[test]
    #[hardwon("#4411: an escaped class alias left external method dispatch exact")]
    fn an_escaped_class_alias_refutes_method_closure() {
        assert!(matches!(
            mutation("from paramiko.client import SSHClient as C\nAlias = C\nconsume(Alias)\n"),
            Some(PythonModuleMemberMutation::Escape(_))
        ));
    }

    #[test]
    fn constructor_uses_and_same_named_workspace_classes_are_not_writes() {
        assert_eq!(
            mutation(
                "from paramiko.client import SSHClient as Client\n\n\ndef connect():\n    client = Client()\n    client.set_missing_host_key_policy(policy)\n"
            ),
            None
        );
        assert_eq!(
            mutation(
                "class SSHClient:\n    pass\n\nSSHClient.set_missing_host_key_policy = fake\n"
            ),
            None
        );
    }
}

#[cfg(test)]
mod module_member_mutation_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn mutation(source: &str) -> Option<PythonModuleMemberMutation> {
        mutation_in(source, "pkg.M")
    }

    fn mutation_in(source: &str, source_module: &str) -> Option<PythonModuleMemberMutation> {
        mutation_for_module(source, source_module, "pkg.M")
    }

    fn mutation_for_module(
        source: &str,
        source_module: &str,
        module: &str,
    ) -> Option<PythonModuleMemberMutation> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("python grammar loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        python_module_member_mutation(
            tree.root_node(),
            source,
            source_module,
            module,
            "NAME",
            4096,
        )
    }

    #[test]
    #[hardwon(
        "#4622: writes through imported module aliases and mock patch APIs must keep a global class unknown"
    )]
    fn imported_module_member_mutation_covers_dynamic_write_forms() {
        for source in [
            "import pkg.M as target\ntarget.NAME = fake\n",
            "import pkg.M as target\ndel target.NAME\n",
            "import pkg.M as target\nsetattr(target, 'NAME', fake)\n",
            "import pkg.M as target\nsetattr(target, name, fake)\n",
            "import pkg.M as target\ntarget.__dict__['NAME'] = fake\n",
            "from unittest import mock\nmock.patch('pkg.M.NAME', fake)\n",
            "from unittest.mock import patch\npatch('pkg.M.NAME', fake)\n",
            "import pkg.M as target\nfrom unittest import mock\nmock.patch.object(target, 'NAME', fake)\n",
        ] {
            assert!(mutation(source).is_some(), "{source}");
        }
        assert_eq!(
            None,
            mutation("from unittest import mock\nmock.patch('pkg.Other.NAME', fake)\n")
        );
    }

    #[test]
    #[hardwon("#4622: unrelated sys.modules reads blocked exact module-global class proofs")]
    fn sys_modules_reads_are_scoped_by_literal_module_identity() {
        assert_eq!(
            None,
            mutation("import sys\nother = sys.modules.get('torch')\n")
        );
        assert_eq!(None, mutation("import sys\nother = sys.modules['torch']\n"));
        assert!(matches!(
            mutation("import sys\nmodule = sys.modules.get('pkg.M')\nmodule.NAME = fake\n"),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert!(matches!(
            mutation("import sys\nmodule = sys.modules['pkg.M']\nmodule.NAME = fake\n"),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert_eq!(
            None,
            mutation("import sys\nmodule = sys.modules['pkg.M']\nconsume(module.NAME)\n")
        );
        assert!(matches!(
            mutation("import sys\nmodule = sys.modules[__name__]\nmodule.NAME = fake\n"),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert_eq!(
            None,
            mutation_in("import sys\nmodule = sys.modules[__name__]\n", "pkg.Other")
        );
        for source in [
            "import sys\nsys.modules['pkg.M'] = fake\n",
            "import sys\nsys.modules.setdefault('pkg.M', fake)\n",
            "import sys\nsys.modules.update({'pkg.M': fake})\n",
            "import sys\nconsume(sys.modules)\n",
        ] {
            assert!(
                matches!(
                    mutation(source),
                    Some(PythonModuleMemberMutation::Escape(_))
                ),
                "{source}"
            );
        }
        for source in [
            "import sys\nmodule = sys.modules[module_name]\n",
            "import sys\ndel sys.modules['torch']\n",
            "import sys\nsys.modules.pop('torch')\n",
            "import sys\nsys.modules.clear()\n",
            "class Shim: pass\nimport sys\nsys.modules['shim'] = Shim()\n",
            "class Shim: pass\nimport sys\nsys.modules.update({'shim': Shim()})\n",
            "import sys\nimport types\nsys.modules['shim'] = types.ModuleType('shim')\n",
            "import sys\nsys.modules['literal'] = None\n",
            "import pkg.Other as shim\nimport sys\nsys.modules['shim'] = shim\n",
        ] {
            assert_eq!(mutation(source), None, "{source}");
        }
    }

    #[test]
    #[hardwon("#8107: monkeypatch.setitem(sys.modules, ...) escaped every module workspace-wide")]
    fn sys_modules_test_helper_edits_are_table_operations() {
        for source in [
            "import sys\ndef test(monkeypatch):\n    monkeypatch.setitem(sys.modules, 'dotenv', None)\n",
            "import sys\ndef test(monkeypatch):\n    monkeypatch.delitem(sys.modules, 'dotenv', raising=False)\n",
            "import sys\nimport pytest\ndef test(mp: pytest.MonkeyPatch):\n    mp.setitem(sys.modules, 'dotenv', None)\n",
            "import sys\nimport pytest\ndef test():\n    mp = pytest.MonkeyPatch()\n    mp.setitem(sys.modules, 'dotenv', None)\n",
            "import sys\nfrom unittest import mock\n@mock.patch.dict(sys.modules, {'dotenv': None})\ndef test():\n    pass\n",
            "import sys\nfrom unittest.mock import patch\ndef test():\n    with patch.dict(sys.modules, values={'dotenv': None}, clear=True, extra=None):\n        pass\n",
        ] {
            assert_eq!(mutation(source), None, "{source}");
        }
        for source in [
            // The stored value may be the queried module.
            "import sys\ndef test(monkeypatch, fake):\n    monkeypatch.setitem(sys.modules, 'pkg.M', fake)\n",
            "import pkg.M as target\nimport sys\ndef test(monkeypatch):\n    monkeypatch.setitem(sys.modules, 'shim', target)\n",
            "import pkg.M as target\nimport sys\nfrom unittest import mock\nmock.patch.dict(sys.modules, {'shim': target})\n",
            "import pkg.M as target\nimport sys\nfrom unittest import mock\nmock.patch.dict(sys.modules, values={'shim': target})\n",
            "import pkg.M as target\nimport sys\nfrom unittest import mock\nmock.patch.dict(sys.modules, shim=target)\n",
            // The receiver is not known to be a MonkeyPatch.
            "import sys\ndef test(mp):\n    mp.setitem(sys.modules, 'dotenv', None)\n",
            "import sys\ndef test(monkeypatch):\n    monkeypatch = other\n    monkeypatch.setitem(sys.modules, 'dotenv', None)\n",
            // sys.modules is not the edited mapping.
            "import sys\ndef test(monkeypatch):\n    monkeypatch.setitem(registry, sys.modules, None)\n",
            "import sys\ndef test(monkeypatch):\n    monkeypatch.setattr(sys.modules, 'dotenv', None)\n",
        ] {
            assert!(
                matches!(
                    mutation(source),
                    Some(PythonModuleMemberMutation::Escape(_))
                ),
                "{source}"
            );
        }
    }

    #[test]
    #[hardwon("#4622: sys.modules values must be followed by module identity")]
    fn dynamic_module_table_reads_follow_only_writes_through_the_possible_alias() {
        assert!(matches!(
            mutation("import pkg.M as target\nimport sys\nsys.modules['shim'] = target\n"),
            Some(PythonModuleMemberMutation::Escape(_))
        ));
        assert_eq!(
            mutation("import sys\ntarget = sys.modules[module_name]\nconsume(target.NAME)\n"),
            None
        );
        assert_eq!(
            mutation(
                "import sys\ntarget = sys.modules[module_name]\nconsume(getattr(target, 'NAME'))\nconsume(hasattr(target, 'NAME'))\n"
            ),
            None
        );
        assert_eq!(
            mutation("import sys\nconsume(sys.modules[module_name].NAME)\n"),
            None
        );
        assert!(matches!(
            mutation("import sys\ntarget = sys.modules[module_name]\ntarget.NAME = fake\n"),
            Some(PythonModuleMemberMutation::Write(_))
        ));
    }

    #[test]
    #[hardwon("#4622: a dominating string filter excludes unrelated dynamic sys.modules aliases")]
    fn dynamic_sys_modules_keys_respect_dominating_string_filters() {
        assert_eq!(
            mutation_for_module(
                "import sys\ndef patch():\n    for module_name in module_names:\n        if 'huggingface' in module_name or module_name.startswith('tqdm'):\n            target = sys.modules[module_name]\n            target.NAME = fake\n",
                "pkg.M",
                "backend.backends",
            ),
            None
        );
        assert!(matches!(
            mutation_for_module(
                "import sys\ndef patch():\n    for module_name in module_names:\n        if module_name.startswith('backend'):\n            target = sys.modules[module_name]\n            target.NAME = fake\n",
                "pkg.M",
                "backend.backends",
            ),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert!(matches!(
            mutation_for_module(
                "import sys\ndef patch(allowed):\n    for module_name in module_names:\n        if module_name in allowed:\n            target = sys.modules[module_name]\n            target.NAME = fake\n",
                "pkg.M",
                "backend.backends",
            ),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert!(matches!(
            mutation_for_module(
                "import sys\ndef patch():\n    for module_name in module_names:\n        if 'huggingface' in module_name:\n            module_name = 'backend.backends'\n            target = sys.modules[module_name]\n            target.NAME = fake\n",
                "pkg.M",
                "backend.backends",
            ),
            Some(PythonModuleMemberMutation::Write(_))
        ));
        assert_eq!(
            mutation_for_module(
                "import sys\ndef patch():\n    for module_name in module_names:\n        if not ('huggingface' in module_name):\n            continue\n        target = sys.modules[module_name]\n        target.NAME = fake\n",
                "pkg.M",
                "backend.backends",
            ),
            None
        );
    }
}
