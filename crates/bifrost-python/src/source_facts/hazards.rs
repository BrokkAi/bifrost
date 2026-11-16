//! File-local may-origins refuse proofs; they never certify builtin identity.
//! A zero bitset means unrecognized, not harmless. Unknown call effects belong
//! to #12522; unresolved frame libraries and self-import identities stay open.
use super::*;
use crate::bindings::{PythonLexicalNameResolution, python_binding_targets_bounded};
use std::collections::VecDeque;

const EXEC: u32 = 1;
const BUILTINS: u32 = 2;
const MAPPING: u32 = 4;
const IMPORT: u32 = 8;
const IMPORTLIB: u32 = 16;
const SYS: u32 = 32;
const MODULES: u32 = 64;
const VARS: u32 = 128;
const GLOBALS: u32 = 256;
const LOCALS: u32 = 512;
const SETATTR: u32 = 1024;
const COMPILE: u32 = 2048;
const MODULE: u32 = 4096;
const FRAME: u32 = 8192;
const GETFRAME: u32 = 16384;
const INSPECT: u32 = 32768;
const MUTATOR: u32 = 65536;
const TYPES: u32 = 131072;
const FUNCTION_FACTORY: u32 = 262144;
const MAPPING_GET: u32 = 524288;
const ESCAPES: u32 = EXEC
    | BUILTINS
    | MAPPING
    | IMPORT
    | VARS
    | GLOBALS
    | LOCALS
    | MUTATOR
    | FUNCTION_FACTORY
    | MAPPING_GET;

fn builtin(name: &str) -> u32 {
    match name {
        "exec" | "eval" => EXEC,
        "__import__" => IMPORT,
        "__builtins__" => BUILTINS | MAPPING,
        "vars" => VARS,
        "globals" => GLOBALS,
        "locals" => LOCALS,
        "setattr" | "delattr" => SETATTR,
        "compile" => COMPILE,
        _ => 0,
    }
}

fn attribute(input: u32, name: &str) -> u32 {
    let mut result = 0;
    if input & BUILTINS != 0 {
        result |= builtin(name);
    }
    if input & (BUILTINS | MODULE) != 0 && name == "__dict__" {
        result |= MAPPING;
    }
    if input & TYPES != 0 && matches!(name, "FunctionType" | "LambdaType") {
        result |= FUNCTION_FACTORY;
    }
    if input & IMPORTLIB != 0 && name == "import_module" {
        result |= IMPORT;
    }
    if input & SYS != 0 {
        result |= match name {
            "modules" => MODULES,
            "_getframe" => GETFRAME,
            _ => 0,
        };
    }
    if input & INSPECT != 0 && name == "currentframe" {
        result |= GETFRAME;
    }
    if input & FRAME != 0 && name == "f_globals" {
        result |= MAPPING;
    }
    if input & MAPPING != 0 && matches!(name, "get" | "__getitem__") {
        result |= MAPPING_GET;
    }
    if input & MAPPING != 0
        && matches!(
            name,
            "__setitem__"
                | "__ior__"
                | "__delitem__"
                | "update"
                | "setdefault"
                | "pop"
                | "popitem"
                | "clear"
        )
    {
        result |= MUTATOR;
    }
    result
}

struct Scope<'tree> {
    owner: Node<'tree>,
    parent: Option<usize>,
    inventory: PythonLexicalScopeInventory<'tree>,
}

fn lexical_parent(
    scope: usize,
    scopes: &[Scope<'_>],
    step: &mut impl FnMut() -> bool,
) -> Option<Option<usize>> {
    let Some(mut parent) = scopes[scope].parent else {
        return Some(None);
    };
    // Bodies never close over a class namespace. Class headers were mapped
    // to their enclosing evaluation scope when the scopes were constructed.
    while scopes[parent].owner.kind() == "class_definition" {
        if !step() {
            return None;
        }
        parent = scopes[parent]
            .parent
            .expect("a class has an enclosing scope");
    }
    Some(Some(parent))
}

fn binding_scope(
    mut scope: usize,
    node: Node<'_>,
    name: &str,
    scopes: &[Scope<'_>],
    step: &mut impl FnMut() -> bool,
) -> Option<Option<usize>> {
    loop {
        if !step() {
            return None;
        }
        match scopes[scope]
            .inventory
            .name_resolution_at_bounded(name, node, &mut *step)?
        {
            PythonLexicalNameResolution::Local => return Some(Some(scope)),
            PythonLexicalNameResolution::Global => return Some(Some(0)),
            PythonLexicalNameResolution::Nonlocal | PythonLexicalNameResolution::Unbound => {}
        }
        let Some(parent) = lexical_parent(scope, scopes, step)? else {
            return Some(None);
        };
        scope = parent;
    }
}

#[derive(Clone, Copy)]
enum Transfer<'tree> {
    Identity,
    Attribute(Node<'tree>),
    Call {
        module: u32,
        module_scope: bool,
        first: Option<usize>,
        member: u32,
    },
    Vars {
        callee: usize,
    },
    Subscript {
        module: u32,
        member: u32,
    },
}

impl Transfer<'_> {
    fn apply(self, input: u32, source: &str, values: &[u32]) -> u32 {
        match self {
            Self::Identity => input,
            Self::Attribute(name) => attribute(
                input,
                name.utf8_text(source.as_bytes()).expect("UTF-8 attribute"),
            ),
            Self::Call {
                module,
                module_scope,
                first,
                member,
            } => {
                let mut result = 0;
                if input & MAPPING_GET != 0 {
                    result |= member;
                }
                if input & IMPORT != 0 {
                    result |= module;
                }
                if input & GLOBALS != 0
                    || (module_scope
                        && (input & LOCALS != 0 || (input & VARS != 0 && first.is_none())))
                {
                    result |= MAPPING;
                }
                if input & GETFRAME != 0 {
                    result |= FRAME;
                }
                if input & VARS != 0
                    && first.is_some_and(|id| values[id] & (BUILTINS | MODULE) != 0)
                {
                    result |= MAPPING;
                }
                result
            }
            Self::Vars { callee } => {
                if input & (BUILTINS | MODULE) != 0 && values[callee] & VARS != 0 {
                    MAPPING
                } else {
                    0
                }
            }
            Self::Subscript { module, member } => {
                let mut result = 0;
                if input & MODULES != 0 {
                    result |= module;
                }
                if input & (BUILTINS | MAPPING) != 0 {
                    result |= member;
                }
                result
            }
        }
    }
}

/// One completed source-local collection, shared by all hazard consumers.
/// Temporary origins and scope inventories are discarded before publication.
pub(crate) struct PythonDynamicHazards {
    sites: HashSet<usize>,
}

impl PythonDynamicHazards {
    pub(crate) fn contains(&self, node: Node<'_>) -> bool {
        self.sites.contains(&node.id())
    }

    pub(crate) fn collect_bounded(
        root: Node<'_>,
        source: &str,
        mut step: impl FnMut() -> bool,
    ) -> Option<Self> {
        let mut scopes = Vec::new();
        let mut nodes = Vec::new();
        let mut scope_at = HashMap::new();
        let mut stack = vec![(root, None)];
        while let Some((node, scope)) = stack.pop() {
            if !step() {
                return None;
            }
            let index = nodes.len();
            nodes.push(node);
            let is_scope = node == root
                || matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                );
            let body_scope = if is_scope {
                let mut parameters = Vec::new();
                if let Some(formals) = node.child_by_field_name("parameters") {
                    let mut cursor = formals.walk();
                    for parameter in formals.named_children(&mut cursor) {
                        if !step() {
                            return None;
                        }
                        if let Some(name) = crate::syntax::python_parameter_name_bounded(
                            parameter, source, &mut step,
                        )? {
                            parameters.push(name);
                        }
                    }
                }
                let id = scopes.len();
                scopes.push(Scope {
                    owner: node,
                    parent: scope,
                    inventory: PythonLexicalScopeInventory::collect_bounded(
                        node, source, parameters, &mut step,
                    )?,
                });
                Some(id)
            } else {
                scope
            };
            scope_at.insert(node.id(), scope.unwrap_or(0));
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !step() {
                    return None;
                }
                let child_scope = if node == root || node.child_by_field_name("body") == Some(child)
                {
                    body_scope
                } else {
                    scope
                };
                stack.push((child, child_scope));
            }
            debug_assert_eq!(nodes[index], node);
        }
        let by_id: HashMap<_, _> = nodes.iter().enumerate().map(|(i, n)| (n.id(), i)).collect();
        let mut values = vec![0u32; nodes.len()];
        let mut edges: Vec<Vec<(usize, Transfer<'_>)>> = vec![Vec::new(); nodes.len()];
        let mut slots = HashMap::new();
        let mut slot_for =
            |scope: usize,
             name: &str,
             values: &mut Vec<u32>,
             edges: &mut Vec<Vec<(usize, Transfer<'_>)>>| {
                *slots.entry((scope, name.to_owned())).or_insert_with(|| {
                    let id = values.len();
                    values.push(0);
                    edges.push(Vec::new());
                    id
                })
            };
        let text = |node: Node<'_>| node.utf8_text(source.as_bytes()).expect("UTF-8 source");
        let module_origin = |node: Node<'_>| {
            if node.kind() == "identifier" && text(node) == "__name__" {
                MODULE
            } else if crate::decode_python_string_value(node, source)
                .ok()
                .as_deref()
                == Some("builtins")
            {
                BUILTINS
            } else {
                0
            }
        };
        struct CallArguments<'tree> {
            first: Option<Node<'tree>>,
            import_name: Option<Node<'tree>>,
        }
        let mut call_arguments = HashMap::new();
        for &node in &nodes {
            if !step() {
                return None;
            }
            if node.kind() != "argument_list" {
                continue;
            }
            let mut first = None;
            let mut keyword_name = None;
            let mut positional = None;
            let mut cursor = node.walk();
            for argument in node.named_children(&mut cursor) {
                if !step() {
                    return None;
                }
                if argument.is_extra() {
                    continue;
                }
                if first.is_none() {
                    first = Some(argument);
                }
                if argument.kind() == "keyword_argument" {
                    if argument
                        .child_by_field_name("name")
                        .is_some_and(|name| text(name) == "name")
                    {
                        keyword_name = argument.child_by_field_name("value");
                    }
                } else if positional.is_none() {
                    positional = Some(argument);
                }
            }
            call_arguments.insert(
                node.id(),
                CallArguments {
                    first,
                    import_name: keyword_name.or(positional),
                },
            );
        }
        // Ordered scopes retain the first completed unconditional binding and
        // possible deletion of each builtin name. Build this once
        // instead of scanning all binders at every identifier read.
        #[derive(Default)]
        struct OrderedBinding {
            bound: Option<usize>,
            deleted: bool,
        }
        let mut first_bindings = Vec::with_capacity(scopes.len());
        for (id, scope) in scopes.iter().enumerate() {
            if !step() {
                return None;
            }
            let mut first: HashMap<&str, OrderedBinding> = HashMap::new();
            if id == 0 || scope.owner.kind() == "class_definition" {
                'bindings: for binding in scope.inventory.binding_nodes() {
                    if !step() {
                        return None;
                    }
                    let name = text(binding);
                    if builtin(name) == 0 {
                        continue;
                    }
                    let mut effect_end = None;
                    let mut enclosing = binding.parent();
                    while let Some(parent) = enclosing {
                        if !step() {
                            return None;
                        }
                        if parent.kind() == "delete_statement" {
                            // Deferred reads may execute after this deletion,
                            // regardless of their textual position. Retain the
                            // builtin candidate for the whole ordered slot.
                            first.entry(name).or_default().deleted = true;
                            continue 'bindings;
                        }
                        if effect_end.is_none()
                            && matches!(
                                parent.kind(),
                                "assignment"
                                    | "augmented_assignment"
                                    | "named_expression"
                                    | "function_definition"
                                    | "class_definition"
                                    | "import_statement"
                                    | "import_from_statement"
                                    | "type_alias_statement"
                            )
                        {
                            // A bare annotation does not bind a module value.
                            if parent.kind() == "assignment"
                                && parent.child_by_field_name("right").is_none()
                            {
                                continue 'bindings;
                            }
                            // In particular, the RHS of `eval = eval` still
                            // reads the builtin before the assignment commits.
                            effect_end = Some(parent.end_byte());
                        }
                        if parent == scope.owner {
                            let position = effect_end.unwrap_or(binding.end_byte());
                            let bound = &mut first.entry(name).or_default().bound;
                            *bound =
                                Some(bound.map_or(position, |previous| previous.min(position)));
                            break;
                        }
                        if matches!(
                            parent.kind(),
                            "if_statement"
                                | "for_statement"
                                | "while_statement"
                                | "try_statement"
                                | "with_statement"
                                | "match_statement"
                        ) {
                            break;
                        }
                        enclosing = parent.parent();
                    }
                }
            }
            first_bindings.push(first);
        }
        for (id, &node) in nodes.iter().enumerate() {
            if !step() {
                return None;
            }
            let scope = scope_at[&node.id()];
            if node.kind() == "identifier" {
                let name = text(node);
                // Comprehension targets block the enclosing slot without
                // contributing assignments to it.
                if scopes[scope]
                    .inventory
                    .comprehension_binds_name_at_bounded(name, node, &mut step)?
                {
                    continue;
                }
                if let Some(owner) = binding_scope(scope, node, name, &scopes, &mut step)? {
                    let slot = slot_for(owner, name, &mut values, &mut edges);
                    edges[slot].push((id, Transfer::Identity));
                    // A later ordered module binding cannot shadow an earlier
                    // builtin read. Function slots block fallback scope-wide.
                    if builtin(name) != 0
                        && (owner == 0 || scopes[owner].owner.kind() == "class_definition")
                    {
                        if !step() {
                            return None;
                        }
                        let earlier = first_bindings[owner].get(name).is_some_and(|binding| {
                            binding
                                .bound
                                .is_some_and(|position| position <= node.start_byte())
                                && !binding.deleted
                        });
                        if !earlier {
                            values[id] |= builtin(name);
                        }
                    }
                } else {
                    values[id] |= builtin(name);
                }
            }
            match node.kind() {
                "attribute" => {
                    if let (Some(object), Some(name)) = (
                        node.child_by_field_name("object"),
                        node.child_by_field_name("attribute"),
                    ) {
                        edges[by_id[&object.id()]].push((id, Transfer::Attribute(name)));
                    }
                }
                "parenthesized_expression" | "conditional_expression" => {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if !step() {
                            return None;
                        }
                        edges[by_id[&child.id()]].push((id, Transfer::Identity));
                    }
                }
                "call" => {
                    if let Some(function) = node.child_by_field_name("function") {
                        let arguments = node
                            .child_by_field_name("arguments")
                            .and_then(|arguments| call_arguments.get(&arguments.id()));
                        let first = arguments.and_then(|arguments| arguments.first);
                        let module = arguments
                            .and_then(|arguments| arguments.import_name)
                            .map_or(0, module_origin);
                        edges[by_id[&function.id()]].push((
                            id,
                            Transfer::Call {
                                module,
                                module_scope: scopes[scope].owner == root,
                                first: first.map(|n| by_id[&n.id()]),
                                member: first
                                    .and_then(|n| crate::decode_python_string_value(n, source).ok())
                                    .map_or(0, |name| builtin(&name)),
                            },
                        ));
                        if let Some(first) = first {
                            edges[by_id[&first.id()]].push((
                                id,
                                Transfer::Vars {
                                    callee: by_id[&function.id()],
                                },
                            ));
                        }
                    }
                }
                "subscript" => {
                    if let (Some(value), Some(key)) = (
                        node.child_by_field_name("value"),
                        node.child_by_field_name("subscript"),
                    ) {
                        edges[by_id[&value.id()]].push((
                            id,
                            Transfer::Subscript {
                                module: module_origin(key),
                                member: crate::decode_python_string_value(key, source)
                                    .ok()
                                    .map_or(0, |name| builtin(&name)),
                            },
                        ));
                    }
                }
                "assignment" | "named_expression" => {
                    let target = node
                        .child_by_field_name("left")
                        .or_else(|| node.child_by_field_name("name"));
                    let rhs = node
                        .child_by_field_name("right")
                        .or_else(|| node.child_by_field_name("value"));
                    if let (Some(target), Some(rhs)) = (target, rhs) {
                        edges[by_id[&rhs.id()]].push((id, Transfer::Identity));
                        for binding in python_binding_targets_bounded(target, source, &mut step)? {
                            let name = text(binding.declaration);
                            let owner = binding_scope(
                                scope,
                                binding.declaration,
                                name,
                                &scopes,
                                &mut step,
                            )?
                            .unwrap_or(scope);
                            let slot = slot_for(owner, name, &mut values, &mut edges);
                            edges[by_id[&rhs.id()]].push((slot, Transfer::Identity));
                        }
                    }
                }
                "import_statement" | "import_from_statement" => {
                    let module = node.child_by_field_name("module_name");
                    let module = module.map(text);
                    let mut cursor = node.walk();
                    for imported in node.children_by_field_name("name", &mut cursor) {
                        if !step() {
                            return None;
                        }
                        let name = imported.child_by_field_name("name").unwrap_or(imported);
                        let binding = imported
                            .child_by_field_name("alias")
                            .unwrap_or_else(|| name.named_child(0).unwrap_or(name));
                        let origin = if node.kind() == "import_from_statement" {
                            match module {
                                Some("builtins") if text(name) == "__dict__" => MAPPING,
                                Some("builtins") => builtin(text(name)),
                                Some("importlib") if text(name) == "import_module" => IMPORT,
                                Some("sys") if text(name) == "modules" => MODULES,
                                Some("sys") if text(name) == "_getframe" => GETFRAME,
                                Some("inspect") if text(name) == "currentframe" => GETFRAME,
                                Some("types")
                                    if matches!(text(name), "FunctionType" | "LambdaType") =>
                                {
                                    FUNCTION_FACTORY
                                }
                                _ => 0,
                            }
                        } else {
                            match text(name) {
                                "builtins" => BUILTINS,
                                "importlib" => IMPORTLIB,
                                "sys" => SYS,
                                "inspect" => INSPECT,
                                "types" => TYPES,
                                _ => 0,
                            }
                        };
                        let owner =
                            binding_scope(scope, binding, text(binding), &scopes, &mut step)?
                                .unwrap_or(scope);
                        let slot = slot_for(owner, text(binding), &mut values, &mut edges);
                        values[slot] |= origin;
                    }
                }
                _ => {}
            }
        }
        let mut pending: VecDeque<_> = (0..values.len()).filter(|&i| values[i] != 0).collect();
        while let Some(input) = pending.pop_front() {
            if !step() {
                return None;
            }
            for &(output, transfer) in &edges[input] {
                if !step() {
                    return None;
                }
                let joined = values[output] | transfer.apply(values[input], source, &values);
                if joined != values[output] {
                    values[output] = joined;
                    pending.push_back(output);
                }
            }
        }
        let mut identity_comparisons = HashSet::new();
        for &node in &nodes {
            if !step() {
                return None;
            }
            if node.kind() != "comparison_operator" || node.has_error() {
                continue;
            }
            let mut only_identity = true;
            let mut operators = 0_usize;
            let complete =
                crate::structural::visit_python_comparison_children(node, |child, operator| {
                    if !step() {
                        return false;
                    }
                    if operator {
                        operators += 1;
                        only_identity &= matches!(child.kind(), "is" | "is not");
                    }
                    true
                });
            if !complete {
                return None;
            }
            if only_identity && operators > 0 {
                identity_comparisons.insert(node.id());
            }
        }
        let mut sites = HashSet::new();
        for (id, &node) in nodes.iter().enumerate() {
            if !step() {
                return None;
            }
            let origin = |n: Node<'_>| values[by_id[&n.id()]];
            if node.kind() == "call"
                && let Some(function) = node.child_by_field_name("function")
            {
                let callee = origin(function);
                let receiver = node
                    .child_by_field_name("arguments")
                    .and_then(|arguments| call_arguments.get(&arguments.id()))
                    .and_then(|arguments| arguments.first);
                // Construction gives opaque code an execution namespace. Even
                // a fresh dictionary can expose builtin mutation to that code.
                let function_factory = callee & FUNCTION_FACTORY != 0;
                if function_factory
                    || callee & (EXEC | MUTATOR) != 0
                    || (callee & SETATTR != 0
                        && receiver.is_some_and(|r| origin(r) & (BUILTINS | MODULE) != 0))
                {
                    sites.insert(node.id());
                }
            }
            if node.kind() == "augmented_assignment"
                && node
                    .child_by_field_name("left")
                    .is_some_and(|left| origin(left) & MAPPING != 0)
            {
                sites.insert(node.id());
            }
            // Find structured write targets without treating reads of a module
            // or its dictionary as a mutation.
            if matches!(node.kind(), "attribute" | "subscript") {
                let mut current = node;
                while let Some(parent) = current.parent() {
                    if !step() {
                        return None;
                    }
                    let write = match parent.kind() {
                        "assignment" | "augmented_assignment" => {
                            parent.child_by_field_name("left") == Some(current)
                        }
                        "delete_statement" => true,
                        "pattern_list" | "tuple_pattern" | "list_pattern" | "expression_list" => {
                            current = parent;
                            continue;
                        }
                        _ => false,
                    };
                    if write {
                        let receiver = node
                            .child_by_field_name("object")
                            .or_else(|| node.child_by_field_name("value"));
                        if receiver.is_some_and(|r| origin(r) & (BUILTINS | MODULE | MAPPING) != 0)
                        {
                            sites.insert(parent.id());
                        }
                    }
                    break;
                }
            }
            if values[id] & ESCAPES != 0
                && let Some(parent) = node.parent()
            {
                let escape = match parent.kind() {
                    "argument_list"
                    | "list_splat"
                    | "dictionary_splat"
                    | "list_comprehension"
                    | "set_comprehension"
                    | "dictionary_comprehension"
                    | "generator_expression" => true,
                    "keyword_argument" | "default_parameter" | "typed_default_parameter" => {
                        parent.child_by_field_name("value") == Some(node)
                    }
                    "lambda" => parent.child_by_field_name("body") == Some(node),
                    "return_statement"
                    | "yield"
                    | "list"
                    | "tuple"
                    | "set"
                    | "pair"
                    | "comparison_operator" => true,
                    "assignment" => {
                        parent.child_by_field_name("right") == Some(node)
                            && parent.child_by_field_name("left").is_some_and(|left| {
                                matches!(left.kind(), "attribute" | "subscript")
                            })
                    }
                    _ => false,
                };
                // Rich comparisons and predicate calls can hand a capability to
                // user code. Only is/is not are unconditionally non-calling.
                let mut token = node;
                let mut in_tuple = false;
                while let Some(wrapper) = token.parent() {
                    if !step() {
                        return None;
                    }
                    match wrapper.kind() {
                        "tuple" => in_tuple = true,
                        "parenthesized_expression" => {}
                        _ => break,
                    }
                    token = wrapper;
                }
                let type_token = !in_tuple
                    && token
                        .parent()
                        .is_some_and(|comparison| identity_comparisons.contains(&comparison.id()));
                if escape && !type_token {
                    sites.insert(node.id());
                }
            }
        }
        step().then_some(Self { sites })
    }
}
