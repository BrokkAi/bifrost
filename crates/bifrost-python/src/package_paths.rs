//! Structured interpretation of surviving package search-path extensions.

use crate::syntax::{python_plain_string_literal, python_static_attribute_path};
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_normalization::NormalizePath;
use std::path::{Component, PathBuf};
use tree_sitter::Node;

/// Surviving package-location-derived extensions, relative to the initializer
/// directory. Literals may be joined onto the anchor, but never establish one.
/// The anchor is symbolic, so these facts remain valid when a blob is remounted.
pub fn appended_path_dirs(root: Node<'_>, source: &str) -> Vec<PathBuf> {
    let mut bound: HashMap<String, PathValue> = HashMap::default();
    bound.insert(
        "__file__".to_owned(),
        PathValue::Anchored {
            parents: 0,
            suffix: PathBuf::from("__init__.py"),
        },
    );
    let mut appended: Vec<PathBuf> = Vec::new();
    // Once `__path__` reaches code this reader does not follow (an alias, a
    // call argument, a function body), that code can change the list, so no
    // recorded directory is proven to survive.
    let mut escaped = false;
    let mut copying = CopyingNames::default();
    walk_named_tree_preorder(root, true, |node| {
        match node.kind() {
            // Only module-level code runs the extension, so a name bound inside
            // a function or class body says nothing about what `__path__`
            // holds after the marker is executed. A body that names `__path__`
            // can still change it when called, which this reader does not follow.
            "function_definition" | "class_definition" | "lambda" => {
                python_unbind(python_bound_names(node, source), &mut bound, &mut copying);
                escaped |= python_subtree_names_path(node, source);
                python_forget_names_in_body(node, source, &mut copying);
                return WalkControl::SkipChildren;
            }
            "identifier" => {
                if python_names_path(Some(node), source)
                    && !python_path_use_is_modelled(node, source, &copying)
                {
                    escaped = true;
                }
                python_check_copying_use(node, source, &mut copying);
            }
            "assignment" => {
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "assignment")
                {
                    return WalkControl::Continue;
                }
                let mut assignment = node;
                loop {
                    if python_targets_path(assignment.child_by_field_name("left"), source) {
                        appended.clear();
                    }
                    match assignment.child_by_field_name("right") {
                        Some(right) if right.kind() == "assignment" => assignment = right,
                        _ => break,
                    }
                }
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "expression_statement")
                    && node
                        .parent()
                        .and_then(|parent| parent.parent())
                        .is_some_and(|parent| parent.kind() == "module")
                {
                    for name in python_bound_names(node, source) {
                        copying.forget(&name);
                    }
                    python_bind_assignment(node, source, &mut bound);
                } else {
                    python_unbind(python_bound_names(node, source), &mut bound, &mut copying);
                }
            }
            "augmented_assignment" | "delete_statement" => {
                let target = if node.kind() == "augmented_assignment" {
                    node.child_by_field_name("left")
                } else {
                    node.named_child(0)
                };
                if python_targets_path(target, source) {
                    appended.clear();
                }
                python_unbind(python_bound_names(node, source), &mut bound, &mut copying);
            }
            "for_statement" | "with_item" | "except_clause" | "named_expression" => {
                python_unbind(python_bound_names(node, source), &mut bound, &mut copying);
            }
            "import_statement" | "import_from_statement" => {
                python_unbind(python_bound_names(node, source), &mut bound, &mut copying);
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "module")
                {
                    python_bind_pkgutil_import(node, source, &mut copying);
                }
                // The imported names are bindings, not uses of a trusted callee.
                return WalkControl::SkipChildren;
            }
            "call" => {
                let Some(function) = node.child_by_field_name("function") else {
                    return WalkControl::Continue;
                };
                let Some(path) = python_static_attribute_path(function) else {
                    return WalkControl::Continue;
                };
                let [object, method] = path.as_slice() else {
                    return WalkControl::Continue;
                };
                if !python_names_path(Some(*object), source) {
                    return WalkControl::Continue;
                }
                let method = method.utf8_text(source.as_bytes()).unwrap_or("");
                if !matches!(method, "append" | "insert" | "extend") {
                    appended.clear();
                    return WalkControl::Continue;
                }
                let directories = python_path_appended_dirs_in_call(node, source, &bound);
                if !python_extension_statement_runs(node, source, &bound, &directories) {
                    appended.clear();
                    return WalkControl::Continue;
                }
                for directory in directories
                    .into_iter()
                    .filter_map(PathValue::relative_directory)
                {
                    if !appended.contains(&directory) {
                        appended.push(directory);
                    }
                }
            }
            _ => {}
        }
        if escaped {
            WalkControl::Break
        } else {
            WalkControl::Continue
        }
    });
    if escaped {
        return Vec::new();
    }
    appended
}

/// Whether one `__path__` occurrence is a use this reader models: the receiver
/// of a method call (modelled or invalidating in the call arm), an assignment or
/// `del` target (invalidating in those arms), an element read, a read-only
/// membership test or loop over it, or the argument of a call whose result
/// replaces `__path__`. Any other use can hand the list to code that changes it
/// under another name.
fn python_path_use_is_modelled(identifier: Node<'_>, source: &str, copying: &CopyingNames) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    if parent.kind() == "argument_list" {
        // `__path__ = extend_path(__path__, __name__)`: pkgutil.extend_path returns
        // a new list and keeps no reference to its argument, and the assignment
        // arm drops every recorded directory. Any other callee could keep the list
        // and return it, so a later change under the kept name would go unseen.
        return parent.named_child(0) == Some(identifier)
            && parent
                .parent()
                .filter(|call| call.kind() == "call")
                .is_some_and(|call| {
                    python_calls_extend_path(call, source, copying)
                        && call.parent().is_some_and(|holder| {
                            holder.kind() == "assignment"
                                && holder.child_by_field_name("right") == Some(call)
                                && python_names_path(holder.child_by_field_name("left"), source)
                        })
                });
    }
    if parent.kind() == "attribute" {
        return parent.child_by_field_name("object") == Some(identifier)
            && parent.parent().is_some_and(|call| {
                call.kind() == "call" && call.child_by_field_name("function") == Some(parent)
            });
    }
    if parent.kind() == "comparison_operator" {
        let mut cursor = parent.walk();
        let membership = parent
            .children_by_field_name("operators", &mut cursor)
            .all(|operator| matches!(operator.kind(), "in" | "not in"));
        return membership && parent.named_child(0) != Some(identifier);
    }
    if parent.kind() == "for_statement" {
        return parent.child_by_field_name("right") == Some(identifier);
    }
    let mut top = identifier;
    while let Some(up) = top
        .parent()
        .filter(|up| up.kind() == "subscript" && up.child_by_field_name("value") == Some(top))
    {
        top = up;
    }
    let Some(holder) = top.parent() else {
        return false;
    };
    match holder.kind() {
        "assignment" | "augmented_assignment" => {
            holder.child_by_field_name("left") == Some(top) || top != identifier
        }
        "delete_statement" => holder.named_child(0) == Some(top),
        "pattern_list" | "tuple_pattern" | "list_pattern" | "as_pattern_target" => false,
        "for_statement" => holder.child_by_field_name("left") != Some(top) && top != identifier,
        // A subscript elsewhere reads one element, which cannot change the list.
        _ => top != identifier,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CopyingCallee {
    PkgutilModule,
    ExtendPath,
}

/// The callees this reader trusts to return a new list without keeping their
/// argument: module-level bindings of `pkgutil` and its `extend_path`, and the
/// builtin `__import__` while nothing in the initializer rebinds it. A trusted
/// name stays trusted only while every reference to it is that call. Any other
/// reference (an attribute write, an argument, a mention in a function body)
/// can change the one shared pkgutil module or its function, so it taints every
/// route to them for the rest of the initializer: other aliases, a later
/// import, and `__import__('pkgutil')`. Reaching pkgutil dynamically
/// (`importlib`, `sys.modules`, another module's code) is outside what a reader
/// of this file can see, like `sys.modules[__name__].__path__`.
#[derive(Default)]
struct CopyingNames {
    callees: HashMap<String, CopyingCallee>,
    import_shadowed: bool,
    pkgutil_tainted: bool,
    /// Names mentioned in a function, class or lambda body. Python resolves them
    /// when the body runs, which can be after a later import binds them, so such
    /// a name never becomes a trusted callee.
    body_names: HashSet<String>,
}

impl CopyingNames {
    /// A rebinding replaces the name only; the module it named is unchanged.
    fn forget(&mut self, name: &str) {
        self.callees.remove(name);
        if name == "__import__" {
            self.import_shadowed = true;
        }
    }

    fn taint_pkgutil(&mut self) {
        self.callees.clear();
        self.pkgutil_tainted = true;
    }
}

fn python_unbind(
    names: Vec<String>,
    bound: &mut HashMap<String, PathValue>,
    copying: &mut CopyingNames,
) {
    for name in names {
        bound.remove(&name);
        copying.forget(&name);
    }
}

/// Forget a trusted callee when one reference to its name is not the trusted
/// call: `p.extend_path(...)` for a `pkgutil` module, `e(...)` for an
/// `extend_path` function, or a call of `__import__`. An attribute's member name
/// is not a reference to a binding, except that writing a `__import__` member
/// (`builtins.__import__ = ...`) can replace the builtin.
fn python_check_copying_use(identifier: Node<'_>, source: &str, copying: &mut CopyingNames) {
    let Ok(name) = identifier.utf8_text(source.as_bytes()) else {
        return;
    };
    let parent = identifier.parent();
    let called = parent.is_some_and(|call| {
        call.kind() == "call" && call.child_by_field_name("function") == Some(identifier)
    });
    if name == "__import__" {
        match parent.filter(|_| called) {
            None => copying.forget(name),
            // `__import__('pkgutil')` reaches the shared pkgutil module, so any use
            // of its result other than the trusted call can change it.
            Some(call) => {
                if python_imports_pkgutil(call, source)
                    && !python_is_extend_path_call_object(call, source)
                {
                    copying.taint_pkgutil();
                }
            }
        }
        return;
    }
    let Some(callee) = copying.callees.get(name).copied() else {
        return;
    };
    let Some(parent) = parent else {
        return;
    };
    if parent.kind() == "attribute" && parent.child_by_field_name("attribute") == Some(identifier) {
        return;
    }
    let trusted = match callee {
        CopyingCallee::ExtendPath => called,
        CopyingCallee::PkgutilModule => python_is_extend_path_call_object(identifier, source),
    };
    if !trusted {
        copying.taint_pkgutil();
    }
}

/// Whether `node` is the receiver of a called `.extend_path`: `node.extend_path(...)`.
fn python_is_extend_path_call_object(node: Node<'_>, source: &str) -> bool {
    node.parent().is_some_and(|attribute| {
        attribute.kind() == "attribute"
            && attribute.child_by_field_name("object") == Some(node)
            && attribute
                .child_by_field_name("attribute")
                .and_then(|member| member.utf8_text(source.as_bytes()).ok())
                == Some("extend_path")
            && attribute.parent().is_some_and(|call| {
                call.kind() == "call" && call.child_by_field_name("function") == Some(attribute)
            })
    })
}

/// Whether `call` is `__import__('pkgutil')`.
fn python_imports_pkgutil(call: Node<'_>, source: &str) -> bool {
    let importer = call
        .child_by_field_name("function")
        .is_some_and(|function| {
            function.kind() == "identifier"
                && function.utf8_text(source.as_bytes()).ok() == Some("__import__")
        });
    let module = call.child_by_field_name("arguments").and_then(|arguments| {
        let mut cursor = arguments.walk();
        let arguments: Vec<Node<'_>> = arguments.named_children(&mut cursor).collect();
        match arguments.as_slice() {
            [only] => python_plain_string_literal(*only, source),
            _ => None,
        }
    });
    importer && module == Some("pkgutil")
}

/// A function, class or lambda body runs when called, which this reader does not
/// follow. One that names pkgutil, `extend_path`, `__import__` or a trusted
/// callee can change the shared pkgutil module whenever it runs, and its names
/// resolve at that time, so none of them can become trusted later either.
fn python_forget_names_in_body(node: Node<'_>, source: &str, copying: &mut CopyingNames) {
    walk_named_tree_preorder(node, false, |child| {
        if child.kind() == "identifier"
            && let Ok(name) = child.utf8_text(source.as_bytes())
        {
            if name == "__import__" {
                copying.forget(name);
            }
            if matches!(name, "pkgutil" | "extend_path" | "__import__")
                || copying.callees.contains_key(name)
            {
                copying.taint_pkgutil();
            }
            copying.body_names.insert(name.to_owned());
        }
        WalkControl::Continue
    });
}

/// Record a module-level `import pkgutil [as p]` or
/// `from pkgutil import extend_path [as e]`.
fn python_bind_pkgutil_import(statement: Node<'_>, source: &str, copying: &mut CopyingNames) {
    if copying.pkgutil_tainted {
        return;
    }
    let text = |node: Node<'_>| node.utf8_text(source.as_bytes()).ok();
    let (imported, callee) = if statement.kind() == "import_from_statement" {
        if statement.child_by_field_name("module_name").and_then(text) != Some("pkgutil") {
            return;
        }
        ("extend_path", CopyingCallee::ExtendPath)
    } else {
        ("pkgutil", CopyingCallee::PkgutilModule)
    };
    let mut cursor = statement.walk();
    for name in statement.children_by_field_name("name", &mut cursor) {
        let (target, binding) = if name.kind() == "aliased_import" {
            (
                name.child_by_field_name("name"),
                name.child_by_field_name("alias"),
            )
        } else {
            (Some(name), Some(name))
        };
        if target.and_then(text) == Some(imported)
            && let Some(binding) = binding.and_then(text)
            && !copying.body_names.contains(binding)
        {
            copying.callees.insert(binding.to_owned(), callee);
        }
    }
}

/// Whether `call` calls pkgutil's `extend_path` through a module-level binding,
/// `p.extend_path` for a bound `pkgutil` module, or `__import__('pkgutil')`.
fn python_calls_extend_path(call: Node<'_>, source: &str, copying: &CopyingNames) -> bool {
    let text = |node: Node<'_>| node.utf8_text(source.as_bytes()).ok();
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    match function.kind() {
        "identifier" => {
            text(function).and_then(|name| copying.callees.get(name))
                == Some(&CopyingCallee::ExtendPath)
        }
        "attribute" => {
            if function.child_by_field_name("attribute").and_then(text) != Some("extend_path") {
                return false;
            }
            let Some(object) = function.child_by_field_name("object") else {
                return false;
            };
            match object.kind() {
                "identifier" => {
                    text(object).and_then(|name| copying.callees.get(name))
                        == Some(&CopyingCallee::PkgutilModule)
                }
                "call" => {
                    python_imports_pkgutil(object, source)
                        && !copying.import_shadowed
                        && !copying.pkgutil_tainted
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether any identifier under `node` is `__path__`.
fn python_subtree_names_path(node: Node<'_>, source: &str) -> bool {
    let mut found = false;
    walk_named_tree_preorder(node, false, |child| {
        if child.kind() == "identifier" && python_names_path(Some(child), source) {
            found = true;
            return WalkControl::Break;
        }
        WalkControl::Continue
    });
    found
}

/// The identifiers a binding construct writes in the module scope. Target walks
/// visit destructuring patterns but never treat an attribute or subscript's
/// object as a binding.
fn python_bound_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut targets = Vec::new();
    match node.kind() {
        "assignment" => {
            let mut current = node;
            loop {
                if let Some(left) = current.child_by_field_name("left") {
                    targets.push(left);
                }
                match current.child_by_field_name("right") {
                    Some(right) if right.kind() == "assignment" => current = right,
                    _ => break,
                }
            }
        }
        "augmented_assignment" | "for_statement" => {
            targets.extend(node.child_by_field_name("left"));
        }
        "named_expression" | "function_definition" | "class_definition" => {
            targets.extend(node.child_by_field_name("name"));
        }
        "except_clause" => targets.extend(node.child_by_field_name("alias")),
        "with_item" => {
            let mut cursor = node.walk();
            targets.extend(
                node.named_children(&mut cursor)
                    .filter(|child| child.kind() == "as_pattern")
                    .filter_map(|child| child.child_by_field_name("alias")),
            );
        }
        "delete_statement" => targets.extend(node.named_child(0)),
        "import_statement" | "import_from_statement" => {
            let mut cursor = node.walk();
            for child in node.children_by_field_name("name", &mut cursor) {
                let name = if child.kind() == "aliased_import" {
                    child.child_by_field_name("alias")
                } else {
                    child.named_child(0)
                };
                targets.extend(name);
            }
        }
        _ => {}
    }
    let mut names = Vec::new();
    while let Some(target) = targets.pop() {
        match target.kind() {
            "identifier" => {
                if let Ok(name) = target.utf8_text(source.as_bytes()) {
                    names.push(name.to_owned());
                }
            }
            "pattern_list" | "tuple_pattern" | "list_pattern" | "expression_list"
            | "as_pattern" | "as_pattern_target" => {
                let mut cursor = target.walk();
                targets.extend(target.named_children(&mut cursor));
            }
            _ => {}
        }
    }
    names
}

fn python_targets_path(target: Option<Node<'_>>, source: &str) -> bool {
    let Some(mut target) = target else {
        return false;
    };
    while target.kind() == "subscript" {
        let Some(value) = target.child_by_field_name("value") else {
            return false;
        };
        target = value;
    }
    python_names_path(Some(target), source)
}

/// Whether `node` -- when it is one -- is the marker's own `__path__` name.
fn python_names_path(node: Option<Node<'_>>, source: &str) -> bool {
    node.is_some_and(|node| {
        node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some("__path__")
    })
}

/// Whether the statement holding one `__path__` extension call is one the
/// interpreter runs before the imports the marker serves.
///
/// Module-level statements run. Inside a branch they run only when the branch
/// tests exactly the fact that makes the extension necessary: the pinned
/// shim's membership guard `if _impl not in __path__:`, whose tested name
/// denotes the directory the branch appends. Every other branch shape is not
/// evidence -- `if False:` never runs the append, a predicate the reader
/// cannot answer says nothing, and a loop, `try` or `else` body is no more
/// proven than a comparison the guard does not state -- so the marker leaves
/// an honest resolution gap rather than a binding. The same rule applies to
/// the guard's own position: the append runs only when the guard does, so a
/// guard that is itself inside another branch -- `if False:` around the pinned
/// membership guard, say -- states nothing and leaves the gap (#3506).
fn python_extension_statement_runs(
    call: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathValue>,
    directories: &[PathValue],
) -> bool {
    let Some(statement) = call.parent() else {
        return false;
    };
    if statement.kind() != "expression_statement" {
        return false;
    }
    let Some(container) = statement.parent() else {
        return false;
    };
    if container.kind() == "module" {
        return true;
    }
    // The call's statement is a guarded body only when its own block is that
    // `if`'s consequence: `else`, `elif`, loop, `try` and `with` bodies all
    // share the block shape, and none of them is this guard. A one-line
    // `if x: y()` puts the statement directly under the `if` instead.
    let guarded = if container.kind() == "block" {
        container.parent().filter(|parent| {
            parent.kind() == "if_statement"
                && parent.child_by_field_name("consequence") == Some(container)
        })
    } else if container.kind() == "if_statement"
        && container.child_by_field_name("consequence") == Some(statement)
    {
        Some(container)
    } else {
        None
    };
    let Some(guarded) = guarded else {
        return false;
    };
    // Execution certainty has to hold for the guard's ancestors too, and the
    // only enclosing scope this reader can vouch for is the marker's own body:
    // a guard under another branch, loop, `with` or `try` is no more proven
    // than the shape that holds it.
    if guarded.parent().map(|parent| parent.kind()) != Some("module") {
        return false;
    }
    let Some(condition) = guarded.child_by_field_name("condition") else {
        return false;
    };
    python_condition_justifies_path_extension(condition, source, bound, directories)
}

/// Whether a branch condition tests exactly the fact that makes the extension
/// necessary: the directory the branch appends is the one missing from
/// `__path__`, which is what the pinned shim's `if _impl not in __path__:`
/// states.
fn python_condition_justifies_path_extension(
    condition: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathValue>,
    directories: &[PathValue],
) -> bool {
    if condition.kind() != "comparison_operator" {
        return false;
    }
    let mut cursor = condition.walk();
    let operators = condition
        .children_by_field_name("operators", &mut cursor)
        .map(|operator| operator.kind())
        .collect::<Vec<_>>();
    if operators.as_slice() != ["not in"] {
        return false;
    }
    // The grammar gives a comparison no operand fields: its named children are
    // the operands in source order.
    let mut cursor = condition.walk();
    let operands: Vec<Node<'_>> = condition.named_children(&mut cursor).collect();
    let [left, right] = operands.as_slice() else {
        return false;
    };
    if !python_names_path(Some(*right), source) {
        return false;
    }
    python_path_expression_dir(*left, source, bound)
        .is_some_and(|directory| directories.contains(&directory))
}

/// Bind the names one `name = value` statement assigns -- and every name of a
/// chained `a = b = value` -- to the directory the value denotes. A value no
/// shape answers leaves the name unbound, so a later use of it contributes no
/// evidence either.
fn python_bind_assignment(
    assignment: Node<'_>,
    source: &str,
    bound: &mut HashMap<String, PathValue>,
) {
    let mut targets: Vec<Node<'_>> = Vec::new();
    let mut current = assignment;
    loop {
        let (Some(left), Some(right)) = (
            current.child_by_field_name("left"),
            current.child_by_field_name("right"),
        ) else {
            return;
        };
        targets.push(left);
        if right.kind() != "assignment" {
            let resolved = python_path_expression_dir(right, source, bound);
            for target in targets {
                if target.kind() != "identifier" {
                    continue;
                }
                let Ok(name) = target.utf8_text(source.as_bytes()) else {
                    continue;
                };
                match &resolved {
                    Some(directory) => {
                        bound.insert(name.to_owned(), directory.clone());
                    }
                    None => {
                        bound.remove(name);
                    }
                }
            }
            return;
        }
        current = right;
    }
}

/// The directories one `__path__.append(...)`, `__path__.insert(...)` or
/// `__path__.extend(...)` call adds.
///
/// The call has to be a method of the marker's own `__path__`, which is the
/// name the interpreter gives the search path it is building; a same-named
/// attribute of anything else is not that list.
fn python_path_appended_dirs_in_call(
    call: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathValue>,
) -> Vec<PathValue> {
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let Some(path) = python_static_attribute_path(function) else {
        return Vec::new();
    };
    let [object, method] = path.as_slice() else {
        return Vec::new();
    };
    if object.utf8_text(source.as_bytes()).ok() != Some("__path__") {
        return Vec::new();
    }
    let Ok(method) = method.utf8_text(source.as_bytes()) else {
        return Vec::new();
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    let arguments: Vec<Node<'_>> = arguments.named_children(&mut cursor).collect();
    let named: Vec<Node<'_>> = match method {
        "append" => arguments.first().copied().into_iter().collect(),
        "insert" => arguments.get(1).copied().into_iter().collect(),
        // `extend` adds the elements of its iterable. Only a list or tuple
        // literal states them; any other iterable, including a path string
        // (whose elements are its characters), adds entries this reader cannot
        // name, so none is recorded.
        "extend" => match arguments.first() {
            Some(literal) if matches!(literal.kind(), "list" | "tuple") => {
                let mut cursor = literal.walk();
                literal.named_children(&mut cursor).collect()
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    named
        .into_iter()
        .filter_map(|node| python_path_expression_dir(node, source, bound))
        .collect()
}

// Parents produced by dirname(anchor) are distinct from a literal ".." suffix:
// dirname(join(anchor, "..")) removes that suffix before any normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathValue {
    Anchored { parents: usize, suffix: PathBuf },
    Literal(PathBuf),
}
impl PathValue {
    fn dirname(self) -> Option<Self> {
        match self {
            Self::Anchored {
                mut parents,
                mut suffix,
            } => {
                if !suffix.pop() {
                    parents += 1;
                }
                Some(Self::Anchored { parents, suffix })
            }
            Self::Literal(path) => path
                .parent()
                .map(|parent| Self::Literal(parent.to_path_buf())),
        }
    }
    fn join(self, tail: Self) -> Self {
        match (self, tail) {
            // The symbolic anchor stands for an absolute package location.
            (_, anchored @ Self::Anchored { .. }) => anchored,
            (_, Self::Literal(path))
                if path.has_root()
                    || path
                        .components()
                        .any(|part| matches!(part, Component::Prefix(_))) =>
            {
                Self::Literal(path)
            }
            (
                Self::Anchored {
                    parents,
                    mut suffix,
                },
                Self::Literal(path),
            ) => {
                suffix.push(path);
                Self::Anchored { parents, suffix }
            }
            (Self::Literal(mut head), Self::Literal(tail)) => {
                head.push(tail);
                Self::Literal(head)
            }
        }
    }
    fn normalized(self) -> Self {
        let (anchored, mut parents, suffix) = match self {
            Self::Anchored { parents, suffix } => (true, parents, suffix),
            Self::Literal(path)
                if path.has_root()
                    || path
                        .components()
                        .any(|part| matches!(part, Component::Prefix(_))) =>
            {
                return Self::Literal(path.normalize());
            }
            Self::Literal(path) => (false, 0, path),
        };
        let mut normalized = PathBuf::new();
        for component in suffix.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() {
                        parents += 1;
                    }
                }
                Component::Normal(name) => normalized.push(name),
                Component::Prefix(_) | Component::RootDir => {
                    unreachable!("symbolic suffix is relative")
                }
            }
        }
        if anchored {
            Self::Anchored {
                parents,
                suffix: normalized,
            }
        } else {
            Self::Literal(Self::relative_path(parents, normalized))
        }
    }
    fn relative_path(parents: usize, suffix: PathBuf) -> PathBuf {
        let mut relative = PathBuf::new();
        for _ in 0..parents {
            relative.push("..");
        }
        relative.push(suffix);
        if relative.as_os_str().is_empty() {
            relative.push(".");
        }
        relative
    }
    fn relative_directory(self) -> Option<PathBuf> {
        match self.normalized() {
            Self::Anchored { parents, suffix } => Some(Self::relative_path(parents, suffix)),
            Self::Literal(_) => None,
        }
    }
}

/// Evaluate structured path expressions without recursive Rust calls. Only
/// anchored values can be made absolute without knowing the process CWD.
fn python_path_expression_dir(
    node: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathValue>,
) -> Option<PathValue> {
    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Dirname,
        Join,
        Normalize,
        Absolute,
    }
    #[derive(Debug)]
    enum Step<'tree> {
        Value(Node<'tree>),
        Apply(Operation, usize),
    }
    let mut pending = vec![Step::Value(node)];
    let mut values: Vec<PathValue> = Vec::new();
    while let Some(step) = pending.pop() {
        match step {
            Step::Value(node) => {
                if let Some(literal) = python_plain_string_literal(node, source) {
                    values.push(PathValue::Literal(PathBuf::from(literal)));
                    continue;
                }
                match node.kind() {
                    "identifier" => {
                        values.push(bound.get(node.utf8_text(source.as_bytes()).ok()?)?.clone())
                    }
                    "call" => {
                        let path =
                            python_static_attribute_path(node.child_by_field_name("function")?)?;
                        let names = path
                            .iter()
                            .map(|part| part.utf8_text(source.as_bytes()).ok())
                            .collect::<Option<Vec<_>>>()?;
                        let operation = match names.as_slice() {
                            ["os", "path", "dirname"] => Operation::Dirname,
                            ["os", "path", "join"] => Operation::Join,
                            ["os", "path", "normpath"] => Operation::Normalize,
                            ["os", "path", "abspath"] => Operation::Absolute,
                            _ => return None,
                        };
                        let arguments = node.child_by_field_name("arguments")?;
                        let mut cursor = arguments.walk();
                        let mut arguments =
                            arguments.named_children(&mut cursor).collect::<Vec<_>>();
                        if arguments.is_empty() {
                            return None;
                        }
                        if !matches!(operation, Operation::Join) {
                            arguments.truncate(1);
                        }
                        pending.push(Step::Apply(operation, arguments.len()));
                        pending.extend(arguments.into_iter().rev().map(Step::Value));
                    }
                    _ => return None,
                }
            }
            Step::Apply(operation, count) => {
                let arguments = values.split_off(
                    values
                        .len()
                        .checked_sub(count)
                        .expect("expression operands"),
                );
                let mut arguments = arguments.into_iter();
                let first = arguments.next().expect("path operation argument");
                values.push(match operation {
                    Operation::Dirname => first.dirname()?,
                    Operation::Join => arguments.fold(first, PathValue::join),
                    Operation::Normalize => first.normalized(),
                    Operation::Absolute => match first {
                        anchored @ PathValue::Anchored { .. } => anchored.normalized(),
                        PathValue::Literal(path) if path.is_absolute() => {
                            PathValue::Literal(path.normalize())
                        }
                        PathValue::Literal(_) => return None,
                    },
                });
            }
        }
    }
    assert_eq!(values.len(), 1, "one path expression result");
    values.pop()
}

#[cfg(test)]
mod tests {
    use super::appended_path_dirs;
    use brokk_bifrost_test_macros::hardwon;
    use std::path::PathBuf;

    fn dirs(source: &str) -> Vec<PathBuf> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error(), "{source}");
        appended_path_dirs(tree.root_node(), source)
    }

    #[test]
    #[hardwon(
        "#9077: package path extensions trusted conditional rebinding and ignored __path__ removals"
    )]
    fn unproven_bindings_do_not_establish_extensions() {
        let prefix = "import os\n_dir = os.path.dirname(__file__)\n";
        let cases = [
            "if False:\n    _dir = os.path.join(_dir, 'other')\n",
            "for _dir in []:\n    pass\n",
            "with open(__file__) as _dir:\n    pass\n",
            "(_dir := os.path.join(_dir, 'other'))\n",
            "_dir += 'other'\n",
            "def _dir():\n    pass\n",
            "class _dir:\n    pass\n",
        ];
        for case in cases {
            let source = format!("{prefix}{case}__path__.append(_dir)\n");
            assert!(dirs(&source).is_empty(), "{case}");
        }
    }

    #[test]
    #[hardwon(
        "#9077: package path extensions trusted conditional rebinding and ignored __path__ removals"
    )]
    fn path_removals_invalidate_prior_extensions() {
        let prefix = "import os\n_dir = os.path.join(os.path.dirname(__file__), 'impl')\n__path__.append(_dir)\n";
        for removal in [
            "__path__.clear()",
            "__path__.remove(_dir)",
            "__path__.pop()",
            "del __path__[0]",
            "__path__[0] = _dir",
            "__path__ += [_dir]",
        ] {
            assert!(
                dirs(&format!("{prefix}{removal}\n")).is_empty(),
                "{removal}"
            );
        }
        assert_eq!(
            dirs(&format!("__path__.clear()\n{prefix}")),
            vec![PathBuf::from("impl")]
        );
        assert_eq!(
            dirs(
                "import os\n_impl = os.path.join(os.path.dirname(__file__), 'impl')\nif _impl not in __path__:\n    __path__.append(_impl)\n"
            ),
            vec![PathBuf::from("impl")]
        );
    }

    #[test]
    #[hardwon(
        "#9077: an alias or callee of __path__ could remove a recorded package path extension"
    )]
    fn escaped_path_list_leaves_extensions_unproven() {
        let prefix = "import os\n_dir = os.path.join(os.path.dirname(__file__), 'impl')\n";
        for (before, after) in [
            ("paths = __path__\n", "paths.clear()\n"),
            ("", "paths = __path__\npaths.clear()\n"),
            ("", "forget(__path__)\n"),
            (
                "",
                "paths = extend_path(__path__, __name__)\npaths.clear()\n",
            ),
            ("__path__ = keep(__path__)\n", "saved.clear()\n"),
            (
                "import pkgutil\npkgutil.extend_path = keep\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
                "saved.clear()\n",
            ),
            (
                "import pkgutil\nmonkey(pkgutil)\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "import pkgutil\ndef patch():\n    pkgutil.extend_path = keep\npatch()\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "__import__ = fake\n__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "import pkgutil as p\np.extend_path = keep\n__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "__import__('pkgutil').extend_path = keep\n__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
                "saved.clear()\n",
            ),
            (
                "module = __import__('pkgutil')\n__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "def patch():\n    __import__('pkgutil').extend_path = keep\npatch()\nimport pkgutil\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
                "saved.clear()\n",
            ),
            (
                "def patch():\n    p.extend_path = keep\nimport pkgutil as p\npatch()\n__path__ = p.extend_path(__path__, __name__)\n",
                "saved.clear()\n",
            ),
            (
                "import pkgutil\npkgutil.extend_path = keep\nimport pkgutil\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "import pkgutil\npkgutil.extend_path = keep\nfrom pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "import pkgutil as p\nimport pkgutil as q\np.extend_path = keep\n__path__ = q.extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "import builtins\nbuiltins.__import__ = fake\n__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
                "",
            ),
            (
                "from pkgutil import extend_path\nextend_path = keep\n__path__ = extend_path(__path__, __name__)\n",
                "saved.clear()\n",
            ),
            (
                "try:\n    from pkgutil import extend_path\nexcept ImportError:\n    pass\n__path__ = extend_path(__path__, __name__)\n",
                "",
            ),
            ("", "clear = __path__.clear\nclear()\n"),
            ("def forget():\n    __path__.clear()\n", "forget()\n"),
            ("", "(lambda: __path__.clear())()\n"),
            ("", "a, __path__ = 1, []\n"),
        ] {
            let source = format!("{prefix}{before}__path__.append(_dir)\n{after}");
            assert!(dirs(&source).is_empty(), "{source}");
        }
        // `extend` records only the elements a list or tuple literal states; a
        // path string extends `__path__` with its characters.
        assert!(dirs(&format!("{prefix}__path__.extend(_dir)\n")).is_empty());
        for literal in ["[_dir]", "(_dir,)"] {
            let source = format!("{prefix}__path__.extend({literal})\n");
            assert_eq!(dirs(&source), vec![PathBuf::from("impl")], "{source}");
        }
        // pkgutil's extend_path returns a new list, so replacing `__path__` with
        // its result before the append keeps the extension.
        for replacement in [
            "from pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n",
            "from pkgutil import extend_path as grow\n__path__ = grow(__path__, __name__)\n",
            "import pkgutil\n__path__ = pkgutil.extend_path(__path__, __name__)\n",
            "__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n",
        ] {
            let source = format!("{prefix}{replacement}__path__.append(_dir)\n");
            assert_eq!(dirs(&source), vec![PathBuf::from("impl")], "{source}");
        }
        // Reads that cannot change the list keep the extension.
        for read in [
            "first = __path__[0]\n",
            "for entry in __path__:\n    pass\n",
            "present = _dir in __path__\n",
        ] {
            let source = format!("{prefix}__path__.append(_dir)\n{read}");
            assert_eq!(dirs(&source), vec![PathBuf::from("impl")], "{source}");
        }
    }
}
