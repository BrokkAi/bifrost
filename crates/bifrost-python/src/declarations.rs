use crate::bindings::python_direct_scope_bindings_bounded;
use crate::imports::python_import_infos_from_node;
use crate::syntax::{
    PythonOverloadDecoratorBindings, expression_name_node, python_plain_string_literal,
};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DispatchExtensibility, ParameterMetadata, SignatureMetadata,
    StructuredImportPathKind,
};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_normalization::NormalizePath;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser, Tree};

/// Intern one qualified-name segment in the process-global interner.
fn py_segment(text: &str, kind: SegmentKind) -> SegmentId {
    segment_interner().intern(text, kind)
}

/// Build the structured module-path prefix for a Python declaration.
///
/// Ordinary modules render as a dotted path such as `mypkg.subpkg.mymodule`,
/// with each original path component represented by one
/// [`SegmentKind::Package`] segment. Hidden directories such as `.agent` and
/// `.github` are also legal components in the analyzer's path-derived Python
/// convention, but their leading dot is ambiguous after a rendered name has
/// been joined.
///
/// Build the structured name from the file path's original components so
/// hidden-directory segments stay intact in cold extraction, synthesized module
/// units, and persisted reconstruction.
pub fn python_module_fq(file: &ProjectFile) -> FqName {
    python_module_fq_from_components(&python_module_components(file))
}

fn python_module_fq_from_components(components: &[String]) -> FqName {
    let mut fq = FqName::new();
    for component in components {
        fq.push(py_segment(component, SegmentKind::Package));
    }
    fq
}

fn python_module_components(file: &ProjectFile) -> Vec<String> {
    let mut components = python_package_components_for_file(file);
    let module_name = file
        .rel_path()
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if module_name != "__init__" || components.is_empty() {
        components.push(module_name.to_string());
    }
    components
}

fn python_package_components_for_file(file: &ProjectFile) -> Vec<String> {
    let Some(parent_rel) = file.rel_path().parent() else {
        return Vec::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return Vec::new();
    }

    if let Some(import_root_rel) = python_configured_import_root(file, parent_rel)
        && let Ok(relative_package) = parent_rel.strip_prefix(import_root_rel)
    {
        return path_components(relative_package);
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    let relative_package = match effective_package_root_rel {
        Some(package_root_rel) => package_root_rel
            .parent()
            .and_then(|import_root_rel| parent_rel.strip_prefix(import_root_rel).ok())
            .unwrap_or(parent_rel),
        None => parent_rel,
    };
    path_components(relative_package)
}

/// Find the nearest setuptools import root that contains this source file.
///
/// `pyproject.toml` roots take precedence over legacy `setup.py` evidence at
/// each ancestor. An unrelated or malformed packaging file does not change the
/// existing `__init__.py` package-root convention.
fn python_configured_import_root(file: &ProjectFile, parent_rel: &Path) -> Option<PathBuf> {
    let mut manifest_dir_rel = Some(parent_rel);
    while let Some(directory) = manifest_dir_rel {
        let manifest_dir = file.root().join(directory);
        let mut roots = setuptools_where_entries(&manifest_dir.join("pyproject.toml"))
            .iter()
            .map(|entry| manifest_dir.join(entry).normalize())
            .filter_map(|root| root.strip_prefix(file.root()).ok().map(Path::to_path_buf))
            .filter(|root| parent_rel.starts_with(root))
            .collect::<Vec<_>>();
        roots.sort_by_key(|root| root.components().count());
        if let Some(root) = roots.pop() {
            return Some(root);
        }
        if let Some(package_dir) = setuptools_setup_py_import_root(&manifest_dir.join("setup.py")) {
            let root = manifest_dir.join(package_dir).normalize();
            if let Ok(root) = root.strip_prefix(file.root())
                && parent_rel.starts_with(root)
            {
                return Some(root.to_path_buf());
            }
        }
        manifest_dir_rel = directory.parent();
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// One manifest's memoized `tool.setuptools.packages.find.where` entries.
///
/// The stamp is what the memo is validated against, so a manifest edited in a
/// long-running server is re-read instead of being answered from a stale parse.
struct ManifestWhereEntries {
    stamp: FileStamp,
    entries: Vec<String>,
}

/// Read the setuptools package-discovery roots declared by one `pyproject.toml`.
///
/// Module identity is resolved once per declaration, not once per file, so this
/// sits on a hot path: a full read plus TOML parse per call made every Python
/// identity question proportional to the size of the nearest manifest. The
/// parse is therefore memoized per manifest and revalidated with one `stat`,
/// which keeps an edited manifest honored while the steady-state cost is a
/// metadata probe. An absent, unreadable, malformed, or non-setuptools manifest
/// declares no roots and leaves the `__init__.py` package-root convention in
/// charge.
fn setuptools_where_entries(manifest: &Path) -> Vec<String> {
    static MEMO: std::sync::OnceLock<
        std::sync::RwLock<std::collections::HashMap<PathBuf, ManifestWhereEntries>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(Default::default);

    let Some(stamp) = file_stamp(manifest) else {
        return Vec::new();
    };
    if let Some(cached) = memo.read().expect("manifest memo").get(manifest)
        && cached.stamp == stamp
    {
        return cached.entries.clone();
    }

    let entries = parse_setuptools_where_entries(manifest);
    memo.write().expect("manifest memo").insert(
        manifest.to_path_buf(),
        ManifestWhereEntries {
            stamp,
            entries: entries.clone(),
        },
    );
    entries
}

/// A memoized static package root recovered from one legacy `setup.py`.
/// `Some(PathBuf::new())` represents the setup script's directory, which is
/// setuptools' default when no `package_dir` is supplied.
struct SetupPyImportRoot {
    stamp: FileStamp,
    package_dir: Option<PathBuf>,
}

/// Read a legacy setuptools import root without executing `setup.py`.
///
/// This is intentionally narrower than Python's runtime packaging semantics:
/// a direct top-level call to an imported setuptools or distutils.core
/// `setup` binding must provide a `packages` argument. A literal `package_dir`
/// establishes the root regardless of the package expression; without one,
/// the package expression must be either a nonempty literal collection or a
/// supported setuptools discovery call. Unsupported argument shapes or a
/// shadowed import leave the source path-derived.
fn setuptools_setup_py_import_root(setup_py: &Path) -> Option<PathBuf> {
    static MEMO: std::sync::OnceLock<
        std::sync::RwLock<std::collections::HashMap<PathBuf, SetupPyImportRoot>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(Default::default);

    let stamp = file_stamp(setup_py)?;
    if let Some(cached) = memo.read().expect("setup.py memo").get(setup_py)
        && cached.stamp == stamp
    {
        return cached.package_dir.clone();
    }

    let package_dir = parse_setuptools_setup_py_import_root(setup_py);
    memo.write().expect("setup.py memo").insert(
        setup_py.to_path_buf(),
        SetupPyImportRoot {
            stamp,
            package_dir: package_dir.clone(),
        },
    );
    package_dir
}

fn parse_setuptools_setup_py_import_root(setup_py: &Path) -> Option<PathBuf> {
    let source = std::fs::read_to_string(setup_py).ok()?;
    let tree = parse_python_tree(&source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut import_root = None;
    for (call, setup_bindings) in setup_py_setup_calls(&source, root) {
        let candidate = setup_py_import_root_from_call(call, &source, &setup_bindings)?;
        if import_root
            .replace(candidate.clone())
            .is_some_and(|root| root != candidate)
        {
            return None;
        }
    }
    import_root
}

/// Read the `python_requires` specifier a legacy `setup.py` declares.
///
/// This is setuptools' spelling of `pyproject.toml`'s `requires-python`, and it
/// is what selects the standard-library semantic pack for a project that has no
/// PEP 621 manifest. The script is read, never executed: only a literal string
/// passed to a top-level call to an imported `setup` binding counts, and two
/// calls that disagree declare nothing.
pub fn setuptools_setup_py_python_requires(setup_py: &Path) -> Option<String> {
    let source = std::fs::read_to_string(setup_py).ok()?;
    let tree = parse_python_tree(&source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut requirement: Option<String> = None;
    for (call, _) in setup_py_setup_calls(&source, root) {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        if arguments.kind() != "argument_list" {
            continue;
        }
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            if argument.kind() != "keyword_argument" {
                continue;
            }
            let Some(name) = argument.child_by_field_name("name") else {
                continue;
            };
            if py_node_text(name, &source).trim() != "python_requires" {
                continue;
            }
            let value = argument.child_by_field_name("value")?;
            let declared = python_plain_string_literal(value, &source)?.to_owned();
            if requirement
                .replace(declared.clone())
                .is_some_and(|previous| previous != declared)
            {
                return None;
            }
        }
    }
    requirement
}

/// Every top-level call to an imported setuptools `setup` binding, paired with
/// the import bindings that were live where the call appears.
///
/// The walk tracks bindings across the module's top-level statements, so a name
/// a later statement rebinds stops being read as setuptools' `setup`. It does
/// not enter function, class, or lambda bodies: a call there is conditional on
/// something this reader does not evaluate.
fn setup_py_setup_calls<'tree>(
    source: &str,
    root: Node<'tree>,
) -> Vec<(Node<'tree>, HashMap<Vec<String>, String>)> {
    let mut setup_bindings: HashMap<Vec<String>, String> = HashMap::default();
    let mut calls = Vec::new();
    let mut cursor = root.walk();

    for statement in root.named_children(&mut cursor) {
        if matches!(
            statement.kind(),
            "import_statement" | "import_from_statement"
        ) {
            for binding in setup_py_bound_names(statement, source) {
                setup_bindings.retain(|path, _| path.first() != Some(&binding));
            }
            for import in python_import_infos_from_node(statement, source) {
                if import.is_wildcard {
                    setup_bindings.clear();
                    continue;
                }
                let Some(path) = import.path else { continue };
                let segments = path.segments.iter().map(String::as_str).collect::<Vec<_>>();
                match path.kind {
                    Some(StructuredImportPathKind::ImportFrom) => {
                        let function_name = match segments.as_slice() {
                            ["setuptools", "setup"] | ["distutils", "core", "setup"] => "setup",
                            ["setuptools", "find_packages"] => "find_packages",
                            ["setuptools", "find_namespace_packages"] => "find_namespace_packages",
                            _ => continue,
                        };
                        setup_bindings.insert(
                            vec![import.identifier.expect("imported function binds a name")],
                            function_name.to_string(),
                        );
                    }
                    Some(StructuredImportPathKind::Namespace) => {
                        let function_names = match segments.as_slice() {
                            ["setuptools"] => {
                                ["setup", "find_packages", "find_namespace_packages"].as_slice()
                            }
                            ["distutils", "core"] => ["setup"].as_slice(),
                            _ => continue,
                        };
                        let binding_prefix = import
                            .alias
                            .map(|alias| vec![alias])
                            .unwrap_or_else(|| path.segments.clone());
                        for function_name in function_names {
                            let mut callable = binding_prefix.clone();
                            callable.push((*function_name).to_string());
                            setup_bindings.insert(callable, (*function_name).to_string());
                        }
                    }
                    _ => continue,
                }
            }
            continue;
        }

        if statement.kind() == "expression_statement"
            && statement.named_child_count() == 1
            && let Some(call) = statement.named_child(0)
            && call.kind() == "call"
            && setup_py_call_imported_function(call, source, &setup_bindings)
                .is_some_and(|function| function == "setup")
        {
            calls.push((call, setup_bindings.clone()));
        }

        for binding in setup_py_bound_names(statement, source) {
            setup_bindings.retain(|path, _| path.first() != Some(&binding));
        }
    }
    calls
}

/// Return names that a top-level statement binds in the module scope.
///
/// The walk is iterative and does not enter function, class, or lambda bodies.
/// Bindings in control-flow statements still invalidate an imported setup name:
/// their execution is conditional, so retaining the import would overclaim its
/// identity at a later top-level call.
fn setup_py_bound_names(statement: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut pending = vec![statement];
    while let Some(node) = pending.pop() {
        for binding in python_direct_scope_bindings_bounded(node, source, || true)
            .expect("unbounded setup.py binding walk")
        {
            let name = py_node_text(binding.declaration, source).trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        pending.extend(
            node.named_children(&mut cursor)
                .filter(|child| Some(child.id()) != excluded_body),
        );
    }
    names
}

fn setup_py_call_imported_function<'a>(
    call: Node<'_>,
    source: &str,
    setup_bindings: &'a HashMap<Vec<String>, String>,
) -> Option<&'a str> {
    let mut function = call.child_by_field_name("function")?;
    let mut path = Vec::new();
    while function.kind() == "attribute" {
        let attribute = function.child_by_field_name("attribute")?;
        path.push(py_node_text(attribute, source).to_string());
        let object = function.child_by_field_name("object")?;
        function = object;
    }
    if function.kind() != "identifier" {
        return None;
    }
    path.push(py_node_text(function, source).to_string());
    path.reverse();
    setup_bindings.get(&path).map(String::as_str)
}

fn setup_py_import_root_from_call(
    call: Node<'_>,
    source: &str,
    setup_bindings: &HashMap<Vec<String>, String>,
) -> Option<PathBuf> {
    let arguments = call.child_by_field_name("arguments")?;
    if arguments.kind() != "argument_list" {
        return None;
    }

    let mut packages = None;
    let mut package_dir = None;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if argument.kind() == "comment" {
            continue;
        }
        // Positional dictionaries and expansions can supply packaging options.
        if argument.kind() != "keyword_argument" {
            return None;
        }
        let name = argument.child_by_field_name("name")?;
        let value = argument.child_by_field_name("value")?;
        match py_node_text(name, source).trim() {
            "packages" if packages.is_none() => packages = Some(value),
            "packages" => return None,
            "package_dir" if package_dir.is_none() => package_dir = Some(value),
            "package_dir" => return None,
            _ => {}
        }
    }

    let packages = packages?;
    if let Some(package_dir) = package_dir {
        return setup_py_static_package_dir(package_dir, source);
    }
    if setup_py_nonempty_literal_packages(packages, source) {
        return Some(PathBuf::new());
    }
    setup_py_discovery_root_from_call(packages, source, setup_bindings)
}

fn setup_py_discovery_root_from_call(
    call: Node<'_>,
    source: &str,
    setup_bindings: &HashMap<Vec<String>, String>,
) -> Option<PathBuf> {
    let function = setup_py_call_imported_function(call, source, setup_bindings)?;
    if !matches!(function, "find_packages" | "find_namespace_packages") {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    if arguments.kind() != "argument_list" {
        return None;
    }

    let mut where_value = None;
    let mut seen_exclude = false;
    let mut seen_include = false;
    let mut positional_index = 0;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if argument.kind() == "comment" {
            continue;
        }
        if matches!(argument.kind(), "list_splat" | "dictionary_splat") {
            return None;
        }
        if argument.kind() == "keyword_argument" {
            let name = py_node_text(argument.child_by_field_name("name")?, source).trim();
            let value = argument.child_by_field_name("value")?;
            match name {
                "where" if where_value.is_none() => where_value = Some(value),
                "where" => return None,
                "exclude" if !seen_exclude => seen_exclude = true,
                "exclude" => return None,
                "include" if !seen_include => seen_include = true,
                "include" => return None,
                _ => return None,
            }
            continue;
        }

        let slot = positional_index;
        positional_index += 1;
        match slot {
            0 if where_value.is_none() => where_value = Some(argument),
            0 => return None,
            1 if !seen_exclude => seen_exclude = true,
            1 => return None,
            2 if !seen_include => seen_include = true,
            2 => return None,
            _ => return None,
        }
    }

    where_value
        .map(|value| python_plain_string_literal(value, source))
        .unwrap_or(Some(""))
        .map(PathBuf::from)
}

fn setup_py_nonempty_literal_packages(value: Node<'_>, source: &str) -> bool {
    let value = setup_py_unwrap_parenthesized(value);
    if !matches!(value.kind(), "list" | "set" | "tuple") {
        return false;
    }
    let mut cursor = value.walk();
    let mut nonempty = false;
    for element in value.named_children(&mut cursor) {
        if element.kind() == "comment" {
            continue;
        }
        let Some(package) = python_plain_string_literal(element, source) else {
            return false;
        };
        if package.is_empty() {
            return false;
        }
        nonempty = true;
    }
    nonempty
}

fn setup_py_static_package_dir(value: Node<'_>, source: &str) -> Option<PathBuf> {
    let value = setup_py_unwrap_parenthesized(value);
    if value.kind() != "dictionary" {
        return None;
    }
    let mut cursor = value.walk();
    let mut pairs = value
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment");
    let Some(pair) = pairs.next() else {
        return Some(PathBuf::new());
    };
    if pairs.next().is_some() || pair.kind() != "pair" {
        return None;
    }
    let key = python_plain_string_literal(pair.child_by_field_name("key")?, source)?;
    if !key.is_empty() {
        return None;
    }
    let root = python_plain_string_literal(pair.child_by_field_name("value")?, source)?;
    let root = PathBuf::from(root);
    (!root.is_absolute()).then_some(root)
}

fn setup_py_unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        node = node.named_child(0).expect("parenthesized expression child");
    }
    node
}

fn parse_setuptools_where_entries(manifest: &Path) -> Vec<String> {
    let Ok(source) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let Ok(document) = source.parse::<toml::Value>() else {
        return Vec::new();
    };
    document
        .get("tool")
        .and_then(|tool| tool.get("setuptools"))
        .and_then(|setuptools| setuptools.get("packages"))
        .and_then(|packages| packages.get("find"))
        .and_then(|find| find.get("where"))
        .and_then(toml::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .filter(|component| !component.is_empty())
        .collect()
}

pub fn python_is_decorated_function_boundary(node: Node<'_>) -> bool {
    if node.kind() != "decorated_definition" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "function_definition")
}

#[derive(Clone)]
pub struct Scope {
    kind: ScopeKind,
    path: String,
    /// The structured qualified name matching `path` (M1 dual representation;
    /// see `.agents/plans/fqname-interned-segments.md`). Tracked independent of
    /// whether this scope level was actually `capture`d as a `CodeUnit`, so a
    /// nested class/function that IS captured can always extend an ancestor's
    /// `fq` even when an intermediate scope level (e.g. a non-captured nested
    /// function) has no `code_unit` of its own to read `.fq()` from.
    fq: FqName,
    code_unit: Option<CodeUnit>,
    method_receiver: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Class,
    Function,
}

pub struct PythonVisitor<'a> {
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub package_name: &'a str,
    module_fq: &'a FqName,
    pub parsed: &'a mut ParsedFile,
    pub module: Option<CodeUnit>,
    pub overload_decorators: &'a PythonOverloadDecoratorBindings,
}

struct PythonContainer<'tree> {
    node: Node<'tree>,
    scope: Vec<Scope>,
    module_control_depth: usize,
}

enum PythonWork<'tree> {
    Container(PythonContainer<'tree>),
    Statement {
        node: Node<'tree>,
        scope: Vec<Scope>,
        module_control_depth: usize,
    },
}

impl<'a> PythonVisitor<'a> {
    pub fn visit_container(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let mut stack = vec![PythonWork::Container(PythonContainer {
            node,
            scope: scope.to_vec(),
            module_control_depth,
        })];
        while let Some(work) = stack.pop() {
            match work {
                PythonWork::Container(container) => {
                    let mut cursor = container.node.walk();
                    let children = container
                        .node
                        .named_children(&mut cursor)
                        .collect::<Vec<_>>();
                    for child in children.into_iter().rev() {
                        stack.push(PythonWork::Statement {
                            node: child,
                            scope: container.scope.clone(),
                            module_control_depth: container.module_control_depth,
                        });
                    }
                }
                PythonWork::Statement {
                    node,
                    scope,
                    module_control_depth,
                } => self.visit_statement(node, &scope, module_control_depth, &mut stack),
            }
        }
    }

    fn visit_statement<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        match node.kind() {
            "decorated_definition" => {
                if let Some(definition) = node.child_by_field_name("definition") {
                    self.visit_definition(
                        definition,
                        Some(node),
                        scope,
                        module_control_depth,
                        stack,
                    );
                }
            }
            "class_definition" | "function_definition" => {
                self.visit_definition(node, None, scope, module_control_depth, stack)
            }
            "expression_statement" => {
                self.visit_expression_statement(node, scope, module_control_depth)
            }
            "import_statement" | "import_from_statement" => self.visit_import_statement(node),
            "if_statement" | "try_statement" | "with_statement" | "for_statement"
            | "while_statement" => {
                let next_depth = if scope.is_empty() {
                    module_control_depth + 1
                } else {
                    module_control_depth
                };
                stack.push(PythonWork::Container(PythonContainer {
                    node,
                    scope: scope.to_vec(),
                    module_control_depth: next_depth,
                }));
            }
            "elif_clause" | "else_clause" | "except_clause" | "finally_clause" => {
                stack.push(PythonWork::Container(PythonContainer {
                    node,
                    scope: scope.to_vec(),
                    module_control_depth,
                }));
            }
            "block" | "module" => stack.push(PythonWork::Container(PythonContainer {
                node,
                scope: scope.to_vec(),
                module_control_depth,
            })),
            _ => {}
        }
    }

    fn visit_definition<'tree>(
        &mut self,
        definition: Node<'tree>,
        wrapper: Option<Node<'tree>>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        match definition.kind() {
            "class_definition" => self.visit_class_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
                stack,
            ),
            "function_definition" => self.visit_function_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
                stack,
            ),
            _ => {}
        }
    }

    fn visit_class_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !scope.is_empty() || module_control_depth <= 1;

        let short_name = scope
            .last()
            .map(|parent| format!("{}${name}", parent.path))
            .unwrap_or_else(|| name.to_string());
        // A nested class (any parent scope, Class or Function) is always joined
        // with a literal `$` in the legacy convention above, which is exactly
        // what `SegmentKind::Nested` renders regardless of the preceding
        // segment's kind; a top-level class has no parent and is a plain `Type`
        // hanging off the module-path `Package` chain.
        let fq = match scope.last() {
            Some(parent) => parent
                .fq
                .clone()
                .with_pushed(py_segment(name, SegmentKind::Nested)),
            None => self
                .module_fq
                .clone()
                .with_pushed(py_segment(name, SegmentKind::Type)),
        };
        let code_unit = CodeUnit::new_fq(
            self.file.clone(),
            CodeUnitType::Class,
            self.package_name.to_string(),
            short_name.clone(),
            fq.clone(),
        );
        if capture {
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            self.parsed.add_signature(
                code_unit.clone(),
                python_class_signature(range_node, self.source),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            self.parsed.set_raw_supertypes(
                code_unit.clone(),
                extract_python_supertypes(node, self.source),
            );
        }

        let mut next_scope = scope.to_vec();
        if capture {
            next_scope.push(Scope {
                kind: ScopeKind::Class,
                path: short_name,
                fq,
                code_unit: Some(code_unit),
                method_receiver: None,
            });
        }
        if let Some(body) = node.child_by_field_name("body") {
            stack.push(PythonWork::Container(PythonContainer {
                node: body,
                scope: next_scope,
                module_control_depth,
            }));
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        stack: &mut Vec<PythonWork<'tree>>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let capture = !python_is_property_mutator(range_node, self.source)
            && ((scope.is_empty() && module_control_depth <= 1)
                || scope
                    .last()
                    .is_some_and(|parent| parent.kind == ScopeKind::Class));
        let short_name = if let Some(parent) = scope.last() {
            match parent.kind {
                ScopeKind::Class => format!("{}.{}", parent.path, name),
                ScopeKind::Function => format!("{}${name}", parent.path),
            }
        } else {
            name.to_string()
        };
        // Mirrors `short_name` above segment-for-segment: a method owned
        // directly by a class joins with `.` (`Member`), while a function
        // nested under another function is a local/closure and joins with the
        // literal `$` that `SegmentKind::Nested` renders.
        let fq = if let Some(parent) = scope.last() {
            match parent.kind {
                ScopeKind::Class => parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(name, SegmentKind::Member)),
                ScopeKind::Function => parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(name, SegmentKind::Nested)),
            }
        } else {
            self.module_fq
                .clone()
                .with_pushed(py_segment(name, SegmentKind::Member))
        };

        if capture {
            let code_unit_type = if python_function_has_decorator(node, self.source, "property") {
                CodeUnitType::Field
            } else {
                CodeUnitType::Function
            };
            let signature = node
                .child_by_field_name("parameters")
                .map(|parameters| py_node_text(parameters, self.source).trim().to_string());
            let code_unit = CodeUnit::with_signature_and_fq(
                self.file.clone(),
                code_unit_type,
                self.package_name.to_string(),
                short_name.clone(),
                signature,
                false,
                fq.clone(),
            );
            self.parsed
                .replace_code_unit(code_unit.clone(), range_node, self.source, None, None);
            let signature = python_function_signature(range_node, self.source);
            self.parsed.add_signature_with_metadata(
                code_unit.clone(),
                python_signature_metadata(signature, node, self.source).with_declaration_only(
                    self.overload_decorators
                        .decorates_as_overload(node, self.source),
                ),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit.clone());
            }
            let scope_code_unit = Some(code_unit);
            let mut next_scope = scope.to_vec();
            next_scope.push(Scope {
                kind: ScopeKind::Function,
                path: short_name,
                fq,
                code_unit: scope_code_unit,
                method_receiver: scope
                    .last()
                    .is_some_and(|parent| parent.kind == ScopeKind::Class)
                    .then(|| python_instance_method_receiver_name(node, self.source))
                    .flatten(),
            });
            if let Some(body) = node.child_by_field_name("body") {
                stack.push(PythonWork::Container(PythonContainer {
                    node: body,
                    scope: next_scope,
                    module_control_depth,
                }));
            }
            return;
        }

        let mut next_scope = scope.to_vec();
        next_scope.push(Scope {
            kind: ScopeKind::Function,
            path: short_name,
            fq,
            code_unit: None,
            method_receiver: None,
        });
        if let Some(body) = node.child_by_field_name("body") {
            stack.push(PythonWork::Container(PythonContainer {
                node: body,
                scope: next_scope,
                module_control_depth,
            }));
        }
    }

    fn visit_expression_statement(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let Some(assignment) = node.named_child(0) else {
            return;
        };
        if assignment.kind() != "assignment" {
            return;
        }
        let targets = python_chained_assignment_targets(assignment);
        if targets.is_empty() {
            return;
        }
        for left in &targets {
            self.visit_instance_attribute_assignment(*left, scope);
        }
        let names = targets
            .iter()
            .flat_map(|left| collect_assigned_names(*left, self.source))
            .collect::<Vec<_>>();
        for name in names {
            let (short_name, fq) = if let Some(parent) = scope.last() {
                if parent.kind != ScopeKind::Class {
                    continue;
                }
                (
                    format!("{}.{}", parent.path, name),
                    parent
                        .fq
                        .clone()
                        .with_pushed(py_segment(&name, SegmentKind::Member)),
                )
            } else if module_control_depth <= 1 {
                (
                    name.clone(),
                    self.module_fq
                        .clone()
                        .with_pushed(py_segment(&name, SegmentKind::Member)),
                )
            } else {
                continue;
            };
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                short_name,
                fq,
            );
            if scope
                .last()
                .is_some_and(|parent| parent.kind == ScopeKind::Class)
            {
                // Reassigning a class attribute does not mint a new logical
                // member. Preserve every physical binding range so class-body
                // references between assignments can select the active one.
                self.parsed
                    .add_code_unit(code_unit.clone(), node, self.source, None, None);
            } else {
                self.parsed
                    .replace_code_unit(code_unit.clone(), node, self.source, None, None);
            }
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(node, self.source).trim().to_string(),
            );
            if let Some(module) = &self.module
                && scope.is_empty()
            {
                self.parsed.add_child(module.clone(), code_unit.clone());
            }
            if let Some(parent) = scope.last()
                && parent.kind == ScopeKind::Class
                && let Some(parent_cu) = &parent.code_unit
            {
                self.parsed.add_child(parent_cu.clone(), code_unit);
            }
        }
    }

    fn visit_instance_attribute_assignment(&mut self, left: Node<'_>, scope: &[Scope]) {
        let Some(function) = scope
            .last()
            .filter(|scope| scope.kind == ScopeKind::Function)
        else {
            return;
        };
        let Some(receiver) = function.method_receiver.as_deref() else {
            return;
        };
        let Some(parent) = scope
            .get(scope.len().saturating_sub(2))
            .filter(|scope| scope.kind == ScopeKind::Class)
        else {
            return;
        };
        let Some(parent_cu) = parent.code_unit.clone() else {
            return;
        };
        for (name, node) in collect_self_assigned_attributes(left, self.source, receiver) {
            let code_unit = CodeUnit::new_fq(
                self.file.clone(),
                CodeUnitType::Field,
                self.package_name.to_string(),
                format!("{}.{}", parent.path, name),
                parent
                    .fq
                    .clone()
                    .with_pushed(py_segment(&name, SegmentKind::Member)),
            );
            if !self.parsed.contains_declaration(&code_unit) {
                self.parsed.replace_code_unit(
                    code_unit.clone(),
                    node,
                    self.source,
                    Some(parent_cu.clone()),
                    Some(parent_cu.clone()),
                );
            }
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(left, self.source).trim().to_string(),
            );
        }
    }

    fn visit_import_statement(&mut self, node: Node<'_>) {
        for info in python_import_infos_from_node(node, self.source) {
            self.parsed.imports.push(info);
        }
    }
}

/// Build the [`ParsedFile`] for one Python source file: module unit, type
/// identifiers, and the declaration walk. `analyzer/python/adapter.rs`'s
/// `LanguageAdapter::parse_file` is the only caller.
pub fn parse_python_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let module_components = python_module_components(file);
    let module_name = module_components.join(".");
    let module_fq = python_module_fq_from_components(&module_components);
    let mut parsed = ParsedFile::new(module_name.clone());
    let root = tree.root_node();

    collect_python_identifiers(root, source, &mut parsed.type_identifiers);

    let module_code_unit = module_code_unit_from_fq(file, &module_components, module_fq.clone());
    if let Some(module) = module_code_unit.clone() {
        parsed.add_code_unit(module, root, source, None, None);
    }

    let overload_decorators = PythonOverloadDecoratorBindings::collect(root, source);
    let mut visitor = PythonVisitor {
        file,
        source,
        package_name: &module_name,
        module_fq: &module_fq,
        parsed: &mut parsed,
        module: module_code_unit,
        overload_decorators: &overload_decorators,
    };
    visitor.visit_container(root, &[], 0);

    parsed
}

pub fn py_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

pub fn python_module_name(file: &ProjectFile) -> String {
    python_module_components(file).join(".")
}

pub fn module_code_unit(file: &ProjectFile, module_fq: &str) -> Option<CodeUnit> {
    if module_fq.is_empty() {
        return None;
    }
    let components = python_module_components(file);
    debug_assert_eq!(
        module_fq,
        components.join("."),
        "module_code_unit must be built from the file's path-derived Python module name"
    );
    let structured_fq = python_module_fq_from_components(&components);
    module_code_unit_from_fq(file, &components, structured_fq)
}

fn module_code_unit_from_fq(
    file: &ProjectFile,
    components: &[String],
    structured_fq: FqName,
) -> Option<CodeUnit> {
    let (short_name, package_components) = components.split_last()?;
    let package_name = package_components.join(".");
    Some(CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Module,
        package_name,
        short_name.clone(),
        structured_fq,
    ))
}

fn python_class_signature(node: Node<'_>, source: &str) -> String {
    python_header_with_decorators(node, source)
}

fn python_function_signature(node: Node<'_>, source: &str) -> String {
    let header = python_header_with_decorators(node, source);
    if let Some((head, tail)) = header.rsplit_once('\n') {
        format!("{head}\n{tail} ...")
    } else {
        format!("{header} ...")
    }
}

fn python_signature_metadata(signature: String, node: Node<'_>, source: &str) -> SignatureMetadata {
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_dispatch_extensibility(DispatchExtensibility::Open);
    };
    let parameter_text = py_node_text(parameters_node, source).trim();
    let Some(parameters_start) = signature.find(parameter_text) else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_dispatch_extensibility(DispatchExtensibility::Open);
    };
    let parameters_end = parameters_start + parameter_text.len();
    let mut search_start = parameters_start;
    let parameters = python_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = py_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
        .with_dispatch_extensibility(DispatchExtensibility::Open)
}

fn python_parameter_label_nodes(parameters_node: Node<'_>) -> Vec<Node<'_>> {
    let mut labels = Vec::new();
    let mut cursor = parameters_node.walk();
    for child in parameters_node.named_children(&mut cursor) {
        if let Some(label_node) = python_parameter_label_node(child) {
            labels.push(label_node);
        }
    }
    labels
}

/// The identifier node that names one parameter's binding.
///
/// The grammar gives `default_parameter` and `typed_default_parameter` a
/// `name` field but gives `typed_parameter` and the two splat patterns none,
/// so a caller that reads only the field loses the binding name of every
/// annotated parameter. Every Python surface that names parameters reads them
/// through this function.
/// Which splat a Python formal parameter spells, looking through the
/// annotation wrapper.
///
/// `*args` is a `list_splat_pattern` and `**kwargs` a
/// `dictionary_splat_pattern`, but the grammar spells `*args: str` as a
/// `typed_parameter` that holds one, so a test on the parameter's own node kind
/// misses every annotated variadic. A parameter that misses it binds like an
/// ordinary formal: one positional actual each, and the rest spill onto the
/// formals that follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonParameterSplat {
    /// `*args`: collects every remaining positional actual.
    Positional,
    /// `**kwargs`: collects every remaining keyword actual.
    Keyword,
}

pub fn python_parameter_splat(parameter: Node<'_>) -> Option<PythonParameterSplat> {
    let splat = match parameter.kind() {
        kind @ ("list_splat_pattern" | "dictionary_splat_pattern") => kind,
        _ => {
            let mut cursor = parameter.walk();
            parameter
                .named_children(&mut cursor)
                .map(|child| child.kind())
                .find(|kind| matches!(*kind, "list_splat_pattern" | "dictionary_splat_pattern"))?
        }
    };
    match splat {
        "list_splat_pattern" => Some(PythonParameterSplat::Positional),
        "dictionary_splat_pattern" => Some(PythonParameterSplat::Keyword),
        _ => unreachable!("the splat kind was matched above"),
    }
}

pub fn python_parameter_label_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "typed_parameter"
        | "typed_default_parameter"
        | "default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "keyword_separator" => node.child_by_field_name("name").or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(python_parameter_label_node)
        }),
        _ => None,
    }
}

fn python_is_property_mutator(node: Node<'_>, source: &str) -> bool {
    python_header_with_decorators(node, source)
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('@'))
        .any(|decorator| decorator.ends_with(".setter") || decorator.ends_with(".deleter"))
}

pub fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = compute_line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            comment_start = line_start;
            continue;
        }

        break;
    }

    comment_start
}

fn python_header_with_decorators(node: Node<'_>, source: &str) -> String {
    let raw = py_node_text(node, source);
    let lines: Vec<_> = raw
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    let mut relevant = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('@')
            || trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("class ")
        {
            relevant.push(trimmed.to_string());
            if trimmed.starts_with("def ")
                || trimmed.starts_with("async def ")
                || trimmed.starts_with("class ")
            {
                break;
            }
        }
    }
    relevant.join("\n")
}

/// Every positional base of a class, as the spelling the hierarchy resolver
/// should look up.
///
/// A base this function omits is indistinguishable from a class that has no
/// such base, so member lookup would treat an incompletely modeled hierarchy
/// as a complete one and prove a member absent that the base declares. Every
/// positional base therefore contributes a spelling:
///
/// * A dotted name is its own spelling.
/// * A subscripted base (`Base[T]`, `MutableMapping[str, Any]`) contributes
///   its generic origin, which is the class the runtime actually inherits.
/// * Any other positional base -- a call such as `namedtuple(...)`, an
///   unpacked base list, a conditional expression -- contributes its source
///   spelling. Resolution fails on it, and the caller reports an unresolved
///   base instead of a complete member list.
///
/// A keyword argument (`metaclass=`, and the arbitrary keywords
/// `__init_subclass__` accepts) is not a base and contributes nothing here.
fn extract_python_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(superclasses) = node.child_by_field_name("superclasses") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let mut cursor = superclasses.walk();
    for child in superclasses.named_children(&mut cursor) {
        if child.kind() == "keyword_argument" {
            continue;
        }
        let named = python_base_origin_node(child);
        let text = py_node_text(named, source).trim();
        if !text.is_empty() {
            result.push(text.to_string());
        }
    }
    result
}

/// The node whose text names a base class: the value a subscripted base
/// applies its type arguments to, or the base expression itself.
///
/// Base spellings recorded by [`extract_python_supertypes`] are looked up
/// again against the class's own syntax, so both sides must reduce a base the
/// same way or a generic base stops matching the spelling it produced.
pub fn python_base_origin_node<'tree>(base: Node<'tree>) -> Node<'tree> {
    if base.kind() != "subscript" {
        return base;
    }
    let Some(value) = base.child_by_field_name("value") else {
        return base;
    };
    if matches!(value.kind(), "identifier" | "attribute") {
        value
    } else {
        base
    }
}

fn collect_assigned_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            // An attribute or subscript target (`foo.bar = …`, `foo[i] = …`)
            // mutates an existing object; it declares neither the receiver nor
            // the member as a name, so do not descend into it.
            "attribute" | "subscript" => WalkControl::SkipChildren,
            "identifier" => {
                let text = py_node_text(node, source).trim();
                if !text.is_empty() {
                    names.push(text.to_string());
                }
                WalkControl::Continue
            }
            _ => WalkControl::Continue,
        }
    });
    names
}

fn collect_self_assigned_attributes<'tree>(
    node: Node<'tree>,
    source: &str,
    receiver_name: &str,
) -> Vec<(String, Node<'tree>)> {
    let mut attributes = Vec::new();
    collect_direct_self_assigned_attributes(node, source, receiver_name, &mut attributes);
    attributes
}

fn collect_direct_self_assigned_attributes<'tree>(
    node: Node<'tree>,
    source: &str,
    receiver_name: &str,
    attributes: &mut Vec<(String, Node<'tree>)>,
) {
    match node.kind() {
        "attribute" => {
            let Some(object) = node.child_by_field_name("object") else {
                return;
            };
            if object.kind() != "identifier" || py_node_text(object, source).trim() != receiver_name
            {
                return;
            }
            let Some(attribute) = node.child_by_field_name("attribute") else {
                return;
            };
            let name = py_node_text(attribute, source).trim();
            if !name.is_empty() {
                attributes.push((name.to_string(), attribute));
            }
        }
        // The grammar spells an unpacking target three ways: a bare comma list
        // is a `pattern_list`, and parentheses or brackets around it make a
        // `tuple_pattern` or a `list_pattern`. Omitting the bracketed forms
        // dropped every attribute a multi-line unpacking assigns.
        "pattern_list"
        | "tuple_pattern"
        | "list_pattern"
        | "tuple"
        | "list"
        | "parenthesized_expression" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_direct_self_assigned_attributes(child, source, receiver_name, attributes);
            }
        }
        _ => {}
    }
}

fn python_instance_method_receiver_name(node: Node<'_>, source: &str) -> Option<String> {
    if python_function_has_decorator(node, source, "staticmethod")
        || python_function_has_decorator(node, source, "classmethod")
    {
        return None;
    }
    python_first_parameter_name(node, source)
}

fn python_function_has_decorator(node: Node<'_>, source: &str, decorator_name: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "decorated_definition" {
        return false;
    }
    let mut cursor = parent.walk();
    parent
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| decorator.named_child(0))
        .filter_map(expression_name_node)
        .any(|name| py_node_text(name, source).trim() == decorator_name)
}

/// The name a callable binds its first parameter to, which for a method is
/// the receiver every `self.x` and `setattr(self, ...)` in its body names.
pub fn python_first_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    let parameters = node.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .find_map(|child| python_parameter_name(child, source))
}

fn python_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(py_node_text(node, source).trim().to_string()),
        "typed_parameter"
        | "default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern" => node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "identifier")
            })
            .and_then(|name| python_parameter_name(name, source)),
        _ => None,
    }
    .filter(|name| !name.is_empty())
}

pub fn collect_python_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    walk_named_tree_preorder(node, true, |node| {
        if node.kind() == "identifier" {
            let text = py_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        WalkControl::Continue
    });
}

pub fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load python parser");
    parser.parse(source, None)
}

#[cfg(test)]
mod supertype_tests {
    use super::extract_python_supertypes;
    use tree_sitter::{Node, Parser};

    fn class_node<'tree>(tree: &'tree tree_sitter::Tree, source: &str) -> Node<'tree> {
        let mut cursor = tree.root_node().walk();
        tree.root_node()
            .named_children(&mut cursor)
            .find(|node| node.kind() == "class_definition")
            .unwrap_or_else(|| panic!("source declares a class: {source}"))
    }

    fn parse(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("the Python grammar loads");
        parser.parse(source, None).expect("the source parses")
    }

    #[test]
    fn every_positional_base_contributes_a_spelling() {
        for (source, expected) in [
            ("class A(Base): pass\n", vec!["Base"]),
            ("class A(pkg.Base): pass\n", vec!["pkg.Base"]),
            // The generic origin is the class the runtime inherits; dropping
            // a subscripted base made an incomplete hierarchy look complete.
            ("class A(Base[int]): pass\n", vec!["Base"]),
            ("class A(pkg.Base[str, int]): pass\n", vec!["pkg.Base"]),
            (
                "class A(Mapping[str, Any], Base): pass\n",
                vec!["Mapping", "Base"],
            ),
            // Not a base: a keyword argument configures class creation.
            ("class A(Base, metaclass=Meta): pass\n", vec!["Base"]),
            ("class A(metaclass=Meta): pass\n", Vec::new()),
            // Unnameable bases still register, so resolution reports an
            // unresolved base rather than a complete member list.
            (
                "class A(namedtuple(\"P\", \"x\")): pass\n",
                vec!["namedtuple(\"P\", \"x\")"],
            ),
            ("class A(*bases): pass\n", vec!["*bases"]),
            ("class A: pass\n", Vec::new()),
        ] {
            let tree = parse(source);
            let node = class_node(&tree, source);
            assert_eq!(
                extract_python_supertypes(node, source),
                expected,
                "supertypes of {source}"
            );
        }
    }
}

/// Every target a possibly chained assignment binds.
///
/// Python's `encrypt = decrypt = process` binds both names, but the grammar
/// spells it as one `assignment` whose `right` is another `assignment`. Reading
/// only the outermost `left` declares `encrypt` and silently drops `decrypt`,
/// so the alias reads as an absent member on the class that defines it.
fn python_chained_assignment_targets<'tree>(assignment: Node<'tree>) -> Vec<Node<'tree>> {
    let mut targets = Vec::new();
    let mut node = assignment;
    loop {
        let Some(left) = node.child_by_field_name("left") else {
            break;
        };
        targets.push(left);
        match node.child_by_field_name("right") {
            Some(right) if right.kind() == "assignment" => node = right,
            _ => break,
        }
    }
    targets
}
