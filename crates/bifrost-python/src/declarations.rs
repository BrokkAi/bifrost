use crate::bindings::python_direct_scope_bindings_bounded;
use crate::imports::{python_import_infos_from_node, python_import_syntaxes_from_node};
use crate::syntax::{
    PythonOverloadDecoratorBindings, PythonOverloadDecoratorName, expression_name_node,
    python_plain_string_literal,
};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CodeUnitType, DispatchExtensibility, ParameterMetadata, SignatureMetadata,
    StructuredImportPathKind, StructuredTypeIdentity,
};
use brokk_bifrost_core::analyzer::parsed_file::{
    ParsedFile, ParsedSourceFacts, SourceDeclarationMetadataLink, SourceImportFact,
};
use brokk_bifrost_core::analyzer::python_facts::{PythonCallableReturnFact, PythonSourceFacts};
use brokk_bifrost_core::analyzer::rust_facts::RustItemSourceFacts;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceImportId,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::collector::StructuralFactCollector;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::structural::spec::{CompiledKinds, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_normalization::NormalizePath;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::{Path, PathBuf};
use tree_sitter::{Node, Parser, Tree};

use crate::source_properties::{python_annotation_references, python_return_type_identity};
use crate::structural::PYTHON_STRUCTURAL_SPEC;

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
    python_module_components_from_root(file, &python_import_root(file))
}

/// The module-name components `file`'s path yields when it is named from the
/// project root, which is the longest name the workspace can give it:
/// `dependency/core/lib/common/__init__.py` is
/// `["dependency", "core", "lib", "common"]`.
///
/// A Python module name is relative to the `sys.path` entry an import of it
/// resolves against, so one file has one valid absolute name per ancestor
/// directory on that path, and each of them is a suffix of this one.
/// [`python_import_root`] picks the single name that becomes the module's
/// identity; this is what an import written against any deeper root has to be
/// matched against (#3506).
pub fn python_project_module_components(file: &ProjectFile) -> Vec<String> {
    python_module_components_from_root(file, Path::new(""))
}

/// `file`'s module-name components relative to `import_root_rel`, which must be
/// a prefix of the file's own relative path.
fn python_module_components_from_root(file: &ProjectFile, import_root_rel: &Path) -> Vec<String> {
    let mut components = python_package_components_for_file(file, import_root_rel);
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

/// The directory `file`'s path-derived Python module name is relative to: the
/// analyzer's stand-in for the `sys.path` entry an absolute import of that
/// module would be resolved against.
///
/// It is the nearest configured setuptools import root, else the parent of the
/// outermost `__init__.py` package chain above the file, else the project root.
/// The result is always a prefix of the file's own relative path, and it is
/// what makes two same-named modules in one snapshot distinguishable:
/// `registry/purview-registry/registry/models.py` and
/// `registry/sql-registry/registry/models.py` are both the module
/// `registry.models`, but they belong to different roots (#3475).
pub fn python_import_root(file: &ProjectFile) -> PathBuf {
    let Some(parent_rel) = file.rel_path().parent() else {
        return PathBuf::new();
    };
    if parent_rel.as_os_str().is_empty() {
        return PathBuf::new();
    }

    if let Some(import_root_rel) = python_configured_import_root(file, parent_rel) {
        return import_root_rel;
    }

    let mut effective_package_root_rel: Option<&Path> = None;
    let mut current_rel = Some(parent_rel);
    while let Some(path) = current_rel {
        if file.root().join(path).join("__init__.py").exists() {
            effective_package_root_rel = Some(path);
        }
        current_rel = path.parent();
    }

    // A package root's own parent is the import root; a file in no package at
    // all is named from the project root.
    effective_package_root_rel
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf()
}

fn python_package_components_for_file(file: &ProjectFile, import_root_rel: &Path) -> Vec<String> {
    let Some(parent_rel) = file.rel_path().parent() else {
        return Vec::new();
    };
    let relative_package = parent_rel
        .strip_prefix(import_root_rel)
        .expect("a Python import root is a prefix of the paths it names modules for");
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

/// The root a packaging manifest declares for this file, whether that root is
/// the project root itself or a directory below it.
///
/// `pyproject.toml`'s `tool.setuptools.packages.find.where` and `setup.py`'s
/// `package_dir` state where a project's packages begin: a file below one of
/// them is named from that directory and from nowhere else. `where = ["."]`
/// declares the project root, and a declaration of the project root is a
/// declaration like any other: it says this project's packages begin here, so a
/// shorter spelling below that root names a different arrangement of the same
/// directories. Only a project whose packaging configuration does not cover
/// this file answers `None` (#3506).
pub fn python_declared_import_root(file: &ProjectFile) -> Option<PathBuf> {
    let parent_rel = file.rel_path().parent()?;
    if parent_rel.as_os_str().is_empty() {
        return None;
    }
    python_configured_import_root(file, parent_rel)
}

/// The directory the package a repeated spelling starts from has to add to its
/// own `__path__` for `source_root_rel` to be a root the specifier is written
/// against, or `None` when the specifier does not spell that root's own path
/// again at its head (#3506).
///
/// A packaging declaration states where a project's packages begin, so a
/// shorter spelling below it normally names a different arrangement of the same
/// directories rather than the module: `otherpkg/vendor/api.py` under
/// `where = ["."]` is `otherpkg.vendor.api`, and `vendor.api`, whose implied
/// root is `otherpkg`, is not another name for it. The double-nested
/// distribution directory is the one shape a declaration leaves open, because
/// the specifier writes the implied root's own path again before the module's
/// path: from `rtdetr_pose/`, `rtdetr_pose.config` names `config.py` in the
/// same-named package that directory holds, the file the workspace indexes as
/// `rtdetr_pose.rtdetr_pose.config`.
///
/// The shape is a naming question only, and it is not evidence that the import
/// works. The interpreter finds the module through the package the specifier
/// starts from -- `rtdetr_pose/__init__.py` -- and only that package's own
/// statement that `rtdetr_pose/rtdetr_pose` is on its search path makes the
/// shorter spelling name the file. The repeated directory name and the empty
/// markers that make the directories packages state nothing on their own, so
/// this returns the directory such a statement has to name, relative to the
/// project root, and the snapshot decides whether the marker states it.
pub(crate) fn python_repeated_root_extension_dir(
    file: &ProjectFile,
    source_root_rel: &Path,
    declared_root_rel: &Path,
) -> Option<PathBuf> {
    let implied_rel = source_root_rel.strip_prefix(declared_root_rel).ok()?;
    let implied = path_components(implied_rel);
    if implied.is_empty()
        || !python_module_components_from_root(file, source_root_rel).starts_with(&implied)
    {
        return None;
    }
    Some(source_root_rel.join(implied_rel))
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

pub struct PythonVisitor<'source, 'parsed, 'structural>
where
    'source: 'structural,
{
    pub file: &'parsed ProjectFile,
    pub source: &'source str,
    pub package_name: &'parsed str,
    module_fq: &'parsed FqName,
    pub parsed: &'parsed mut ParsedFile,
    pub module: Option<CodeUnit>,
    overload_decorators: PythonOverloadDecoratorBindings,
    source_facts: PrimarySourceFactCollector<'source>,
    structural: StructuralFactCollector<'structural, 'structural>,
    structural_kinds: &'structural CompiledKinds,
    call_site_context: &'structural CallSiteContext,
    structural_parents: Vec<Option<u32>>,
    source_imports: Vec<SourceImportFact>,
    generic_imports: Vec<SourceImportId>,
    source_declaration_units: Vec<(SourceDeclarationId, CodeUnit)>,
    python_source_facts: PythonSourceFacts,
    python_callable_return_by_node: HashMap<usize, usize>,
    overload_metadata: Vec<(CodeUnit, usize, Vec<PythonOverloadDecoratorName>)>,
}

struct PythonFrame<'tree> {
    node: Node<'tree>,
    scope: Vec<Scope>,
    module_control_depth: usize,
    declaration: bool,
    wrapper: Option<Node<'tree>>,
    lexical_scopes: Vec<Node<'tree>>,
}

enum PythonWork<'tree> {
    Enter(PythonFrame<'tree>),
    Exit,
}

struct DeclarationChildren<'tree> {
    body: Option<(Node<'tree>, Vec<Scope>)>,
    container_scope: Option<Vec<Scope>>,
    container_depth: usize,
}

impl<'source, 'parsed, 'structural> PythonVisitor<'source, 'parsed, 'structural>
where
    'source: 'structural,
{
    pub fn visit_container(
        &mut self,
        node: Node<'_>,
        scope: &[Scope],
        module_control_depth: usize,
    ) {
        let mut stack = vec![PythonWork::Enter(PythonFrame {
            node,
            scope: scope.to_vec(),
            module_control_depth,
            declaration: true,
            wrapper: None,
            lexical_scopes: Vec::new(),
        })];
        while let Some(work) = stack.pop() {
            let PythonWork::Enter(frame) = work else {
                self.structural_parents
                    .pop()
                    .expect("Python structural parent stack must balance");
                continue;
            };
            let structural_parent = self.structural_parents.last().copied().flatten();
            let structural_id = self.admit_structural(frame.node, structural_parent);
            self.structural_parents
                .push(structural_id.or(structural_parent));

            if frame.node.kind() == "identifier" {
                let text = py_node_text(frame.node, self.source).trim();
                if !text.is_empty() {
                    self.parsed.type_identifiers.insert(text.to_string());
                }
            }

            if frame.node.kind() == "function_definition" {
                self.capture_function_return_fact(frame.node, frame.wrapper);
            }

            if matches!(
                frame.node.kind(),
                "import_statement" | "import_from_statement"
            ) {
                self.visit_import_statement(frame.node, &frame.lexical_scopes);
            }

            let declaration_children = if frame.declaration {
                self.visit_statement(
                    frame.node,
                    &frame.scope,
                    frame.module_control_depth,
                    frame.wrapper,
                )
            } else {
                DeclarationChildren {
                    body: None,
                    container_scope: None,
                    container_depth: frame.module_control_depth,
                }
            };

            let mut children = Vec::new();
            let mut cursor = frame.node.walk();
            for child in frame.node.named_children(&mut cursor) {
                let mut child_scope = frame.scope.clone();
                let mut declaration = false;
                let mut wrapper = None;
                let mut child_depth = frame.module_control_depth;

                if let Some((body, scope)) = &declaration_children.body
                    && child.id() == body.id()
                {
                    declaration = true;
                    child_scope = scope.clone();
                } else if let Some(scope) = &declaration_children.container_scope {
                    declaration = true;
                    child_scope = scope.clone();
                    child_depth = declaration_children.container_depth;
                } else if frame.declaration
                    && frame.node.kind() == "decorated_definition"
                    && matches!(child.kind(), "class_definition" | "function_definition")
                {
                    // The wrapper owns the source range, while its concrete
                    // definition owns the declaration semantics.
                    declaration = true;
                    wrapper = Some(frame.node);
                }

                let mut lexical_scopes = frame.lexical_scopes.clone();
                if matches!(
                    frame.node.kind(),
                    "class_definition" | "function_definition" | "lambda"
                ) {
                    lexical_scopes.push(frame.node);
                }
                children.push(PythonFrame {
                    node: child,
                    scope: child_scope,
                    module_control_depth: child_depth,
                    declaration,
                    wrapper,
                    lexical_scopes,
                });
            }

            stack.push(PythonWork::Exit);
            stack.extend(children.into_iter().rev().map(PythonWork::Enter));
        }
    }

    fn admit_structural(&mut self, node: Node<'_>, parent: Option<u32>) -> Option<u32> {
        if !node.is_named() {
            return parent;
        }
        let Some(raw_kind) = self.structural_kinds.kind_of(&node) else {
            return parent;
        };
        if !PYTHON_STRUCTURAL_SPEC.should_extract(node, raw_kind) {
            return parent;
        }
        let kind = PYTHON_STRUCTURAL_SPEC.refine_kind(
            node,
            raw_kind,
            parent.map(|id| self.structural.normalized_kind(id)),
            self.source,
            self.call_site_context,
        );
        let fact_id = self
            .structural
            .enter(node, kind, parent, &mut self.source_facts)
            .expect("Python structural fact collection must remain unbounded");
        let mut sink = self.structural.role_sink(&mut self.source_facts);
        PYTHON_STRUCTURAL_SPEC.extract(node, kind, &mut sink);
        self.structural
            .accept_roles(fact_id, sink.into_parts())
            .expect("Python structural role collection must remain unbounded");
        Some(fact_id)
    }

    fn replace_source_declaration(
        &mut self,
        declaration_node: Node<'_>,
        name_node: Option<Node<'_>>,
        unit: CodeUnit,
        metadata_ordinal: Option<usize>,
    ) -> SourceDeclarationId {
        self.source_declaration_units
            .retain(|(_, existing)| existing != &unit);
        self.parsed
            .source_declaration_metadata
            .retain(|link| link.unit != unit);
        self.record_source_declaration(declaration_node, name_node, unit, metadata_ordinal)
    }

    fn record_source_declaration(
        &mut self,
        declaration_node: Node<'_>,
        name_node: Option<Node<'_>>,
        unit: CodeUnit,
        metadata_ordinal: Option<usize>,
    ) -> SourceDeclarationId {
        let occurrence = self.source_facts.intern_node(declaration_node);
        let name = name_node.map(|node| self.source_facts.intern_node(node));
        let declaration = self.source_facts.declare(occurrence, name);
        self.source_declaration_units
            .push((declaration, unit.clone()));
        if let Some(metadata_ordinal) = metadata_ordinal {
            self.parsed
                .source_declaration_metadata
                .push(SourceDeclarationMetadataLink {
                    declaration,
                    unit,
                    metadata_ordinal,
                });
        }
        declaration
    }

    fn capture_function_return_fact<'tree>(
        &mut self,
        node: Node<'tree>,
        wrapper: Option<Node<'tree>>,
    ) {
        let declaration_node = wrapper
            .or_else(|| {
                node.parent()
                    .filter(|parent| parent.kind() == "decorated_definition")
            })
            .unwrap_or(node);
        let occurrence = self.source_facts.intern_node(declaration_node);
        let name = node
            .child_by_field_name("name")
            .map(|name| self.source_facts.intern_node(name));
        let declaration = self.source_facts.declare(occurrence, name);
        let return_annotation = node
            .child_by_field_name("return_type")
            .map(|annotation| self.source_facts.intern_node(annotation));
        let annotation_references = node
            .child_by_field_name("return_type")
            .map(|annotation| {
                python_annotation_references(annotation, self.source, &mut self.source_facts)
            })
            .unwrap_or_default();
        let runtime_type = node
            .child_by_field_name("return_type")
            .and_then(|annotation| python_return_type_identity(annotation, self.source));
        let fact_index = self.python_source_facts.callable_returns.len();
        self.python_source_facts
            .callable_returns
            .push(PythonCallableReturnFact {
                declaration,
                return_annotation,
                annotation_references,
                runtime_type,
            });
        assert!(
            self.python_callable_return_by_node
                .insert(node.id(), fact_index)
                .is_none(),
            "each Python function definition must have one callable return fact"
        );
    }

    fn link_source_declaration(
        &mut self,
        declaration: SourceDeclarationId,
        unit: CodeUnit,
        metadata_ordinal: Option<usize>,
    ) {
        self.source_declaration_units
            .push((declaration, unit.clone()));
        if let Some(metadata_ordinal) = metadata_ordinal {
            self.parsed
                .source_declaration_metadata
                .push(SourceDeclarationMetadataLink {
                    declaration,
                    unit,
                    metadata_ordinal,
                });
        }
    }

    fn visit_statement<'tree>(
        &mut self,
        node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
        wrapper: Option<Node<'tree>>,
    ) -> DeclarationChildren<'tree> {
        match node.kind() {
            "decorated_definition" => DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            },
            "class_definition" | "function_definition" => {
                self.visit_definition(node, wrapper, scope, module_control_depth)
            }
            "expression_statement" => {
                self.visit_expression_statement(node, scope, module_control_depth);
                DeclarationChildren {
                    body: None,
                    container_scope: None,
                    container_depth: module_control_depth,
                }
            }
            "import_statement" | "import_from_statement" => DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            },
            "if_statement" | "try_statement" | "with_statement" | "for_statement"
            | "while_statement" => {
                let next_depth = if scope.is_empty() {
                    module_control_depth + 1
                } else {
                    module_control_depth
                };
                DeclarationChildren {
                    body: None,
                    container_scope: Some(scope.to_vec()),
                    container_depth: next_depth,
                }
            }
            "elif_clause" | "else_clause" | "except_clause" | "finally_clause" => {
                DeclarationChildren {
                    body: None,
                    container_scope: Some(scope.to_vec()),
                    container_depth: module_control_depth,
                }
            }
            "block" | "module" => DeclarationChildren {
                body: None,
                container_scope: Some(scope.to_vec()),
                container_depth: module_control_depth,
            },
            _ => DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            },
        }
    }

    fn visit_definition<'tree>(
        &mut self,
        definition: Node<'tree>,
        wrapper: Option<Node<'tree>>,
        scope: &[Scope],
        module_control_depth: usize,
    ) -> DeclarationChildren<'tree> {
        match definition.kind() {
            "class_definition" => self.visit_class_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
            ),
            "function_definition" => self.visit_function_definition(
                definition,
                wrapper.unwrap_or(definition),
                scope,
                module_control_depth,
            ),
            _ => DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            },
        }
    }

    fn visit_class_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
    ) -> DeclarationChildren<'tree> {
        let Some(name_node) = node.child_by_field_name("name") else {
            return DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            };
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            };
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
            self.replace_source_declaration(range_node, Some(name_node), code_unit.clone(), None);
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
        DeclarationChildren {
            body: node
                .child_by_field_name("body")
                .map(|body| (body, next_scope)),
            container_scope: None,
            container_depth: module_control_depth,
        }
    }

    fn visit_function_definition<'tree>(
        &mut self,
        node: Node<'tree>,
        range_node: Node<'tree>,
        scope: &[Scope],
        module_control_depth: usize,
    ) -> DeclarationChildren<'tree> {
        let Some(name_node) = node.child_by_field_name("name") else {
            return DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            };
        };
        let name = py_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return DeclarationChildren {
                body: None,
                container_scope: None,
                container_depth: module_control_depth,
            };
        }

        // Only the shapes a reviewed summary can name are declarations: a
        // function written at module level (at most one control level deep, so
        // a `def` under `if TYPE_CHECKING:` still counts) or directly in a
        // class body. A function nested inside another function's body is a
        // local binding of its enclosing function, not a member of any owner,
        // so it mints no declaration and no procedure key; `@x.setter` is a
        // write into its class's attribute rather than a callable member.
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
            let fact_index = *self
                .python_callable_return_by_node
                .get(&node.id())
                .expect("function return fact must precede declaration admission");
            let return_fact = &self.python_source_facts.callable_returns[fact_index];
            let return_declaration = return_fact.declaration;
            let return_type_identity = return_fact.runtime_type.clone();
            let return_type_text = return_fact.return_annotation.map(|annotation| {
                let range = self.source_facts.occurrence(annotation).range;
                self.source[range.start_byte..range.end_byte].to_string()
            });
            let metadata_ordinal = self.parsed.add_signature_with_metadata(
                code_unit.clone(),
                python_signature_metadata(
                    signature,
                    node,
                    self.source,
                    return_type_text.as_deref(),
                    return_type_identity,
                ),
            );
            self.overload_metadata
                .retain(|(existing, _, _)| existing != &code_unit);
            self.overload_metadata.push((
                code_unit.clone(),
                metadata_ordinal,
                PythonOverloadDecoratorBindings::overload_decorator_names(node, self.source),
            ));
            self.source_declaration_units
                .retain(|(_, existing)| existing != &code_unit);
            self.parsed
                .source_declaration_metadata
                .retain(|link| link.unit != code_unit);
            self.link_source_declaration(
                return_declaration,
                code_unit.clone(),
                Some(metadata_ordinal),
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
            return DeclarationChildren {
                body: node
                    .child_by_field_name("body")
                    .map(|body| (body, next_scope)),
                container_scope: None,
                container_depth: module_control_depth,
            };
        }

        let mut next_scope = scope.to_vec();
        next_scope.push(Scope {
            kind: ScopeKind::Function,
            path: short_name,
            fq,
            code_unit: None,
            method_receiver: None,
        });
        DeclarationChildren {
            body: node
                .child_by_field_name("body")
                .map(|body| (body, next_scope)),
            container_scope: None,
            container_depth: module_control_depth,
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
            .flat_map(|left| collect_assigned_name_nodes(*left, self.source));
        for name_node in names {
            let name = py_node_text(name_node, self.source).trim().to_string();
            if name.is_empty() {
                continue;
            }
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
            if scope
                .last()
                .is_some_and(|parent| parent.kind == ScopeKind::Class)
            {
                self.record_source_declaration(node, Some(name_node), code_unit.clone(), None);
            } else {
                self.replace_source_declaration(node, Some(name_node), code_unit.clone(), None);
            }
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
                self.record_source_declaration(node, Some(node), code_unit.clone(), None);
            }
            self.parsed.add_signature(
                code_unit.clone(),
                py_node_text(node, self.source).trim().to_string(),
            );
        }
    }

    fn visit_import_statement(&mut self, node: Node<'_>, lexical_scopes: &[Node<'_>]) {
        for syntax in python_import_syntaxes_from_node(node, self.source) {
            if lexical_scopes.is_empty() {
                self.overload_decorators.collect_import(&syntax.info);
            }
            let declaration = self.source_facts.intern_node(syntax.declaration);
            let target = syntax
                .target
                .map(|node| self.source_facts.intern_node(node));
            let alias_occurrence = syntax.alias.map(|node| self.source_facts.intern_node(node));
            let lexical_scopes = lexical_scopes
                .iter()
                .map(|node| self.source_facts.intern_node(*node))
                .collect();
            let source_import = SourceImportFact::from_import(
                syntax.info,
                declaration,
                target,
                alias_occurrence,
                lexical_scopes,
            );
            let id = SourceImportId::try_from_index(self.source_imports.len())
                .expect("Python source import ids must fit in a u32");
            self.source_imports.push(source_import);
            self.generic_imports.push(id);
        }
    }

    fn finish(self) {
        let PythonVisitor {
            parsed,
            source,
            source_facts,
            structural,
            structural_parents,
            source_imports,
            generic_imports,
            source_declaration_units,
            python_source_facts,
            python_callable_return_by_node: _,
            overload_decorators,
            overload_metadata,
            ..
        } = self;
        assert_eq!(structural_parents, vec![None]);
        let structural = structural
            .finish()
            .expect("Python structural fact collection must finish");
        let occurrences = source_facts.finish();
        assert!(
            python_source_facts.valid_links(&occurrences),
            "Python callable return facts must link to exact source identities"
        );
        for (unit, metadata_ordinal, decorators) in overload_metadata {
            let declaration_only = decorators
                .iter()
                .any(|name| overload_decorators.matches_overload_binding(name));
            if declaration_only
                && let Some(metadata) = parsed
                    .signature_metadata
                    .get_mut(&unit)
                    .and_then(|entries| entries.get_mut(metadata_ordinal))
            {
                *metadata = metadata.clone().with_declaration_only(true);
            }
        }
        parsed.imports = generic_imports
            .iter()
            .map(|id| source_imports[id.index()].import_info(&occurrences))
            .collect();
        parsed.source_declaration_units = source_declaration_units;
        parsed.source_facts = Some(ParsedSourceFacts {
            cpp: None,
            go: None,
            java: None,
            js_ts: None,
            php: None,
            scala: None,
            ruby: None,
            source_bytes: source.len(),
            occurrences,
            structural,
            python: Some(python_source_facts),
            native_site_occurrences: Vec::new(),
            native_declaration_sources: Vec::new(),
            declaration_visibilities: None,
            rust_declaration_properties: Vec::new(),
            rust_modules: None,
            rust_types: Vec::new(),
            rust_items: RustItemSourceFacts::default(),
            imports: source_imports,
            generic_imports,
            rust_import_contexts: Vec::new(),
        });
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

    let module_code_unit = module_code_unit_from_fq(file, &module_components, module_fq.clone());
    if let Some(module) = module_code_unit.clone() {
        parsed.add_code_unit(module, root, source, None, None);
    }

    let overload_decorators = PythonOverloadDecoratorBindings::default();
    let structural_kinds = CompiledKinds::compile(
        &tree_sitter_python::LANGUAGE.into(),
        PYTHON_STRUCTURAL_SPEC.kind_table(),
    );
    let call_site_context = PYTHON_STRUCTURAL_SPEC.call_site_context(root, source);
    let mut visitor = PythonVisitor {
        file,
        source,
        package_name: &module_name,
        module_fq: &module_fq,
        parsed: &mut parsed,
        module: module_code_unit,
        overload_decorators,
        source_facts: PrimarySourceFactCollector::new(source),
        structural: StructuralFactCollector::new(
            &PYTHON_STRUCTURAL_SPEC,
            source,
            &call_site_context,
            ParentIndex::new(root),
            usize::MAX,
            None,
        ),
        structural_kinds: &structural_kinds,
        call_site_context: &call_site_context,
        structural_parents: vec![None],
        source_imports: Vec::new(),
        generic_imports: Vec::new(),
        source_declaration_units: Vec::new(),
        python_source_facts: PythonSourceFacts::default(),
        python_callable_return_by_node: HashMap::default(),
        overload_metadata: Vec::new(),
    };
    visitor.visit_container(root, &[], 0);
    visitor.finish();

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

fn python_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    return_type_text: Option<&str>,
    return_type_identity: Option<StructuredTypeIdentity>,
) -> SignatureMetadata {
    let Some(parameters_node) = node
        .child_by_field_name("parameters")
        .filter(|parameters| parameters.start_position().row == parameters.end_position().row)
    else {
        return SignatureMetadata::new(signature, Vec::new())
            .with_return_type_text(return_type_text)
            .with_return_type_identity(return_type_identity)
            .with_dispatch_extensibility(DispatchExtensibility::Open)
            .with_callable_modifiers(
                python_callable_is_static(node, source),
                false,
                DeclaredVisibility::Unknown,
            );
    };
    // The display header is the last line after any decorators. Parameter
    // labels use offsets from their exact AST nodes, so repeated spellings in
    // annotations/defaults cannot masquerade as another parameter's identity.
    // The existing one-line display omits multiline continuations; omitted
    // labels remain unavailable rather than pointing into unrelated text.
    let header_start = signature.rfind('\n').map_or(0, |offset| offset + 1);
    let parameters = python_parameter_label_nodes(parameters_node)
        .into_iter()
        .filter_map(|label_node| {
            let label = py_node_text(label_node, source);
            let start_byte = header_start + label_node.start_byte() - node.start_byte();
            let end_byte = start_byte + label.len();
            (signature.get(start_byte..end_byte) == Some(label))
                .then(|| ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    SignatureMetadata::new(signature, parameters)
        .with_return_type_text(return_type_text)
        .with_return_type_identity(return_type_identity)
        .with_dispatch_extensibility(DispatchExtensibility::Open)
        .with_callable_modifiers(
            python_callable_is_static(node, source),
            false,
            DeclaredVisibility::Unknown,
        )
}

/// Whether this Python callable binds no instance receiver, read from its own
/// declaration nodes (#3451).
///
/// Recording the fact is what makes a Python declaration keyable for
/// procedure-summary binding: `receiver_contract_of` refuses to answer for a
/// callable whose adapter never inspected modifiers, so before this every
/// Python workspace callee contributed `callee_unkeyable` and no Python effect
/// coverage could be exhaustive.
///
/// Only a callable written in a class body can bind an instance receiver, and
/// the two decorators that remove it are `@staticmethod` and `@classmethod`.
/// The decorator check is the language's own
/// [`python_function_has_decorator`], read through the `decorated_definition`
/// node that owns the decorators, so the receiver contract agrees with the
/// receiver [`python_instance_method_receiver_name`] already resolves. A
/// module-level function, and a function nested in another function's body, has
/// no type owner at all, so its contract falls out of the owner rather than out
/// of this flag; it is not static either.
///
/// Python spells no constructor modifier for `__init__`: calling the class
/// reaches an ordinary instance method, exactly as Ruby's `initialize`, so the
/// constructor flag stays false and its receiver contract is `Instance`.
/// Visibility is a naming convention (`_name`), not a declaration node, so it
/// stays `Unknown`.
fn python_callable_is_static(node: Node<'_>, source: &str) -> bool {
    debug_assert!(
        node.kind() == "function_definition",
        "Python callable signature metadata is built for function_definition, not {}",
        node.kind()
    );
    python_function_has_decorator(node, source, "staticmethod")
        || python_function_has_decorator(node, source, "classmethod")
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

fn collect_assigned_name_nodes<'tree>(node: Node<'tree>, _source: &str) -> Vec<Node<'tree>> {
    let mut names = Vec::new();
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            // An attribute or subscript target (`foo.bar = …`, `foo[i] = …`)
            // mutates an existing object; it declares neither the receiver nor
            // the member as a name, so do not descend into it.
            "attribute" | "subscript" => WalkControl::SkipChildren,
            "identifier" => {
                names.push(node);
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
mod primary_tests {
    use super::*;
    use brokk_bifrost_core::analyzer::python_facts::PythonAnnotationReferenceName;

    fn parse(source: &str) -> ParsedFile {
        let file = ProjectFile::new(std::env::temp_dir(), "m4.py");
        let tree = parse_python_tree(source).expect("Python fixture tree");
        parse_python_file(&file, source, &tree)
    }

    #[test]
    fn replacing_a_class_withdraws_descendant_metadata_links() {
        let parsed = parse(
            "class Replaced:\n    def obsolete(self): pass\n    class Nested:\n        def stale(self): pass\n\nclass Kept:\n    def stable(self): pass\n\nclass Replaced:\n    def current(self): pass\n",
        );
        let mut names = parsed
            .source_declaration_metadata
            .iter()
            .map(|link| {
                assert!(
                    parsed.signature_metadata[&link.unit]
                        .get(link.metadata_ordinal)
                        .is_some(),
                    "the link must name retained callable metadata: {link:?}"
                );
                link.unit.short_name().to_string()
            })
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["Kept.stable", "Replaced.current"]);
    }

    #[test]
    fn canonical_declarations_share_structural_name_identity_and_exact_ranges() {
        let source = "@decorate\nclass Item:\n    value = 1\n    value = 2\n    def write(self):\n        self.member = 1\n        self.member = 2\n\nfirst, second = 1, 2\n";
        let parsed = parse(source);
        let facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical Python facts");
        for (id, unit) in &parsed.source_declaration_units {
            let declaration = facts.occurrences.declaration(*id);
            let range = facts.occurrences.occurrence(declaration.occurrence).range;
            assert!(parsed.ranges[unit].contains(&range), "{unit:?}: {range:?}");
            let name = declaration.name.expect("source declaration name");
            assert!(
                facts
                    .structural
                    .nodes()
                    .iter()
                    .any(|node| node.occurrence == name),
                "shared name identity for {unit:?}"
            );
        }
        let fields = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| unit.short_name() == "Item.value")
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 2);
        assert_ne!(fields[0].0, fields[1].0);
        assert_eq!(
            parsed
                .source_declaration_units
                .iter()
                .filter(|(_, unit)| unit.short_name() == "Item.member")
                .count(),
            1
        );
        let class = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.short_name() == "Item")
            .expect("decorated class");
        let range = facts
            .occurrences
            .occurrence(facts.occurrences.declaration(class.0).occurrence)
            .range;
        assert_eq!(range.start_byte, 0);
        assert_eq!(&source[range.start_byte..range.start_byte + 9], "@decorate");
    }

    #[test]
    fn imports_keep_scope_order_and_late_overload_capture_without_local_pollution() {
        let source = "@overload\ndef public(value: int):\n    pass\nfrom typing import overload\n\ndef outer():\n    from typing import overload as local_only\n@local_only\ndef ordinary(value: int):\n    pass\nmatch 1:\n    case 1:\n        from .models import Item as Imported\n";
        let parsed = parse(source);
        let facts = parsed.source_facts.as_ref().expect("canonical imports");
        assert_eq!(facts.imports.len(), 3);
        assert!(
            facts.imports[0]
                .path
                .as_ref()
                .unwrap()
                .lexical_scopes
                .is_empty()
        );
        assert_eq!(
            facts.imports[1].path.as_ref().unwrap().lexical_scopes.len(),
            1
        );
        assert!(
            facts.imports[2]
                .path
                .as_ref()
                .unwrap()
                .lexical_scopes
                .is_empty()
        );
        for (id, import) in facts.generic_imports.iter().zip(&parsed.imports) {
            assert_eq!(
                &facts.imports[id.index()].import_info(&facts.occurrences),
                import
            );
        }
        let metadata = |name: &str| {
            parsed
                .signature_metadata
                .iter()
                .find(|(unit, _)| unit.short_name() == name)
                .unwrap()
                .1
        };
        assert!(metadata("public")[0].is_declaration_only());
        assert!(!metadata("ordinary")[0].is_declaration_only());
    }

    #[test]
    fn aliased_import_leaves_keep_the_statement_and_exact_binder_tokens() {
        let source = "from pkg import alpha as beta, beta as alpha\n";
        let parsed = parse(source);
        assert_eq!(parsed.imports.len(), 2);
        for (import, name) in parsed.imports.iter().zip(["beta", "alpha"]) {
            assert_eq!(import.path.as_ref().unwrap().declaration_start_byte, 0);
            let span = import.binder_span.as_ref().expect("exact alias binder");
            assert_eq!(&source[span.start_byte..span.end_byte], name);
        }
    }

    #[test]
    fn parameter_offsets_use_ast_tokens_instead_of_annotation_spelling() {
        let source = "@decorate(\"(first, second)\")\ndef call(first: Literal[\"second\"], second: int):\n    pass\n";
        let parsed = parse(source);
        let metadata = parsed
            .signature_metadata
            .values()
            .flatten()
            .find(|metadata| metadata.parameters().len() == 2)
            .expect("parameter metadata");
        let second = &metadata.parameters()[1];
        assert_eq!(
            &metadata.label()[second.start_byte()..second.end_byte()],
            "second"
        );
        assert_eq!(
            second.start_byte(),
            metadata.label().rfind("second:").unwrap()
        );
    }

    #[test]
    fn empty_and_recovered_python_publish_canonical_structural_facts() {
        for source in [
            "",
            "class Broken(:\n    pass\ndef valid(value):\n    return value\n",
        ] {
            let parsed = parse(source);
            let facts = parsed.source_facts.expect("complete producer publication");
            assert_eq!(facts.source_bytes, source.len());
            assert!(facts.python.is_some());
            assert_eq!(parsed.resolution_facts, Default::default());
            assert!(
                facts
                    .occurrences
                    .occurrences()
                    .iter()
                    .all(|occurrence| occurrence.range.end_byte <= source.len())
            );
        }
    }

    #[test]
    fn unmounted_annotated_functions_keep_source_declarations_and_return_facts() {
        let source = "if outer:\n    if inner:\n        def hidden(value: int) -> Hidden:\n            pass\n\ndef visible() -> Visible:\n    pass\n";
        let parsed = parse(source);
        let facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical Python facts");
        let python = facts.python.as_ref().expect("Python source facts");
        assert_eq!(python.callable_returns.len(), 2);

        let fact_named = |name: &str| {
            python
                .callable_returns
                .iter()
                .find(|fact| {
                    let declaration = facts.occurrences.declaration(fact.declaration);
                    let Some(name_occurrence) = declaration.name else {
                        return false;
                    };
                    let range = facts.occurrences.occurrence(name_occurrence).range;
                    &source[range.start_byte..range.end_byte] == name
                })
                .expect("callable return fact")
        };
        let hidden = fact_named("hidden");
        let hidden_declaration = facts.occurrences.declaration(hidden.declaration);
        let hidden_range = facts
            .occurrences
            .occurrence(hidden_declaration.occurrence)
            .range;
        assert_eq!(
            &source[hidden_range.start_byte..hidden_range.start_byte + 3],
            "def"
        );
        let hidden_annotation = hidden.return_annotation.expect("hidden annotation");
        let hidden_annotation_range = facts.occurrences.occurrence(hidden_annotation).range;
        assert_eq!(
            &source[hidden_annotation_range.start_byte..hidden_annotation_range.end_byte],
            "Hidden"
        );
        assert!(
            parsed
                .source_declaration_units
                .iter()
                .all(|(_, unit)| unit.short_name() != "hidden")
        );

        let visible = fact_named("visible");
        assert!(visible.return_annotation.is_some());
        assert!(visible.runtime_type.is_some());
        assert!(
            parsed
                .source_declaration_units
                .iter()
                .any(|(_, unit)| unit.short_name() == "visible")
        );
        let visible_metadata = parsed
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.short_name() == "visible")
            .and_then(|(_, metadata)| metadata.first())
            .expect("visible signature metadata");
        assert_eq!(visible_metadata.return_type_text(), Some("Visible"));
        assert_eq!(
            visible_metadata.return_type_identity(),
            visible.runtime_type.as_ref()
        );
    }

    #[test]
    fn return_fact_preserves_unsupported_annotation_without_runtime_identity() {
        let source = "def unsupported() -> Left | Right:\n    pass\n\ndef plain():\n    pass\n";
        let parsed = parse(source);
        let facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical Python facts");
        let python = facts.python.as_ref().expect("Python source facts");
        let by_name = |name: &str| {
            python
                .callable_returns
                .iter()
                .find(|fact| {
                    let declaration = facts.occurrences.declaration(fact.declaration);
                    let Some(name_occurrence) = declaration.name else {
                        return false;
                    };
                    let range = facts.occurrences.occurrence(name_occurrence).range;
                    &source[range.start_byte..range.end_byte] == name
                })
                .expect("callable return fact")
        };
        let unsupported = by_name("unsupported");
        assert!(unsupported.return_annotation.is_some());
        assert!(unsupported.runtime_type.is_none());
        let plain = by_name("plain");
        assert!(plain.return_annotation.is_none());
        assert!(plain.runtime_type.is_none());
    }

    #[test]
    fn return_annotation_references_preserve_runtime_owners() {
        let source = "def generic() -> list[User]:\n    pass\n\ndef nested() -> list[pkg.User]:\n    pass\n\ndef direct() -> pkg.User:\n    pass\n\ndef quoted() -> \"pkg.User\":\n    pass\n\ndef unsupported() -> Left | Right:\n    pass\n";
        let parsed = parse(source);
        let facts = parsed
            .source_facts
            .as_ref()
            .expect("canonical Python facts");
        let python = facts.python.as_ref().expect("Python source facts");
        let fact_named = |name: &str| {
            python
                .callable_returns
                .iter()
                .find(|fact| {
                    let declaration = facts.occurrences.declaration(fact.declaration);
                    let Some(name_occurrence) = declaration.name else {
                        return false;
                    };
                    let range = facts.occurrences.occurrence(name_occurrence).range;
                    &source[range.start_byte..range.end_byte] == name
                })
                .expect("callable return fact")
        };
        let generic = fact_named("generic");
        assert_eq!(
            generic
                .annotation_references
                .iter()
                .map(|reference| &reference.name)
                .collect::<Vec<_>>(),
            vec![&PythonAnnotationReferenceName::Lexical("list".to_string())]
        );

        // Generic arguments describe elements, not the returned runtime owner.
        let nested = fact_named("nested");
        assert_eq!(nested.annotation_references.len(), 1);
        assert!(matches!(
            &nested.annotation_references[0].name,
            PythonAnnotationReferenceName::Lexical(name) if name == "list"
        ));

        let direct = fact_named("direct");
        assert_eq!(direct.annotation_references.len(), 3);
        assert_eq!(direct.annotation_references[0].subtree_end, 3);
        assert_eq!(direct.annotation_references[0].lookup_depth, 1);
        assert!(matches!(
            &direct.annotation_references[0].name,
            PythonAnnotationReferenceName::Qualified(path)
                if path == &vec!["pkg".to_string(), "User".to_string()]
        ));

        let quoted = fact_named("quoted");
        assert_eq!(quoted.annotation_references.len(), 1);
        assert!(matches!(
            &quoted.annotation_references[0].name,
            PythonAnnotationReferenceName::Lexical(name) if name == "pkg.User"
        ));
        assert_eq!(quoted.annotation_references[0].lookup_depth, 2);

        let unsupported = fact_named("unsupported");
        assert!(
            unsupported
                .annotation_references
                .iter()
                .all(|reference| !matches!(
                    &reference.name,
                    PythonAnnotationReferenceName::Qualified(_)
                ))
        );
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
    while let Some(left) = node.child_by_field_name("left") {
        targets.push(left);
        match node.child_by_field_name("right") {
            Some(right) if right.kind() == "assignment" => node = right,
            _ => break,
        }
    }
    targets
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

#[cfg(test)]
mod callable_modifier_tests {
    use super::*;

    /// The Python half of #3451. Every declaration this walk mints as a
    /// callable states whether it binds an instance receiver, read from its own
    /// decorator and definition nodes: `@staticmethod` and `@classmethod`
    /// remove the receiver, every other `def` in a class body keeps it, and a
    /// module-level or async function has none to keep. `receiver_contract_of`
    /// reports no contract at all for a callable whose adapter never inspected
    /// modifiers, so without this every Python procedure key is refused.
    ///
    /// The kinds that are deliberately not keyable are asserted here with their
    /// reason, so the coverage is the walk's decision rather than an omission:
    ///
    /// - `@property` is a `Field`, because Python reads it as an attribute; a
    ///   member whose unit kind is not a callable minted no key before and does
    ///   not now.
    /// - `assigned = lambda ...` is a `Field` too: the module walk records the
    ///   assignment as a field and never mints a callable declaration for the
    ///   lambda, so there are no signature modifiers to read and nothing for a
    ///   reviewed summary to bind.
    /// - `inner`, a function defined inside another function's body, is a local
    ///   binding of its enclosing function rather than a member of any owner, so
    ///   this walk mints no declaration, no `SignatureMetadata`, and no
    ///   procedure key for it.
    #[test]
    fn callable_metadata_records_python_receiver_contracts_structurally() {
        let source = "def free(value):\n    return value\n\nclass Widget:\n    def __init__(self, spec):\n        self.spec = spec\n\n    def render(self, target):\n        return target\n\n    @staticmethod\n    def build(spec):\n        return spec\n\n    @classmethod\n    def measure(cls, target):\n        return target\n\n    @property\n    def label(self):\n        return \"widget\"\n\nasync def fetch_all(url):\n    return url\n\ndef outer(seed):\n    def inner(value):\n        return value\n    return inner(seed)\n\nassigned = lambda value: value\n";
        let file = ProjectFile::new(std::env::temp_dir(), "widget.py");
        let tree = parse_python_tree(source).expect("parse the Python fixture");
        let parsed = parse_python_file(&file, source, &tree);

        let entry = |fq_name: &str| {
            parsed
                .signature_metadata
                .iter()
                .find(|(unit, _)| unit.fq_name() == fq_name)
                .unwrap_or_else(|| {
                    panic!(
                        "missing Python declaration {fq_name}; recorded {:?}",
                        parsed
                            .signature_metadata
                            .keys()
                            .map(CodeUnit::fq_name)
                            .collect::<Vec<_>>()
                    )
                })
        };
        let modifiers = |fq_name: &str| {
            let (_, entries) = entry(fq_name);
            let metadata = entries
                .first()
                .unwrap_or_else(|| panic!("{fq_name} carries no signature metadata"));
            assert!(
                metadata.callable_modifiers_recorded(),
                "{fq_name} must record that the walk read its declaration shape"
            );
            (
                metadata.callable_is_static(),
                metadata.callable_is_constructor(),
                metadata.parameters().len(),
            )
        };

        assert_eq!(modifiers("widget.free"), (false, false, 1));
        assert_eq!(
            modifiers("widget.Widget.__init__"),
            (false, false, 2),
            "`__init__` is an ordinary instance method, exactly as Ruby's `initialize`"
        );
        assert_eq!(modifiers("widget.Widget.render"), (false, false, 2));
        assert_eq!(
            modifiers("widget.Widget.build"),
            (true, false, 1),
            "`@staticmethod` binds no instance receiver"
        );
        assert_eq!(
            modifiers("widget.Widget.measure"),
            (true, false, 2),
            "`@classmethod` receives the class, not an instance"
        );
        assert_eq!(
            modifiers("widget.fetch_all"),
            (false, false, 1),
            "an async def is the same function_definition node"
        );
        assert_eq!(modifiers("widget.outer"), (false, false, 1));

        let (property_unit, property_entries) = entry("widget.Widget.label");
        assert_eq!(
            property_unit.kind(),
            CodeUnitType::Field,
            "`@property` is read as an attribute, so it mints a Field and no key"
        );
        assert!(!property_unit.is_callable());
        assert!(
            property_entries
                .first()
                .expect("the property still carries signature metadata")
                .callable_modifiers_recorded(),
            "the shared metadata path records modifiers for every declaration it mints"
        );

        // The assignment walk records `assigned` as a field through
        // `add_signature`, which mints no `SignatureMetadata` at all, so there
        // are no callable modifiers to record and nothing a reviewed summary
        // could bind.
        let lambda_unit = parsed
            .declarations()
            .iter()
            .find(|unit| unit.fq_name() == "widget.assigned")
            .expect("the module walk still records the name-bound lambda's assignment");
        assert_eq!(
            lambda_unit.kind(),
            CodeUnitType::Field,
            "a name-bound lambda is recorded as a field, not as a callable declaration"
        );
        assert!(
            !parsed.signature_metadata.contains_key(lambda_unit),
            "a field assignment carries signature text but no callable signature metadata"
        );
        assert!(
            parsed
                .declarations()
                .iter()
                .all(|unit| unit.terminal_name() != "inner"),
            "a function nested in another function is a local binding, not a declaration"
        );
    }
}
