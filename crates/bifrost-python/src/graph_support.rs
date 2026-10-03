//! The language half of Python's resolution logic: module lookup, the export
//! index, the import binder, base-class resolution and the skeleton renderer,
//! written as free functions over a source trait instead of as methods on
//! `PythonAnalyzer`.
//!
//! `PythonAnalyzer` (in `brokk-bifrost-analysis`) owns the lazy cells (seven
//! moka caches, one `OnceLock` and two `PoolSafeMemo`s) and implements
//! [`PythonSource`] out of its own accessors, so the functions below
//! reach back for the memoized products they need without naming the analyzer
//! type.

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::prepared_syntax::{IndexedFileFacts, PreparedSyntaxTree};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

use crate::declarations::{
    collect_python_identifiers, module_code_unit, parse_python_tree, python_declared_import_root,
    python_import_root, python_module_name, python_project_module_components,
    python_repeated_root_extension_dir,
};
use crate::imports::{
    PythonImportDetails, python_import_details, python_namespace_binding_module,
    python_namespace_binding_name, resolve_exported_fqn, resolve_import_bindings,
    resolve_python_relative_module,
};
use crate::syntax::{python_plain_string_literal, python_static_attribute_path};
use crate::usage_index::PythonUsageIndex;

/// The analyzer-resident products Python's language logic resolves through, on
/// top of the two core capability traits it reads declarations and imports
/// with. The analyzer is the only implementor and every method forwards to one
/// of its own accessors, so the cells stay where they are and no free function
/// can reach past this surface.
///
/// The usage index is deliberately absent: [`PythonUsageIndex::build`] and
/// everything it calls take this trait, so the build cannot re-enter the memo
/// it is filling. Code that runs once the index exists takes
/// [`PythonUsageSource`].
pub trait PythonSource:
    CodeUnitIndex + ImportAnalysisProvider + crate::source_facts::PythonSourceFactProvider
{
    /// Path-derived module units for `module_fq`; `None` when the store could
    /// not answer the path-symbol query at all.
    fn path_module_fqn(&self, module_fq: &str) -> Option<Vec<CodeUnit>>;

    /// [`Self::path_module_fqn`] for a whole batch, resolved in one store
    /// transaction.
    fn path_module_fqns_batch(&self, module_fqs: &[String]) -> Vec<Option<Vec<CodeUnit>>>;

    fn definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// Every workspace Python module's project-root name, for resolving an
    /// absolute specifier written against a source root below the project root.
    ///
    /// Memoized for the analyzer generation by the implementor: the product is
    /// path math over the workspace file listing, and every import whose
    /// specifier names no indexed module asks for it.
    fn module_spellings(&self) -> Arc<PythonModuleSpellings>;

    /// Shared by handle: both products are immutable for the analyzer
    /// generation that cached them, and callers ask for them once per receiver
    /// type, annotation or export name, so deep-cloning the whole map out of
    /// the cache on every hit was pure waste.
    fn import_binder_of(&self, file: &ProjectFile) -> Arc<ImportBinder>;

    fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex>;

    /// The admitted active syntax for executable-body and use-site queries.
    /// Captured declaration properties are read from signature metadata.
    /// `None` is unavailable and does not authorize a declaration parser
    /// fallback. The token proves the request cache is live.
    fn prepared_syntax(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<PreparedSyntaxTree>>;

    /// Every file's indexed facts, visited in the analyzer's own bulk-read
    /// batches. `None` marks a file the index carries no record for.
    fn visit_file_facts(
        &self,
        files: &[ProjectFile],
        visit: &mut dyn FnMut(&ProjectFile, Option<&dyn IndexedFileFacts>),
    );
}

/// [`PythonSource`] plus the built usage index. Everything reached from
/// the export/importer walks needs it; the index build itself must not.
pub trait PythonUsageSource: PythonSource {
    fn usage_index(&self) -> Arc<PythonUsageIndex>;
}

pub fn extract_type_identifiers(source: &str) -> BTreeSet<String> {
    let Some(tree) = parse_python_tree(source) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    collect_python_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers.into_iter().collect()
}

/// Keep only the candidates an absolute import written in `importer` can mean.
///
/// A Python module name is path-derived and relative to an import root, so one
/// snapshot that vendors two distributions side by side spells the same module
/// twice: Feathr's `registry/purview-registry/registry/models.py` and
/// `registry/sql-registry/registry/models.py` are both `registry.models`
/// (#3475). Python resolves an absolute import against the `sys.path` entries
/// the importing program runs with, and the entry always on it is the root the
/// importing file itself lives under, so that root's module is the one the
/// import means. An enclosing root qualifies as well as the importer's own
/// package root, which is what lets a distribution's top-level script import
/// its own packages; when more than one qualifies, the nearest one shadows the
/// rest the way a closer `sys.path` entry does.
///
/// A candidate set that no containing root owns survives whole. That leaves a
/// genuine cross-root import resolvable and keeps the ambiguity visible to
/// whichever caller asked for a unique identity, rather than inventing a
/// preference the workspace does not state.
pub fn retain_modules_for_importer<T>(
    importer: &ProjectFile,
    candidates: &mut Vec<T>,
    source_of: impl Fn(&T) -> &ProjectFile,
) {
    retain_nearest_owning_root(importer, candidates, |candidate| {
        let source = source_of(candidate);
        debug_assert_eq!(
            importer.root(),
            source.root(),
            "one workspace's Python files share one project root"
        );
        python_import_root(source)
    });
}

/// The `sys.path`-entry shadowing rule on its own: keep the candidates whose
/// root contains `importer`, nearest first, and leave a set no candidate root
/// owns untouched.
///
/// Shared by the two ways a candidate gets a root. A candidate found by its
/// identity has the root [`python_import_root`] named for it; a candidate found
/// by [`PythonModuleSpellings`] has the root the specifier was written against.
/// Both are resolved against the importing program's path the same way.
fn retain_nearest_owning_root<T>(
    importer: &ProjectFile,
    candidates: &mut Vec<T>,
    root_of: impl Fn(&T) -> PathBuf,
) {
    if candidates.len() < 2 {
        return;
    }
    let owning_depth = |candidate: &T| {
        let root = root_of(candidate);
        importer
            .rel_path()
            .starts_with(&root)
            .then(|| root.components().count())
    };
    let depths = candidates.iter().map(owning_depth).collect::<Vec<_>>();
    let Some(nearest) = depths.iter().copied().flatten().max() else {
        return;
    };
    *candidates = std::mem::take(candidates)
        .into_iter()
        .zip(depths)
        .filter(|(_, depth)| *depth == Some(nearest))
        .map(|(candidate, _)| candidate)
        .collect();
}

/// One workspace Python module, named from the project root.
#[derive(Clone, Debug)]
struct ProjectRootModuleName {
    file: ProjectFile,
    components: Vec<String>,
}

/// A module whose project-root name *ends with* an absolute specifier, and the
/// source root that spelling would have to be written against.
///
/// This is candidate evidence, not binding evidence: a tail match only says the
/// file could be the module if its implied root were on the importing program's
/// path. [`PythonModuleSpellings::establishes_source_root`] decides whether the
/// workspace's own structure makes that root real, and only an established
/// candidate ever binds.
#[derive(Clone, Debug)]
pub struct PythonSourceRootModule {
    pub file: ProjectFile,
    /// The directory the specifier is resolved against: `file`'s relative path
    /// with the specifier's own components removed. Never empty, because the
    /// project root is the spelling the module index already answers exactly.
    pub source_root: PathBuf,
}

/// Every workspace Python module's project-root name, keyed by its last
/// component.
///
/// A Python module name is path-derived and relative to a `sys.path` entry, so
/// one file has one valid absolute name per ancestor directory on that path:
/// `dependency/core/lib/common/__init__.py` is `dependency.core.lib.common`
/// from the project root and `core.lib.common` from `dependency/`, which is the
/// entry dayu's `PYTHONPATH` adds and the only one its sources ever write
/// (#3506). Exactly one of those names is the module's identity, so an import
/// written against any other root has to be matched against the *end* of the
/// project-root name. The last component is the one part every name of a module
/// shares, so it is the key.
///
/// Built from path math over the workspace file listing: no parse, no store
/// read, and no `sys.path` guess -- a candidate only ever comes back paired
/// with the root that would have to be on the path for it to be the answer.
/// The same listing states which directories are packages, which is the
/// evidence a root without a packaging declaration is established by. A root
/// below a packaging declaration is established by the one thing the listing
/// cannot state -- the package marker's own `__path__` extension -- so those
/// markers, and only the markers that could state one, are read.
#[derive(Debug, Default)]
pub struct PythonModuleSpellings {
    by_last_component: HashMap<String, Vec<ProjectRootModuleName>>,
    /// Every directory of the snapshot that holds an `__init__.py`, i.e. every
    /// package directory the workspace states.
    package_dirs: HashSet<PathBuf>,
    /// The directories a package marker adds to its own `__path__`, by the
    /// package directory that states them, once the statements a later
    /// `__path__` assignment replaces are dropped.
    ///
    /// `rtdetr_pose/__init__.py` appending `rtdetr_pose/rtdetr_pose` is what
    /// makes the shorter spelling `rtdetr_pose.config` name the file the
    /// declared root already names `rtdetr_pose.rtdetr_pose.config`, and it is
    /// the only thing that does: the repeated directory name, and the empty
    /// markers that make the directories packages, state nothing -- nor does
    /// an append in a branch that never runs, one whose guard another branch
    /// holds, or one a later `__path__ = ...` discards (#3506).
    path_extensions: HashMap<PathBuf, HashSet<PathBuf>>,
}

impl PythonModuleSpellings {
    /// Index the snapshot's Python files.
    ///
    /// `read_source` answers a file's bytes from the same snapshot the listing
    /// came from -- the project's own read, so an overlay's unsaved marker text
    /// is what the evidence sees -- and is called only for markers that can
    /// state a path extension.
    pub fn build(
        files: impl IntoIterator<Item = ProjectFile>,
        mut read_source: impl FnMut(&ProjectFile) -> Option<String>,
    ) -> Self {
        let mut by_last_component: HashMap<String, Vec<ProjectRootModuleName>> = HashMap::default();
        let mut package_dirs: HashSet<PathBuf> = HashSet::default();
        let mut package_markers: Vec<ProjectFile> = Vec::new();
        for file in files {
            if file.rel_path().file_name().and_then(|name| name.to_str()) == Some("__init__.py")
                && let Some(directory) = file.rel_path().parent()
            {
                package_dirs.insert(directory.to_path_buf());
                package_markers.push(file.clone());
            }
            let components = python_project_module_components(&file);
            let Some(last) = components.last() else {
                continue;
            };
            by_last_component
                .entry(last.clone())
                .or_default()
                .push(ProjectRootModuleName { file, components });
        }
        let mut path_extensions: HashMap<PathBuf, HashSet<PathBuf>> = HashMap::default();
        for marker in package_markers {
            let Some(directory) = marker.rel_path().parent() else {
                continue;
            };
            if !python_package_holds_a_repeat_of_itself(directory, &package_dirs) {
                continue;
            }
            let Some(source) = read_source(&marker) else {
                continue;
            };
            let extended = python_appended_path_dirs(&source, marker.rel_path());
            if !extended.is_empty() {
                path_extensions
                    .entry(directory.to_path_buf())
                    .or_default()
                    .extend(extended);
            }
        }
        Self {
            by_last_component,
            package_dirs,
            path_extensions,
        }
    }

    /// The modules whose project-root name ends with `module_fq`, each with the
    /// source root that would make the shorter name the right one.
    ///
    /// The project-root name itself is deliberately absent: that one is the
    /// module's identity, which the module index answers exactly, so this
    /// reports only the additional names and only for a dotted specifier. A
    /// single-component specifier names a top-level module, every top-level
    /// workspace module is already named from the project root, and a bare name
    /// that merely matches the last component of a deeper module is a
    /// coincidence rather than a source root -- the stdlib `typing` must not
    /// resolve to a workspace's own `seaborn._core.typing`.
    pub fn suffix_candidates(&self, module_fq: &str) -> Vec<PythonSourceRootModule> {
        // A leading dot makes the specifier relative to the importing file's own
        // package, which `resolve_python_relative_module` resolves before any
        // lookup; no `sys.path` entry takes part in it.
        if module_fq.starts_with('.') {
            return Vec::new();
        }
        let components = parse_symbol_path(Language::Python, module_fq);
        let Some(last) = components.last().filter(|_| components.len() > 1) else {
            return Vec::new();
        };
        let mut modules = Vec::new();
        for candidate in self
            .by_last_component
            .get(last.as_str())
            .into_iter()
            .flatten()
        {
            // A proper suffix only, so a shorter or equal-length name cannot
            // match: an equal one is the identity this does not answer.
            let Some(dropped) = candidate
                .components
                .len()
                .checked_sub(components.len())
                .filter(|dropped| *dropped > 0)
            else {
                continue;
            };
            if candidate.components[dropped..] != components[..] {
                continue;
            }
            // The dropped components are the leading directories of the file's
            // own relative path, so they are the source root exactly.
            let source_root: PathBuf = candidate
                .file
                .rel_path()
                .components()
                .take(dropped)
                .collect();
            debug_assert!(
                !source_root.as_os_str().is_empty(),
                "dropping a component of {:?} leaves a directory",
                candidate.file.rel_path()
            );
            modules.push(PythonSourceRootModule {
                file: candidate.file.clone(),
                source_root,
            });
        }
        modules
    }

    /// Whether the workspace's own structure establishes `candidate`'s implied
    /// source root as a root the candidate's specifier can be written against.
    ///
    /// Two kinds of evidence count, and a candidate with neither stays only a
    /// candidate.
    ///
    /// A packaging manifest that declares a root for the candidate's file
    /// (`tool.setuptools.packages.find.where`, `setup.py`'s `package_dir`) is
    /// the workspace stating the root itself, and it is authoritative for the
    /// files below it: the specifier is then the file's declared module name
    /// and nowhere else. `source/realpkg/vendor/api.py` under
    /// `where = ["source"]` is `realpkg.vendor.api`, so `vendor.api` -- whose
    /// implied root is `source/realpkg` -- does not name it, even though a
    /// package chain runs from that implied root down to it. A declaration of
    /// the project root counts the same way: `where = ["."]` is the workspace
    /// saying its packages begin at the project root, which is not the same as
    /// saying nothing, so `otherpkg/vendor/api.py` is `otherpkg.vendor.api` and
    /// `vendor.api` -- whose implied root is `otherpkg`, a package the
    /// declaration names -- does not name it either (#3506).
    ///
    /// A declaration leaves one shorter spelling open, the double-nested
    /// distribution directory, because there the specifier writes the implied
    /// root's own name again before the module's path:
    /// `rtdetr_pose/rtdetr_pose/config.py` is `rtdetr_pose.config` from
    /// `rtdetr_pose/`. The shape is not the evidence, because it is only a
    /// repeated directory name: the package the specifier starts from has to
    /// state that the repeated directory is on its search path, by adding it to
    /// its own `__path__` in its `__init__.py`
    /// ([`python_repeated_root_extension_dir`] names the directory that
    /// statement has to name), and the statement has to be one the interpreter
    /// runs and keeps: an append behind `if False:` and an append a later
    /// `__path__ = ...` replaces are not that statement. With that statement,
    /// and only with it, the declared root keeps admitting the spelling; the
    /// module still has to be reached through a real package chain from the
    /// implied root.
    ///
    /// Without a declaration the evidence has to be the snapshot's own package
    /// chain: every directory from the implied root down to the candidate's own
    /// directory must hold an `__init__.py`, so the specifier names a complete
    /// package/module chain that starts at that root. This is what
    /// `dependency/core/lib/common/__init__.py` has for `core.lib.common` when
    /// `dependency/` is on `PYTHONPATH`, and what
    /// `rtdetr_pose/rtdetr_pose/config.py` has for `rtdetr_pose.config` in a
    /// project that declares no packages at all. A bare tail match with no
    /// chain behind it is not proof of a root and never binds (#3506).
    pub fn establishes_source_root(&self, candidate: &PythonSourceRootModule) -> bool {
        if let Some(declared) = python_declared_import_root(&candidate.file) {
            if declared == candidate.source_root {
                return true;
            }
            let Some(extension) = python_repeated_root_extension_dir(
                &candidate.file,
                &candidate.source_root,
                &declared,
            ) else {
                return false;
            };
            return self.package_chain_reaches_module(candidate)
                && self
                    .path_extensions
                    .get(&candidate.source_root)
                    .is_some_and(|extended| extended.contains(&extension));
        }
        self.package_chain_reaches_module(candidate)
    }

    /// Whether a complete `__init__.py` package chain runs from the candidate's
    /// implied source root down to its own module.
    ///
    /// This is the snapshot's own evidence that the implied root is a root the
    /// specifier can be written against: every directory from it down to the
    /// file's directory is a package the workspace states, so the written name
    /// runs through that package chain rather than through a coincidence of the
    /// file's last path component.
    fn package_chain_reaches_module(&self, candidate: &PythonSourceRootModule) -> bool {
        debug_assert!(
            candidate
                .file
                .rel_path()
                .starts_with(&candidate.source_root),
            "a candidate's implied root is a prefix of its own path"
        );
        let mut directory = candidate.file.rel_path().parent();
        while let Some(current) = directory {
            if !self.package_dirs.contains(current) {
                return false;
            }
            if current == candidate.source_root {
                return true;
            }
            directory = current.parent();
        }
        false
    }
}

/// Whether `directory` is a package that holds a directory of its own name
/// which is also a package.
///
/// This is the only layout a package marker has a repeated spelling to extend
/// `__path__` for, and it is a name-only question the listing answers, so the
/// markers whose source could state a path extension are the only ones ever
/// read (#3506).
fn python_package_holds_a_repeat_of_itself(
    directory: &Path,
    package_dirs: &HashSet<PathBuf>,
) -> bool {
    directory
        .file_name()
        .is_some_and(|name| package_dirs.contains(&directory.join(name)))
}

/// The project-relative directories the package marker `marker_rel_path` adds
/// to its own `__path__` and keeps there for the imports that follow.
///
/// The pinned YOLOZU shim states
/// `__path__.append(os.path.join(os.path.dirname(__file__), "rtdetr_pose"))`,
/// behind `if _impl not in __path__:`, and that executed statement -- not the
/// nested directory's repeated name -- is what makes `rtdetr_pose.config` name
/// `rtdetr_pose/rtdetr_pose/config.py`. Every part is recovered from AST
/// fields: a name is the assignment that bound it, `__file__` is the marker's
/// own path, `os.path.dirname` takes the parent and `os.path.join` joins. A
/// statement a later `__path__ = ...` replaces contributes nothing, and a
/// statement no shape shows the interpreter runs contributes nothing either,
/// so an unfamiliar spelling of the same idea is a missing positive rather
/// than a wrong one.
fn python_appended_path_dirs(source: &str, marker_rel_path: &Path) -> Vec<PathBuf> {
    let Some(tree) = parse_python_tree(source) else {
        return Vec::new();
    };
    let mut bound: HashMap<String, PathBuf> = HashMap::default();
    bound.insert("__file__".to_owned(), marker_rel_path.to_path_buf());
    let mut appended: Vec<PathBuf> = Vec::new();
    walk_named_tree_preorder(tree.root_node(), true, |node| {
        match node.kind() {
            // Only module-level code runs the extension, so a name bound inside
            // a function or class body says nothing about what `__path__`
            // holds after the marker is executed.
            "function_definition" | "class_definition" | "lambda" => {
                return WalkControl::SkipChildren;
            }
            "assignment" => {
                // A marker runs from the top, so a statement that assigns
                // `__path__` throws away every directory appended before it:
                // however many appends came first, `__path__ = [_base]` is the
                // list the imports that follow will search.
                if python_names_path(node.child_by_field_name("left"), source) {
                    appended.clear();
                }
                python_bind_assignment(node, source, &mut bound);
            }
            "call" => {
                let directories = python_path_appended_dirs_in_call(node, source, &bound);
                if directories.is_empty()
                    || !python_extension_statement_runs(node, source, &bound, &directories)
                {
                    return WalkControl::Continue;
                }
                for directory in directories {
                    if directory.is_relative()
                        && !directory.as_os_str().is_empty()
                        && !appended.contains(&directory)
                    {
                        appended.push(directory);
                    }
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
    appended
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
    bound: &HashMap<String, PathBuf>,
    directories: &[PathBuf],
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
    bound: &HashMap<String, PathBuf>,
    directories: &[PathBuf],
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
    bound: &mut HashMap<String, PathBuf>,
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
    bound: &HashMap<String, PathBuf>,
) -> Vec<PathBuf> {
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
        "extend" => match arguments.first() {
            Some(list) if list.kind() == "list" => {
                let mut cursor = list.walk();
                list.named_children(&mut cursor).collect()
            }
            Some(iterator) => vec![*iterator],
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    named
        .into_iter()
        .filter_map(|node| python_path_expression_dir(node, source, bound))
        .collect()
}

/// The project-relative directory a marker's own expression denotes under the
/// names it has bound so far: a plain string literal, a bound name, or the
/// `os.path` call that computes a directory from them.
fn python_path_expression_dir(
    node: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    if let Some(literal) = python_plain_string_literal(node, source) {
        let directory = PathBuf::from(literal);
        return (!directory.as_os_str().is_empty()).then_some(directory);
    }
    match node.kind() {
        "identifier" => bound.get(node.utf8_text(source.as_bytes()).ok()?).cloned(),
        "call" => python_path_call_dir(node, source, bound),
        _ => None,
    }
}

/// The directory one `os.path.dirname(...)` or `os.path.join(...)` call
/// computes.
fn python_path_call_dir(
    call: Node<'_>,
    source: &str,
    bound: &HashMap<String, PathBuf>,
) -> Option<PathBuf> {
    let path = python_static_attribute_path(call.child_by_field_name("function")?)?;
    let names: Vec<&str> = path
        .iter()
        .map(|node| node.utf8_text(source.as_bytes()).ok())
        .collect::<Option<Vec<_>>>()?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let arguments: Vec<Node<'_>> = arguments.named_children(&mut cursor).collect();
    match names.as_slice() {
        ["os", "path", "dirname"] => {
            let directory = python_path_expression_dir(*arguments.first()?, source, bound)?;
            Some(directory.parent()?.to_path_buf())
        }
        ["os", "path", "join"] => {
            let mut parts = arguments.iter();
            let mut joined = python_path_expression_dir(*parts.next()?, source, bound)?;
            for part in parts {
                joined.push(python_path_expression_dir(*part, source, bound)?);
            }
            Some(joined)
        }
        _ => None,
    }
}

/// The module `module_fq` names, as written in `importer`.
///
/// `importer` is `None` for an FQN-level question that no import statement
/// asked -- a dotted name looked up on its own has no import root to be
/// resolved against. With an importer the candidates are narrowed by
/// [`retain_modules_for_importer`] first, and a specifier the index holds under
/// no name at all falls through to [`module_under_source_root`].
pub fn resolve_module_code_unit(
    python: &dyn PythonSource,
    importer: Option<&ProjectFile>,
    module_fq: &str,
) -> Option<CodeUnit> {
    let indexed = match python.path_module_fqn(module_fq) {
        // A path lookup that succeeds but finds no module unit is an answer:
        // it does not fall through to the definition lookup.
        Some(units) => indexed_module_for_importer(importer, units),
        None => indexed_module_for_importer(importer, python.definition_fqn(module_fq)),
    };
    match indexed {
        IndexedModuleLookup::Unique(module) => Some(module),
        // The index spells the specifier more than once and the workspace does
        // not say which of them the import means. A tail match elsewhere names
        // a different module, so it cannot break this tie.
        IndexedModuleLookup::Ambiguous => None,
        IndexedModuleLookup::Missing => {
            let importer = importer?;
            module_under_source_root(&python.module_spellings(), importer, module_fq)
        }
    }
}

/// What the exact index says about a module specifier, before any source-root
/// inference runs.
///
/// The three cases are kept apart because only one of them may fall through to
/// the source-root candidates. A specifier the index spells exactly but several
/// times is an ambiguity of identity (#3475): answering it with a suffix
/// candidate that happens to end in the same name would replace a module the
/// import names with an unrelated one the workspace never offered.
enum IndexedModuleLookup {
    Unique(CodeUnit),
    Ambiguous,
    Missing,
}

fn indexed_module_for_importer(
    importer: Option<&ProjectFile>,
    units: Vec<CodeUnit>,
) -> IndexedModuleLookup {
    let mut modules = units
        .into_iter()
        .filter(CodeUnit::is_module)
        .collect::<Vec<_>>();
    if let Some(importer) = importer {
        retain_modules_for_importer(importer, &mut modules, CodeUnit::source);
    }
    match modules.len() {
        0 => IndexedModuleLookup::Missing,
        1 => IndexedModuleLookup::Unique(modules.remove(0)),
        _ => IndexedModuleLookup::Ambiguous,
    }
}

/// The file an absolute `module_fq` names when it is written against a source
/// root the workspace's own structure establishes.
///
/// Python resolves an absolute import against the `sys.path` entries the
/// importing program runs with. A workspace states the project root and its
/// packaging roots, and [`python_import_root`] names modules from those; it does
/// not state an entry only `PYTHONPATH` adds -- dayu's `dependency/`, whose
/// `core.lib.common` is indexed as `dependency.core.lib.common` -- and a
/// distribution directory holding a same-named package makes the inner package
/// importable under both spellings, so YOLOZU's `rtdetr_pose/rtdetr_pose` is
/// indexed as `rtdetr_pose.rtdetr_pose.config` and written as
/// `rtdetr_pose.config` (#3506).
///
/// A tail match alone is not that evidence: `source/realpkg/vendor/api.py`
/// ends in `vendor/api.py`, but under `where = ["source"]` it is
/// `realpkg.vendor.api` and nothing else. What establishes a root is the
/// snapshot's own structure -- a packaging manifest that declares it, or a
/// complete `__init__.py` package chain from it down to the module -- and only
/// a candidate whose implied root is established that way binds.
/// [`PythonModuleSpellings::establishes_source_root`] is that decision; the
/// candidates it rejects stay visible to the diagnostics as the spellings the
/// workspace does index, which is a resolution gap and not externality.
///
/// Uniqueness is required after the same nearest-root narrowing an indexed
/// module gets: two workspace copies of one module are an ambiguity the
/// workspace does not resolve, and choosing between them here would invent a
/// preference it never stated (#3475's rule, applied to the roots it cannot
/// see).
pub fn python_module_file_under_source_root(
    spellings: &PythonModuleSpellings,
    importer: &ProjectFile,
    module_fq: &str,
) -> Option<ProjectFile> {
    let mut candidates = spellings.suffix_candidates(module_fq);
    retain_nearest_owning_root(importer, &mut candidates, |candidate| {
        candidate.source_root.clone()
    });
    candidates.retain(|candidate| spellings.establishes_source_root(candidate));
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    debug_assert_eq!(
        importer.root(),
        candidate.file.root(),
        "one workspace's Python files share one project root"
    );
    Some(candidate.file.clone())
}

/// [`python_module_file_under_source_root`] as the module unit the store-backed
/// resolvers answer with. The unit is built from the file's own path, which is
/// where its identity comes from, so it is the same unit the path-symbol index
/// holds for that file.
fn module_under_source_root(
    spellings: &PythonModuleSpellings,
    importer: &ProjectFile,
    module_fq: &str,
) -> Option<CodeUnit> {
    let file = python_module_file_under_source_root(spellings, importer, module_fq)?;
    module_code_unit(&file, &python_module_name(&file))
}

/// Batched sibling of `resolve_module_code_unit`: resolves every FQN's path-symbol lookup in one
/// store transaction instead of one per FQN, then falls back to the (unbatched, rarer)
/// definition-lookup path per FQN exactly as the single-FQN version does. Preserves its per-item
/// semantics precisely, including that a path lookup which succeeds but finds no module unit does
/// *not* fall through to the definition lookup.
pub fn resolve_module_code_units_batch(
    python: &dyn PythonSource,
    importer: Option<&ProjectFile>,
    module_fqs: &[String],
) -> Vec<Option<CodeUnit>> {
    let path_results = python.path_module_fqns_batch(module_fqs);
    let mut lookups: Vec<IndexedModuleLookup> = Vec::with_capacity(module_fqs.len());
    let mut needs_definition_fallback = Vec::new();
    for (i, units) in path_results.into_iter().enumerate() {
        match units {
            Some(units) => lookups.push(indexed_module_for_importer(importer, units)),
            None => {
                needs_definition_fallback.push(i);
                // Placeholder, replaced by the definition lookup below.
                lookups.push(IndexedModuleLookup::Missing);
            }
        }
    }
    for i in needs_definition_fallback {
        lookups[i] = indexed_module_for_importer(importer, python.definition_fqn(&module_fqs[i]));
    }
    let mut results: Vec<Option<CodeUnit>> = vec![None; module_fqs.len()];
    let mut needs_source_root = Vec::new();
    for (i, lookup) in lookups.into_iter().enumerate() {
        match lookup {
            IndexedModuleLookup::Unique(module) => results[i] = Some(module),
            IndexedModuleLookup::Ambiguous => {}
            IndexedModuleLookup::Missing => needs_source_root.push(i),
        }
    }
    if let Some(importer) = importer
        && !needs_source_root.is_empty()
    {
        // One memo handle for the whole batch: a workspace's external imports
        // all miss the index, so this arm runs for most of the batch.
        let spellings = python.module_spellings();
        for i in needs_source_root {
            results[i] = module_under_source_root(&spellings, importer, &module_fqs[i]);
        }
    }
    results
}

pub fn compute_export_index_of(
    python: &dyn PythonSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let mut events = Vec::new();
    let declarations = python.top_level_declarations(file);
    collect_local_export_events(
        declarations.iter(),
        |code_unit| {
            python
                .ranges(code_unit)
                .iter()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX)
        },
        &mut events,
    );

    let imports = python.import_info_of(token, file);
    collect_reexport_events_from_imports(python, file, &imports, &mut events, &mut index);

    finish_export_index(events, index)
}

pub fn export_index_from_file_facts(
    python: &dyn PythonSource,
    file: &ProjectFile,
    facts: &dyn IndexedFileFacts,
    module_name: &str,
) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let mut events = Vec::new();
    collect_local_export_events(
        facts.top_level_declarations().iter(),
        |code_unit| {
            facts
                .declaration_ranges(code_unit)
                .into_iter()
                .flatten()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX)
        },
        &mut events,
    );

    if !facts
        .top_level_declarations()
        .iter()
        .any(CodeUnit::is_module)
        && let Some(identifier) = module_name.rsplit('.').next()
        && !identifier.is_empty()
        && !identifier.starts_with('_')
    {
        events.push((
            0,
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        ));
    }

    collect_reexport_events_from_imports(python, file, facts.imports(), &mut events, &mut index);

    finish_export_index(events, index)
}

fn collect_local_export_events<'a>(
    declarations: impl IntoIterator<Item = &'a CodeUnit>,
    mut start_byte: impl FnMut(&CodeUnit) -> usize,
    events: &mut Vec<(usize, String, ExportEntry)>,
) -> HashSet<String> {
    let mut local_names = HashSet::default();
    for code_unit in declarations {
        let identifier = code_unit.identifier().trim();
        if identifier.is_empty() {
            continue;
        }
        local_names.insert(identifier.to_string());
        events.push((
            start_byte(code_unit),
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        ));
    }
    local_names
}

fn finish_export_index(
    mut events: Vec<(usize, String, ExportEntry)>,
    mut index: ExportIndex,
) -> ExportIndex {
    events.sort_by_key(|(start_byte, _, _)| *start_byte);
    for (_, exported_name, entry) in events {
        index.exports_by_name.insert(exported_name, entry);
    }
    index
}

fn collect_reexport_events_from_imports(
    python: &dyn PythonSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
    events: &mut Vec<(usize, String, ExportEntry)>,
    index: &mut ExportIndex,
) {
    for import in imports {
        if import
            .path
            .as_ref()
            .is_none_or(|path| !path.lexical_scopes.is_empty())
        {
            continue;
        }
        record_single_reexport_event(python, file, import, events, index);
    }
}

fn record_single_reexport_event(
    python: &dyn PythonSource,
    file: &ProjectFile,
    import: &ImportInfo,
    events: &mut Vec<(usize, String, ExportEntry)>,
    index: &mut ExportIndex,
) {
    let Some(PythonImportDetails::FromImport {
        module,
        name,
        alias,
        wildcard,
    }) = python_import_details(import)
    else {
        return;
    };
    let start_byte = import
        .path
        .as_ref()
        .map(|path| path.declaration_start_byte)
        .unwrap_or(usize::MAX);
    let resolved_module = if module.starts_with('.') {
        resolve_python_relative_module(file, &module)
    } else {
        Some(module.clone())
    };
    let Some(resolved_module) = resolved_module else {
        return;
    };

    if wildcard {
        index.reexport_stars.push(ReexportStar {
            module_specifier: resolved_module,
        });
        return;
    }
    let exported_name = alias.unwrap_or(name.clone());
    // `from P import S` binds the submodule `P.S` itself when that module
    // exists, exactly as the import binder reads it below. Recording it as
    // "the name S inside module P.S" would follow the subpackage's own
    // exports, which silently mis-resolves whenever the subpackage re-exports
    // a member named after itself (issue #1762).
    let module_candidate = format!("{resolved_module}.{name}");
    if resolve_module_code_unit(python, Some(file), &module_candidate).is_some() {
        events.push((
            start_byte,
            exported_name,
            ExportEntry::ReexportedModule {
                module_specifier: module_candidate,
            },
        ));
        return;
    }
    events.push((
        start_byte,
        exported_name,
        ExportEntry::ReexportedNamed {
            module_specifier: resolved_module,
            imported_name: name,
        },
    ));
}

pub fn import_binder_from_imports(
    python: &dyn PythonSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> ImportBinder {
    let mut binder = ImportBinder::empty();

    for (local_name, binding) in import_bindings_from_imports(python, file, imports) {
        binder.bindings.insert(local_name, binding);
    }

    binder
}

/// Resolve each structured import without collapsing repeated local names.
///
/// Candidate discovery needs every lexical binding. The ordinary binder keeps
/// one effective binding for simple lookups.
pub fn import_bindings_from_imports(
    python: &dyn PythonSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Vec<(String, ImportBinding)> {
    let mut bindings = Vec::new();

    for import in imports {
        let Some(details) = python_import_details(import) else {
            continue;
        };
        match details {
            PythonImportDetails::Import { module, alias } => {
                let local_name = python_namespace_binding_name(import, alias.as_deref(), &module);
                let module_specifier =
                    python_namespace_binding_module(import, alias.as_deref(), &module);
                bindings.push((
                    local_name,
                    ImportBinding {
                        module_specifier,
                        namespace_imported_module: Some(module),
                        kind: ImportKind::Namespace,
                        imported_name: None,
                    },
                ));
            }
            PythonImportDetails::FromImport {
                module,
                name,
                wildcard,
                ..
            } => {
                let resolved_module = if module.starts_with('.') {
                    resolve_python_relative_module(file, &module)
                } else {
                    Some(module.clone())
                };
                let Some(resolved_module) = resolved_module else {
                    continue;
                };
                if wildcard {
                    // A glob import introduces each public declaration as a
                    // real local binding. Expand it from the structured module
                    // declarations so constructor and receiver inference can
                    // resolve the same names Python places in the namespace.
                    bindings.extend(
                        public_declarations_in_module(python, file, &resolved_module)
                            .into_iter()
                            .map(|declaration| {
                                let name = declaration.identifier().to_string();
                                (
                                    name.clone(),
                                    ImportBinding {
                                        module_specifier: resolved_module.clone(),
                                        namespace_imported_module: None,
                                        kind: ImportKind::Named,
                                        imported_name: Some(name),
                                    },
                                )
                            }),
                    );
                    continue;
                }
                // Non-wildcard from-imports always populate `identifier`
                // as `alias ?? name` (see `python_import_details`), so
                // `local_name()` reproduces the same alias-first fallback
                // without re-deriving it here.
                let local_name = import
                    .local_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| name.clone());
                let module_candidate = format!("{resolved_module}.{name}");
                if resolve_module_code_unit(python, Some(file), &module_candidate).is_some() {
                    bindings.push((
                        local_name,
                        ImportBinding {
                            module_specifier: module_candidate,
                            namespace_imported_module: None,
                            kind: ImportKind::Namespace,
                            imported_name: None,
                        },
                    ));
                    continue;
                }
                bindings.push((
                    local_name,
                    ImportBinding {
                        module_specifier: resolved_module,
                        namespace_imported_module: None,
                        kind: ImportKind::Named,
                        imported_name: Some(name),
                    },
                ));
            }
        }
    }

    bindings
}

pub fn public_declarations_in_module(
    python: &dyn PythonSource,
    importer: &ProjectFile,
    module_fq: &str,
) -> Vec<CodeUnit> {
    let Some(module_code_unit) = resolve_module_code_unit(python, Some(importer), module_fq) else {
        return Vec::new();
    };
    python
        .direct_children(&module_code_unit)
        .into_iter()
        .filter(|code_unit| !code_unit.identifier().starts_with('_'))
        .collect()
}

pub fn resolve_base_class(
    python: &dyn PythonSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let binder = python.import_binder_of(code_unit.source());
    if let Some((head, tail)) = trimmed.split_once('.') {
        if let Some(binding) = binder.bindings.get(head)
            && binding.kind == ImportKind::Namespace
        {
            let fq_name = format!("{}.{}", binding.module_specifier, tail);
            return python.definitions(&fq_name).next();
        }
        return python.definitions(trimmed).next();
    }

    if let Some(binding) = binder.bindings.get(trimmed) {
        match binding.kind {
            ImportKind::Namespace => {
                return resolve_module_code_unit(
                    python,
                    Some(code_unit.source()),
                    &binding.module_specifier,
                );
            }
            ImportKind::Named => {
                let imported_name = binding.imported_name.as_ref()?;
                let fqn = format!("{}.{}", binding.module_specifier, imported_name);
                return resolve_exported_fqn(python, Some(code_unit.source()), &fqn)
                    .into_iter()
                    .next()
                    .or_else(|| python.definitions(&fqn).next());
            }
            _ => {}
        }
    }

    if python
        .import_info_of(token, code_unit.source())
        .iter()
        .any(|import| import.is_wildcard)
        && let Some(imported) =
            resolve_import_bindings(python, token, code_unit.source()).get(trimmed)
    {
        return Some(imported.clone());
    }

    let local_fq_name = format!("{}.{}", code_unit.package_name(), trimmed);
    python
        .definitions(&local_fq_name)
        .next()
        .or_else(|| python.definitions(trimmed).next())
}

pub fn render_skeleton_recursive(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    indent: &str,
    header_only: bool,
    out: &mut String,
) {
    enum Work {
        Declaration(CodeUnit, String),
        Elision(String),
    }
    let mut stack = vec![Work::Declaration(code_unit.clone(), indent.to_string())];
    while let Some(work) = stack.pop() {
        let Work::Declaration(unit, indent) = work else {
            let Work::Elision(indent) = work else {
                unreachable!()
            };
            out.push_str(&indent);
            out.push_str("[...]\n");
            continue;
        };
        if !unit.is_module()
            && !unit.is_file_scope()
            && let Some(signature) = index.signatures(&unit).first()
        {
            // A property's declaration label is callable-shaped, but the
            // skeleton has always displayed its header as a field.
            let signature = if unit.is_field() {
                signature.strip_suffix(" ...").unwrap_or(signature)
            } else {
                signature
            };
            for line in signature.lines() {
                out.push_str(&indent);
                out.push_str(line);
                out.push('\n');
            }
        }
        let children = index.direct_children(&unit);
        let child_indent = format!("{indent}  ");
        if header_only && children.iter().any(|child| !child.is_field()) {
            stack.push(Work::Elision(child_indent.clone()));
        }
        for child in children
            .into_iter()
            .rev()
            .filter(|child| !header_only || child.is_field())
        {
            stack.push(Work::Declaration(child, child_indent.clone()));
        }
    }
}
