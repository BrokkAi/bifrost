//! Query-local, bounded may-escape discovery for saved Python defaults.
//!
//! Import binders and exact direct callees do not expose a function object.
//! Other value reads do. Namespace edges are joined after all files have been
//! collected, so reexports and package attachments do not depend on file order.

use crate::analyzer::python::PythonAnalyzer;

use crate::analyzer::python::default_arguments::MAX_METADATA_SCAN_FILE_BYTES;

use crate::analyzer::python::default_arguments::MAX_SAVED_DEFAULT_FUNCTIONS_PER_KIND;

use crate::analyzer::python::default_arguments::consume;

use brokk_bifrost_analysis::analyzer::languages::SavedDefaultFunction;
use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::routes::CuratedExportSurface;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_core::analyzer::tree_walk::{is_field_child, named_children_iter};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_python::bindings::{
    PythonLexicalNameResolution, PythonLexicalScopeBindings, python_binding_targets_bounded,
    python_direct_scope_bindings_bounded,
};
use brokk_bifrost_python::declarations::{python_module_name, python_parameter_label_node};
use brokk_bifrost_python::graph_support::{PythonSource, retain_modules_for_importer};
use brokk_bifrost_python::imports::{
    PythonImportDetails, python_import_details, python_import_syntaxes_from_node,
    resolve_python_module_specifier,
};
use brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;
use brokk_bifrost_python::syntax::python_static_value_path_bounded;
use std::collections::VecDeque;
use tree_sitter::Node;

/// `None` is incomplete evidence, including exhaustion during preparation.
/// All inventories below die with this query; only the capped result escapes.
pub(in crate::analyzer::python::default_arguments) fn escaped_functions(
    analyzer: &PythonAnalyzer,
    token: QueryToken<'_>,
    remaining_nodes: &mut usize,
    remaining_source_bytes: &mut usize,
) -> Option<HashSet<SavedDefaultFunction>> {
    consume(remaining_nodes)?;
    if *remaining_source_bytes == 0 {
        return None;
    }
    let files = analyzer.analyzed_files();
    let mut prepared_files = Vec::new();
    let mut graph = EscapeGraph::default();
    for file in &files {
        consume(remaining_nodes)?;
        let (_, prepared) = analyzer
            .inner
            .prepared_syntax_limited(
                token,
                file,
                (*remaining_source_bytes).min(MAX_METADATA_SCAN_FILE_BYTES),
            )
            .ok()??;
        *remaining_source_bytes = remaining_source_bytes.checked_sub(prepared.source().len())?;
        if prepared.tree().root_node().has_error() {
            return None;
        }
        let index = graph.add_scope(None, ScopeKind::Module, None, None);
        assert_eq!(index, prepared_files.len());
        graph.file_modules.insert(file.clone(), index);
        let module = python_module_name(analyzer.project(), file);
        // These are structured module identities, not source spelling parses.
        *graph
            .module_tail_counts
            .entry(module.rsplit('.').next()?.to_owned())
            .or_default() += 1;
        graph.modules.entry(module).or_default().push(index);
        prepared_files.push(prepared);
    }
    // Namespace packages need identities too, but merely existing on disk
    // does not attach their children. Only imports add those namespace edges.
    for file in &files {
        let mut module = python_module_name(analyzer.project(), file);
        while let Some((parent, _)) = module.rsplit_once('.') {
            consume(remaining_nodes)?;
            module = parent.to_owned();
            if !graph.modules.contains_key(&module) {
                let scope = graph.add_scope(None, ScopeKind::Module, None, None);
                graph.modules.insert(module.clone(), vec![scope]);
            }
        }
    }
    for (file_index, prepared) in prepared_files.iter().enumerate() {
        let path = WorkspaceRelativePath::try_from_path(files[file_index].rel_path()).ok()?;
        let before = *remaining_nodes;
        graph.collect_file(
            prepared.tree().root_node(),
            prepared.source(),
            &path,
            file_index,
            remaining_nodes,
        )?;
        if files[file_index]
            .rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            == Some("__init__.py")
        {
            graph.root_preparation_nodes += before - *remaining_nodes;
        }
    }
    graph.link_imports(analyzer, &files, remaining_nodes)?;
    graph.find_escapes(&prepared_files, remaining_nodes)?;
    if *remaining_nodes == 0 || *remaining_source_bytes == 0 {
        return None;
    }
    Some(graph.escaped)
}

#[derive(Clone)]
enum Value {
    Function(SavedDefaultFunction),
    Namespace(usize),
    Member(usize, Box<str>),
    External(String),
    Other,
    Deleted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Class,
    Callable,
    Comprehension,
    Generator,
}

struct Binding {
    value: Value,
    completion: Option<usize>,
    // Guaranteed only within the execution scope that owns this binding.
    direct: bool,
}

enum StarExports {
    Implicit,
    Pending,
    Explicit(HashSet<Box<str>>),
    Incomplete,
}

struct Scope {
    parent: Option<usize>,
    module: usize,
    kind: ScopeKind,
    lexical: Option<PythonLexicalScopeBindings>,
    created_at: Option<usize>,
    names: HashMap<Box<str>, Vec<Binding>>,
    stars: Vec<usize>,
    external_stars: Vec<String>,
    exports: StarExports,
    star_names: HashSet<Box<str>>,
    star_incomplete: bool,
}

struct Import {
    file: usize,
    scope: usize,
    name: Option<String>,
    details: PythonImportDetails,
    completion: usize,
    direct: bool,
}

#[derive(Clone, Copy)]
struct Site<'tree> {
    node: Node<'tree>,
    scope: usize,
    file: usize,
}

#[derive(Default)]
struct EscapeGraph<'tree> {
    scopes: Vec<Scope>,
    modules: HashMap<String, Vec<usize>>,
    file_modules: HashMap<ProjectFile, usize>,
    imports: Vec<Import>,
    sites: Vec<Site<'tree>>,
    escaped: HashSet<SavedDefaultFunction>,
    implicit_namespaces: Vec<usize>,
    methods: HashMap<Box<str>, Vec<SavedDefaultFunction>>,
    binders: HashSet<(usize, usize)>,
    module_lookups: HashMap<(usize, String), Vec<usize>>,
    module_tail_counts: HashMap<String, usize>,
    root_preparation_nodes: usize,
    root_preparation_reserved: bool,
    indirect_exports: bool,
}

impl<'tree> EscapeGraph<'tree> {
    fn add_scope(
        &mut self,
        parent: Option<usize>,
        kind: ScopeKind,
        module: Option<usize>,
        lexical: Option<PythonLexicalScopeBindings>,
    ) -> usize {
        let scope = self.scopes.len();
        self.scopes.push(Scope {
            parent,
            module: module.unwrap_or(scope),
            kind,
            lexical,
            created_at: None,
            names: HashMap::default(),
            stars: Vec::new(),
            external_stars: Vec::new(),
            exports: StarExports::Implicit,
            star_names: HashSet::default(),
            star_incomplete: false,
        });
        scope
    }

    fn bind(&mut self, scope: usize, name: &str, value: Value) {
        self.scopes[scope]
            .names
            .entry(name.into())
            .or_default()
            .push(Binding {
                value,
                completion: None,
                direct: false,
            });
    }

    fn bind_at(&mut self, scope: usize, name: &str, value: Value, completion: usize, direct: bool) {
        self.scopes[scope]
            .names
            .entry(name.into())
            .or_default()
            .push(Binding {
                value,
                completion: Some(completion),
                direct,
            });
    }

    fn enclosing_lexical_scope(&self, mut scope: usize, remaining: &mut usize) -> Option<usize> {
        loop {
            consume(remaining)?;
            if self.scopes[scope].kind != ScopeKind::Class {
                return Some(scope);
            }
            scope = self.scopes[scope]
                .parent
                .expect("class scopes have an enclosing lexical scope");
        }
    }

    fn binding_scope(
        &self,
        mut scope: usize,
        name: &str,
        declaration: Node<'_>,
        remaining: &mut usize,
    ) -> Option<usize> {
        let mut nonlocal = false;
        loop {
            consume(remaining)?;
            let current = &self.scopes[scope];
            let Some(lexical) = &current.lexical else {
                return if nonlocal { None } else { Some(scope) };
            };
            match lexical
                .name_resolution_at_bounded(name, declaration, || consume(remaining).is_some())?
            {
                PythonLexicalNameResolution::Global => {
                    return if nonlocal { None } else { Some(current.module) };
                }
                PythonLexicalNameResolution::Nonlocal => {
                    nonlocal = true;
                    scope = current.parent?;
                }
                PythonLexicalNameResolution::Unbound if nonlocal => scope = current.parent?,
                _ => return Some(scope),
            }
        }
    }

    fn escape(&mut self, function: SavedDefaultFunction) -> Option<()> {
        self.escaped.insert(function);
        (self.escaped.len() <= MAX_SAVED_DEFAULT_FUNCTIONS_PER_KIND).then_some(())
    }

    fn collect_file(
        &mut self,
        root: Node<'tree>,
        source: &str,
        path: &WorkspaceRelativePath,
        file: usize,
        remaining: &mut usize,
    ) -> Option<()> {
        #[derive(Clone, Copy)]
        struct Frame<'tree> {
            node: Node<'tree>,
            scope: usize,
            outer_iterable: Option<(usize, usize)>,
        }
        let before = *remaining;
        let mut stack = vec![Frame {
            node: root,
            scope: file,
            outer_iterable: None,
        }];
        while let Some(frame) = stack.pop() {
            consume(remaining)?;
            let node = frame.node;
            if node.child_by_field_name("type_parameters").is_some() {
                // PEP 695 annotation scopes have different header evaluation
                // regions. Without their binding provenance this query cannot
                // certify that a same-named global function stays closed.
                return None;
            }
            let mut body_scope = frame.scope;
            let mut comprehension = None;
            match node.kind() {
                "global_statement" | "nonlocal_statement" => {
                    if self.scopes[frame.scope].kind == ScopeKind::Class {
                        return None;
                    }
                    continue;
                }
                "import_statement" | "import_from_statement" => {
                    // Import syntax helpers are not metered internally. Admit
                    // every descendant before invoking their structured walk.
                    charge_tree(node, remaining)?;
                    for syntax in python_import_syntaxes_from_node(node, source) {
                        consume(remaining)?;
                        let details = python_import_details(&syntax.info)?;
                        let scope = if let Some(name) = syntax.info.identifier.as_deref() {
                            self.binding_scope(frame.scope, name, syntax.declaration, remaining)?
                        } else {
                            frame.scope
                        };
                        if syntax.info.identifier.as_deref() == Some("__all__")
                            && self.scopes[scope].kind == ScopeKind::Module
                        {
                            self.scopes[scope].exports = StarExports::Incomplete;
                        }
                        self.imports.push(Import {
                            file,
                            scope,
                            name: syntax.info.identifier.clone(),
                            details,
                            completion: node.end_byte(),
                            direct: scope == frame.scope && direct_binding(node, remaining)?,
                        });
                    }
                    continue;
                }
                "function_definition" | "lambda" => {
                    let function = SavedDefaultFunction::new(
                        path.clone(),
                        u32::try_from(node.start_byte())
                            .expect("bounded Python source fits in u32"),
                    );
                    if let Some(name) = node.child_by_field_name("name") {
                        self.binders.insert((file, name.id()));
                        let scope =
                            self.binding_scope(frame.scope, text(name, source)?, name, remaining)?;
                        self.bind_at(
                            scope,
                            text(name, source)?,
                            Value::Function(function.clone()),
                            node.end_byte(),
                            scope == frame.scope && direct_binding(node, remaining)?,
                        );
                        if self.scopes[frame.scope].kind == ScopeKind::Class {
                            self.methods
                                .entry(text(name, source)?.into())
                                .or_default()
                                .push(function.clone());
                        }
                    } else if !direct_callee(node, remaining)? {
                        self.escape(function.clone())?;
                    }
                    if node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "decorated_definition")
                    {
                        // Decoration passes the newly created function object
                        // as an implicit argument, even without a name read.
                        self.escape(function)?;
                    }
                    let lexical =
                        crate::analyzer::python::lexical_scope::python_lexical_scope_inventory_bounded(
                            node,
                            source,
                            || consume(remaining).is_some(),
                        )?
                        .into_bindings();
                    // Class namespaces are not lexical parents of methods.
                    let parent = self.enclosing_lexical_scope(frame.scope, remaining)?;
                    body_scope = self.add_scope(
                        Some(parent),
                        ScopeKind::Callable,
                        Some(file),
                        Some(lexical),
                    );
                }
                "class_definition" => {
                    let parent = self.enclosing_lexical_scope(frame.scope, remaining)?;
                    body_scope = self.add_scope(Some(parent), ScopeKind::Class, Some(file), None);
                    let name = node.child_by_field_name("name")?;
                    self.binders.insert((file, name.id()));
                    let scope =
                        self.binding_scope(frame.scope, text(name, source)?, name, remaining)?;
                    self.bind_at(
                        scope,
                        text(name, source)?,
                        Value::Namespace(body_scope),
                        node.end_byte(),
                        scope == frame.scope && direct_binding(node, remaining)?,
                    );
                    if node.child_by_field_name("superclasses").is_some()
                        || node
                            .parent()
                            .is_some_and(|parent| parent.kind() == "decorated_definition")
                    {
                        // Decorators, metaclasses and base-class creation
                        // hooks receive the class and its function namespace.
                        self.implicit_namespaces.push(body_scope);
                    }
                }
                "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression" => {
                    let parent = self.enclosing_lexical_scope(frame.scope, remaining)?;
                    let kind = if node.kind() == "generator_expression" {
                        ScopeKind::Generator
                    } else {
                        ScopeKind::Comprehension
                    };
                    body_scope = self.add_scope(Some(parent), kind, Some(file), None);
                    for child in named_children_iter(node) {
                        consume(remaining)?;
                        if child.kind() == "for_in_clause" {
                            comprehension = child
                                .child_by_field_name("right")
                                .map(|right| (right.id(), frame.scope));
                            break;
                        }
                    }
                }
                _ => {}
            }
            if body_scope != frame.scope {
                self.scopes[body_scope].created_at = Some(node.start_byte());
            }
            if matches!(
                node.kind(),
                "assignment"
                    | "annotated_assignment"
                    | "augmented_assignment"
                    | "type_alias_statement"
                    | "named_expression"
                    | "for_statement"
                    | "async_for_statement"
                    | "for_in_clause"
                    | "with_statement"
                    | "delete_statement"
                    | "as_pattern"
                    | "except_clause"
                    | "case_clause"
            ) {
                let bindings = if node.kind() == "for_in_clause" {
                    python_binding_targets_bounded(
                        node.child_by_field_name("left")?,
                        source,
                        || consume(remaining).is_some(),
                    )?
                } else {
                    python_direct_scope_bindings_bounded(node, source, || {
                        consume(remaining).is_some()
                    })?
                };
                // Exception aliases are deleted at handler exit. The current
                // grammar nests the alias in as_pattern; older shapes expose
                // it directly on except_clause. Other as-patterns persist.
                let exception_cleanup = match node.kind() {
                    "except_clause" => Some(node.end_byte()),
                    "as_pattern" => {
                        consume(remaining)?;
                        node.parent()
                            .filter(|parent| parent.kind() == "except_clause")
                            .map(|parent| parent.end_byte())
                    }
                    _ => None,
                };
                // PEP 572 binds assignment expressions in the containing
                // scope, including through multiple nested comprehensions.
                let mut binding_context = frame.scope;
                if node.kind() == "named_expression" {
                    while matches!(
                        self.scopes[binding_context].kind,
                        ScopeKind::Comprehension | ScopeKind::Generator
                    ) {
                        consume(remaining)?;
                        binding_context = self.scopes[binding_context]
                            .parent
                            .expect("comprehensions have an enclosing lexical scope");
                    }
                }
                for binding in bindings {
                    consume(remaining)?;
                    self.binders.insert((file, binding.declaration.id()));
                    let name = text(binding.declaration, source)?;
                    let scope =
                        self.binding_scope(binding_context, name, binding.declaration, remaining)?;
                    // A global/nonlocal writer might never execute. Its
                    // destination retains earlier values as may alternatives.
                    let direct = scope == frame.scope && direct_binding(node, remaining)?;
                    let value = if node.kind() == "delete_statement" {
                        Value::Deleted
                    } else {
                        Value::Other
                    };
                    self.bind_at(scope, name, value, node.end_byte(), direct);
                    if let Some(end) = exception_cleanup {
                        consume(remaining)?;
                        // The handler may not execute; preserve both its
                        // cleanup and earlier bindings as may alternatives.
                        self.bind_at(scope, name, Value::Deleted, end, false);
                    }
                    if name == "__all__" && self.scopes[scope].kind == ScopeKind::Module {
                        let exports = if matches!(self.scopes[scope].exports, StarExports::Implicit)
                            && direct
                            && node.kind() == "assignment"
                            && frame.scope == file
                        {
                            StarExports::Pending
                        } else {
                            StarExports::Incomplete
                        };
                        self.scopes[scope].exports = exports;
                    }
                }
            }
            if matches!(node.kind(), "identifier" | "attribute") {
                if node.kind() == "attribute"
                    && text(node.child_by_field_name("attribute")?, source)? == "__all__"
                {
                    // Indirect export-list access can change another module's
                    // wildcard surface. Do not certify those surfaces from
                    // their defining files alone; named imports stay usable.
                    self.indirect_exports = true;
                }
                if node.kind() == "identifier"
                    && text(node, source)? == "__all__"
                    && !self.binders.contains(&(file, node.id()))
                    && value_read(node, remaining)?
                {
                    self.scopes[file].exports = StarExports::Incomplete;
                }
                self.sites.push(Site {
                    node,
                    scope: frame.scope,
                    file,
                });
            }
            let body = node.child_by_field_name("body");
            for child in named_children_iter(node) {
                consume(remaining)?;
                let outer_iterable = comprehension.or(frame.outer_iterable);
                let scope = if outer_iterable.is_some_and(|(id, _)| id == child.id()) {
                    outer_iterable.expect("matched outer iterable").1
                } else if comprehension.is_some() || Some(child) == body {
                    body_scope
                } else {
                    frame.scope
                };
                stack.push(Frame {
                    node: child,
                    scope,
                    outer_iterable,
                });
            }
        }
        if matches!(self.scopes[file].exports, StarExports::Pending) {
            // The existing export reader owns literal __all__ interpretation.
            // It performs binding, import, dynamic-definition, and literal
            // walks internally. Reserve six complete admitted preparation
            // passes before entering it, including all binder/header work.
            let preparation = before - *remaining;
            for _ in 0..6 {
                *remaining = remaining.checked_sub(preparation)?;
            }
            self.scopes[file].exports =
                match PYTHON_STRUCTURAL_SPEC.curated_export_surface(root, source) {
                    CuratedExportSurface::Listed(names) => {
                        let mut exported = HashSet::default();
                        for name in names {
                            consume(remaining)?;
                            exported.insert(name.into_boxed_str());
                        }
                        StarExports::Explicit(exported)
                    }
                    CuratedExportSurface::Absent | CuratedExportSurface::Unreadable => {
                        StarExports::Incomplete
                    }
                };
        }
        Some(())
    }

    fn module_targets(
        &mut self,
        analyzer: &PythonAnalyzer,
        files: &[ProjectFile],
        importer: usize,
        module: &str,
        remaining: &mut usize,
    ) -> Option<Vec<usize>> {
        consume(remaining)?;
        let key = (importer, module.to_owned());
        if let Some(targets) = self.module_lookups.get(&key) {
            for _ in targets {
                consume(remaining)?;
            }
            return Some(targets.clone());
        }
        let units = analyzer
            .path_module_fqn(module)
            .unwrap_or_else(|| analyzer.definition_fqn(module));
        let mut modules = Vec::new();
        for unit in units {
            consume(remaining)?;
            if unit.is_module() {
                modules.push(unit);
            }
        }
        // The shared hook owns Python's nearest-import-root rule. Charge its
        // full candidate input before it performs its internal filtering.
        for _ in &modules {
            consume(remaining)?;
        }
        retain_modules_for_importer(analyzer.project(), &files[importer], &mut modules, |unit| {
            unit.source()
        });
        if !modules.is_empty() {
            let mut targets = Vec::new();
            for unit in modules {
                consume(remaining)?;
                targets.push(*self.file_modules.get(unit.source())?);
            }
            self.module_lookups.insert(key, targets.clone());
            return Some(targets);
        }
        if let Some(modules) = self.modules.get(module) {
            for _ in modules {
                consume(remaining)?;
            }
            // Ambiguity preserves every possible identity rather than proving
            // an absent escape from a failed unique lookup.
            let targets = modules.clone();
            self.module_lookups.insert(key, targets.clone());
            return Some(targets);
        }
        // The existing module-spelling helper deliberately excludes bare
        // coincidences such as stdlib typing and workspace pkg.typing. Its
        // dotted source-root candidates remain relevant workspace identities;
        // retain all proven alternatives and refuse an unresolved route.
        // Building source-root facts can inspect package-marker ASTs. Admit
        // that complete preparation once; later suffix lookups inspect only
        // the preplanned bucket for this module's final identity component.
        if !self.root_preparation_reserved {
            *remaining = remaining.checked_sub(self.root_preparation_nodes)?;
            *remaining = remaining.checked_sub(self.file_modules.len())?;
            self.root_preparation_reserved = true;
        }
        *remaining = remaining.checked_sub(module.len())?;
        let tail = module.rsplit('.').next()?;
        *remaining =
            remaining.checked_sub(self.module_tail_counts.get(tail).copied().unwrap_or(0))?;
        let spellings = analyzer.module_spellings();
        let candidates = spellings.suffix_candidates(module);
        let had_candidates = !candidates.is_empty();
        let mut targets = Vec::new();
        for candidate in candidates {
            consume(remaining)?;
            if spellings.establishes_source_root(&candidate) {
                targets.push(*self.file_modules.get(&candidate.file)?);
            }
        }
        if !targets.is_empty() {
            self.module_lookups.insert(key, targets.clone());
            return Some(targets);
        }
        if had_candidates {
            return None;
        }
        self.module_lookups.insert(key, Vec::new());
        Some(Vec::new())
    }

    fn attach_module(
        &mut self,
        analyzer: &PythonAnalyzer,
        files: &[ProjectFile],
        importer: usize,
        module: &str,
        remaining: &mut usize,
    ) -> Option<()> {
        // These are structured module identity components, not source syntax.
        let mut child = module.to_owned();
        while let Some((parent, member)) = child.rsplit_once('.') {
            consume(remaining)?;
            let children = self.module_targets(analyzer, files, importer, &child, remaining)?;
            let parents = self.module_targets(analyzer, files, importer, parent, remaining)?;
            for parent in parents {
                for child in &children {
                    consume(remaining)?;
                    self.bind(parent, member, Value::Namespace(*child));
                }
            }
            child = parent.to_owned();
        }
        Some(())
    }

    fn link_imports(
        &mut self,
        analyzer: &PythonAnalyzer,
        files: &[ProjectFile],
        remaining: &mut usize,
    ) -> Option<()> {
        let imports = std::mem::take(&mut self.imports);
        for import in imports {
            consume(remaining)?;
            match import.details {
                PythonImportDetails::Import { module, alias } => {
                    self.attach_module(analyzer, files, import.file, &module, remaining)?;
                    let bound_module = if alias.is_some() {
                        module.clone()
                    } else {
                        module.split('.').next()?.to_owned()
                    };
                    let targets = self.module_targets(
                        analyzer,
                        files,
                        import.file,
                        &bound_module,
                        remaining,
                    )?;
                    let name = import.name?;
                    if targets.is_empty() {
                        self.bind_at(
                            import.scope,
                            &name,
                            Value::External(bound_module),
                            import.completion,
                            import.direct,
                        );
                    } else {
                        for target in targets {
                            consume(remaining)?;
                            self.bind_at(
                                import.scope,
                                &name,
                                Value::Namespace(target),
                                import.completion,
                                import.direct,
                            );
                        }
                    }
                }
                PythonImportDetails::FromImport {
                    module,
                    name,
                    wildcard,
                    ..
                } => {
                    let module = resolve_python_module_specifier(
                        analyzer.project(),
                        &files[import.file],
                        &module,
                    )?;
                    self.attach_module(analyzer, files, import.file, &module, remaining)?;
                    let targets =
                        self.module_targets(analyzer, files, import.file, &module, remaining)?;
                    if wildcard {
                        if targets.is_empty()
                            && matches!(module.as_str(), "sys" | "importlib" | "builtins")
                        {
                            self.scopes[import.scope].external_stars.push(module);
                        }
                        self.scopes[import.scope].stars.extend(targets);
                        continue;
                    }
                    let submodule = format!("{module}.{name}");
                    let children =
                        self.module_targets(analyzer, files, import.file, &submodule, remaining)?;
                    if !children.is_empty() {
                        self.attach_module(analyzer, files, import.file, &submodule, remaining)?;
                    }
                    let bound_name = import.name?;
                    if targets.is_empty() && children.is_empty() {
                        self.bind_at(
                            import.scope,
                            &bound_name,
                            Value::External(submodule),
                            import.completion,
                            import.direct,
                        );
                    } else {
                        // A named reexport and an attached child can be may
                        // alternatives. Keep their union under ambiguity.
                        for target in targets {
                            consume(remaining)?;
                            self.bind_at(
                                import.scope,
                                &bound_name,
                                Value::Member(target, name.clone().into()),
                                import.completion,
                                import.direct,
                            );
                        }
                        for child in children {
                            consume(remaining)?;
                            self.bind_at(
                                import.scope,
                                &bound_name,
                                Value::Namespace(child),
                                import.completion,
                                import.direct,
                            );
                        }
                    }
                }
            }
        }
        self.derive_star_exports(remaining)
    }

    fn derive_star_exports(&mut self, remaining: &mut usize) -> Option<()> {
        let mut importers = vec![Vec::new(); self.scopes.len()];
        let mut queue = VecDeque::new();
        for (index, scope) in self.scopes.iter_mut().enumerate() {
            consume(remaining)?;
            if self.indirect_exports && scope.kind == ScopeKind::Module {
                scope.star_incomplete = true;
            }
            match &scope.exports {
                StarExports::Implicit => {
                    for name in scope.names.keys() {
                        consume(remaining)?;
                        if !name.starts_with('_') {
                            scope.star_names.insert(name.clone());
                        }
                    }
                }
                StarExports::Explicit(names) => {
                    for name in names {
                        consume(remaining)?;
                        scope.star_names.insert(name.clone());
                    }
                }
                StarExports::Incomplete => scope.star_incomplete = true,
                StarExports::Pending => {
                    unreachable!("curated exports are prepared before import closure")
                }
            }
            for source in &scope.stars {
                consume(remaining)?;
                importers[*source].push(index);
            }
            queue.push_back(index);
        }
        while let Some(source) = queue.pop_front() {
            consume(remaining)?;
            for importer in &importers[source] {
                consume(remaining)?;
                if !self.scopes[*importer].star_incomplete
                    && (self.scopes[source].star_incomplete
                        || (self.scopes[*importer].kind == ScopeKind::Module
                            && self.scopes[source].star_names.contains("__all__")))
                {
                    self.scopes[*importer].star_incomplete = true;
                    queue.push_back(*importer);
                }
                if !matches!(self.scopes[*importer].exports, StarExports::Implicit) {
                    continue;
                }
                let mut names = Vec::new();
                for name in &self.scopes[source].star_names {
                    consume(remaining)?;
                    if !name.starts_with('_') {
                        names.push(name.clone());
                    }
                }
                let mut changed = false;
                for name in names {
                    consume(remaining)?;
                    changed |= self.scopes[*importer].star_names.insert(name);
                }
                if changed {
                    queue.push_back(*importer);
                }
            }
        }
        Some(())
    }

    fn expand(&self, values: Vec<Value>, remaining: &mut usize) -> Option<Vec<Value>> {
        enum Step {
            Enter(Value),
            Leave(usize, Box<str>),
        }
        let mut stack = values.into_iter().map(Step::Enter).collect::<Vec<_>>();
        let mut seen = HashSet::default();
        let mut active = HashSet::default();
        let mut result = Vec::new();
        while let Some(step) = stack.pop() {
            consume(remaining)?;
            let value = match step {
                Step::Enter(value) => value,
                Step::Leave(scope, name) => {
                    active.remove(&(scope, name.clone()));
                    seen.insert((scope, name));
                    continue;
                }
            };
            match value {
                Value::Member(scope, name) => {
                    let key = (scope, name.clone());
                    if active.contains(&key) {
                        return None;
                    }
                    if seen.contains(&key) {
                        continue;
                    }
                    active.insert(key);
                    stack.push(Step::Leave(scope, name.clone()));
                    let mut found = false;
                    if let Some(values) = self.scopes[scope].names.get(&name) {
                        found = true;
                        for value in values {
                            consume(remaining)?;
                            if name.as_ref() == "__all__"
                                && self.scopes[scope].kind == ScopeKind::Module
                                && matches!(value.value, Value::Other)
                            {
                                // A mutable export list can be imported under
                                // an alias and changed outside its module.
                                // Import binders alone never expand its value.
                                return None;
                            }
                            stack.push(Step::Enter(value.value.clone()));
                        }
                    }
                    for star in &self.scopes[scope].stars {
                        consume(remaining)?;
                        if self.scopes[*star].star_incomplete {
                            return None;
                        }
                        if self.scopes[*star].star_names.contains(&name) {
                            found = true;
                            stack.push(Step::Enter(Value::Member(*star, name.clone())));
                        }
                    }
                    for module in &self.scopes[scope].external_stars {
                        consume(remaining)?;
                        found = true;
                        stack.push(Step::Enter(Value::External(format!("{module}.{name}"))));
                    }
                    if !found {
                        // Some module attributes exist without source binders.
                        match name.as_ref() {
                            "__name__" | "__file__" | "__package__" | "__doc__" | "__path__"
                            | "__spec__" | "__loader__" | "__cached__" => result.push(Value::Other),
                            "__dict__" => result.push(Value::Namespace(scope)),
                            _ => return None,
                        }
                    }
                }
                Value::External(ref path)
                    if matches!(
                        path.as_str(),
                        "sys.modules"
                            | "importlib.import_module"
                            | "builtins.__import__"
                            | "builtins.globals"
                            | "builtins.locals"
                            | "builtins.vars"
                            | "builtins.eval"
                            | "builtins.exec"
                    ) =>
                {
                    return None;
                }
                value => result.push(value),
            }
        }
        Some(result)
    }

    fn lexical_values(
        &self,
        scope: usize,
        name: &str,
        site: Site<'_>,
        remaining: &mut usize,
    ) -> Option<Vec<Value>> {
        let current = &self.scopes[scope];
        let Some(bindings) = current.names.get(name) else {
            let mut values = Vec::new();
            for star in &current.stars {
                consume(remaining)?;
                if self.scopes[*star].star_incomplete {
                    return None;
                }
                if self.scopes[*star].star_names.contains(name) {
                    values.push(Value::Member(*star, name.into()));
                }
            }
            for module in &current.external_stars {
                consume(remaining)?;
                values.push(Value::External(format!("{module}.{name}")));
            }
            return self.expand(values, remaining);
        };
        // Same-scope reads have an exact source-order cutoff. A deferred
        // body can run after later bindings too, but a binding completed before
        // its enclosing declaration was created already shadows earlier values.
        let ordered = scope == site.scope
            && !matches!(
                current.kind,
                ScopeKind::Comprehension | ScopeKind::Generator
            );
        let mut cutoff = site.node.start_byte();
        if !ordered {
            cutoff = 0;
            let mut child = site.scope;
            while child != scope {
                consume(remaining)?;
                if self.scopes[child].parent == Some(scope) {
                    cutoff = self.scopes[child].created_at.unwrap_or(0);
                    break;
                }
                child = self.scopes[child].parent?;
            }
        }
        let mut barrier = 0;
        for binding in bindings {
            consume(remaining)?;
            if binding.direct
                && let Some(end) = binding.completion
                && end <= cutoff
            {
                barrier = barrier.max(end);
            }
        }
        let mut values = Vec::new();
        for binding in bindings {
            consume(remaining)?;
            if binding
                .completion
                .is_none_or(|end| barrier <= end && (!ordered || end <= site.node.start_byte()))
            {
                values.push(binding.value.clone());
            }
        }
        for star in &current.stars {
            consume(remaining)?;
            if self.scopes[*star].star_incomplete {
                return None;
            }
            if self.scopes[*star].star_names.contains(name) {
                values.push(Value::Member(*star, name.into()));
            }
        }
        for module in &current.external_stars {
            consume(remaining)?;
            values.push(Value::External(format!("{module}.{name}")));
        }
        // A nested read has the same value role as any other read. Capturing
        // a name used only as a direct callee is not a function-object escape.
        self.expand(values, remaining)
    }

    fn name_values(&self, site: Site<'_>, name: &str, remaining: &mut usize) -> Option<Vec<Value>> {
        let mut scope = Some(site.scope);
        let mut nonlocal = false;
        let mut class_alternatives = Vec::new();
        while let Some(index) = scope {
            consume(remaining)?;
            let current = &self.scopes[index];
            if let Some(lexical) = &current.lexical {
                match lexical
                    .name_resolution_at_bounded(name, site.node, || consume(remaining).is_some())?
                {
                    PythonLexicalNameResolution::Global => {
                        scope = Some(current.module);
                        continue;
                    }
                    PythonLexicalNameResolution::Nonlocal => {
                        nonlocal = true;
                        scope = current.parent;
                        continue;
                    }
                    PythonLexicalNameResolution::Local => {
                        let mut local = self.lexical_values(index, name, site, remaining)?;
                        if local.is_empty() {
                            local.push(Value::Other);
                        }
                        class_alternatives.extend(local);
                        return Some(class_alternatives);
                    }
                    PythonLexicalNameResolution::Unbound => {}
                }
            }
            if nonlocal && current.kind == ScopeKind::Module {
                return None;
            }
            if current.names.contains_key(name)
                || !current.stars.is_empty()
                || !current.external_stars.is_empty()
            {
                let mut may_be_absent = false;
                for value in self.lexical_values(index, name, site, remaining)? {
                    consume(remaining)?;
                    if matches!(value, Value::Deleted) {
                        may_be_absent = true;
                    } else {
                        class_alternatives.push(value);
                    }
                }
                let mut definitely_bound = false;
                if current.kind == ScopeKind::Class
                    && !may_be_absent
                    && let Some(bindings) = current.names.get(name)
                {
                    for binding in bindings {
                        consume(remaining)?;
                        definitely_bound |= binding.direct
                            && binding
                                .completion
                                .is_some_and(|end| end <= site.node.start_byte());
                    }
                }
                // Class LOAD_NAME falls back outward after deletion too. A
                // conditional deletion retains local and outer candidates;
                // a later definite assignment removes the deletion at the
                // source-order barrier in lexical_values. Callable symbol
                // tables, in contrast, shadow for the whole body.
                if definitely_bound
                    || (current.kind != ScopeKind::Class && !class_alternatives.is_empty())
                {
                    return Some(class_alternatives);
                }
            }
            scope = current.parent;
        }
        if nonlocal {
            None
        } else {
            Some(class_alternatives)
        }
    }

    fn reflection_is_lexically_shadowed(
        &self,
        site: Site<'_>,
        name: &str,
        remaining: &mut usize,
    ) -> Option<bool> {
        let mut scope = Some(site.scope);
        while let Some(index) = scope {
            consume(remaining)?;
            if let Some(lexical) = &self.scopes[index].lexical {
                match lexical
                    .name_resolution_at_bounded(name, site.node, || consume(remaining).is_some())?
                {
                    PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal => {
                        return Some(true);
                    }
                    PythonLexicalNameResolution::Global => return Some(false),
                    PythonLexicalNameResolution::Unbound => {}
                }
            }
            if matches!(
                self.scopes[index].kind,
                ScopeKind::Comprehension | ScopeKind::Generator
            ) && self.scopes[index].names.contains_key(name)
            {
                return Some(true);
            }
            scope = self.scopes[index].parent;
        }
        Some(false)
    }

    fn expression_values(
        &self,
        site: Site<'_>,
        source: &str,
        remaining: &mut usize,
    ) -> Option<Vec<Value>> {
        let Some(path) =
            python_static_value_path_bounded(site.node, || consume(remaining).is_some())?
        else {
            // Structured name-based candidates cover unknown instance receivers.
            // Function/module assignment origins already escape at their RHS.
            let mut values = Vec::new();
            if let Some(member) = site.node.child_by_field_name("attribute")
                && let Some(methods) = self.methods.get(text(member, source)?)
            {
                for method in methods {
                    consume(remaining)?;
                    values.push(Value::Function(method.clone()));
                }
            }
            return Some(values);
        };
        let (node, members) = path
            .split_first()
            .expect("static paths have a root identifier");
        let mut values = self.name_values(
            Site {
                node: *node,
                ..site
            },
            text(*node, source)?,
            remaining,
        )?;
        for member in members {
            consume(remaining)?;
            let member = text(*member, source)?;
            let mut selected = Vec::new();
            if values.is_empty()
                && let Some(methods) = self.methods.get(member)
            {
                for method in methods {
                    consume(remaining)?;
                    selected.push(Value::Function(method.clone()));
                }
            }
            for value in values {
                consume(remaining)?;
                match value {
                    Value::Namespace(scope) => selected.push(Value::Member(scope, member.into())),
                    Value::External(path) => {
                        selected.push(Value::External(format!("{path}.{member}")))
                    }
                    Value::Other => {
                        if let Some(methods) = self.methods.get(member) {
                            for method in methods {
                                consume(remaining)?;
                                selected.push(Value::Function(method.clone()));
                            }
                        }
                    }
                    Value::Function(_) | Value::Deleted => {}
                    Value::Member(_, _) => unreachable!("namespace member routes are expanded"),
                }
            }
            values = self.expand(selected, remaining)?;
        }
        Some(values)
    }

    fn find_escapes(
        &mut self,
        files: &[std::sync::Arc<
            brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        >],
        remaining: &mut usize,
    ) -> Option<()> {
        let sites = std::mem::take(&mut self.sites);
        let mut exposed = std::mem::take(&mut self.implicit_namespaces);
        for site in sites {
            consume(remaining)?;
            let node = site.node;
            let source = files[site.file].source();
            if self.binders.contains(&(site.file, node.id())) || !value_read(node, remaining)? {
                continue;
            }
            let direct = direct_callee(node, remaining)?;
            let wrapped = after_parentheses(node, remaining)?;
            let receiver = wrapped.parent().is_some_and(|parent| {
                parent.kind() == "attribute" && is_field_child(parent, wrapped, "object")
            });
            let values = self.expression_values(site, source, remaining)?;
            if node.kind() == "identifier"
                && matches!(
                    text(node, source)?,
                    "globals" | "locals" | "vars" | "eval" | "exec" | "__import__"
                )
                && !self.reflection_is_lexically_shadowed(site, text(node, source)?, remaining)?
            {
                // Module-level conditional rebinding does not exclude the
                // builtin alternative. Keep its reflection path incomplete.
                return None;
            }
            for value in values {
                consume(remaining)?;
                match value {
                    Value::External(path)
                        if !receiver
                            && matches!(path.as_str(), "sys" | "importlib" | "builtins") =>
                    {
                        return None;
                    }
                    Value::Function(function) if !direct => self.escape(function)?,
                    Value::Namespace(scope)
                        if !receiver
                            && (!direct || self.scopes[scope].kind != ScopeKind::Class) =>
                    {
                        // Exact construction does not expose the class's
                        // function objects. Modules retain namespace exposure.
                        exposed.push(scope)
                    }
                    _ => {}
                }
            }
        }
        let mut seen = HashSet::default();
        while let Some(scope) = exposed.pop() {
            consume(remaining)?;
            if !seen.insert(scope) {
                continue;
            }
            if !self.scopes[scope].external_stars.is_empty() {
                return None;
            }
            let mut values = Vec::new();
            for star in &self.scopes[scope].stars {
                consume(remaining)?;
                if self.scopes[*star].star_incomplete {
                    return None;
                }
                for name in &self.scopes[*star].star_names {
                    consume(remaining)?;
                    values.push(Value::Member(*star, name.clone()));
                }
            }
            for bindings in self.scopes[scope].names.values() {
                for value in bindings {
                    consume(remaining)?;
                    values.push(value.value.clone());
                }
            }
            for value in self.expand(values, remaining)? {
                consume(remaining)?;
                match value {
                    Value::Function(function) => self.escape(function)?,
                    Value::External(path)
                        if matches!(path.as_str(), "sys" | "importlib" | "builtins") =>
                    {
                        return None;
                    }
                    Value::Namespace(namespace) => exposed.push(namespace),
                    _ => {}
                }
            }
        }
        Some(())
    }
}

fn text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    node.utf8_text(source.as_bytes()).ok()
}

fn charge_tree(root: Node<'_>, remaining: &mut usize) -> Option<()> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        consume(remaining)?;
        for child in named_children_iter(node) {
            consume(remaining)?;
            stack.push(child);
        }
    }
    Some(())
}

fn after_parentheses<'tree>(mut node: Node<'tree>, remaining: &mut usize) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        consume(remaining)?;
        if parent.kind() != "parenthesized_expression" {
            break;
        }
        node = parent;
    }
    Some(node)
}

fn direct_callee(node: Node<'_>, remaining: &mut usize) -> Option<bool> {
    let node = after_parentheses(node, remaining)?;
    Some(
        node.parent().is_some_and(|parent| {
            parent.kind() == "call" && is_field_child(parent, node, "function")
        }),
    )
}

fn value_read(node: Node<'_>, remaining: &mut usize) -> Option<bool> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        consume(remaining)?;
        match parent.kind() {
            "attribute" if is_field_child(parent, current, "attribute") => return Some(false),
            "dotted_name" if parent.named_child(0) != Some(current) => return Some(false),
            "keyword_argument" if is_field_child(parent, current, "name") => return Some(false),
            "keyword_pattern" if parent.named_child(0) == Some(current) => return Some(false),
            "parameters" | "lambda_parameters" => return Some(false),
            "default_parameter"
            | "typed_default_parameter"
            | "typed_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern"
            | "keyword_separator" => {
                charge_tree(parent, remaining)?;
                return Some(python_parameter_label_node(parent) != Some(node));
            }
            "assignment"
            | "annotated_assignment"
            | "named_expression"
            | "for_statement"
            | "for_in_clause"
                if is_field_child(parent, current, "left")
                    || is_field_child(parent, current, "name") =>
            {
                return Some(false);
            }
            "delete_statement" => return Some(false),
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "tuple"
            | "list"
            | "parenthesized_expression" => current = parent,
            _ => return Some(true),
        }
    }
    Some(true)
}

/// A completed straight-line binding replaces earlier values. Branches and
/// zero-iteration loop targets preserve the may-candidate union.
fn direct_binding(mut node: Node<'_>, remaining: &mut usize) -> Option<bool> {
    if !matches!(
        node.kind(),
        "function_definition"
            | "class_definition"
            | "import_statement"
            | "import_from_statement"
            | "assignment"
            | "delete_statement"
    ) || (node.kind() == "assignment" && node.child_by_field_name("right").is_none())
    {
        return Some(false);
    }
    while let Some(parent) = node.parent() {
        consume(remaining)?;
        match parent.kind() {
            "expression_statement" | "decorated_definition" => node = parent,
            "module" => return Some(true),
            "block" => {
                return Some(parent.parent().is_some_and(|owner| {
                    matches!(owner.kind(), "function_definition" | "class_definition")
                }));
            }
            _ => return Some(false),
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {

    use crate::analyzer::python::default_arguments::escapes::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::LanguageDialect;

    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource, PreparedSyntaxTree,
    };
    use brokk_bifrost_core::text_utils::compute_line_starts;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    #[test]
    #[hardwon("#5044: unexecuted nonlocal writers hid escapes and nested direct calls escaped")]
    fn nested_writes_and_direct_calls_preserve_escape_roles() {
        // Public dispatch cannot reach these nested targets. Exercise the
        // bounded escape graph with their real lexical scopes instead.
        let source = r#"
def consume(value):
    pass

def outer():
    def reassigned(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def redefined(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def reclassed(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def nested_direct(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def nested_returned(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def hidden(pos="saved-pos", *, key="saved-key"):
        return pos, key
    def conditional_member(pos="saved-pos", *, key="saved-key"):
        return pos, key

    class NestedConstructor:
        def __init__(self, pos="saved-pos", *, key="saved-key"):
            pass

    class NestedNamespace:
        def receiver_only(pos="saved-pos", *, key="saved-key"):
            return pos, key

    class ConditionalMember:
        def conditional_member(pos="saved-pos", *, key="saved-key"):
            return pos, key
        if condition:
            del conditional_member
        saved = conditional_member

    def reset():
        nonlocal reassigned, redefined, reclassed
        reassigned = None
        def redefined(pos="replacement", *, key="replacement"):
            return pos, key
        class reclassed:
            pass

    def inner():
        nested_direct(key="explicit")
        nested_direct("explicit")
        NestedConstructor()
        NestedNamespace.receiver_only()

    def shadow():
        hidden = None
        consume(hidden)

    def read():
        consume(reassigned)
        consume(redefined)
        consume(reclassed)
        return nested_returned
"#;
        let files = [Arc::new(PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            brokk_bifrost_python::declarations::parse_python_tree(source).unwrap(),
            compute_line_starts(source),
            LanguageDialect::Standard(Language::Python),
            PreparedSourceOrigin::Disk,
            None,
        ))];
        let mut remaining = 100_000;
        let mut graph = EscapeGraph::default();
        graph.add_scope(None, ScopeKind::Module, None, None);
        graph
            .collect_file(
                files[0].tree().root_node(),
                source,
                &WorkspaceRelativePath::new("nested.py").unwrap(),
                0,
                &mut remaining,
            )
            .expect("nested scope preparation completes");
        graph
            .find_escapes(&files, &mut remaining)
            .expect("nested scope escape discovery completes");
        for (name, expected_escape) in [
            ("reassigned", true),
            ("redefined", true),
            ("reclassed", true),
            ("nested_returned", true),
            ("conditional_member", true),
            ("nested_direct", false),
            ("__init__", false),
            ("receiver_only", false),
            ("hidden", false),
        ] {
            let mut found = false;
            for scope in &graph.scopes {
                if let Some(bindings) = scope.names.get(name) {
                    for binding in bindings {
                        if let Value::Function(function) = &binding.value {
                            found = true;
                            assert_eq!(
                                graph.escaped.contains(function),
                                expected_escape,
                                "{name}: nested reads must preserve their value roles"
                            );
                        }
                    }
                }
            }
            assert!(found, "missing nested function {name}");
        }
    }

    #[test]
    #[hardwon("#5044: exhausted escape preparation and namespace closure must remain incomplete")]
    fn escape_preparation_and_closure_preserve_exhaustion() {
        let path = WorkspaceRelativePath::new("example.py").unwrap();
        let source = "def target(value=1):\n    return value\n";
        let tree = brokk_bifrost_python::declarations::parse_python_tree(source).unwrap();
        for mut remaining in [0_usize, 1, 2] {
            let mut graph = EscapeGraph::default();
            graph.add_scope(None, ScopeKind::Module, None, None);
            assert!(
                graph
                    .collect_file(tree.root_node(), source, &path, 0, &mut remaining)
                    .is_none()
            );
        }

        let mut graph = EscapeGraph::default();
        let facade = graph.add_scope(None, ScopeKind::Module, None, None);
        let defining = graph.add_scope(None, ScopeKind::Module, None, None);
        graph.bind(facade, "exported", Value::Member(defining, "target".into()));
        graph.bind(
            defining,
            "target",
            Value::Function(SavedDefaultFunction::new(path, 0)),
        );
        for mut remaining in [0_usize, 1, 2] {
            assert!(
                graph
                    .expand(
                        vec![Value::Member(facade, "exported".into())],
                        &mut remaining
                    )
                    .is_none()
            );
        }
        let mut remaining = 100;
        let values = graph
            .expand(
                vec![
                    Value::Member(facade, "exported".into()),
                    Value::Member(facade, "exported".into()),
                ],
                &mut remaining,
            )
            .unwrap();
        assert_eq!(values.len(), 1);
        assert!(matches!(values[0], Value::Function(_)));
    }
}
