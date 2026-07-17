use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const PYTHON_RECEIVER_TYPE_CACHE_LIMIT: usize = 512;

pub(super) fn resolve_python(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("python_parse_failed", "Python source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        );
    };
    if python_is_non_reference_context(node) || python_is_declaration_identifier(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Python reference site", site.text),
        );
    }

    let ctx = context.python_context(py, file);
    let support = context.bounded_support();
    let reference = python_reference_node(node);
    match reference {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let object_text = python_slice(object, source);
            let attribute_text = python_slice(attribute, source);
            if object_text.is_empty() || attribute_text.is_empty() {
                return no_definition("no_reference_text", "Python attribute reference is blank");
            }
            let object_shadowed = python_name_shadowed_at(
                object_text,
                tree.root_node(),
                site.range.start_byte,
                source,
            );
            if !object_shadowed && let Some(module) = ctx.namespace_module_for_object(object_text) {
                return python_fqn_outcome(
                    py,
                    support,
                    &format!("{module}.{attribute_text}"),
                    site.text.as_str(),
                );
            }
            if !object_shadowed
                && let Some(receiver_type) = ctx.receiver_type_for_object(py, support, object_text)
            {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                object,
            ) {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if object_shadowed {
                return no_definition(
                    "local_variable_reference",
                    format!("`{object_text}` is a local Python value"),
                );
            }
            if python_unresolved_import_boundary(file, analyzer, object_text, Some(attribute_text))
            {
                return boundary(format!(
                    "`{object_text}.{attribute_text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "`{}` did not resolve to an indexed Python definition",
                    site.text
                ),
            )
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let text = python_slice(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "Python identifier is blank");
            }
            if python_name_shadowed_at(text, tree.root_node(), site.range.start_byte, source) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Python value"),
                );
            }
            if let Some(candidates) = python_visible_module_binding_candidates(
                analyzer,
                py,
                support,
                &ctx,
                source,
                tree.root_node(),
                identifier,
                text,
            ) {
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
                return no_definition(
                    "no_indexed_definition",
                    format!("`{text}` is bound locally but has no indexed Python definition"),
                );
            }
            if let Some(fqn) = ctx.named.get(text).or_else(|| ctx.namespace.get(text)) {
                return python_fqn_outcome(py, support, fqn, text);
            }
            if let Some(candidates) = ctx.same_file.get(text)
                && !candidates.is_empty()
            {
                let candidates =
                    python_visible_same_file_candidates(analyzer, file, identifier, candidates);
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if python_unresolved_import_boundary(file, analyzer, text, None) {
                return boundary(format!(
                    "`{text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Python definition"),
            )
        }
        Some(PythonReferenceNode::KeywordArgument { call, name }) => {
            let name_text = python_slice(name, source);
            if name_text.is_empty() {
                return no_definition("no_reference_text", "Python keyword argument is blank");
            }
            let Some(function) = call.child_by_field_name("function") else {
                return no_definition("no_function_name", "Python call has no callee");
            };
            // `Foo(a=..)` -> `a` is a member/parameter of the callee's type (e.g. a
            // dataclass field `Foo.a`). Type the callee and look the name up as a
            // member.
            if let Some(receiver_type) = python_receiver_type_unit(
                analyzer,
                py,
                support,
                &ctx,
                file,
                source,
                tree.root_node(),
                function,
            ) {
                return python_member_outcome(analyzer, support, receiver_type, name_text);
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "keyword argument `{name_text}` did not resolve to an indexed Python member"
                ),
            )
        }
        None => no_definition(
            "unsupported_python_reference_shape",
            format!(
                "`{}` is a Python `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn python_visible_module_binding_candidates(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<Vec<CodeUnit>> {
    let timeline = context.module_bindings(source, root);
    let events = timeline.get(name)?;
    let cutoff = if python_reference_is_deferred_function_body(node) {
        usize::MAX
    } else {
        node.start_byte()
    };
    let visible: Vec<_> = events
        .iter()
        .filter(|event| event.visible_from <= cutoff)
        .collect();
    if visible.is_empty() {
        return Some(Vec::new());
    }
    let start = visible
        .iter()
        .rposition(|event| !event.conditional)
        .unwrap_or(0);
    let mut candidates = Vec::new();
    for event in &visible[start..] {
        match &event.kind {
            ModuleBindingEventKind::FromImport {
                module,
                imported_name,
            } => {
                let mut resolved = false;
                for module_file in py.usage_resolve_module_files(&context.file, module) {
                    let Some(module_fqn) = analyzer
                        .declarations(&module_file)
                        .into_iter()
                        .find(CodeUnit::is_module)
                        .map(|unit| unit.fq_name())
                    else {
                        continue;
                    };
                    resolved = true;
                    let fqn = format!("{module_fqn}.{imported_name}");
                    candidates.extend(
                        py.resolve_fqn_candidates(&fqn, |candidate| support.fqn(candidate)),
                    );
                }
                if !resolved {
                    let fqn = if module.ends_with('.') {
                        format!("{module}{imported_name}")
                    } else {
                        format!("{module}.{imported_name}")
                    };
                    candidates.extend(
                        py.resolve_fqn_candidates(&fqn, |candidate| support.fqn(candidate)),
                    );
                }
            }
            ModuleBindingEventKind::ImportModule(module) => {
                candidates
                    .extend(py.resolve_fqn_candidates(module, |candidate| support.fqn(candidate)));
            }
            ModuleBindingEventKind::Other => {
                if let Some(local) = context.same_file.get(name) {
                    candidates.extend(python_visible_same_file_candidates(
                        analyzer,
                        &context.file,
                        node,
                        local,
                    ));
                }
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates)
}

fn python_visible_same_file_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing_class = analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|mut scope| {
            if scope.is_function() && !python_function_declaration_expression_is_class_scoped(node)
            {
                return None;
            }
            loop {
                if scope.is_class() {
                    break Some(scope);
                }
                if scope.is_module() {
                    break None;
                }
                scope = analyzer.parent_of(&scope)?;
            }
        });
    candidates
        .iter()
        .filter(|candidate| {
            analyzer.parent_of(candidate).is_some_and(|parent| {
                parent.is_module()
                    || enclosing_class
                        .as_ref()
                        .is_some_and(|scope| scope == &parent)
            })
        })
        .cloned()
        .collect()
}

fn python_function_declaration_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            return parent.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= site_start && site_end <= body.end_byte())
            });
        }
        if parent.kind() == "decorated_definition" {
            return current.kind() == "decorator";
        }
        if parent.kind() == "class_definition" {
            break;
        }
        current = parent;
    }
    false
}

fn python_reference_is_deferred_function_body(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return true;
        }
        current = parent;
    }
    false
}

pub(super) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

pub(super) struct PythonDefinitionContext {
    file: ProjectFile,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
    scope_facts: OnceLock<Arc<HashMap<CodeUnit, LocalBindingsSnapshot<String>>>>,
    module_bindings: OnceLock<Arc<ModuleBindingTimeline>>,
    receiver_types: Mutex<PythonReceiverTypeCache>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

struct PythonReceiverTypeCache {
    limit: usize,
    values: HashMap<(String, bool), Option<CodeUnit>>,
}

impl PythonReceiverTypeCache {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            values: HashMap::default(),
        }
    }
}

impl PythonDefinitionContext {
    pub(super) fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        #[cfg(test)] build_counters: Arc<PythonDefinitionBuildCounters>,
    ) -> Self {
        let binder = py.import_binder_of(file);
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
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
        let mut same_file: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in same_file.values_mut() {
            sort_units(units);
        }
        Self {
            file: file.clone(),
            named,
            namespace,
            same_file,
            scope_facts: OnceLock::new(),
            module_bindings: OnceLock::new(),
            receiver_types: Mutex::new(PythonReceiverTypeCache::new(
                PYTHON_RECEIVER_TYPE_CACHE_LIMIT,
            )),
            #[cfg(test)]
            build_counters,
        }
    }

    fn namespace_module_for_object(&self, object: &str) -> Option<&str> {
        if let Some(module) = self.namespace.get(object) {
            return Some(module.as_str());
        }
        self.namespace
            .values()
            .find(|module| module.as_str() == object)
            .map(String::as_str)
    }

    fn receiver_type_for_object(
        &self,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        object: &str,
    ) -> Option<CodeUnit> {
        if let Some(fqn) = self.named.get(object) {
            return python_class_for_fqn(py, support, fqn);
        }
        self.same_file
            .get(object)?
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    }

    fn receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        let raw_type = raw_type.trim();
        if &self.file != file {
            return self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file);
        }

        let key = (raw_type.to_string(), target_self_file);
        if let Some(cached) = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .get(&key)
        {
            return cached.clone();
        }

        #[cfg(test)]
        self.build_counters
            .receiver_type_cache_misses
            .fetch_add(1, Ordering::Relaxed);

        let resolved = self
            .receiver_type_for_object(py, support, raw_type)
            .or_else(|| self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file));

        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        if cache.values.len() < cache.limit {
            cache.values.insert(key, resolved.clone());
        }
        resolved
    }

    fn generic_receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        #[cfg(test)]
        self.build_counters
            .generic_receiver_type_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        resolve_python_receiver_type(analyzer, py, file, raw_type, target_self_file)
    }

    #[cfg(test)]
    pub(super) fn set_receiver_type_cache_limit(&self, limit: usize) {
        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        cache.limit = limit;
        cache.values.clear();
    }

    #[cfg(test)]
    pub(super) fn receiver_type_cache_len(&self) -> usize {
        self.receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .len()
    }

    fn scope_facts(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        source: &str,
        root: Node<'_>,
    ) -> Arc<HashMap<CodeUnit, LocalBindingsSnapshot<String>>> {
        self.scope_facts
            .get_or_init(|| {
                let _scope = crate::profiling::scope("get_definition::python::scope_facts");
                #[cfg(test)]
                self.build_counters
                    .scope_fact_builds
                    .fetch_add(1, Ordering::Relaxed);
                Arc::new(collect_scope_facts_from_parsed_source(
                    analyzer, py, file, source, root,
                ))
            })
            .clone()
    }

    fn module_bindings(&self, source: &str, root: Node<'_>) -> Arc<ModuleBindingTimeline> {
        self.module_bindings
            .get_or_init(|| Arc::new(collect_module_binding_timeline(root, source)))
            .clone()
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct PythonDefinitionBuildCounters {
    pub(super) context_builds: AtomicUsize,
    pub(super) scope_fact_builds: AtomicUsize,
    pub(super) receiver_type_cache_misses: AtomicUsize,
    pub(super) generic_receiver_type_fallbacks: AtomicUsize,
}

enum PythonReferenceNode<'tree> {
    Identifier(Node<'tree>),
    Attribute {
        object: Node<'tree>,
        attribute: Node<'tree>,
    },
    /// A keyword argument `name=value` in a call `Callee(name=..)`: `name` resolves
    /// to the callee type's member/parameter (e.g. a dataclass field `Foo.a`), not
    /// a name in scope.
    KeywordArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A keyword-argument identifier (`a` in `Foo(a=3)`): the `name` of a
/// `keyword_argument` inside a call's `argument_list`.
fn python_keyword_argument(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    if node.kind() != "identifier" {
        return None;
    }
    let kwarg = node
        .parent()
        .filter(|parent| parent.kind() == "keyword_argument")?;
    if kwarg.child_by_field_name("name") != Some(node) {
        return None;
    }
    let call = kwarg
        .parent()
        .filter(|parent| parent.kind() == "argument_list")?
        .parent()
        .filter(|parent| parent.kind() == "call")?;
    Some(PythonReferenceNode::KeywordArgument { call, name: node })
}

fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    if let Some(keyword) = python_keyword_argument(node) {
        return Some(keyword);
    }
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if parent.kind() == "attribute" {
            if parent.child_by_field_name("attribute") == Some(node)
                || parent.child_by_field_name("attribute") == Some(original)
            {
                node = parent;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            Some(PythonReferenceNode::Attribute { object, attribute })
        }
        "identifier" => Some(PythonReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn python_fqn_outcome(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    let candidates = py.resolve_fqn_candidates(fqn, |name| support.fqn(name));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if python_crosses_unindexed_boundary(support, fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial Python workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed Python definition was found"),
    )
}

fn python_class_for_fqn(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Option<CodeUnit> {
    py.resolve_fqn_candidates(fqn, |name| support.fqn(name))
        .into_iter()
        .find(|unit| unit.is_class())
}

fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    receiver_type: CodeUnit,
    member: &str,
) -> DefinitionLookupOutcome {
    // Members use a `.` separator; a nested class is indexed with `$`
    // (`Outer$Inner`), so try both.
    let member_candidates = |owner: &str| {
        let mut units = support.fqn(&format!("{owner}.{member}"));
        if units.is_empty() {
            units = support.fqn(&format!("{owner}${member}"));
        }
        units
    };
    let mut candidates = member_candidates(&receiver_type.fq_name());
    if candidates.is_empty()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        for ancestor in provider.get_ancestors(&receiver_type) {
            candidates.extend(member_candidates(&ancestor.fq_name()));
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "`{}.{member}` is not indexed as a Python definition",
                receiver_type.fq_name()
            ),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn python_crosses_unindexed_boundary(support: &dyn BoundedDefinitionLookup, fqn: &str) -> bool {
    let Some((module, _)) = fqn.rsplit_once('.') else {
        return !python_workspace_module_exists(support, "");
    };
    !python_workspace_module_exists(support, module)
}

fn python_workspace_module_exists(support: &dyn BoundedDefinitionLookup, module: &str) -> bool {
    if module.is_empty() {
        return false;
    }
    support.package_exists(module) || support.fqn_exists(module)
}

#[allow(clippy::too_many_arguments)]
fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "identifier" => {
            let receiver = python_slice(object, source);
            if let Some(unit) =
                python_self_receiver_type(analyzer, py, file, root, object, receiver)
            {
                return Some(unit);
            }
            // A typed-variable receiver: use the local/parameter's inferred type.
            let facts_by_scope = context.scope_facts(analyzer, py, file, source, root);
            if let Some(facts) = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)
                && let Some(raw_type) = facts
                    .resolution_for(receiver)
                    .as_precise()
                    .and_then(|targets| targets.iter().next().cloned())
                && let Some(unit) =
                    context.receiver_type(analyzer, py, support, file, &raw_type, false)
            {
                return Some(unit);
            }
            // A class-name receiver: `ClassName.Nested` / `ClassName.member`
            // accesses a member on the class itself.
            let class = context.receiver_type(analyzer, py, support, file, receiver, false);
            if class.is_some() {
                return class;
            }
            let binder = py.import_binder_of(file);
            let binding = binder.bindings.get(receiver)?;
            let imported = binding.imported_name.as_ref()?;
            let fqn = format!("{}.{}", binding.module_specifier, imported);
            python_class_for_fqn(py, support, &fqn)
        }
        // A call receiver: `Foo().bar` (construction) or `make().bar` (the
        // called function/method's return type).
        "call" => {
            python_call_result_type(analyzer, py, support, context, file, source, root, object)
        }
        _ => None,
    }
}

/// The type produced by a call expression: the class for a construction
/// (`Foo()`), or the resolved return type of the called function/method
/// (`make()`, `obj.make()`).
#[allow(clippy::too_many_arguments)]
fn python_call_result_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<CodeUnit> {
    let function = call.child_by_field_name("function")?;
    let callee =
        python_resolve_callable(analyzer, py, support, context, file, source, root, function)?;
    if callee.is_class() {
        return Some(callee);
    }
    python_callable_return_type(analyzer, py, support, context, &callee)
}

/// Resolve a call's callee expression to the class or function/method being
/// called.
#[allow(clippy::too_many_arguments)]
fn python_resolve_callable(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
) -> Option<CodeUnit> {
    match function.kind() {
        "identifier" => {
            let name = python_slice(function, source);
            if let Some(class) = context.receiver_type(analyzer, py, support, file, name, false) {
                return Some(class);
            }
            analyzer
                .declarations(file)
                .into_iter()
                .find(|unit| unit.identifier() == name && unit.is_function())
        }
        "attribute" => {
            let receiver = function.child_by_field_name("object")?;
            let method = python_slice(function.child_by_field_name("attribute")?, source);
            let receiver_type = python_receiver_type_unit(
                analyzer, py, support, context, file, source, root, receiver,
            )?;
            analyzer
                .definitions(&format!("{}.{}", receiver_type.fq_name(), method))
                .next()
        }
        _ => None,
    }
}

/// The declared or inferred return type of a Python function/method: read a
/// `-> T` annotation, else infer from a `return T(...)` / `return T` in the
/// body. Resolved in the callable's own file.
fn python_callable_return_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    callable: &CodeUnit,
) -> Option<CodeUnit> {
    let file = callable.source();
    let source = analyzer.get_source(callable, false)?;
    let tree = parse_python_tree(&source)?;
    let function = python_first_function_definition(tree.root_node())?;

    if let Some(return_type) = function.child_by_field_name("return_type") {
        let text = python_slice(return_type, &source).trim();
        if let Some(class) = context.receiver_type(analyzer, py, support, file, text, true) {
            return Some(class);
        }
    }

    let body = function.child_by_field_name("body")?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        // Don't descend into nested functions/classes — their returns are theirs.
        if matches!(node.kind(), "function_definition" | "class_definition") {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
        {
            let name = match value.kind() {
                "call" => value
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|f| python_slice(f, &source)),
                "identifier" => Some(python_slice(value, &source)),
                _ => None,
            };
            let class = name
                .and_then(|name| context.receiver_type(analyzer, py, support, file, name, true));
            if let Some(class) = class {
                return Some(class);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_first_function_definition(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_self_receiver_type(
    analyzer: &dyn IAnalyzer,
    _py: &PythonAnalyzer,
    file: &ProjectFile,
    _root: Node<'_>,
    object: Node<'_>,
    receiver: &str,
) -> Option<CodeUnit> {
    if receiver != "self" && receiver != "cls" {
        return None;
    }
    let range = Range {
        start_byte: object.start_byte(),
        end_byte: object.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .filter(|unit| unit.is_class())
}

fn python_unresolved_import_boundary(
    file: &ProjectFile,
    analyzer: &dyn IAnalyzer,
    local: &str,
    attribute: Option<&str>,
) -> bool {
    let Some(provider) = analyzer.import_analysis_provider() else {
        return false;
    };
    for import in provider.import_info_of(file) {
        let alias_or_identifier = import.alias.as_deref().or(import.identifier.as_deref());
        if alias_or_identifier == Some(local) {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != local);
        }
        if let Some(attribute) = attribute
            && import.identifier.as_deref() == Some(attribute)
            && import.alias.as_deref().unwrap_or(attribute) == attribute
        {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != attribute);
        }
    }
    false
}

fn python_name_shadowed_at(name: &str, root: Node<'_>, byte: usize, source: &str) -> bool {
    let Some(scope) = python_enclosing_function(root, byte) else {
        return false;
    };
    let mut locals = HashSet::default();
    if let Some(parameters) = scope.child_by_field_name("parameters") {
        python_collect_parameter_names(parameters, source, &mut locals);
    }
    if let Some(body) = scope.child_by_field_name("body") {
        python_collect_bound_targets(body, source, &mut locals);
    }
    locals.contains(name)
}

fn python_enclosing_function<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if matches!(node.kind(), "function_definition" | "lambda") {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn python_collect_parameter_names(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let name = match child.kind() {
            "identifier" => Some(child),
            _ => child.child_by_field_name("name").or_else(|| {
                child
                    .named_child(0)
                    .filter(|node| node.kind() == "identifier")
            }),
        };
        if let Some(name) = name {
            let text = python_slice(name, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
        }
    }
}

fn python_collect_bound_targets(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = python_slice(name, source).trim();
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
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn python_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "import_statement"
                | "import_from_statement"
                | "comment"
                | "string"
                | "string_content"
                | "module"
        ) && current.kind() != "module"
        {
            return true;
        }
        parent = current.parent();
    }
    false
}
