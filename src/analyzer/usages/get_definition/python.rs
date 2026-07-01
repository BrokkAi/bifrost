use super::*;

pub(super) fn resolve_python(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
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

    let ctx = PythonDefinitionContext::build(py, analyzer, support, file, source);
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
                && let Some(receiver_type) = ctx.receiver_type_for_object(support, object_text)
            {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if let Some(receiver_type) =
                python_receiver_type_unit(analyzer, py, file, source, tree.root_node(), object)
            {
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
            if let Some(fqn) = ctx.named.get(text).or_else(|| ctx.namespace.get(text)) {
                return python_fqn_outcome(py, support, fqn, text);
            }
            if let Some(candidates) = ctx.same_file.get(text)
                && !candidates.is_empty()
            {
                return candidates_outcome(candidates.clone());
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

pub(super) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

struct PythonDefinitionContext {
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
}

impl PythonDefinitionContext {
    fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        _support: &DefinitionLookupIndex,
        file: &ProjectFile,
        _source: &str,
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
            named,
            namespace,
            same_file,
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
        support: &DefinitionLookupIndex,
        object: &str,
    ) -> Option<CodeUnit> {
        if let Some(fqn) = self.named.get(object) {
            return support.fqn(fqn).into_iter().find(|unit| unit.is_class());
        }
        self.same_file
            .get(object)?
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    }
}

enum PythonReferenceNode<'tree> {
    Identifier(Node<'tree>),
    Attribute {
        object: Node<'tree>,
        attribute: Node<'tree>,
    },
}

fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
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
    support: &DefinitionLookupIndex,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let candidates = py.resolve_exported_fqn(fqn);
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

fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
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

fn python_crosses_unindexed_boundary(support: &DefinitionLookupIndex, fqn: &str) -> bool {
    let Some((module, _)) = fqn.rsplit_once('.') else {
        return !python_workspace_module_exists(support, "");
    };
    !python_workspace_module_exists(support, module)
}

fn python_workspace_module_exists(support: &DefinitionLookupIndex, module: &str) -> bool {
    support.package_exists(module) || support.fqn_exists(module)
}

fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
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
            let facts_by_scope = collect_scope_facts(analyzer, file, &[], "", true);
            if let Some(facts) = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)
                && let Some(raw_type) = facts
                    .resolution_for(receiver)
                    .as_precise()
                    .and_then(|targets| targets.iter().next().cloned())
                && let Some(unit) = resolve_python_receiver_type(analyzer, file, &raw_type, false)
            {
                return Some(unit);
            }
            // A class-name receiver: `ClassName.Nested` / `ClassName.member`
            // accesses a member on the class itself.
            resolve_python_receiver_type(analyzer, file, receiver, false)
        }
        // A construction receiver `Foo().bar` is typed by the class being called.
        "call" => {
            let function = object.child_by_field_name("function")?;
            if function.kind() != "identifier" {
                return None;
            }
            let name = python_slice(function, source);
            resolve_python_receiver_type(analyzer, file, name, false)
        }
        _ => None,
    }
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
