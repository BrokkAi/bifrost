use super::GoAnalyzer;
use super::declarations::{determine_go_package_name, go_node_text};
use super::imports::extract_go_import_path;
use crate::analyzer::type_relations::{MethodKey, MethodSet};
#[cfg(test)]
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::usages::go_graph::default_go_import_local_name;
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::{Node, Parser};

const EMPTY_INTERFACE_DESCENDANT_CAP: usize = 0;
const MAX_STRUCTURAL_SATISFACTION_PAIRS: usize = 2_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GoTypeKind {
    Concrete,
    Interface,
}

#[derive(Clone, Debug)]
struct GoTypeInfo {
    unit: CodeUnit,
    kind: GoTypeKind,
    method_set: MethodSet,
    pointer_method_set: MethodSet,
    own_method_names: HashSet<String>,
    embedded: Vec<EmbeddedType>,
    alias_target: Option<String>,
    has_type_terms: bool,
}

#[derive(Clone, Debug)]
struct EmbeddedType {
    fqn: String,
    pointer: bool,
}

struct EmbeddedTypeRef<'tree> {
    node: Node<'tree>,
    pointer: bool,
}

#[derive(Default)]
pub(super) struct GoHierarchyIndex {
    direct_ancestors: HashMap<String, Vec<CodeUnit>>,
    direct_descendants: HashMap<String, HashSet<CodeUnit>>,
    supported: HashSet<String>,
    #[cfg(test)]
    relations: Vec<TypeRelation>,
}

impl GoHierarchyIndex {
    pub(super) fn build(analyzer: &GoAnalyzer) -> Self {
        let mut builder = GoHierarchyBuilder::new(analyzer);
        builder.collect();
        builder.finish()
    }

    pub(super) fn direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendants
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn supports(&self, code_unit: &CodeUnit) -> bool {
        self.supported.contains(&code_unit.fq_name())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn relations(&self) -> &[TypeRelation] {
        &self.relations
    }
}

struct ParsedGoFile {
    file: ProjectFile,
    source: Arc<String>,
    root: tree_sitter::Tree,
    package_name: String,
    imports: HashMap<String, Vec<String>>,
    dot_imports: Vec<String>,
}

struct GoHierarchyBuilder<'a> {
    analyzer: &'a GoAnalyzer,
    files: Vec<ParsedGoFile>,
    types: HashMap<String, GoTypeInfo>,
    aliases: HashMap<String, String>,
    alias_units: HashMap<String, CodeUnit>,
    #[cfg(test)]
    relations: Vec<TypeRelation>,
}

impl<'a> GoHierarchyBuilder<'a> {
    fn new(analyzer: &'a GoAnalyzer) -> Self {
        Self {
            analyzer,
            files: Vec::new(),
            types: HashMap::default(),
            aliases: HashMap::default(),
            alias_units: HashMap::default(),
            #[cfg(test)]
            relations: Vec::new(),
        }
    }

    fn collect(&mut self) {
        self.parse_files();
        self.collect_types();
        self.collect_type_details();
        self.collect_methods();
        self.resolve_aliases();
        self.propagate_type_terms();
        self.promote_embedded_methods();
    }

    fn finish(self) -> GoHierarchyIndex {
        let mut direct_ancestors: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut supported = HashSet::default();
        #[cfg(test)]
        let mut relations = self.relations;

        let interfaces: Vec<_> = self
            .types
            .values()
            .filter(|info| info.kind == GoTypeKind::Interface)
            .cloned()
            .collect();

        for info in self.types.values() {
            if info.alias_target.is_none() {
                supported.insert(info.unit.fq_name());
            }
        }

        let concrete_count = self
            .types
            .values()
            .filter(|info| info.kind == GoTypeKind::Concrete && info.alias_target.is_none())
            .count();
        let interface_count = interfaces
            .iter()
            .filter(|info| !info.has_type_terms && !info.method_set.methods.is_empty())
            .count();
        if concrete_count.saturating_mul(interface_count) <= MAX_STRUCTURAL_SATISFACTION_PAIRS {
            for concrete in self
                .types
                .values()
                .filter(|info| info.kind == GoTypeKind::Concrete && info.alias_target.is_none())
            {
                for interface in &interfaces {
                    if interface.has_type_terms
                        || interface.method_set.methods.len() == EMPTY_INTERFACE_DESCENDANT_CAP
                    {
                        continue;
                    }
                    if method_set_satisfies(&concrete.method_set, &interface.method_set) {
                        record_structural_relation(
                            &mut direct_ancestors,
                            #[cfg(test)]
                            &mut relations,
                            &concrete.unit,
                            &interface.unit,
                        );
                    }
                }
            }
        }

        if interface_count.saturating_mul(interface_count) <= MAX_STRUCTURAL_SATISFACTION_PAIRS {
            for candidate in interfaces
                .iter()
                .filter(|info| !info.has_type_terms && info.alias_target.is_none())
            {
                for interface in &interfaces {
                    if interface.has_type_terms
                        || interface.method_set.methods.len() == EMPTY_INTERFACE_DESCENDANT_CAP
                        || interface.unit == candidate.unit
                    {
                        continue;
                    }
                    if method_set_satisfies(&candidate.method_set, &interface.method_set) {
                        record_structural_relation(
                            &mut direct_ancestors,
                            #[cfg(test)]
                            &mut relations,
                            &candidate.unit,
                            &interface.unit,
                        );
                    }
                }
            }
        }

        for ancestors in direct_ancestors.values_mut() {
            ancestors.sort();
            ancestors.dedup();
        }
        prune_transitive_ancestors(&mut direct_ancestors);
        let units_by_fqn: HashMap<String, CodeUnit> = self
            .types
            .values()
            .map(|info| (info.unit.fq_name(), info.unit.clone()))
            .collect();
        let mut direct_descendants = rebuild_direct_descendants(&direct_ancestors, &units_by_fqn);

        for (alias_fqn, target_fqn) in &self.aliases {
            let Some(alias_unit) = self.alias_units.get(alias_fqn) else {
                continue;
            };
            supported.insert(alias_unit.fq_name());
            if let Some(ancestors) = direct_ancestors.get(target_fqn).cloned() {
                direct_ancestors.insert(alias_unit.fq_name(), ancestors);
            }
            if let Some(descendants) = direct_descendants.get(target_fqn).cloned() {
                direct_descendants.insert(alias_unit.fq_name(), descendants);
            }
        }

        GoHierarchyIndex {
            direct_ancestors,
            direct_descendants,
            supported,
            #[cfg(test)]
            relations,
        }
    }

    fn parse_files(&mut self) {
        let mut files: Vec<_> = self.analyzer.get_analyzed_files().into_iter().collect();
        files.sort();
        let mut parsed_files = Vec::new();
        let mut package_index = Vec::new();
        let mut declared_names = HashMap::default();
        for file in files {
            let Ok(source) = self.analyzer.project().read_source(&file) else {
                continue;
            };
            let mut parser = Parser::new();
            if parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .is_err()
            {
                continue;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                continue;
            };
            let declared_name = determine_go_package_name(tree.root_node(), &source);
            let package_name = super::packages::canonical_go_package_name(&file, &declared_name);
            declared_names
                .entry(package_name.clone())
                .or_insert(declared_name);
            package_index.push((file.clone(), package_name.clone()));
            parsed_files.push(ParsedGoFile {
                file: file.clone(),
                source: Arc::new(source),
                root: tree,
                package_name,
                imports: HashMap::default(),
                dot_imports: Vec::new(),
            });
        }
        for mut parsed in parsed_files {
            let (imports, dot_imports) =
                import_packages(self.analyzer, &parsed.file, &package_index, &declared_names);
            parsed.imports = imports;
            parsed.dot_imports = dot_imports;
            self.files.push(parsed);
        }
    }

    fn collect_types(&mut self) {
        let mut discovered = Vec::new();
        for file in &self.files {
            let mut stack = vec![file.root.root_node()];
            while let Some(node) = stack.pop() {
                match node.kind() {
                    "type_spec" => {
                        if let Some(info) = self.type_skeleton(file, node) {
                            discovered.push(info);
                        }
                    }
                    _ => {
                        let mut cursor = node.walk();
                        for child in node.named_children(&mut cursor) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        for info in discovered {
            self.types.insert(info.unit.fq_name(), info);
        }
    }

    fn type_skeleton(&self, file: &ParsedGoFile, node: Node<'_>) -> Option<GoTypeInfo> {
        let name_node = node.child_by_field_name("name")?;
        let type_node = node.child_by_field_name("type")?;
        let name = go_node_text(name_node, &file.source).trim();
        if name.is_empty() {
            return None;
        }
        let unit = self.type_unit(&file.file, &file.package_name, name)?;
        let kind = if type_node.kind() == "interface_type" {
            GoTypeKind::Interface
        } else {
            GoTypeKind::Concrete
        };
        Some(GoTypeInfo {
            method_set: MethodSet::new(unit.clone()),
            pointer_method_set: MethodSet::new(unit.clone()),
            own_method_names: HashSet::default(),
            unit,
            kind,
            embedded: Vec::new(),
            alias_target: None,
            has_type_terms: false,
        })
    }

    fn collect_type_details(&mut self) {
        self.collect_aliases();
        let mut embedded_by_type: HashMap<String, Vec<EmbeddedType>> = HashMap::default();
        let mut methods_by_type: HashMap<String, Vec<MethodKey>> = HashMap::default();
        let mut has_type_terms = HashSet::default();

        for file in &self.files {
            let mut stack = vec![file.root.root_node()];
            while let Some(node) = stack.pop() {
                match node.kind() {
                    "type_spec" => {
                        let Some(name_node) = node.child_by_field_name("name") else {
                            continue;
                        };
                        let Some(type_node) = node.child_by_field_name("type") else {
                            continue;
                        };
                        let name = go_node_text(name_node, &file.source).trim();
                        let fqn = format!("{}.{name}", file.package_name);
                        match type_node.kind() {
                            "interface_type" => {
                                let mut embedded = Vec::new();
                                let mut methods = Vec::new();
                                self.collect_interface_details(
                                    file,
                                    type_node,
                                    &mut embedded,
                                    &mut methods,
                                    &mut has_type_terms,
                                );
                                embedded_by_type.insert(fqn.clone(), embedded);
                                methods_by_type.insert(fqn, methods);
                            }
                            "struct_type" => {
                                let embedded = embedded_type_refs(type_node)
                                    .filter_map(|embedded| {
                                        self.resolve_type_node(file, embedded.node).map(|fqn| {
                                            EmbeddedType {
                                                fqn,
                                                pointer: embedded.pointer,
                                            }
                                        })
                                    })
                                    .collect();
                                embedded_by_type.insert(fqn, embedded);
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        let mut cursor = node.walk();
                        for child in node.named_children(&mut cursor) {
                            stack.push(child);
                        }
                    }
                }
            }
        }

        for (fqn, embedded) in embedded_by_type {
            if let Some(info) = self.types.get_mut(&fqn) {
                info.embedded.extend(embedded);
            }
        }
        for (fqn, methods) in methods_by_type {
            if let Some(info) = self.types.get_mut(&fqn) {
                for method in methods {
                    info.method_set.insert(method);
                }
            }
        }
        for fqn in has_type_terms {
            if let Some(info) = self.types.get_mut(&fqn) {
                info.has_type_terms = true;
            }
        }
    }

    fn collect_aliases(&mut self) {
        let mut aliases = HashMap::default();
        let mut alias_units = HashMap::default();
        for file in &self.files {
            let mut stack = vec![file.root.root_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == "type_alias" {
                    let Some(name_node) = node.child_by_field_name("name") else {
                        continue;
                    };
                    let Some(type_node) = node.child_by_field_name("type") else {
                        continue;
                    };
                    let name = go_node_text(name_node, &file.source).trim();
                    let alias_fqn = format!("{}.{name}", file.package_name);
                    if let Some(target) = self.resolve_type_node(file, type_node) {
                        aliases.insert(alias_fqn.clone(), target);
                    }
                    let alias_unit = self.analyzer.definitions(&alias_fqn).next().cloned();
                    let alias_unit = alias_unit.or_else(|| {
                        self.analyzer
                            .declarations(&file.file)
                            .find(|unit| unit.identifier() == name)
                            .cloned()
                    });
                    if let Some(unit) = alias_unit {
                        alias_units.insert(alias_fqn, unit);
                    }
                    continue;
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
        self.aliases.extend(aliases);
        self.alias_units.extend(alias_units);
    }

    fn collect_interface_details(
        &self,
        file: &ParsedGoFile,
        node: Node<'_>,
        embedded: &mut Vec<EmbeddedType>,
        methods: &mut Vec<MethodKey>,
        has_type_terms: &mut HashSet<String>,
    ) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "method_elem" => {
                    if let Some(method) =
                        method_key(child, &file.source, &file.package_name, |ty| {
                            self.type_token(file, ty)
                        })
                    {
                        methods.push(method);
                    }
                }
                "type_elem" => {
                    let mut type_cursor = child.walk();
                    for type_child in child.named_children(&mut type_cursor) {
                        if let Some(target) = self.resolve_type_node(file, type_child) {
                            let target = resolve_alias_fqn(&self.aliases, &target);
                            if self
                                .types
                                .get(&target)
                                .is_some_and(|info| info.kind == GoTypeKind::Interface)
                            {
                                embedded.push(EmbeddedType {
                                    fqn: target,
                                    pointer: false,
                                });
                            } else if let Some(name_node) = node
                                .parent()
                                .and_then(|parent| parent.child_by_field_name("name"))
                            {
                                if is_empty_interface_embed(type_child, &file.source) {
                                    continue;
                                }
                                has_type_terms.insert(format!(
                                    "{}.{}",
                                    file.package_name,
                                    go_node_text(name_node, &file.source).trim()
                                ));
                            }
                        } else if let Some(name_node) = node
                            .parent()
                            .and_then(|parent| parent.child_by_field_name("name"))
                        {
                            if is_empty_interface_embed(type_child, &file.source) {
                                continue;
                            }
                            has_type_terms.insert(format!(
                                "{}.{}",
                                file.package_name,
                                go_node_text(name_node, &file.source).trim()
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_methods(&mut self) {
        let mut additions: Vec<(String, bool, MethodKey)> = Vec::new();
        for file in &self.files {
            let mut stack = vec![file.root.root_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == "method_declaration" {
                    if let Some((receiver, pointer_receiver, method)) =
                        self.method_declaration(file, node)
                    {
                        additions.push((receiver, pointer_receiver, method));
                    }
                    continue;
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }
        for (receiver, pointer_receiver, method) in additions {
            if let Some(info) = self.types.get_mut(&receiver)
                && info.kind == GoTypeKind::Concrete
            {
                if pointer_receiver {
                    info.pointer_method_set.insert(method);
                } else {
                    info.own_method_names.insert(method.name.clone());
                    info.method_set.insert(method);
                }
            }
        }
    }

    fn method_declaration(
        &self,
        file: &ParsedGoFile,
        node: Node<'_>,
    ) -> Option<(String, bool, MethodKey)> {
        let receiver = node.child_by_field_name("receiver")?;
        let receiver_type = receiver_type_node(receiver)?;
        let pointer_receiver = receiver_type.kind() == "pointer_type";
        let receiver_fqn = self.resolve_type_node(file, receiver_type)?;
        let method = method_key(node, &file.source, &file.package_name, |ty| {
            self.type_token(file, ty)
        })?;
        Some((receiver_fqn, pointer_receiver, method))
    }

    fn resolve_aliases(&mut self) {
        let aliases = self.aliases.clone();
        for target in self.aliases.values_mut() {
            *target = resolve_alias_fqn(&aliases, target);
        }
        for info in self.types.values_mut() {
            for embedded in &mut info.embedded {
                embedded.fqn = resolve_alias_fqn(&aliases, &embedded.fqn);
            }
        }
    }

    fn propagate_type_terms(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            let constrained: HashSet<String> = self
                .types
                .iter()
                .filter(|(_fqn, info)| info.has_type_terms)
                .map(|(fqn, _info)| fqn.clone())
                .collect();
            for info in self.types.values_mut() {
                if info.has_type_terms {
                    continue;
                }
                if info
                    .embedded
                    .iter()
                    .any(|embedded| constrained.contains(&embedded.fqn))
                {
                    info.has_type_terms = true;
                    changed = true;
                }
            }
        }
    }

    fn promote_embedded_methods(&mut self) {
        let snapshot = self.types.clone();
        let keys: Vec<_> = self.types.keys().cloned().collect();
        for fqn in keys {
            let Some(original) = snapshot.get(&fqn) else {
                continue;
            };
            let promoted = match original.kind {
                GoTypeKind::Interface => interface_promoted_methods(&snapshot, &original.embedded),
                GoTypeKind::Concrete => struct_promoted_methods(&snapshot, original),
            };
            let Some(info) = self.types.get_mut(&fqn) else {
                continue;
            };
            info.method_set.extend(&promoted);
            #[cfg(test)]
            for embedded in &original.embedded {
                if let Some(embedded_unit) =
                    snapshot.get(&embedded.fqn).map(|info| info.unit.clone())
                {
                    self.relations.push(TypeRelation {
                        from: info.unit.clone(),
                        to: embedded_unit,
                        kind: TypeRelationKind::Embedding,
                    });
                }
            }
        }
    }

    fn resolve_type_node(&self, file: &ParsedGoFile, node: Node<'_>) -> Option<String> {
        let reference = type_ref_node(node)?;
        match reference.kind() {
            "qualified_type" => {
                let qualifier = reference.child_by_field_name("package")?;
                let name = reference.child_by_field_name("name")?;
                let qualifier = go_node_text(qualifier, &file.source).trim();
                let name = go_node_text(name, &file.source).trim();
                file.imports.get(qualifier)?.iter().find_map(|package| {
                    let candidate = format!("{package}.{name}");
                    (self.types.contains_key(&candidate) || self.aliases.contains_key(&candidate))
                        .then_some(candidate)
                })
            }
            "type_identifier" | "identifier" => {
                let name = go_node_text(reference, &file.source).trim();
                if name == "any" {
                    return None;
                }
                let same_package = format!("{}.{name}", file.package_name);
                if self.types.contains_key(&same_package)
                    || self.aliases.contains_key(&same_package)
                {
                    return Some(same_package);
                }
                file.dot_imports
                    .iter()
                    .map(|package| format!("{package}.{name}"))
                    .find(|candidate| {
                        self.types.contains_key(candidate) || self.aliases.contains_key(candidate)
                    })
            }
            _ => None,
        }
    }

    fn type_token(&self, file: &ParsedGoFile, node: Node<'_>) -> String {
        match node.kind() {
            "qualified_type" => self
                .resolve_type_node(file, node)
                .map(|fqn| resolve_alias_fqn(&self.aliases, &fqn))
                .or_else(|| external_qualified_type_token(file, node))
                .unwrap_or_else(|| go_node_text(node, &file.source).trim().to_string()),
            "type_identifier" | "identifier" => self
                .resolve_type_node(file, node)
                .map(|fqn| resolve_alias_fqn(&self.aliases, &fqn))
                .unwrap_or_else(|| {
                    let name = go_node_text(node, &file.source).trim();
                    if is_predeclared_go_type(name) {
                        name.to_string()
                    } else {
                        format!("{}.{name}", file.package_name)
                    }
                }),
            "pointer_type" => node
                .named_child(0)
                .map(|child| format!("*{}", self.type_token(file, child)))
                .unwrap_or_else(|| go_node_text(node, &file.source).trim().to_string()),
            "slice_type" => node
                .named_child(0)
                .map(|child| format!("[]{}", self.type_token(file, child)))
                .unwrap_or_else(|| go_node_text(node, &file.source).trim().to_string()),
            "array_type" => {
                let length = node
                    .child_by_field_name("length")
                    .map(|child| go_node_text(child, &file.source).trim().to_string())
                    .unwrap_or_default();
                let element = node
                    .child_by_field_name("element")
                    .map(|child| self.type_token(file, child))
                    .unwrap_or_default();
                format!("[{length}]{element}")
            }
            "map_type" => {
                let key = node
                    .child_by_field_name("key")
                    .map(|child| self.type_token(file, child))
                    .unwrap_or_default();
                let value = node
                    .child_by_field_name("value")
                    .map(|child| self.type_token(file, child))
                    .unwrap_or_default();
                format!("map[{key}]{value}")
            }
            "channel_type" => {
                let direction = channel_direction(node);
                let value = node
                    .named_child(0)
                    .map(|child| self.type_token(file, child))
                    .unwrap_or_else(|| go_node_text(node, &file.source).trim().to_string());
                format!("{direction}{value}")
            }
            "generic_type" => {
                let mut cursor = node.walk();
                let parts: Vec<_> = node
                    .named_children(&mut cursor)
                    .map(|child| self.type_token(file, child))
                    .collect();
                parts.join("[")
            }
            "type_elem" | "type_constraint" | "parenthesized_type" => {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .map(|child| self.type_token(file, child))
                    .collect::<Vec<_>>()
                    .join("|")
            }
            "negated_type" => node
                .named_child(0)
                .map(|child| format!("~{}", self.type_token(file, child)))
                .unwrap_or_else(|| go_node_text(node, &file.source).trim().to_string()),
            _ => go_node_text(node, &file.source).trim().to_string(),
        }
    }

    fn type_unit(&self, file: &ProjectFile, package_name: &str, name: &str) -> Option<CodeUnit> {
        let fqn = format!("{package_name}.{name}");
        self.analyzer
            .definitions(&fqn)
            .find(|unit| unit.source() == file && unit.is_class())
            .cloned()
            .or_else(|| {
                self.analyzer
                    .declarations(file)
                    .find(|unit| unit.is_class() && unit.identifier() == name)
                    .cloned()
            })
    }
}

fn import_packages(
    analyzer: &GoAnalyzer,
    file: &ProjectFile,
    package_index: &[(ProjectFile, String)],
    declared_names: &HashMap<String, String>,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut by_alias: HashMap<String, Vec<String>> = HashMap::default();
    let mut dot_imports = Vec::new();
    for import in analyzer.import_info_of(file) {
        let alias = import.alias.as_deref();
        if alias == Some("_") {
            continue;
        }
        let Some(path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        let mut packages: Vec<_> = package_index
            .iter()
            .filter(|(candidate, _package)| candidate != file)
            .filter(|(candidate, package)| {
                package == &path || path_suffix_matches(&candidate.parent(), &path)
            })
            .map(|(_candidate, package)| package.clone())
            .collect();
        if packages.is_empty() {
            packages.push(path.clone());
        }
        packages.sort();
        packages.dedup();
        if packages.is_empty() {
            continue;
        }
        match alias {
            Some(".") => dot_imports.extend(packages),
            Some(alias) => by_alias
                .entry(alias.to_string())
                .or_default()
                .extend(packages),
            None => {
                for package in packages {
                    let local = declared_names
                        .get(&package)
                        .cloned()
                        .unwrap_or_else(|| default_go_import_local_name(&package));
                    by_alias.entry(local).or_default().push(package);
                }
            }
        }
    }
    for packages in by_alias.values_mut() {
        packages.sort();
        packages.dedup();
    }
    dot_imports.sort();
    dot_imports.dedup();
    (by_alias, dot_imports)
}

fn method_key(
    node: Node<'_>,
    source: &str,
    package_name: &str,
    mut type_token: impl FnMut(Node<'_>) -> String,
) -> Option<MethodKey> {
    let name_node = node.child_by_field_name("name")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let name = if is_exported_go_identifier(name) {
        name.to_string()
    } else {
        format!("{package_name}.{name}")
    };
    let mut tokens = Vec::new();
    if let Some(parameters) = node.child_by_field_name("parameters") {
        tokens.push(format!(
            "params({})",
            parameter_type_tokens(parameters, &mut type_token).join(",")
        ));
    }
    if let Some(result) = node.child_by_field_name("result") {
        let result_types = if result.kind() == "parameter_list" {
            parameter_type_tokens(result, &mut type_token)
        } else {
            vec![type_token(result)]
        };
        tokens.push(format!("results({})", result_types.join(",")));
    }
    Some(MethodKey::new(name, Some(tokens.join(" "))))
}

fn parameter_type_tokens(
    node: Node<'_>,
    type_token: &mut impl FnMut(Node<'_>) -> String,
) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                let Some(ty) = parameter_type_node(child) else {
                    continue;
                };
                let token = type_token(ty);
                let count = parameter_name_count(child).max(1);
                types.extend(std::iter::repeat_n(token, count));
            }
            "variadic_parameter_declaration" => {
                let Some(ty) = parameter_type_node(child) else {
                    continue;
                };
                let token = format!("...{}", type_token(ty));
                let count = parameter_name_count(child).max(1);
                types.extend(std::iter::repeat_n(token, count));
            }
            _ => {}
        }
    }
    types
}

fn parameter_type_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type")
        .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
}

fn parameter_name_count(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .count()
}

fn receiver_type_node(receiver: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = receiver.walk();
    receiver
        .named_children(&mut cursor)
        .find(|child| child.kind() == "parameter_declaration")
        .and_then(parameter_type_node)
}

fn embedded_type_refs(node: Node<'_>) -> impl Iterator<Item = EmbeddedTypeRef<'_>> {
    let mut embedded = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "field_declaration" => collect_embedded_field(child, &mut embedded),
            "field_declaration_list" => {
                let mut field_cursor = child.walk();
                for field in child.named_children(&mut field_cursor) {
                    if field.kind() == "field_declaration" {
                        collect_embedded_field(field, &mut embedded);
                    }
                }
            }
            _ => {}
        }
    }
    embedded.into_iter()
}

fn collect_embedded_field<'tree>(field: Node<'tree>, embedded: &mut Vec<EmbeddedTypeRef<'tree>>) {
    if is_embedded_field(field)
        && let Some(ty) = field.child_by_field_name("type")
    {
        embedded.push(EmbeddedTypeRef {
            node: ty,
            pointer: is_pointer_embedded_field(field, ty),
        });
    }
}

fn is_embedded_field(node: Node<'_>) -> bool {
    node.child_by_field_name("name")
        .is_none_or(|name| name.kind() == "type_identifier")
}

fn is_pointer_embedded_field(field: Node<'_>, ty: Node<'_>) -> bool {
    if ty.kind() == "pointer_type" {
        return true;
    }
    (0..field.child_count()).any(|index| {
        field
            .child(index)
            .is_some_and(|child| child.end_byte() <= ty.start_byte() && child.kind() == "*")
    })
}

fn type_ref_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "identifier" | "qualified_type" => Some(node),
        "pointer_type" | "generic_type" | "parenthesized_type" | "negated_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).find_map(type_ref_node)
        }
        _ => None,
    }
}

fn is_empty_interface_embed(node: Node<'_>, source: &str) -> bool {
    if matches!(node.kind(), "identifier" | "type_identifier")
        && go_node_text(node, source).trim() == "any"
    {
        return true;
    }
    if node.kind() != "interface_type" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next().is_none()
}

fn resolve_alias_fqn(aliases: &HashMap<String, String>, fqn: &str) -> String {
    let mut current = fqn.to_string();
    let mut seen = HashSet::default();
    while seen.insert(current.clone()) {
        let Some(next) = aliases.get(&current) else {
            break;
        };
        current = next.clone();
    }
    current
}

fn interface_promoted_methods(
    types: &HashMap<String, GoTypeInfo>,
    embedded: &[EmbeddedType],
) -> MethodSet {
    let mut promoted = MethodSet {
        methods: HashSet::default(),
    };
    let mut stack: Vec<_> = embedded
        .iter()
        .map(|embedded| embedded.fqn.clone())
        .collect();
    let mut seen = HashSet::default();
    while let Some(fqn) = stack.pop() {
        if !seen.insert(fqn.clone()) {
            continue;
        }
        let Some(info) = types.get(&fqn) else {
            continue;
        };
        promoted.extend(&info.method_set);
        stack.extend(info.embedded.iter().map(|embedded| embedded.fqn.clone()));
    }
    promoted
}

fn struct_promoted_methods(types: &HashMap<String, GoTypeInfo>, info: &GoTypeInfo) -> MethodSet {
    let mut candidates: HashMap<String, Vec<(usize, MethodKey)>> = HashMap::default();
    let mut stack: Vec<_> = info
        .embedded
        .iter()
        .map(|embedded| {
            (
                embedded.fqn.clone(),
                embedded.pointer,
                1usize,
                Vec::<String>::new(),
            )
        })
        .collect();
    while let Some((fqn, pointer_path, depth, path)) = stack.pop() {
        if path.iter().any(|seen| seen == &fqn) {
            continue;
        }
        let mut next_path = path;
        next_path.push(fqn.clone());
        let Some(embedded_info) = types.get(&fqn) else {
            continue;
        };
        for method in &embedded_info.method_set.methods {
            candidates
                .entry(method.name.clone())
                .or_default()
                .push((depth, method.clone()));
        }
        if pointer_path {
            for method in &embedded_info.pointer_method_set.methods {
                candidates
                    .entry(method.name.clone())
                    .or_default()
                    .push((depth, method.clone()));
            }
        }
        for nested in &embedded_info.embedded {
            stack.push((
                nested.fqn.clone(),
                pointer_path || nested.pointer,
                depth + 1,
                next_path.clone(),
            ));
        }
    }

    let mut promoted = MethodSet {
        methods: HashSet::default(),
    };
    for (name, methods) in candidates {
        if info.own_method_names.contains(&name) {
            continue;
        }
        let Some(min_depth) = methods.iter().map(|(depth, _method)| *depth).min() else {
            continue;
        };
        let at_min: Vec<_> = methods
            .into_iter()
            .filter_map(|(depth, method)| (depth == min_depth).then_some(method))
            .collect();
        if at_min.len() == 1 {
            promoted.insert(at_min[0].clone());
        }
    }
    promoted
}

fn prune_transitive_ancestors(direct_ancestors: &mut HashMap<String, Vec<CodeUnit>>) {
    let snapshot = direct_ancestors.clone();
    for (from, ancestors) in direct_ancestors {
        ancestors.retain(|ancestor| {
            !snapshot.get(from).is_some_and(|siblings| {
                siblings.iter().any(|middle| {
                    middle != ancestor
                        && snapshot
                            .get(&middle.fq_name())
                            .is_some_and(|middle_ancestors| middle_ancestors.contains(ancestor))
                })
            })
        });
    }
}

fn rebuild_direct_descendants(
    direct_ancestors: &HashMap<String, Vec<CodeUnit>>,
    units_by_fqn: &HashMap<String, CodeUnit>,
) -> HashMap<String, HashSet<CodeUnit>> {
    let mut direct_descendants: HashMap<String, HashSet<CodeUnit>> = HashMap::default();
    for (from_fqn, ancestors) in direct_ancestors {
        let Some(from) = units_by_fqn.get(from_fqn) else {
            continue;
        };
        for ancestor in ancestors {
            direct_descendants
                .entry(ancestor.fq_name())
                .or_default()
                .insert(from.clone());
        }
    }
    direct_descendants
}

fn path_suffix_matches(path: &std::path::Path, suffix: &str) -> bool {
    let parent = path.to_string_lossy().replace('\\', "/");
    parent == suffix || parent.ends_with(&format!("/{suffix}"))
}

fn is_exported_go_identifier(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_uppercase())
}

fn is_predeclared_go_type(name: &str) -> bool {
    matches!(
        name,
        "any"
            | "bool"
            | "byte"
            | "comparable"
            | "complex64"
            | "complex128"
            | "error"
            | "float32"
            | "float64"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "rune"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
    )
}

fn channel_direction(node: Node<'_>) -> &'static str {
    let mut chan_start = None;
    let mut arrow_start = None;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        match child.kind() {
            "<-" => arrow_start = Some(child.start_byte()),
            "chan" => chan_start = Some(child.start_byte()),
            _ => {}
        }
    }
    match (arrow_start, chan_start) {
        (Some(arrow), Some(chan)) if arrow < chan => "<-chan ",
        (Some(_), Some(_)) => "chan<- ",
        _ => "chan ",
    }
}

fn external_qualified_type_token(file: &ParsedGoFile, node: Node<'_>) -> Option<String> {
    let qualifier = node.child_by_field_name("package")?;
    let name = node.child_by_field_name("name")?;
    let qualifier = go_node_text(qualifier, &file.source).trim();
    let name = go_node_text(name, &file.source).trim();
    let mut packages = file.imports.get(qualifier)?.iter();
    let package = packages.next()?;
    packages
        .next()
        .is_none()
        .then(|| format!("{package}.{name}"))
}

fn method_set_satisfies(candidate: &MethodSet, required: &MethodSet) -> bool {
    candidate.satisfies_with(required, |candidate, required| candidate == required)
}

fn record_structural_relation(
    direct_ancestors: &mut HashMap<String, Vec<CodeUnit>>,
    #[cfg(test)] relations: &mut Vec<TypeRelation>,
    from: &CodeUnit,
    to: &CodeUnit,
) {
    let ancestors = direct_ancestors.entry(from.fq_name()).or_default();
    if !ancestors.contains(to) {
        ancestors.push(to.clone());
    }
    #[cfg(test)]
    relations.push(TypeRelation {
        from: from.clone(),
        to: to.clone(),
        kind: TypeRelationKind::StructuralSatisfaction,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;
    use crate::analyzer::{Language, TestProject};
    use std::fs;
    use tempfile::tempdir;

    fn analyzer(files: &[(&str, &str)]) -> GoAnalyzer {
        let temp = tempdir().unwrap();
        let root = temp.keep();
        fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.22\n").unwrap();
        for (path, source) in files {
            let path = root.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, source).unwrap();
        }
        GoAnalyzer::from_project(TestProject::new(root, Language::Go))
    }

    #[test]
    fn structural_relation_records_satisfied_interface() {
        let analyzer = analyzer(&[(
            "service.go",
            "package app\ntype Runner interface { Run() error }\ntype Worker struct{}\nfunc (Worker) Run() error { return nil }\n",
        )]);
        let index = GoHierarchyIndex::build(&analyzer);
        assert!(index.relations().iter().any(|relation| {
            relation.kind == TypeRelationKind::StructuralSatisfaction
                && relation.from.identifier() == "Worker"
                && relation.to.identifier() == "Runner"
        }));
    }
}
