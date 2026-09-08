//! The pre-#1748 Go hierarchy build, kept as a parity oracle.
//!
//! This is the builder as it stood at `bd8a4491a`: it reads and parses every
//! Go file itself in a sequential loop, walks each file's AST once per phase,
//! asks the store for each declared type's definition and for each file's
//! declarations, and deep-clones the type table to promote embedded methods.
//! The build that replaced it parses once for both workspace indexes, records
//! every phase's sites in one walk per file, and reads the workspace's
//! declarations in one batch.
//!
//! It exists so that change can be certified rather than argued: both builds
//! run in one process over the same analyzer, and
//! [`GoHierarchyIndex::facts_text`] must be equal. Nothing outside a test
//! calls it, and only the pieces that changed are duplicated here -- the
//! satisfaction pass in [`GoHierarchyBuilder::finish`], the method-key and
//! promotion helpers, and the package/import tables are the same code both
//! builds run.

use super::*;
use crate::declarations::determine_go_package_name;
use std::sync::Arc;
use tree_sitter::Parser;

/// One Go file the oracle read and parsed itself.
struct ParsedGoFile {
    file: ProjectFile,
    source: Arc<String>,
    root: tree_sitter::Tree,
    package_name: String,
    imports: HashMap<String, Vec<String>>,
    dot_imports: Vec<String>,
}

struct OracleBuilder<'a> {
    token: QueryToken<'a>,
    index: &'a dyn CodeUnitIndex,
    imports: &'a dyn ImportAnalysisProvider,
    files: Vec<ParsedGoFile>,
    types: HashMap<String, GoTypeInfo>,
    aliases: HashMap<String, String>,
    alias_units: HashMap<String, CodeUnit>,
    all_files_parsed: bool,
    package_lookups: usize,
    relations: Vec<TypeRelation>,
}

impl GoHierarchyIndex {
    /// Build the index the way the pre-#1748 builder did.
    pub fn build_oracle(
        token: QueryToken<'_>,
        index: &dyn CodeUnitIndex,
        imports: &dyn ImportAnalysisProvider,
    ) -> Self {
        let mut oracle = OracleBuilder {
            token,
            index,
            imports,
            files: Vec::new(),
            types: HashMap::default(),
            aliases: HashMap::default(),
            alias_units: HashMap::default(),
            all_files_parsed: true,
            package_lookups: 0,
            relations: Vec::new(),
        };
        oracle.collect();
        let mut builder = GoHierarchyBuilder::new(index, oracle.all_files_parsed);
        builder.types = oracle.types;
        builder.aliases = oracle.aliases;
        builder.alias_units = oracle.alias_units;
        builder.package_lookups = oracle.package_lookups;
        builder.relations = oracle.relations;
        builder.finish()
    }
}

impl OracleBuilder<'_> {
    fn collect(&mut self) {
        self.parse_files();
        self.prefetch_declared_type_definitions();
        self.collect_types();
        self.collect_type_details();
        self.collect_methods();
        self.resolve_aliases();
        self.propagate_type_terms();
        self.promote_embedded_methods();
        self.resolve_member_units();
    }

    /// Every persisted definition the hierarchy will ask for is named by a
    /// parsed type declaration. Resolve those exact names as one request batch
    /// before [`Self::type_unit`] and [`Self::collect_aliases`] issue their
    /// ordinary lookups. The ordinary path remains authoritative and retains
    /// its per-file declaration fallback when a definition is not materialized.
    fn prefetch_declared_type_definitions(&self) {
        let mut fq_names = Vec::new();
        for file in &self.files {
            let mut stack = vec![file.root.root_node()];
            while let Some(node) = stack.pop() {
                if matches!(node.kind(), "type_spec" | "type_alias") {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = go_node_text(name_node, &file.source).trim();
                        if !name.is_empty() {
                            fq_names.push(format!("{}.{name}", file.package_name));
                        }
                    }
                    continue;
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
        fq_names.sort();
        fq_names.dedup();
        self.index.prefetch_definitions(&fq_names);
    }

    fn parse_files(&mut self) {
        let mut files: Vec<_> = self.index.get_analyzed_files().into_iter().collect();
        files.sort();
        let mut parsed_files = Vec::new();
        let mut package_index = Vec::new();
        let mut declared_names = HashMap::default();
        for file in files {
            let Ok(source) = self.index.project().read_source(&file) else {
                self.all_files_parsed = false;
                continue;
            };
            let mut parser = Parser::new();
            if parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .is_err()
            {
                self.all_files_parsed = false;
                continue;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                self.all_files_parsed = false;
                continue;
            };
            let declared_name = determine_go_package_name(tree.root_node(), &source);
            let package_name = canonical_go_package_name(&file, &declared_name);
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
        let package_index = GoPackageIndex::new(package_index);
        for mut parsed in parsed_files {
            let (imports, dot_imports) = import_packages(
                self.token,
                self.imports,
                &parsed.file,
                &package_index,
                &declared_names,
            );
            parsed.imports = imports;
            parsed.dot_imports = dot_imports;
            self.files.push(parsed);
        }
        self.package_lookups = package_index.lookups.get();
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
            declared_methods: Vec::new(),
            method_units: HashMap::default(),
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
        let mut methods_by_type: HashMap<String, Vec<DeclaredMethod>> = HashMap::default();
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
                    info.method_set.insert(method.key.clone());
                    info.declared_methods.push(method);
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
                    let alias_unit = self.index.definitions(&alias_fqn).next();
                    let alias_unit = alias_unit.or_else(|| {
                        self.index
                            .declarations(&file.file)
                            .into_iter()
                            .find(|unit| unit.identifier() == name)
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
        methods: &mut Vec<DeclaredMethod>,
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
        let mut additions: Vec<(String, bool, DeclaredMethod)> = Vec::new();
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
                    info.pointer_method_set.insert(method.key.clone());
                } else {
                    info.own_method_names.insert(method.key.name.clone());
                    info.method_set.insert(method.key.clone());
                }
                info.declared_methods.push(method);
            }
        }
    }

    fn method_declaration(
        &self,
        file: &ParsedGoFile,
        node: Node<'_>,
    ) -> Option<(String, bool, DeclaredMethod)> {
        let receiver = node.child_by_field_name("receiver")?;
        let receiver_type = receiver_type_node(receiver)?;
        let pointer_receiver = receiver_type.kind() == "pointer_type";
        let receiver_fqn = self.resolve_type_node(file, receiver_type)?;
        let method = method_key(node, &file.source, &file.package_name, |ty| {
            self.type_token(file, ty)
        })?;
        Some((receiver_fqn, pointer_receiver, method))
    }

    /// Join every declared method key to the `CodeUnit` the analyzer recorded
    /// for that declaration.
    ///
    /// The join is by owning type and terminal identifier rather than by a
    /// reconstructed fully-qualified name, because a Go method lives in a file
    /// of its own: `direct_children` reads one file's children, and a package
    /// routinely declares `type Worker` in one file and `func (Worker) Run` in
    /// another. Go has no method overloading, so an owner and an identifier
    /// name at most one method, and the key that decides satisfaction is
    /// carried alongside rather than rebuilt from the unit.
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

    fn resolve_member_units(&mut self) {
        let mut by_owner: HashMap<(String, String), CodeUnit> = HashMap::default();
        for file in &self.files {
            for unit in self.index.declarations(&file.file) {
                if !unit.is_function() {
                    continue;
                }
                let Some(owner) = unit.owner_identifier() else {
                    continue;
                };
                let key = (
                    format!("{}.{owner}", file.package_name),
                    unit.identifier().to_string(),
                );
                by_owner.entry(key).or_insert(unit);
            }
        }
        let resolved: Vec<(String, HashMap<MethodKey, CodeUnit>)> = self
            .types
            .iter()
            .map(|(fqn, info)| {
                let units = info
                    .declared_methods
                    .iter()
                    .filter_map(|declared| {
                        by_owner
                            .get(&(fqn.clone(), declared.identifier.clone()))
                            .map(|unit| (declared.key.clone(), unit.clone()))
                    })
                    .collect();
                (fqn.clone(), units)
            })
            .collect();
        for (fqn, units) in resolved {
            if let Some(info) = self.types.get_mut(&fqn) {
                info.method_units = units;
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
        self.index
            .definitions(&fqn)
            .find(|unit| unit.source() == file && unit.is_class())
            .or_else(|| {
                self.index
                    .declarations(file)
                    .into_iter()
                    .find(|unit| unit.is_class() && unit.identifier() == name)
            })
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
