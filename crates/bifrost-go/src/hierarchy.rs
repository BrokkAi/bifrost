//! Go's type hierarchy: embedding, interface satisfaction, and type aliases.
//!
//! Built from source rather than from persisted supertypes because Go's
//! subtyping is structural -- a concrete type satisfies an interface by having
//! its method set, with nothing written at either declaration site.

use crate::declarations::{
    determine_go_package_name, go_field_declaration_is_embedded, go_identifier_is_exported,
    go_node_text, is_predeclared_go_type,
};
use crate::imports::{
    default_go_import_local_name, go_import_path, parent_path_key, path_suffixes,
};
use crate::packages::canonical_go_package_name;
use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::type_relations::{MethodKey, MethodSet};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
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
    /// Every method this type declares itself, in declaration order: the key
    /// that decides satisfaction and the plain identifier that joins the key
    /// back to the declaration's own `CodeUnit`.
    declared_methods: Vec<DeclaredMethod>,
    /// The `CodeUnit` of each declared method, once [`GoHierarchyBuilder::
    /// resolve_member_units`] has joined `declared_methods` against the
    /// analyzer's declarations. A method whose declaration the index never
    /// recorded is simply absent, which removes it from the member family
    /// rather than guessing a unit for it.
    method_units: HashMap<MethodKey, CodeUnit>,
    embedded: Vec<EmbeddedType>,
    alias_target: Option<String>,
    has_type_terms: bool,
}

/// One method declaration as the satisfaction pass reads it.
#[derive(Clone, Debug)]
struct DeclaredMethod {
    key: MethodKey,
    identifier: String,
}

/// One member-level family edge: the member at the other end of the edge and
/// the type that declares it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoMemberFamilyEdge {
    pub member: CodeUnit,
    pub owner: CodeUnit,
}

/// What this index can state about one Go method's interface family.
///
/// Go has no override chains and nothing is written at either declaration
/// site: a type satisfies an interface exactly when its method set covers the
/// interface's. The member family is that same proof read one level down --
/// which of the satisfying type's methods answers each interface method --
/// so an edge exists only where the two method keys are equal, never where
/// two names merely agree.
#[derive(Clone, Debug)]
pub enum GoMemberFamily {
    /// The member is not a Go method this index recorded, so it has no
    /// interface family to state.
    NotTracked,
    /// The member is a method this index recorded, but the satisfaction pass
    /// did not enumerate its family exhaustively: a source file did not parse,
    /// the workspace exceeded the satisfaction pair cap, or the owning
    /// interface carries type terms the pass skips.
    NotEnumerable,
    /// The complete family over the indexed workspace: the interface methods
    /// this member implements, and the members that implement it.
    Proven {
        implements: Vec<GoMemberFamilyEdge>,
        implemented_by: Vec<GoMemberFamilyEdge>,
    },
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
pub struct GoHierarchyIndex {
    direct_ancestors: HashMap<String, Vec<CodeUnit>>,
    direct_descendants: HashMap<String, HashSet<CodeUnit>>,
    supported: HashSet<String>,
    /// Concrete method -> the interface methods it implements.
    member_implements: HashMap<String, Vec<GoMemberFamilyEdge>>,
    /// Interface method -> the concrete methods that implement it. Built by
    /// indexing the same pair vector `member_implements` is built from, so the
    /// two directions cannot disagree.
    member_implemented_by: HashMap<String, Vec<GoMemberFamilyEdge>>,
    /// Methods whose family the satisfaction pass enumerated.
    tracked_methods: HashSet<String>,
    /// Methods of an interface the satisfaction pass skipped, so their family
    /// was never enumerated even though the declaration was recorded.
    unenumerated_methods: HashSet<String>,
    /// Whether the satisfaction pass saw the whole workspace. False when a
    /// file did not parse or the pair cap fired, in which case no member's
    /// family can be stated as exhaustive.
    enumeration_complete: bool,
    /// [`GoPackageIndex::packages_for`] calls the import pass made, which is
    /// one per resolvable import when the package table is indexed.
    #[cfg(any(test, feature = "test-support"))]
    package_lookups: usize,
    #[cfg(any(test, feature = "test-support"))]
    relations: Vec<TypeRelation>,
}

impl GoHierarchyIndex {
    pub fn build(
        token: QueryToken<'_>,
        index: &dyn CodeUnitIndex,
        imports: &dyn ImportAnalysisProvider,
    ) -> Self {
        let mut builder = GoHierarchyBuilder::new(token, index, imports);
        builder.collect();
        builder.finish()
    }

    pub fn direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_ancestors
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    pub fn direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendants
            .get(&code_unit.fq_name())
            .cloned()
            .unwrap_or_default()
    }

    pub fn supports(&self, code_unit: &CodeUnit) -> bool {
        self.supported.contains(&code_unit.fq_name())
    }

    /// One method's complete interface family, or the honest reason this index
    /// cannot state it.
    pub fn member_family(&self, member: &CodeUnit) -> GoMemberFamily {
        let fq_name = member.fq_name();
        if self.unenumerated_methods.contains(&fq_name) {
            return GoMemberFamily::NotEnumerable;
        }
        if !self.tracked_methods.contains(&fq_name) {
            return GoMemberFamily::NotTracked;
        }
        if !self.enumeration_complete {
            return GoMemberFamily::NotEnumerable;
        }
        GoMemberFamily::Proven {
            implements: self
                .member_implements
                .get(&fq_name)
                .cloned()
                .unwrap_or_default(),
            implemented_by: self
                .member_implemented_by
                .get(&fq_name)
                .cloned()
                .unwrap_or_default(),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub fn relations(&self) -> &[TypeRelation] {
        &self.relations
    }

    /// How many times the import pass probed the package table. One probe per
    /// import is the indexed cost; the scan this replaced had no probe count
    /// because it visited every workspace file for every import.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub fn package_lookups(&self) -> usize {
        self.package_lookups
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
    token: QueryToken<'a>,
    index: &'a dyn CodeUnitIndex,
    imports: &'a dyn ImportAnalysisProvider,
    files: Vec<ParsedGoFile>,
    types: HashMap<String, GoTypeInfo>,
    aliases: HashMap<String, String>,
    alias_units: HashMap<String, CodeUnit>,
    /// Whether every analyzed Go file was read and parsed. A skipped file can
    /// hold a type that satisfies an interface, so the member family it would
    /// have contributed to is not exhaustive.
    all_files_parsed: bool,
    /// [`GoPackageIndex::packages_for`] calls the import pass made.
    #[cfg(any(test, feature = "test-support"))]
    package_lookups: usize,
    #[cfg(any(test, feature = "test-support"))]
    relations: Vec<TypeRelation>,
}

impl<'a> GoHierarchyBuilder<'a> {
    fn new(
        token: QueryToken<'a>,
        index: &'a dyn CodeUnitIndex,
        imports: &'a dyn ImportAnalysisProvider,
    ) -> Self {
        Self {
            token,
            index,
            imports,
            files: Vec::new(),
            types: HashMap::default(),
            aliases: HashMap::default(),
            alias_units: HashMap::default(),
            all_files_parsed: true,
            #[cfg(any(test, feature = "test-support"))]
            package_lookups: 0,
            #[cfg(any(test, feature = "test-support"))]
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
        self.resolve_member_units();
    }

    fn finish(self) -> GoHierarchyIndex {
        let mut direct_ancestors: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut supported = HashSet::default();
        #[cfg(any(test, feature = "test-support"))]
        let mut relations = self.relations;

        let interfaces: Vec<(String, GoTypeInfo)> = self
            .types
            .iter()
            .filter(|(_fqn, info)| info.kind == GoTypeKind::Interface)
            .map(|(fqn, info)| (fqn.clone(), info.clone()))
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
            .filter(|(_fqn, info)| !info.has_type_terms && !info.method_set.methods.is_empty())
            .count();
        let dispatch_units = dispatch_member_units(&self.types);
        let mut member_implements: HashMap<String, Vec<GoMemberFamilyEdge>> = HashMap::default();
        let mut member_implemented_by: HashMap<String, Vec<GoMemberFamilyEdge>> =
            HashMap::default();
        // Every method key required by an interface the satisfaction pass
        // skips. A method that answers one of those keys has a family the pass
        // never enumerated -- on the interface's side because its declaration
        // was skipped, and on the implementor's side because the forward edge
        // to it was never emitted -- so both ends say so instead of publishing
        // a set that silently omits the skipped interface.
        let skipped_interface_keys: HashSet<MethodKey> = interfaces
            .iter()
            .filter(|(_fqn, info)| info.has_type_terms)
            .flat_map(|(_fqn, info)| info.method_set.methods.iter().cloned())
            .collect();
        let mut tracked_methods = HashSet::default();
        let mut unenumerated_methods = HashSet::default();
        for info in self.types.values() {
            for (key, member) in &info.method_units {
                let unenumerable = (info.kind == GoTypeKind::Interface && info.has_type_terms)
                    || skipped_interface_keys.contains(key);
                if unenumerable {
                    unenumerated_methods.insert(member.fq_name());
                } else {
                    tracked_methods.insert(member.fq_name());
                }
            }
        }

        let pairs_within_cap =
            concrete_count.saturating_mul(interface_count) <= MAX_STRUCTURAL_SATISFACTION_PAIRS;
        if pairs_within_cap {
            for (concrete_fqn, concrete) in self.types.iter().filter(|(_fqn, info)| {
                info.kind == GoTypeKind::Concrete && info.alias_target.is_none()
            }) {
                let concrete_dispatch = dispatch_units.get(concrete_fqn);
                for (interface_fqn, interface) in &interfaces {
                    if interface.has_type_terms
                        || interface.method_set.methods.len() == EMPTY_INTERFACE_DESCENDANT_CAP
                    {
                        continue;
                    }
                    if method_set_satisfies(&concrete.method_set, &interface.method_set) {
                        record_structural_relation(
                            &mut direct_ancestors,
                            #[cfg(any(test, feature = "test-support"))]
                            &mut relations,
                            &concrete.unit,
                            &interface.unit,
                        );
                    }
                    let (Some(concrete_dispatch), Some(interface_dispatch)) =
                        (concrete_dispatch, dispatch_units.get(interface_fqn))
                    else {
                        continue;
                    };
                    record_member_family(
                        &mut member_implements,
                        &mut member_implemented_by,
                        &interface.method_set,
                        interface_dispatch,
                        concrete_dispatch,
                    );
                }
            }
        }

        if interface_count.saturating_mul(interface_count) <= MAX_STRUCTURAL_SATISFACTION_PAIRS {
            for (_candidate_fqn, candidate) in interfaces
                .iter()
                .filter(|(_fqn, info)| !info.has_type_terms && info.alias_target.is_none())
            {
                for (_interface_fqn, interface) in &interfaces {
                    if interface.has_type_terms
                        || interface.method_set.methods.len() == EMPTY_INTERFACE_DESCENDANT_CAP
                        || interface.unit == candidate.unit
                    {
                        continue;
                    }
                    if method_set_satisfies(&candidate.method_set, &interface.method_set) {
                        record_structural_relation(
                            &mut direct_ancestors,
                            #[cfg(any(test, feature = "test-support"))]
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

        for edges in member_implements
            .values_mut()
            .chain(member_implemented_by.values_mut())
        {
            edges.sort_by(|left, right| left.member.cmp(&right.member));
            edges.dedup();
        }

        GoHierarchyIndex {
            direct_ancestors,
            direct_descendants,
            supported,
            member_implements,
            member_implemented_by,
            tracked_methods,
            unenumerated_methods,
            enumeration_complete: self.all_files_parsed && pairs_within_cap,
            #[cfg(any(test, feature = "test-support"))]
            package_lookups: self.package_lookups,
            #[cfg(any(test, feature = "test-support"))]
            relations,
        }
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
        #[cfg(any(test, feature = "test-support"))]
        {
            self.package_lookups = package_index.lookups.get();
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
            #[cfg(any(test, feature = "test-support"))]
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

/// The workspace package table, keyed by every import path spelling that can
/// bind to a file, so [`import_packages`] costs one hash probe per import
/// instead of a scan of every workspace file (#1748: 48.6% of the samples in a
/// warm `scan_usages_by_reference` on kubernetes were that scan).
///
/// The scan this replaces accepted a candidate when the candidate's canonical
/// package equalled the import path, or when the import path was a trailing
/// component sequence of the candidate's parent directory. The second rule is
/// exactly "the import path is one of [`path_suffixes`] of the candidate's
/// [`parent_path_key`]", so those suffixes are the keys and the package name
/// is one more key. The rule is a disjunction, so a single bucket per spelling
/// reproduces it exactly, and no separate predicate function is left that
/// could drift away from the keys.
struct GoPackageIndex {
    /// `(file, canonical package)` for every parsed file, in the order the
    /// scan visited them.
    entries: Vec<(ProjectFile, String)>,
    /// Import path spelling -> the `entries` positions that spelling binds.
    by_import_path: HashMap<String, Vec<usize>>,
    /// Counts [`Self::packages_for`] calls so a test can pin that resolution
    /// stays one probe per import.
    #[cfg(any(test, feature = "test-support"))]
    lookups: std::cell::Cell<usize>,
}

impl GoPackageIndex {
    fn new(entries: Vec<(ProjectFile, String)>) -> Self {
        let mut by_import_path: HashMap<String, Vec<usize>> = HashMap::default();
        for (position, (file, package)) in entries.iter().enumerate() {
            // Positions arrive in increasing order, so the only position a
            // bucket can already end with is this one. That happens whenever a
            // file's package name is also a suffix of its own directory, the
            // normal shape under a `go.mod`.
            let mut bind = |key: &str| {
                let bucket = by_import_path.entry(key.to_string()).or_default();
                if bucket.last() != Some(&position) {
                    bucket.push(position);
                }
            };
            bind(package);
            for suffix in path_suffixes(&parent_path_key(file)) {
                bind(suffix);
            }
        }
        Self {
            entries,
            by_import_path,
            #[cfg(any(test, feature = "test-support"))]
            lookups: std::cell::Cell::new(0),
        }
    }

    /// Every canonical package an `import "import_path"` written in `file`
    /// binds, sorted and deduplicated. A file never answers its own import.
    fn packages_for(&self, file: &ProjectFile, import_path: &str) -> Vec<String> {
        #[cfg(any(test, feature = "test-support"))]
        self.lookups.set(self.lookups.get() + 1);
        let mut packages: Vec<String> = self
            .by_import_path
            .get(import_path)
            .into_iter()
            .flatten()
            .map(|position| &self.entries[*position])
            .filter(|(candidate, _package)| candidate != file)
            .map(|(_candidate, package)| package.clone())
            .collect();
        packages.sort();
        packages.dedup();
        packages
    }
}

fn import_packages(
    token: QueryToken<'_>,
    imports: &dyn ImportAnalysisProvider,
    file: &ProjectFile,
    package_index: &GoPackageIndex,
    declared_names: &HashMap<String, String>,
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut by_alias: HashMap<String, Vec<String>> = HashMap::default();
    let mut dot_imports = Vec::new();
    for import in imports.import_info_of(token, file) {
        let alias = import.alias.as_deref();
        if alias == Some("_") {
            continue;
        }
        let Some(path) = go_import_path(&import) else {
            continue;
        };
        let mut packages = package_index.packages_for(file, &path);
        if packages.is_empty() {
            // Nothing in the workspace declares this package: keep the source
            // spelling so callers can still report an import boundary.
            packages.push(path.clone());
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
) -> Option<DeclaredMethod> {
    let name_node = node.child_by_field_name("name")?;
    let identifier = go_node_text(name_node, source).trim();
    if identifier.is_empty() {
        return None;
    }
    let identifier = identifier.to_string();
    let name = if go_identifier_is_exported(&identifier) {
        identifier.clone()
    } else {
        format!("{package_name}.{identifier}")
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
    Some(DeclaredMethod {
        key: MethodKey::new(name, Some(tokens.join(" "))),
        identifier,
    })
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
    if go_field_declaration_is_embedded(field)
        && let Some(ty) = field.child_by_field_name("type")
    {
        embedded.push(EmbeddedTypeRef {
            node: ty,
            pointer: is_pointer_embedded_field(field, ty),
        });
    }
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

/// Every method key each type answers, and the declaration that answers it.
///
/// This is the *dispatch* surface, which is deliberately wider than the value
/// method set the type relation above is built from. A Go method with a
/// pointer receiver is not in `T`'s method set, so `T` does not satisfy the
/// interface -- but `*T` does, and the code that runs when the interface
/// method is called is still that pointer-receiver declaration. Class-
/// hierarchy analysis asks which members could run, so it must see them; the
/// subtype relation asks whether `T` itself is assignable, so it must not.
///
/// A key the type does not declare is resolved through the embedding graph
/// breadth-first, and only when exactly one embedded type answers it at the
/// nearest depth -- the same shallowest-and-unique rule Go promotion uses, and
/// the same one [`struct_promoted_methods`] applies to the key set. A name the
/// type redeclares with a different signature shadows the embedded method
/// rather than promoting it.
fn dispatch_member_units(
    types: &HashMap<String, GoTypeInfo>,
) -> HashMap<String, HashMap<MethodKey, GoMemberFamilyEdge>> {
    types
        .iter()
        .map(|(fqn, info)| {
            let mut units: HashMap<MethodKey, GoMemberFamilyEdge> = info
                .method_units
                .iter()
                .map(|(key, member)| {
                    (
                        key.clone(),
                        GoMemberFamilyEdge {
                            member: member.clone(),
                            owner: info.unit.clone(),
                        },
                    )
                })
                .collect();
            for key in info
                .method_set
                .methods
                .iter()
                .chain(info.pointer_method_set.methods.iter())
            {
                if units.contains_key(key) {
                    continue;
                }
                if let Some(promoted) = promoted_member(types, info, key) {
                    units.insert(key.clone(), promoted);
                }
            }
            (fqn.clone(), units)
        })
        .collect()
}

/// The single embedded declaration that answers `key` on `info`, at the
/// nearest embedding depth. `None` when the type shadows the name, when no
/// embedded type answers, or when two answer at the same depth -- the
/// ambiguity Go itself rejects.
fn promoted_member(
    types: &HashMap<String, GoTypeInfo>,
    info: &GoTypeInfo,
    key: &MethodKey,
) -> Option<GoMemberFamilyEdge> {
    if info.own_method_names.contains(&key.name) {
        return None;
    }
    let mut frontier: Vec<(String, Vec<String>)> = info
        .embedded
        .iter()
        .map(|embedded| (embedded.fqn.clone(), Vec::new()))
        .collect();
    while !frontier.is_empty() {
        let mut found: Vec<GoMemberFamilyEdge> = Vec::new();
        let mut next = Vec::new();
        for (fqn, path) in frontier {
            if path.contains(&fqn) {
                continue;
            }
            let Some(embedded_info) = types.get(&fqn) else {
                continue;
            };
            if let Some(member) = embedded_info.method_units.get(key) {
                found.push(GoMemberFamilyEdge {
                    member: member.clone(),
                    owner: embedded_info.unit.clone(),
                });
                continue;
            }
            let mut next_path = path;
            next_path.push(fqn);
            for nested in &embedded_info.embedded {
                next.push((nested.fqn.clone(), next_path.clone()));
            }
        }
        if found.len() == 1 {
            return found.pop();
        }
        if !found.is_empty() {
            return None;
        }
        frontier = next;
    }
    None
}

/// Record the member-level family of one satisfying (concrete type,
/// interface) pair, in both directions from the same pass.
///
/// The pair contributes edges only when the concrete type's dispatch surface
/// answers *every* method the interface requires, which is the same covering
/// condition [`method_set_satisfies`] states for types, evaluated over the
/// dispatch surface. Each edge then joins the declaration that requires the
/// key to the declaration that answers it: two declarations whose method keys
/// -- name plus resolved parameter and result type tokens -- are equal.
fn record_member_family(
    member_implements: &mut HashMap<String, Vec<GoMemberFamilyEdge>>,
    member_implemented_by: &mut HashMap<String, Vec<GoMemberFamilyEdge>>,
    required: &MethodSet,
    interface_dispatch: &HashMap<MethodKey, GoMemberFamilyEdge>,
    concrete_dispatch: &HashMap<MethodKey, GoMemberFamilyEdge>,
) {
    if !required
        .methods
        .iter()
        .all(|key| concrete_dispatch.contains_key(key))
    {
        return;
    }
    for key in &required.methods {
        let (Some(declared), Some(implementor)) =
            (interface_dispatch.get(key), concrete_dispatch.get(key))
        else {
            continue;
        };
        member_implements
            .entry(implementor.member.fq_name())
            .or_default()
            .push(declared.clone());
        member_implemented_by
            .entry(declared.member.fq_name())
            .or_default()
            .push(implementor.clone());
    }
}

fn record_structural_relation(
    direct_ancestors: &mut HashMap<String, Vec<CodeUnit>>,
    #[cfg(any(test, feature = "test-support"))] relations: &mut Vec<TypeRelation>,
    from: &CodeUnit,
    to: &CodeUnit,
) {
    let ancestors = direct_ancestors.entry(from.fq_name()).or_default();
    if !ancestors.contains(to) {
        ancestors.push(to.clone());
    }
    #[cfg(any(test, feature = "test-support"))]
    relations.push(TypeRelation {
        from: from.clone(),
        to: to.clone(),
        kind: TypeRelationKind::StructuralSatisfaction,
    });
}

#[cfg(test)]
mod tests {
    use super::GoPackageIndex;
    use brokk_bifrost_core::analyzer::ProjectFile;

    /// The scan [`GoPackageIndex`] replaced, kept here as an oracle that does
    /// not share a line of code with the index: a candidate binds an import
    /// path when its canonical package equals the path, or when the path is a
    /// trailing component sequence of the candidate's directory.
    fn scan(
        entries: &[(ProjectFile, String)],
        file: &ProjectFile,
        import_path: &str,
    ) -> Vec<String> {
        let mut packages: Vec<String> = entries
            .iter()
            .filter(|(candidate, _package)| candidate != file)
            .filter(|(candidate, package)| {
                let parent = candidate.parent().to_string_lossy().replace('\\', "/");
                package == import_path
                    || parent == import_path
                    || parent.ends_with(&format!("/{import_path}"))
            })
            .map(|(_candidate, package)| package.clone())
            .collect();
        packages.sort();
        packages.dedup();
        packages
    }

    /// Same-suffix directories (`a/pkg`, `b/pkg`, `pkg`) plus a vendored copy,
    /// which is where a suffix index can differ from the scan if its keys are
    /// not derived from the same rule.
    #[test]
    fn package_index_answers_exactly_what_the_scan_answered() {
        let root = std::env::temp_dir().join("bifrost-go-package-index");
        let entries: Vec<(ProjectFile, String)> = [
            ("a/pkg/one.go", "example.com/app/a/pkg"),
            ("b/pkg/two.go", "example.com/app/b/pkg"),
            ("pkg/three.go", "example.com/app/pkg"),
            ("pkg/four.go", "example.com/app/pkg"),
            (
                "vendor/k8s.io/utils/pkg/five.go",
                "example.com/app/vendor/k8s.io/utils/pkg",
            ),
        ]
        .into_iter()
        .map(|(path, package)| (ProjectFile::new(root.clone(), path), package.to_string()))
        .collect();
        let index = GoPackageIndex::new(entries.clone());

        for (file, _package) in &entries {
            for import_path in [
                "pkg",
                "a/pkg",
                "b/pkg",
                "utils/pkg",
                "k8s.io/utils/pkg",
                "vendor/k8s.io/utils/pkg",
                "example.com/app/pkg",
                "example.com/app/a/pkg",
                "example.com/app/vendor/k8s.io/utils/pkg",
                "example.com/app",
                "nowhere/at/all",
            ] {
                assert_eq!(
                    index.packages_for(file, import_path),
                    scan(&entries, file, import_path),
                    "import {import_path:?} from {file}"
                );
            }
        }
    }
}
