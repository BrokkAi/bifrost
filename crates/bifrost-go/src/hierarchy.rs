//! Go's type hierarchy: embedding, interface satisfaction, and type aliases.
//!
//! Built from source rather than from persisted supertypes because Go's
//! subtyping is structural -- a concrete type satisfies an interface by having
//! its method set, with nothing written at either declaration site.

use crate::declarations::go_identifier_is_exported;
use crate::graph::resolver::{
    GoFactFile, GoGraphBuildError, GoGraphSource, go_fact_file_is_complete, go_fact_owner_fqns,
    go_unit_parent_fqn, load_go_fact_files, mounted_units,
};
use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::go_facts::{
    GoChannelDirection, GoSourceTypeId, GoSourceTypeShape, GoTypeCompoundKind,
};
use brokk_bifrost_core::analyzer::type_relations::{MethodKey, MethodSet};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use brokk_bifrost_core::hash::{HashMap, HashSet};

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

enum NominalTypeResolution {
    Resolved(String),
    ExternalOrPredeclared,
    Ambiguous,
    Unresolved,
    Unsupported,
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
    #[cfg(any(test, feature = "test-support"))]
    relations: Vec<TypeRelation>,
}

impl GoHierarchyIndex {
    pub fn build(source: GoGraphSource<'_>) -> Result<Self, GoGraphBuildError> {
        let mut builder = GoHierarchyBuilder::new(source);
        builder.collect()?;
        Ok(builder.finish())
    }

    /// Build from a fact snapshot already loaded for a sibling workspace
    /// product. This keeps the hierarchy on the same canonical source inputs
    /// as the inverse edge index instead of loading each publication again.
    pub(crate) fn build_from_fact_files(source: GoGraphSource<'_>, files: Vec<GoFactFile>) -> Self {
        let mut builder = GoHierarchyBuilder::new(source);
        builder.all_files_parsed = files.iter().all(go_fact_file_is_complete);
        builder.owner_by_id = go_fact_owner_fqns(&files);
        builder.files = files;
        builder.collect_types();
        builder.collect_aliases();
        builder.collect_type_details();
        builder.collect_methods();
        builder.resolve_aliases();
        builder.propagate_type_terms();
        builder.promote_embedded_methods();
        builder.resolve_member_units();
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
            // A declaration-backed function with a type owner can be absent
            // from the mounted facts when that source file was unavailable.
            // During an incomplete pass this is an unknown method, not proof
            // that it has no family. File-scope functions remain a complete
            // NotTracked answer.
            if !self.enumeration_complete && member.owner_is_type_scope() {
                return GoMemberFamily::NotEnumerable;
            }
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
}

struct GoHierarchyBuilder<'a> {
    source: GoGraphSource<'a>,
    files: Vec<GoFactFile>,
    owner_by_id: HashMap<(brokk_bifrost_core::analyzer::ProjectFile, GoSourceTypeId), Vec<String>>,
    types: HashMap<String, GoTypeInfo>,
    aliases: HashMap<String, String>,
    alias_names: HashSet<String>,
    alias_units: HashMap<String, CodeUnit>,
    /// Whether every analyzed Go file was read and parsed. A skipped file can
    /// hold a type that satisfies an interface, so the member family it would
    /// have contributed to is not exhaustive.
    all_files_parsed: bool,
    #[cfg(any(test, feature = "test-support"))]
    relations: Vec<TypeRelation>,
}

impl<'a> GoHierarchyBuilder<'a> {
    fn new(source: GoGraphSource<'a>) -> Self {
        Self {
            source,
            files: Vec::new(),
            owner_by_id: HashMap::default(),
            types: HashMap::default(),
            aliases: HashMap::default(),
            alias_names: HashSet::default(),
            alias_units: HashMap::default(),
            all_files_parsed: true,
            #[cfg(any(test, feature = "test-support"))]
            relations: Vec::new(),
        }
    }

    fn collect(&mut self) -> Result<(), GoGraphBuildError> {
        self.load_facts()?;
        self.collect_types();
        self.collect_aliases();
        self.collect_type_details();
        self.collect_methods();
        self.resolve_aliases();
        self.propagate_type_terms();
        self.promote_embedded_methods();
        self.resolve_member_units();
        Ok(())
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
            relations,
        }
    }

    fn load_facts(&mut self) -> Result<(), GoGraphBuildError> {
        let (files, unavailable) =
            load_go_fact_files(self.source, self.source.index.get_analyzed_files());
        if !unavailable.is_empty() {
            return Err(GoGraphBuildError::from_files(unavailable));
        }
        self.files = files;
        // A valid but incomplete publication is retained as an explicitly
        // unenumerated result. Only a missing/invalid canonical file input
        // makes construction fail; pair caps and unsupported syntax remain
        // ordinary hierarchy uncertainty in the returned index.
        self.all_files_parsed = self.files.iter().all(go_fact_file_is_complete);
        self.owner_by_id = go_fact_owner_fqns(&self.files);
        Ok(())
    }

    fn collect_types(&mut self) {
        let mut discovered = Vec::new();
        for file in &self.files {
            for declaration in &file.facts.facts.declarations {
                if !declaration.file_scope {
                    continue;
                }
                let kind = match &file.facts.facts.types[declaration.ty.index()].shape {
                    GoSourceTypeShape::Interface { .. } => GoTypeKind::Interface,
                    _ => GoTypeKind::Concrete,
                };
                for unit in
                    mounted_units(file, declaration.declaration).filter(|unit| unit.is_class())
                {
                    discovered.push((unit, kind));
                }
            }
            // Inline struct/interface containers are owned by the field's
            // mounted CodeUnit rather than by a type-declaration row. They
            // still participate in method sets and must retain that owner.
            for field in &file.facts.facts.fields {
                let Some(type_id) = field.ty else { continue };
                let kind = match &file.facts.facts.types[type_id.index()].shape {
                    GoSourceTypeShape::Interface { .. } => GoTypeKind::Interface,
                    GoSourceTypeShape::Struct { .. } => GoTypeKind::Concrete,
                    _ => continue,
                };
                for unit in mounted_units(file, field.declaration).filter(|unit| unit.is_field()) {
                    discovered.push((unit, kind));
                }
            }
        }
        for (unit, kind) in discovered {
            let unit_fqn = unit.fq_name();
            self.types.entry(unit_fqn).or_insert_with(|| GoTypeInfo {
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
            });
        }
    }

    fn type_owner_fqns(&self, file: &GoFactFile, id: GoSourceTypeId) -> Vec<String> {
        self.owner_by_id
            .get(&(file.file.clone(), id))
            .cloned()
            .unwrap_or_default()
    }

    fn collect_type_details(&mut self) {
        let files = self.files.iter().collect::<Vec<_>>();
        for file in files {
            for field in &file.facts.facts.fields {
                if !field.embedded {
                    continue;
                }
                let owners = self.type_owner_fqns(file, field.owner);
                let Some(type_id) = field.ty else {
                    self.all_files_parsed = false;
                    continue;
                };
                let target = match self.resolve_type_id_status(file, type_id) {
                    NominalTypeResolution::Resolved(target) => target,
                    // A predeclared or external embedded type has no
                    // workspace method set to project. It is valid evidence,
                    // not a missing file that should truncate unrelated
                    // families.
                    NominalTypeResolution::ExternalOrPredeclared
                    | NominalTypeResolution::Unsupported => {
                        continue;
                    }
                    NominalTypeResolution::Ambiguous | NominalTypeResolution::Unresolved => {
                        self.all_files_parsed = false;
                        continue;
                    }
                };
                let target = resolve_alias_fqn(&self.aliases, &target);
                let pointer = field
                    .ty
                    .is_some_and(|id| self.receiver_is_pointer(file, id));
                for owner in owners {
                    if self.types.contains_key(&target)
                        && let Some(info) = self.types.get_mut(&owner)
                    {
                        info.embedded.push(EmbeddedType {
                            fqn: target.clone(),
                            pointer,
                        });
                    }
                }
            }
            for embedding in &file.facts.facts.embeddings {
                let owners = self.type_owner_fqns(file, embedding.owner);
                let target = self
                    .resolve_type_id(file, embedding.ty)
                    .map(|target| resolve_alias_fqn(&self.aliases, &target));
                for owner in owners {
                    if let Some(target) = target.as_ref().and_then(|target| {
                        self.types
                            .get(target)
                            .filter(|info| info.kind == GoTypeKind::Interface)
                            .map(|_| target.clone())
                    }) {
                        if let Some(info) = self.types.get_mut(&owner) {
                            info.embedded.push(EmbeddedType {
                                fqn: target,
                                pointer: false,
                            });
                        }
                    } else if !self.is_empty_interface(file, embedding.ty)
                        && let Some(info) = self.types.get_mut(&owner)
                    {
                        info.has_type_terms = true;
                    }
                }
            }
            for callable in &file.facts.facts.callables {
                let Some(owner) = callable.owner else {
                    continue;
                };
                let Some(method) = self.method_key(file, callable) else {
                    self.all_files_parsed = false;
                    continue;
                };
                for owner_fqn in self.type_owner_fqns(file, owner) {
                    if let Some(info) = self.types.get_mut(&owner_fqn) {
                        info.method_set.insert(method.key.clone());
                        info.declared_methods.push(method.clone());
                    }
                }
            }
        }
    }

    fn collect_aliases(&mut self) {
        for file in &self.files {
            for alias in &file.facts.facts.aliases {
                let alias_fqn = format!("{}.{}", file.package_name, alias.name);
                self.alias_names.insert(alias_fqn.clone());
                if let Some(unit) =
                    mounted_units(file, alias.declaration).find(|unit| unit.is_field())
                {
                    self.alias_units.insert(alias_fqn, unit);
                }
            }
        }
        for file in &self.files {
            for alias in &file.facts.facts.aliases {
                let alias_fqn = format!("{}.{}", file.package_name, alias.name);
                let Some(target) = alias.target else {
                    continue;
                };
                match self.resolve_type_id_status(file, target) {
                    NominalTypeResolution::Resolved(target) => {
                        self.aliases.insert(alias_fqn, target);
                    }
                    NominalTypeResolution::Ambiguous | NominalTypeResolution::Unresolved => {
                        // A workspace name with multiple canonical import
                        // candidates is unresolved evidence, not an empty
                        // alias relation. Keep unrelated method families
                        // honest by downgrading this hierarchy pass.
                        self.all_files_parsed = false;
                    }
                    NominalTypeResolution::ExternalOrPredeclared
                    | NominalTypeResolution::Unsupported => {}
                }
            }
        }
    }

    fn collect_methods(&mut self) {
        for file in &self.files {
            for callable in &file.facts.facts.callables {
                let Some(receiver) = callable.receiver else {
                    continue;
                };
                let Some(method) = self.method_key(file, callable) else {
                    self.all_files_parsed = false;
                    continue;
                };
                let Some(receiver_fqn) = self.resolve_type_id(file, receiver) else {
                    self.all_files_parsed = false;
                    continue;
                };
                let pointer_receiver = self.receiver_is_pointer(file, receiver);
                if let Some(info) = self.types.get_mut(&receiver_fqn) {
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
            for callable in &file.facts.facts.callables {
                let Some(owner_id) = callable.receiver.or(callable.owner) else {
                    continue;
                };
                let owners = callable
                    .receiver
                    .and_then(|id| self.resolve_type_id(file, id))
                    .into_iter()
                    .chain(
                        callable
                            .receiver
                            .is_none()
                            .then(|| self.type_owner_fqns(file, owner_id))
                            .into_iter()
                            .flatten(),
                    )
                    .collect::<Vec<_>>();
                if owners.is_empty() {
                    continue;
                }
                for unit in
                    mounted_units(file, callable.declaration).filter(|unit| unit.is_function())
                {
                    let Some(owner) = go_unit_parent_fqn(&unit) else {
                        continue;
                    };
                    if !owners.iter().any(|candidate| candidate == &owner) {
                        continue;
                    }
                    by_owner
                        .entry((owner, callable.name.clone()))
                        .or_insert(unit);
                }
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

    fn resolve_type_id(&self, file: &GoFactFile, id: GoSourceTypeId) -> Option<String> {
        match self.resolve_type_id_status(file, id) {
            NominalTypeResolution::Resolved(fqn) => Some(fqn),
            NominalTypeResolution::Ambiguous
            | NominalTypeResolution::ExternalOrPredeclared
            | NominalTypeResolution::Unresolved
            | NominalTypeResolution::Unsupported => None,
        }
    }

    fn resolve_type_id_status(
        &self,
        file: &GoFactFile,
        id: GoSourceTypeId,
    ) -> NominalTypeResolution {
        let mut current = id;
        let mut seen = HashSet::default();
        loop {
            if !seen.insert(current) {
                return NominalTypeResolution::Unresolved;
            }
            match &file.facts.facts.types[current.index()].shape {
                GoSourceTypeShape::Named(name) => {
                    let path = name.path();
                    let Some(member) = path.last() else {
                        return NominalTypeResolution::Unresolved;
                    };
                    if path.len() == 1 {
                        let candidate = format!("{}.{}", file.package_name, member);
                        if self.types.contains_key(&candidate)
                            || self.alias_names.contains(&candidate)
                        {
                            return NominalTypeResolution::Resolved(candidate);
                        }
                        let imported_package_count =
                            file.dot_imports.len() + file.dot_external_imports.len();
                        if imported_package_count > 1 {
                            return NominalTypeResolution::Ambiguous;
                        }
                        if imported_package_count == 0 {
                            return if is_predeclared_go_type(member) {
                                NominalTypeResolution::ExternalOrPredeclared
                            } else {
                                NominalTypeResolution::Unresolved
                            };
                        }
                        let mut candidates: Vec<_> = file
                            .dot_imports
                            .iter()
                            .map(|package| format!("{package}.{member}"))
                            .filter(|candidate| {
                                self.types.contains_key(candidate)
                                    || self.alias_names.contains(candidate)
                            })
                            .collect();
                        candidates.sort_unstable();
                        candidates.dedup();
                        return match candidates.len() {
                            0 if !file.dot_external_imports.is_empty() => {
                                NominalTypeResolution::ExternalOrPredeclared
                            }
                            0 => NominalTypeResolution::Unresolved,
                            1 => NominalTypeResolution::Resolved(
                                candidates.pop().expect("one candidate"),
                            ),
                            _ => NominalTypeResolution::Ambiguous,
                        };
                    }
                    if path.len() != 2 {
                        return NominalTypeResolution::Unsupported;
                    }
                    let Some(qualifier) = path.first() else {
                        return NominalTypeResolution::Unresolved;
                    };
                    let imported_package_count = file.imports.get(qualifier).map_or(0, Vec::len)
                        + file.external_imports.get(qualifier).map_or(0, Vec::len);
                    if imported_package_count > 1 {
                        return NominalTypeResolution::Ambiguous;
                    }
                    if imported_package_count == 0 {
                        return NominalTypeResolution::Unresolved;
                    }
                    let mut candidates: Vec<_> = file
                        .imports
                        .get(qualifier)
                        .into_iter()
                        .flatten()
                        .map(|package| format!("{package}.{member}"))
                        .filter(|candidate| {
                            self.types.contains_key(candidate)
                                || self.alias_names.contains(candidate)
                        })
                        .collect();
                    candidates.sort_unstable();
                    candidates.dedup();
                    return match candidates.len() {
                        0 if file
                            .external_imports
                            .get(qualifier)
                            .is_some_and(|packages| !packages.is_empty()) =>
                        {
                            NominalTypeResolution::ExternalOrPredeclared
                        }
                        0 => NominalTypeResolution::Unresolved,
                        1 => NominalTypeResolution::Resolved(
                            candidates.pop().expect("one candidate"),
                        ),
                        _ => NominalTypeResolution::Ambiguous,
                    };
                }
                GoSourceTypeShape::Pointer(inner) | GoSourceTypeShape::Negated(inner) => {
                    current = *inner
                }
                GoSourceTypeShape::Generic { base, .. } => current = *base,
                GoSourceTypeShape::Compound {
                    kind: GoTypeCompoundKind::Parenthesized | GoTypeCompoundKind::Element,
                    children,
                } if children.len() == 1 => current = children[0],
                _ => return NominalTypeResolution::Unsupported,
            }
        }
    }

    fn is_empty_interface(&self, file: &GoFactFile, id: GoSourceTypeId) -> bool {
        let mut current = id;
        let mut seen = HashSet::default();
        loop {
            if !seen.insert(current) {
                return false;
            }
            match &file.facts.facts.types[current.index()].shape {
                GoSourceTypeShape::Named(name)
                    if name.path().len() == 1 && name.path()[0] == "any" =>
                {
                    return true;
                }
                GoSourceTypeShape::Interface {
                    has_named_children: false,
                    ..
                } => return true,
                GoSourceTypeShape::Compound {
                    kind: GoTypeCompoundKind::Parenthesized | GoTypeCompoundKind::Element,
                    children,
                } if children.len() == 1 => current = children[0],
                _ => return false,
            }
        }
    }

    fn receiver_is_pointer(&self, file: &GoFactFile, id: GoSourceTypeId) -> bool {
        matches!(
            &file.facts.facts.types[id.index()].shape,
            GoSourceTypeShape::Pointer(_)
        )
    }

    fn type_token(&self, file: &GoFactFile, id: GoSourceTypeId) -> Option<String> {
        // Render directly into one buffer. Source type depth is unbounded;
        // recursive calls and a full String for every nested wrapper are not.
        enum Part<'a> {
            Type(GoSourceTypeId),
            Text(&'a str),
        }
        let mut pending = vec![Part::Type(id)];
        let mut output = String::new();
        while let Some(part) = pending.pop() {
            let current = match part {
                Part::Text(text) => {
                    output.push_str(text);
                    continue;
                }
                Part::Type(current) => current,
            };
            match &file.facts.facts.types[current.index()].shape {
                GoSourceTypeShape::Named(name) => {
                    let token = {
                        let path = name.path();
                        let member = path.last()?;
                        let candidate = self.resolve_type_id(file, current);
                        if let Some(candidate) = candidate {
                            resolve_alias_fqn(&self.aliases, &candidate)
                        } else {
                            let package = if path.len() == 1 {
                                let mut packages = file
                                    .dot_imports
                                    .iter()
                                    .chain(file.dot_external_imports.iter());
                                let package = packages.next();
                                (packages.next().is_none()).then_some(package).flatten()
                            } else if path.len() == 2 {
                                let qualifier = &path[0];
                                let mut packages =
                                    file.imports.get(qualifier).into_iter().flatten().chain(
                                        file.external_imports.get(qualifier).into_iter().flatten(),
                                    );
                                let package = packages.next();
                                (packages.next().is_none()).then_some(package).flatten()
                            } else {
                                None
                            };
                            if let Some(package) = package {
                                format!("{package}.{member}")
                            } else if path.len() == 1
                                && file.dot_imports.is_empty()
                                && file.dot_external_imports.is_empty()
                                && is_predeclared_go_type(member)
                            {
                                member.clone()
                            } else if path.len() == 1
                                && file.dot_imports.is_empty()
                                && file.dot_external_imports.is_empty()
                            {
                                // Preserve the established package-scoped
                                // token for an unresolved local name. This is
                                // not an import fallback: any present dot
                                // binding must be unique and known above.
                                format!("{}.{}", file.package_name, member)
                            } else {
                                return None;
                            }
                        }
                    };
                    output.push_str(&token);
                }
                GoSourceTypeShape::Pointer(inner) => {
                    output.push('*');
                    pending.push(Part::Type(*inner));
                }
                GoSourceTypeShape::Slice(inner) => {
                    output.push_str("[]");
                    pending.push(Part::Type(*inner));
                }
                GoSourceTypeShape::Array {
                    element,
                    length_text,
                    ..
                } => {
                    output.push('[');
                    output.push_str(length_text);
                    output.push(']');
                    pending.push(Part::Type(*element));
                }
                GoSourceTypeShape::Map { key, value } => {
                    output.push_str("map[");
                    pending.push(Part::Type(*value));
                    pending.push(Part::Text("]"));
                    pending.push(Part::Type(*key));
                }
                GoSourceTypeShape::Channel { direction, element } => {
                    output.push_str(match direction {
                        GoChannelDirection::Both => "chan ",
                        GoChannelDirection::Receive => "<-chan ",
                        GoChannelDirection::Send => "chan<- ",
                    });
                    pending.push(Part::Type(*element));
                }
                GoSourceTypeShape::Generic {
                    base,
                    argument_text,
                    ..
                } => {
                    // Preserve the prior named-child join, including its raw
                    // argument-list spelling. An uncaptured list is unknown.
                    pending.push(Part::Text(argument_text.as_deref()?));
                    pending.push(Part::Text("["));
                    pending.push(Part::Type(*base));
                }
                GoSourceTypeShape::Compound { children, .. } => {
                    if children.is_empty() {
                        return None;
                    }
                    for (ordinal, child) in children.iter().enumerate().rev() {
                        pending.push(Part::Type(*child));
                        if ordinal != 0 {
                            pending.push(Part::Text("|"));
                        }
                    }
                }
                GoSourceTypeShape::Negated(inner) => {
                    output.push('~');
                    pending.push(Part::Type(*inner));
                }
                GoSourceTypeShape::ImplicitArray { text, .. }
                | GoSourceTypeShape::Struct { text }
                | GoSourceTypeShape::Interface { text, .. }
                | GoSourceTypeShape::Opaque { text } => output.push_str(text.as_deref()?),
            }
        }
        Some(output)
    }

    fn method_key(
        &self,
        file: &GoFactFile,
        callable: &brokk_bifrost_core::analyzer::go_facts::GoCallableFact,
    ) -> Option<DeclaredMethod> {
        let identifier = callable.name.clone();
        if identifier.is_empty() {
            return None;
        }
        let name = if go_identifier_is_exported(&identifier) {
            identifier.clone()
        } else {
            format!("{}.{}", file.package_name, identifier)
        };
        let mut tokens = Vec::new();
        if let Some(parameters) = &callable.parameters {
            let types = parameters
                .iter()
                .map(|parameter| {
                    let ty = parameter.ty.and_then(|id| self.type_token(file, id))?;
                    Some(if parameter.variadic {
                        format!("...{ty}")
                    } else {
                        ty
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            tokens.push(format!("params({})", types.join(",")));
        }
        if callable.result.is_some() {
            let types = callable
                .results
                .iter()
                .map(|parameter| parameter.ty.and_then(|id| self.type_token(file, id)))
                .collect::<Option<Vec<_>>>()?;
            tokens.push(format!("results({})", types.join(",")));
        }
        Some(DeclaredMethod {
            key: MethodKey::new(name, Some(tokens.join(" "))),
            identifier,
        })
    }
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
