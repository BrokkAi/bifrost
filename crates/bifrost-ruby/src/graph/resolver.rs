use crate::declarations::{RubyFieldScope, extract_name_path};
use crate::graph::RubyGraphSource;
use crate::graph_support::{RubySemanticFacts, RubySource};
use crate::mixins::{ruby_forward_mixin_specs, ruby_forward_superclass_targets};
use brokk_bifrost_core::analyzer::model::RubyMethodDispatchMode;
use brokk_bifrost_core::analyzer::type_relations::TypeRelationKind;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RubyTargetKind {
    TypeOrConstant,
    Method,
    Field(RubyFieldScope),
}

pub struct RubyTargetSpec {
    pub target: CodeUnit,
    pub kind: RubyTargetKind,
    pub member_name: String,
    pub field_owner: Option<String>,
}

pub struct RubyFieldTarget {
    pub owner: String,
    pub scope: RubyFieldScope,
    pub member: String,
}

impl RubyTargetSpec {
    pub fn from_target(
        graph: &RubyGraphSource<'_>,
        ruby: &dyn RubySource,
        target: &CodeUnit,
    ) -> Option<Self> {
        if target.is_field()
            && let Some(field) = ruby_field_target(target)
        {
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::Field(field.scope),
                member_name: field.member,
                field_owner: Some(field.owner),
            });
        }
        if target.is_class() || target.is_module() || target.is_field() {
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::TypeOrConstant,
                member_name: target.identifier().to_string(),
                field_owner: None,
            });
        }
        if target.is_function() {
            let class_side_declaration = matches!(
                ruby.method_dispatch_mode(target),
                RubyMethodDispatchMode::Singleton | RubyMethodDispatchMode::ModuleFunction
            );
            if graph.index.parent_of(target).is_none() && class_side_declaration {
                return None;
            }
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::Method,
                member_name: target.identifier().to_string(),
                field_owner: None,
            });
        }
        None
    }
}

pub fn ruby_field_target(target: &CodeUnit) -> Option<RubyFieldTarget> {
    let member = target.identifier();
    // fqname-M4: `owner` below is compared against a package-less class-name
    // reference-text `owner` parsed at a field-reference site (see
    // `field_reference_matches_target`); `fq.parent()`/`default_parent_fq_name`
    // would render the package-qualified owner, a different string that would
    // never match there.
    let short_name = target.short_name();
    if member.starts_with("@@") {
        let owner = short_name.strip_suffix(&format!(".{member}"))?;
        return (!owner.is_empty()).then(|| RubyFieldTarget {
            owner: owner.to_string(),
            scope: RubyFieldScope::ClassVariable,
            member: member.to_string(),
        });
    }
    if member.starts_with('@') {
        let singleton_suffix = format!(".$singleton.{member}");
        if let Some(owner) = short_name.strip_suffix(&singleton_suffix) {
            return (!owner.is_empty()).then(|| RubyFieldTarget {
                owner: owner.to_string(),
                scope: RubyFieldScope::SingletonClass,
                member: member.to_string(),
            });
        }
        let owner = short_name.strip_suffix(&format!(".{member}"))?;
        return (!owner.is_empty()).then(|| RubyFieldTarget {
            owner: owner.to_string(),
            scope: RubyFieldScope::Instance,
            member: member.to_string(),
        });
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReceiverMode {
    Instance,
    Class,
    TopLevel,
}

#[derive(Clone, Copy)]
pub enum ExplicitReceiverLookup {
    Bare,
    ReceiverOnly,
}

#[derive(Clone)]
pub struct ReceiverType {
    pub owner_fq_name: String,
    pub mode: ReceiverMode,
}

pub struct RubySemanticIndex<'a> {
    pub graph: RubyGraphSource<'a>,
    pub ruby: &'a dyn RubySource,
    facts: Option<&'a RubySemanticFacts>,
    target: Option<CodeUnit>,
    forward_owner_facts: RefCell<HashMap<String, RubyForwardOwnerFacts>>,
    pub factory_return_cache: RefCell<HashMap<FactoryInferenceKey, Option<String>>>,
}

#[derive(Clone, Default)]
struct RubyForwardOwnerFacts {
    ancestors: Vec<String>,
    included: Vec<String>,
    prepended: Vec<String>,
    extended: Vec<String>,
}

impl<'a> RubySemanticIndex<'a> {
    pub fn build(
        graph: RubyGraphSource<'a>,
        ruby: &'a dyn RubySource,
        spec: &RubyTargetSpec,
    ) -> Self {
        Self::build_with_target(graph, ruby, Some(spec.target.clone()))
    }

    pub fn build_for_lookup(graph: RubyGraphSource<'a>, ruby: &'a dyn RubySource) -> Self {
        Self::build_with_target(graph, ruby, None)
    }

    fn build_with_target(
        graph: RubyGraphSource<'a>,
        ruby: &'a dyn RubySource,
        target: Option<CodeUnit>,
    ) -> Self {
        Self {
            graph,
            ruby,
            facts: target.as_ref().map(|_| ruby.semantic_facts()),
            target,
            forward_owner_facts: RefCell::new(HashMap::default()),
            factory_return_cache: RefCell::new(HashMap::default()),
        }
    }

    pub fn visible_files_from(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut visible = HashSet::default();
        visible.insert(file.clone());
        if let Some(zeitwerk_files) =
            crate::imports::ruby_zeitwerk_visible_files_for(self.ruby, file)
        {
            visible.extend(zeitwerk_files.iter().cloned());
        }
        let mut stack = crate::imports::ruby_required_files(self.ruby, file);
        while let Some(next) = stack.pop() {
            if !visible.insert(next.clone()) {
                continue;
            }
            stack.extend(crate::imports::ruby_required_files(self.ruby, &next));
        }
        visible
    }

    /// Follows only explicit project-local `require` edges and fails closed
    /// when the dependency closure is too broad for a latency-sensitive caller.
    ///
    /// Diagnostics use this instead of the navigation-oriented visibility
    /// closure. Callers that want convention-derived Zeitwerk visibility must
    /// continue using [`Self::visible_files_from`].
    pub fn visible_files_from_bounded(
        &self,
        file: &ProjectFile,
        max_files: usize,
    ) -> Option<HashSet<ProjectFile>> {
        let mut visible = HashSet::default();
        visible.insert(file.clone());
        let mut stack = crate::imports::ruby_required_files(self.ruby, file);
        while let Some(next) = stack.pop() {
            if !visible.insert(next.clone()) {
                continue;
            }
            if visible.len() > max_files {
                return None;
            }
            stack.extend(crate::imports::ruby_required_files(self.ruby, &next));
        }
        Some(visible)
    }

    pub fn resolve_constant(
        &self,
        file: &ProjectFile,
        visible_files: &HashSet<ProjectFile>,
        lexical_stack: &[String],
        node: Node<'_>,
        source: &str,
    ) -> Option<CodeUnit> {
        let path = extract_name_path(node, source);
        self.resolve_constant_path(
            file,
            visible_files,
            lexical_stack,
            &path.segments,
            path.absolute,
            true,
        )
    }

    /// Resolves only indexed declarations in the supplied project-local
    /// visibility closure. This avoids initializing the workspace-wide
    /// `autoload` index for conservative, latency-sensitive diagnostics.
    pub fn resolve_project_local_constant(
        &self,
        file: &ProjectFile,
        visible_files: &HashSet<ProjectFile>,
        lexical_stack: &[String],
        node: Node<'_>,
        source: &str,
    ) -> Option<CodeUnit> {
        let path = extract_name_path(node, source);
        self.resolve_constant_path(
            file,
            visible_files,
            lexical_stack,
            &path.segments,
            path.absolute,
            false,
        )
    }

    pub fn resolve_constant_name(
        &self,
        file: &ProjectFile,
        visible_files: &HashSet<ProjectFile>,
        lexical_stack: &[String],
        name: &str,
    ) -> Option<CodeUnit> {
        self.resolve_constant_path(
            file,
            visible_files,
            lexical_stack,
            &[name.to_string()],
            false,
            true,
        )
    }

    fn resolve_constant_path(
        &self,
        file: &ProjectFile,
        visible_files: &HashSet<ProjectFile>,
        lexical_stack: &[String],
        segments: &[String],
        absolute: bool,
        include_autoload: bool,
    ) -> Option<CodeUnit> {
        let candidates = constant_lookup_candidates(lexical_stack, segments, absolute)?;

        candidates.into_iter().find_map(|candidate| {
            let autoload_files = if include_autoload {
                crate::imports::ruby_autoload_visible_files_for_constant(self.ruby, &candidate)
            } else {
                HashSet::default()
            };
            self.graph.index.definitions(&candidate).find(|unit| {
                visible_files.contains(unit.source())
                    || unit.source() == file
                    || autoload_files.contains(unit.source())
            })
        })
    }

    pub fn target_matches_constant(&self, unit: &CodeUnit) -> bool {
        self.target
            .as_ref()
            .is_some_and(|target| unit == target || unit.fq_name() == target.fq_name())
    }

    pub fn resolve_method_candidates(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
    ) -> Vec<CodeUnit> {
        self.method_candidates(support, visible_files, receiver, member, None)
    }

    /// [`Self::resolve_method_candidates`], reporting where the group it
    /// returns was found (#1477).
    ///
    /// The lookup returns the first non-empty group it reaches, so one owner
    /// and one edge describe every candidate in that group. A caller that does
    /// not ask keeps the plain entry point and pays nothing.
    pub fn resolve_method_candidates_traced(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
        find: &mut Option<RubyMethodFind>,
    ) -> Vec<CodeUnit> {
        self.method_candidates(support, visible_files, receiver, member, Some(find))
    }

    fn method_candidates(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
        mut find: Option<&mut Option<RubyMethodFind>>,
    ) -> Vec<CodeUnit> {
        let visible_files: Vec<ProjectFile> = visible_files.iter().cloned().collect();
        let mut seen = HashSet::default();
        let mut push_owner = |owner: &str, mode: RubyMethodLookupMode, out: &mut Vec<CodeUnit>| {
            for unit in support.fqn_direct_children(owner) {
                if unit.is_function()
                    && unit.identifier() == member
                    && visible_files.contains(unit.source())
                    && ruby_method_lookup_mode_matches(self.ruby, &unit, mode)
                    && seen.insert(unit.clone())
                {
                    out.push(unit);
                }
            }
        };

        match receiver.mode {
            ReceiverMode::TopLevel => {
                self.resolve_top_level_method_candidates(support, &visible_files, member)
            }
            ReceiverMode::Instance => {
                for owner in self.forward_receiver_owner_lookup_order(
                    support,
                    &visible_files,
                    &receiver.owner_fq_name,
                ) {
                    let mut prepended = Vec::new();
                    let mut prepended_from = None;
                    for mixin in self
                        .mixin_owners(
                            support,
                            &visible_files,
                            &owner,
                            TypeRelationKind::MixinPrepend,
                        )
                        .into_iter()
                        .rev()
                    {
                        push_owner(&mixin, RubyMethodLookupMode::InstanceMethod, &mut prepended);
                        if !prepended.is_empty() {
                            prepended_from = Some(mixin);
                            break;
                        }
                    }
                    if !prepended.is_empty() {
                        record_find(
                            &mut find,
                            &owner,
                            prepended_from,
                            Some(TypeRelationKind::MixinPrepend),
                            false,
                        );
                        return prepended;
                    }

                    let mut direct = Vec::new();
                    push_owner(&owner, RubyMethodLookupMode::InstanceMethod, &mut direct);
                    if !direct.is_empty() {
                        record_find(&mut find, &owner, None, None, false);
                        return direct;
                    }

                    let mut included = Vec::new();
                    let mut included_from = None;
                    for mixin in self
                        .mixin_owners(
                            support,
                            &visible_files,
                            &owner,
                            TypeRelationKind::MixinInclude,
                        )
                        .into_iter()
                        .rev()
                    {
                        push_owner(&mixin, RubyMethodLookupMode::InstanceMethod, &mut included);
                        if !included.is_empty() {
                            included_from = Some(mixin);
                            break;
                        }
                    }
                    if !included.is_empty() {
                        record_find(
                            &mut find,
                            &owner,
                            included_from,
                            Some(TypeRelationKind::MixinInclude),
                            false,
                        );
                        return included;
                    }
                }
                Vec::new()
            }
            ReceiverMode::Class => {
                for owner in self.forward_receiver_owner_lookup_order(
                    support,
                    &visible_files,
                    &receiver.owner_fq_name,
                ) {
                    let mut direct = Vec::new();
                    push_owner(&owner, RubyMethodLookupMode::SingletonMethod, &mut direct);
                    if !direct.is_empty() {
                        record_find(&mut find, &owner, None, None, true);
                        return direct;
                    }

                    let mut extended = Vec::new();
                    let mut extended_from = None;
                    for mixin in self
                        .mixin_owners(
                            support,
                            &visible_files,
                            &owner,
                            TypeRelationKind::MixinExtend,
                        )
                        .into_iter()
                        .rev()
                    {
                        push_owner(&mixin, RubyMethodLookupMode::InstanceMethod, &mut extended);
                        if !extended.is_empty() {
                            extended_from = Some(mixin);
                            break;
                        }
                    }
                    if !extended.is_empty() {
                        record_find(
                            &mut find,
                            &owner,
                            extended_from,
                            Some(TypeRelationKind::MixinExtend),
                            true,
                        );
                        return extended;
                    }
                }
                Vec::new()
            }
        }
    }

    pub fn resolve_bare_method_candidates(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
    ) -> Vec<CodeUnit> {
        self.bare_method_candidates(support, visible_files, receiver, member, None)
    }

    /// [`Self::resolve_bare_method_candidates`], reporting where the group it
    /// returns was found (#1477).
    ///
    /// A bare name that falls through to the top-level scope reports no find:
    /// a top-level method belongs to no owner, so there is nothing to
    /// attribute it to.
    pub fn resolve_bare_method_candidates_traced(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
        find: &mut Option<RubyMethodFind>,
    ) -> Vec<CodeUnit> {
        self.bare_method_candidates(support, visible_files, receiver, member, Some(find))
    }

    fn bare_method_candidates(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
        find: Option<&mut Option<RubyMethodFind>>,
    ) -> Vec<CodeUnit> {
        let candidates = self.method_candidates(support, visible_files, receiver, member, find);
        if !candidates.is_empty() || receiver.mode == ReceiverMode::TopLevel {
            return candidates;
        }
        let visible_files: Vec<ProjectFile> = visible_files.iter().cloned().collect();
        self.resolve_top_level_method_candidates(support, &visible_files, member)
    }

    /// The direct ancestors of `owner`: the exact edges
    /// [`Self::forward_ancestor_lookup_order`] walks, before it flattens them
    /// into a lookup order that no longer says which owner reached which.
    pub fn direct_ancestor_owners(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Vec<String> {
        if let Some(facts) = self.facts {
            let mut direct: Vec<String> = facts
                .ancestors
                .get(owner)
                .map(|items| items.iter().cloned().collect())
                .unwrap_or_default();
            direct.sort();
            return direct;
        }
        self.forward_owner_facts(support, visible_files, owner)
            .ancestors
    }

    /// The mixins `owner` composes in through `kind`, in the order the method
    /// lookup considers them.
    pub fn mixin_owners_of(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
        kind: TypeRelationKind,
    ) -> Vec<String> {
        self.mixin_owners(support, visible_files, owner, kind)
    }

    /// The class or module declaration `owner` names, as the lookup resolves
    /// it: an indexed class or module of that exact fq name, visible from the
    /// referencing file.
    pub fn owner_unit(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Option<CodeUnit> {
        support.fqn(owner).into_iter().find(|unit| {
            (unit.is_class() || unit.is_module())
                && unit.fq_name() == owner
                && visible_files.contains(unit.source())
        })
    }

    fn resolve_top_level_method_candidates(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        member: &str,
    ) -> Vec<CodeUnit> {
        support
            .file_identifier_in_files(visible_files, member)
            .into_iter()
            .filter(|unit| {
                unit.is_function()
                    && unit.identifier() == member
                    && self.graph.index.parent_of(unit).is_none()
                    && !ruby_method_lookup_mode_matches(
                        self.ruby,
                        unit,
                        RubyMethodLookupMode::SingletonMethod,
                    )
            })
            .collect()
    }

    fn mixin_owners(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
        kind: TypeRelationKind,
    ) -> Vec<String> {
        if let Some(facts) = self.facts {
            let index = match kind {
                TypeRelationKind::MixinInclude => &facts.mixin_included_owners,
                TypeRelationKind::MixinPrepend => &facts.mixin_prepended_owners,
                TypeRelationKind::MixinExtend => &facts.mixin_class_owners,
                _ => return Vec::new(),
            };
            return index.get(owner).cloned().unwrap_or_default();
        }
        let facts = self.forward_owner_facts(support, visible_files, owner);
        match kind {
            TypeRelationKind::MixinInclude => facts.included,
            TypeRelationKind::MixinPrepend => facts.prepended,
            TypeRelationKind::MixinExtend => facts.extended,
            _ => Vec::new(),
        }
    }

    pub fn ancestor_lookup_order(&self, owner: &str) -> Vec<String> {
        let Some(facts) = self.facts else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut visited = HashSet::default();
        let mut stack: Vec<String> = facts
            .ancestors
            .get(owner)
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(candidate) = stack.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            out.push(candidate.clone());
            if let Some(next) = facts.ancestors.get(&candidate) {
                stack.extend(next.iter().cloned());
            }
        }
        out
    }

    pub fn forward_ancestor_lookup_order(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Vec<String> {
        if self.facts.is_some() {
            return self.ancestor_lookup_order(owner);
        }
        let mut out = Vec::new();
        let mut visited = HashSet::default();
        let mut stack = self
            .forward_owner_facts(support, visible_files, owner)
            .ancestors;
        stack.reverse();
        while let Some(candidate) = stack.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            out.push(candidate.clone());
            let mut next = self
                .forward_owner_facts(support, visible_files, &candidate)
                .ancestors;
            next.reverse();
            stack.extend(next);
        }
        out
    }

    fn forward_receiver_owner_lookup_order(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Vec<String> {
        let mut owners = vec![owner.to_string()];
        owners.extend(self.forward_ancestor_lookup_order(support, visible_files, owner));
        owners
    }

    fn forward_owner_facts(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> RubyForwardOwnerFacts {
        if let Some(cached) = self.forward_owner_facts.borrow().get(owner) {
            return cached.clone();
        }
        let Some(owner_unit) = self.owner_unit(support, visible_files, owner) else {
            self.forward_owner_facts
                .borrow_mut()
                .insert(owner.to_string(), RubyForwardOwnerFacts::default());
            return RubyForwardOwnerFacts::default();
        };

        let specs = ruby_forward_mixin_specs(self.ruby, &owner_unit);
        let mixin_names: HashSet<String> =
            specs.iter().map(|spec| spec.raw_target.clone()).collect();
        let mut facts = RubyForwardOwnerFacts::default();
        for spec in specs {
            let Some(target) =
                self.resolve_forward_owner_name(support, visible_files, owner, &spec.raw_target)
            else {
                continue;
            };
            match spec.kind {
                TypeRelationKind::MixinInclude => facts.included.push(target),
                TypeRelationKind::MixinPrepend => facts.prepended.push(target),
                TypeRelationKind::MixinExtend => facts.extended.push(target),
                _ => {}
            }
        }
        for raw in ruby_forward_superclass_targets(self.ruby, &owner_unit) {
            if mixin_names.contains(&raw) {
                continue;
            }
            if let Some(target) =
                self.resolve_forward_owner_name(support, visible_files, owner, &raw)
            {
                facts.ancestors.push(target);
            }
        }
        facts.ancestors.dedup();
        facts.included.dedup();
        facts.prepended.dedup();
        facts.extended.dedup();
        self.forward_owner_facts
            .borrow_mut()
            .insert(owner.to_string(), facts.clone());
        facts
    }

    fn resolve_forward_owner_name(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        lexical_owner: &str,
        raw: &str,
    ) -> Option<String> {
        let mut candidate_names = vec![raw.to_string()];
        let mut prefix = lexical_owner;
        // fqname-M4: walks the `$`-joined lexical-owner *string* (not a CodeUnit) to enumerate
        // enclosing-scope candidate names; fq not threaded to this string-keyed support probe
        while let Some((parent, _)) = prefix.rsplit_once('$') {
            candidate_names.push(format!("{parent}${raw}"));
            prefix = parent;
        }
        for candidate in candidate_names {
            let mut matches = support.fqn(&candidate);
            matches.retain(|unit| {
                (unit.is_class() || unit.is_module()) && visible_files.contains(unit.source())
            });
            matches.sort();
            matches.dedup();
            if matches.len() == 1 {
                return Some(matches.remove(0).fq_name());
            }
        }

        let identifier = raw.rsplit('$').next().unwrap_or(raw); // fqname-M4: leaf of a `$`-joined reference string (no CodeUnit here)
        let mut matches = support.file_identifier_in_files(visible_files, identifier);
        matches.retain(|unit| {
            (unit.is_class() || unit.is_module()) && unit.identifier() == identifier
        });
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0).fq_name())
    }
}

/// Where a method lookup found the group of candidates it returned (#1477).
///
/// The lookup walks the receiver's ancestor order and returns the first
/// non-empty group it reaches, so exactly one owner and one edge describe
/// every candidate in that group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyMethodFind {
    /// The owner in the receiver's ancestor lookup order the group was
    /// reached from.
    pub reached_from: String,
    /// The owner that declares the group: `reached_from` itself, or the module
    /// `mixin` names.
    pub owner: String,
    /// The mixin edge from `reached_from` to `owner`, absent when the group
    /// was declared by `reached_from` itself.
    pub mixin: Option<TypeRelationKind>,
    /// Whether the lookup was on the owner's class side.
    pub class_side: bool,
}

/// Record one find, when the caller asked for one. Every argument is a fact
/// the branch that calls this has just decided; nothing here re-derives one.
fn record_find(
    find: &mut Option<&mut Option<RubyMethodFind>>,
    reached_from: &str,
    mixin_owner: Option<String>,
    mixin: Option<TypeRelationKind>,
    class_side: bool,
) {
    let Some(slot) = find.as_deref_mut() else {
        return;
    };
    debug_assert_eq!(
        mixin_owner.is_some(),
        mixin.is_some(),
        "a mixin edge and the module it reaches are recorded together"
    );
    *slot = Some(RubyMethodFind {
        owner: mixin_owner.unwrap_or_else(|| reached_from.to_owned()),
        reached_from: reached_from.to_owned(),
        mixin,
        class_side,
    });
}

#[derive(Clone, Copy)]
pub enum RubyMethodLookupMode {
    InstanceMethod,
    SingletonMethod,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FactoryInferenceKey {
    pub method: CodeUnit,
    pub invocation_owner_fq_name: String,
}

pub struct FactoryInferenceFrame {
    pub method: CodeUnit,
    pub invocation_owner_fq_name: String,
}

pub enum FactoryMethodOutcome {
    Owner(String),
    Chain(Vec<FactoryInferenceFrame>),
    Unknown,
}

pub fn ruby_method_lookup_mode_matches(
    ruby: &dyn RubySource,
    unit: &CodeUnit,
    mode: RubyMethodLookupMode,
) -> bool {
    matches!(
        (ruby.method_dispatch_mode(unit), mode),
        (
            RubyMethodDispatchMode::Instance,
            RubyMethodLookupMode::InstanceMethod
        ) | (
            RubyMethodDispatchMode::Singleton,
            RubyMethodLookupMode::SingletonMethod
        ) | (RubyMethodDispatchMode::ModuleFunction, _)
    )
}

fn constant_lookup_candidates(
    lexical_stack: &[String],
    segments: &[String],
    absolute: bool,
) -> Option<Vec<String>> {
    if segments.is_empty() {
        return None;
    }

    let name = segments.join("$");
    let mut candidates = Vec::new();
    if !absolute {
        for owner in lexical_stack.iter().rev() {
            candidates.push(format!("{owner}${name}"));
        }
    }
    candidates.push(name);

    let Some((constant_name, owner_segments)) = segments.split_last() else {
        return Some(candidates);
    };
    if owner_segments.is_empty() {
        if !absolute {
            for owner in lexical_stack.iter().rev() {
                candidates.push(format!("{owner}.{constant_name}"));
            }
        }
        return Some(candidates);
    }

    let owner_name = owner_segments.join("$");
    if !absolute {
        for owner in lexical_stack.iter().rev() {
            candidates.push(format!("{owner}${owner_name}.{constant_name}"));
        }
    }
    candidates.push(format!("{owner_name}.{constant_name}"));

    Some(candidates)
}
