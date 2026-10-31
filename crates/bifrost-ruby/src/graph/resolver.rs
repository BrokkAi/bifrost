use crate::declarations::{RubyFieldScope, extract_name_path};
use crate::graph::RubyGraphSource;
use crate::graph::syntax::is_declaration_constant;
use crate::graph_support::RubySource;
use crate::imports::{is_ruby_autoload_symbol_argument, ruby_symbol_name};
use crate::mixins::{ruby_forward_mixin_specs, ruby_forward_superclass_targets};
use brokk_bifrost_core::analyzer::memo_attribution::{
    MemoAttribution, ReplayingMemo, ReplayingMemoEntry,
};
use brokk_bifrost_core::analyzer::model::RubyMethodDispatchMode;
use brokk_bifrost_core::analyzer::type_relations::TypeRelationKind;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnit, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::cell::RefCell;
use std::sync::Arc;
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

pub struct RubyConstantReference {
    pub unit: CodeUnit,
    pub is_autoload_symbol: bool,
}

impl RubyTargetSpec {
    pub fn from_target<A: MemoAttribution>(
        graph: &RubyGraphSource<'_, A>,
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

type ResolutionMemo<K, V, R> = ReplayingMemo<RefCell<HashMap<K, Arc<ReplayingMemoEntry<V, R>>>>>;

pub struct RubySemanticIndex<'a, A: MemoAttribution> {
    pub graph: RubyGraphSource<'a, A>,
    pub ruby: &'a dyn RubySource,
    target: Option<CodeUnit>,
    forward_owner_facts: ResolutionMemo<String, RubyForwardOwnerFacts, A::Key>,
    pub factory_return_cache: ResolutionMemo<FactoryInferenceKey, Option<String>, A::Key>,
}

#[derive(Clone, Default)]
struct RubyForwardOwnerFacts {
    ancestors: Vec<String>,
    included: Vec<String>,
    prepended: Vec<String>,
    extended: Vec<String>,
}

impl<'a, A: MemoAttribution> RubySemanticIndex<'a, A> {
    pub fn build(
        graph: RubyGraphSource<'a, A>,
        ruby: &'a dyn RubySource,
        spec: &RubyTargetSpec,
    ) -> Self {
        Self::build_with_target(graph, ruby, Some(spec.target.clone()))
    }

    pub fn build_for_lookup(graph: RubyGraphSource<'a, A>, ruby: &'a dyn RubySource) -> Self {
        Self::build_with_target(graph, ruby, None)
    }

    fn build_with_target(
        graph: RubyGraphSource<'a, A>,
        ruby: &'a dyn RubySource,
        target: Option<CodeUnit>,
    ) -> Self {
        Self {
            graph,
            ruby,
            target,
            forward_owner_facts: ReplayingMemo::new(RefCell::new(HashMap::default())),
            factory_return_cache: ReplayingMemo::new(RefCell::new(HashMap::default())),
        }
    }

    pub fn visible_files_from(&self, file: &ProjectFile) -> Option<HashSet<ProjectFile>> {
        let mut visible = HashSet::default();
        visible.insert(file.clone());
        if let Some(zeitwerk_files) =
            crate::imports::ruby_zeitwerk_visible_files_for(self.ruby, file)
        {
            visible.extend(zeitwerk_files.iter().cloned());
        }
        let mut stack =
            crate::imports::ruby_required_files_checked(self.ruby, self.graph.token, file)?;
        while let Some(next) = stack.pop() {
            if !visible.insert(next.clone()) {
                continue;
            }
            stack.extend(crate::imports::ruby_required_files_checked(
                self.ruby,
                self.graph.token,
                &next,
            )?);
        }
        Some(visible)
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
        let mut stack = vec![file.clone()];
        while let Some(next) = stack.pop() {
            if !visible.insert(next.clone()) {
                continue;
            }
            if visible.len() > max_files {
                return None;
            }
            stack.extend(crate::imports::ruby_required_files_checked(
                self.ruby,
                self.graph.token,
                &next,
            )?);
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

    /// Whether the workspace declares the constant path `node` spells anywhere
    /// at all, ignoring which files the referencing file can reach.
    ///
    /// [`Self::resolve_constant`] answers the navigation question -- can this
    /// file reach the declaration -- and a cross-workspace boundary claim must
    /// not be built on it. A project file that declares the constant without
    /// being required is still a workspace declaration, and reporting the
    /// reference as leaving the workspace would be false. This is the weaker,
    /// visibility-blind question such a claim has to ask first.
    pub fn declares_constant_anywhere(
        &self,
        lexical_stack: &[String],
        node: Node<'_>,
        source: &str,
    ) -> bool {
        let path = extract_name_path(node, source);
        let Some(candidates) =
            constant_lookup_candidates(lexical_stack, &path.segments, path.absolute)
        else {
            return false;
        };
        candidates
            .iter()
            .any(|candidate| self.graph.index.definitions(candidate).next().is_some())
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
                crate::imports::ruby_autoload_visible_files_for_constant(self.ruby, &candidate)?
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
            for unit in support.members_for_owner_name(owner, owner, member) {
                if unit.is_function()
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
        self.forward_owner_facts(support, visible_files, owner)
            .ancestors
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
        let facts = self.forward_owner_facts(support, visible_files, owner);
        match kind {
            TypeRelationKind::MixinInclude => facts.included,
            TypeRelationKind::MixinPrepend => facts.prepended,
            TypeRelationKind::MixinExtend => facts.extended,
            _ => Vec::new(),
        }
    }

    pub fn forward_ancestor_lookup_order(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Vec<String> {
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
        let facts = self
            .forward_owner_facts
            .read(self.graph.attribution, |cache, capture| {
                if let Some(entry) = cache.borrow().get(owner) {
                    return Ok::<_, std::convert::Infallible>(Arc::clone(entry));
                }
                let entry = Arc::new(capture.build(|| {
                    let owner_units = support
                        .fqn(owner)
                        .into_iter()
                        .filter(|unit| {
                            (unit.is_class() || unit.is_module())
                                && unit.fq_name() == owner
                                && visible_files.contains(unit.source())
                        })
                        .collect::<Vec<_>>();
                    let specs = owner_units
                        .iter()
                        .flat_map(|unit| ruby_forward_mixin_specs(self.ruby, unit))
                        .collect::<Vec<_>>();
                    let mixin_names: HashSet<String> =
                        specs.iter().map(|spec| spec.raw_target.clone()).collect();
                    let mut facts = RubyForwardOwnerFacts::default();
                    for spec in specs {
                        let Some(target) = self.resolve_forward_owner_name(
                            support,
                            visible_files,
                            owner,
                            &spec.raw_target,
                        ) else {
                            continue;
                        };
                        match spec.kind {
                            TypeRelationKind::MixinInclude => facts.included.push(target),
                            TypeRelationKind::MixinPrepend => facts.prepended.push(target),
                            TypeRelationKind::MixinExtend => facts.extended.push(target),
                            _ => {}
                        }
                    }
                    for raw in owner_units
                        .iter()
                        .flat_map(|unit| ruby_forward_superclass_targets(self.ruby, unit))
                    {
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

                    facts
                }));
                cache
                    .borrow_mut()
                    .insert(owner.to_string(), Arc::clone(&entry));
                Ok(entry)
            })
            .expect("owner fact build is infallible");
        (*facts).clone()
    }

    /// The `include`/`prepend`/`extend` targets every visible declaration of
    /// `owner` writes, each resolved from that owner's own forward facts the
    /// way method lookup resolves them. `None` when any written mixin does not
    /// resolve to exactly one visible class or module. Unlike the analyzer's
    /// workspace mixin graph, this reads only `owner`'s declarations, so a
    /// warm per-call query stays bounded by the ancestry it asks about.
    pub fn forward_mixin_targets(
        &self,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        owner: &str,
    ) -> Option<Vec<String>> {
        let mut owner_units = support
            .fqn(owner)
            .into_iter()
            .filter(|unit| {
                (unit.is_class() || unit.is_module())
                    && unit.fq_name() == owner
                    && visible_files.contains(unit.source())
            })
            .collect::<Vec<_>>();
        owner_units.sort();
        owner_units.dedup();
        owner_units
            .iter()
            .flat_map(|unit| ruby_forward_mixin_specs(self.ruby, unit))
            .map(|spec| {
                self.resolve_forward_owner_name(support, visible_files, owner, &spec.raw_target)
            })
            .collect()
    }

    /// Resolve one superclass or mixin name `lexical_owner` writes, among the
    /// visible files, the way method lookup resolves it.
    pub fn resolve_forward_owner_name(
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
            matches.dedup_by(|left, right| left.fq_name() == right.fq_name());
            if matches.len() == 1 {
                return Some(matches.remove(0).fq_name());
            }
        }

        // A missing qualified prefix cannot nominate an unrelated same-leaf type.
        if raw.contains('$') {
            return None;
        }
        let identifier = raw.rsplit('$').next().unwrap_or(raw); // fqname-M4: leaf of a `$`-joined reference string (no CodeUnit here)
        let mut matches = support.file_identifier_in_files(visible_files, identifier);
        matches.retain(|unit| {
            (unit.is_class() || unit.is_module()) && unit.identifier() == identifier
        });
        matches.sort_by_key(CodeUnit::fq_name);
        matches.dedup_by(|left, right| left.fq_name() == right.fq_name());
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

pub fn ruby_dispatch_matches_lookup_mode(
    declaration: RubyMethodDispatchMode,
    mode: RubyMethodLookupMode,
) -> bool {
    matches!(
        (declaration, mode),
        (
            RubyMethodDispatchMode::Instance,
            RubyMethodLookupMode::InstanceMethod
        ) | (
            RubyMethodDispatchMode::Singleton,
            RubyMethodLookupMode::SingletonMethod
        ) | (RubyMethodDispatchMode::ModuleFunction, _)
    )
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
    ruby_dispatch_matches_lookup_mode(ruby.method_dispatch_mode(unit), mode)
}

fn constant_lookup_candidates(
    lexical_stack: &[String],
    segments: &[String],
    absolute: bool,
) -> Option<Vec<String>> {
    if segments.is_empty() {
        return None;
    }

    let (constant_name, owner_segments) = segments.split_last().expect("nonempty path");
    let name = segments.join("$");
    let mut candidates = Vec::new();
    if !absolute {
        for owner in lexical_stack.iter().rev() {
            candidates.push(format!("{owner}${name}"));
            let field_owner = if owner_segments.is_empty() {
                owner.clone()
            } else {
                format!("{owner}${}", owner_segments.join("$"))
            };
            candidates.push(format!("{field_owner}.{constant_name}"));
        }
    }
    candidates.push(name);
    if !owner_segments.is_empty() {
        candidates.push(format!("{}.{constant_name}", owner_segments.join("$")));
    }

    Some(candidates)
}

pub fn resolve_constant_reference<A: MemoAttribution>(
    semantic: &RubySemanticIndex<'_, A>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    node: Node<'_>,
    source: &str,
) -> Option<RubyConstantReference> {
    if is_ruby_autoload_symbol_argument(node, source) {
        let name = ruby_symbol_name(node, source)?;
        return Some(RubyConstantReference {
            unit: semantic.resolve_constant_name(file, visible_files, lexical_stack, &name)?,
            is_autoload_symbol: true,
        });
    }
    if !matches!(node.kind(), "constant" | "scope_resolution") || is_declaration_constant(node) {
        return None;
    }
    let mut current = node;
    let mut in_superclass = false;
    let mut type_scopes = 0;
    while let Some(parent) = current.parent() {
        in_superclass |= parent.kind() == "superclass";
        if matches!(parent.kind(), "class" | "module") {
            type_scopes += 1;
        }
        current = parent;
    }
    // Both graph walks visit the superclass before entering the class and
    // again during ordinary descent. The superclass belongs to the outer cref.
    let lexical_stack = if in_superclass && lexical_stack.len() == type_scopes {
        &lexical_stack[..lexical_stack.len() - 1]
    } else {
        lexical_stack
    };
    Some(RubyConstantReference {
        unit: semantic.resolve_constant(file, visible_files, lexical_stack, node, source)?,
        is_autoload_symbol: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::capabilities::{
        ImportAnalysisProvider, TypeHierarchyProvider,
    };
    use brokk_bifrost_core::analyzer::model::Range;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::project::Project;
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use brokk_bifrost_core::analyzer::ruby_facts::RubyFileSourceInfo;
    use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    // The parser and the persisted relation reader evolve independently. The
    // fixture reads the actual parser projection, including reopenings; unused
    // services panic so a new dependency cannot silently pass with fake data.
    #[derive(Default)]
    struct Fixture {
        files: Vec<(ProjectFile, ParsedFile)>,
        autoload: HashMap<String, HashSet<ProjectFile>>,
        empty: HashSet<ProjectFile>,
        types: HashMap<String, Vec<CodeUnit>>,
    }

    impl Fixture {
        fn add(&mut self, name: &str, source: &str) -> ProjectFile {
            let file = ProjectFile::new(std::env::temp_dir().join("ruby-resolution"), name);
            let tree = crate::declarations::parse_ruby_tree(source).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            let parsed = crate::adapter::parse_ruby_file(&file, source, &tree);
            for unit in parsed
                .declarations()
                .iter()
                .filter(|unit| unit.is_class() || unit.is_module())
            {
                self.types
                    .entry(unit.identifier().into())
                    .or_default()
                    .push(unit.clone());
            }
            self.files.push((file.clone(), parsed));
            file
        }
        fn parsed(&self, file: &ProjectFile) -> &ParsedFile {
            &self.files.iter().find(|(path, _)| path == file).unwrap().1
        }
    }

    impl CodeUnitIndex for Fixture {
        fn project(&self) -> &dyn Project {
            unimplemented!()
        }
        fn languages(&self) -> BTreeSet<Language> {
            [Language::Ruby].into_iter().collect()
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(
                self.files
                    .iter()
                    .flat_map(|(_, parsed)| parsed.declarations().iter().cloned()),
            )
        }
        fn definitions(&self, name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            let name = name.to_string();
            Box::new(
                self.all_declarations()
                    .filter(move |unit| unit.fq_name() == name),
            )
        }
        fn parent_of(&self, unit: &CodeUnit) -> Option<CodeUnit> {
            self.parsed(unit.source())
                .children
                .iter()
                .find(|(_, children)| children.contains(unit))
                .map(|(owner, _)| owner.clone())
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
            None
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<CodeUnit> {
            None
        }
        fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }
    impl TypeHierarchyProvider for Fixture {
        fn get_direct_ancestors(
            &self,
            unit: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            let edges = crate::hierarchy::ruby_direct_ancestors(self, unit);
            brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer::complete(edges)
        }
        fn get_direct_descendants(
            &self,
            _: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            unimplemented!()
        }
    }
    impl ImportAnalysisProvider for Fixture {
        fn imported_code_units_of(&self, _: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
            unimplemented!()
        }
        fn referencing_files_of(&self, _: &ProjectFile) -> HashSet<ProjectFile> {
            unimplemented!()
        }
    }
    impl RubySource for Fixture {
        fn all_files(&self) -> Vec<ProjectFile> {
            self.files.iter().map(|(file, _)| file.clone()).collect()
        }
        fn source_files(&self) -> Option<Vec<ProjectFile>> {
            Some(self.all_files())
        }
        fn source_facts(&self, _: &ProjectFile) -> Option<RubyFileSourceInfo> {
            Some(RubyFileSourceInfo {
                loads: Vec::new(),
                source_bytes: 0,
                has_parse_errors: false,
                runtime_boundary: None,
            })
        }
        fn autoload_constant_files(
            &self,
        ) -> Option<std::sync::Arc<HashMap<String, HashSet<ProjectFile>>>> {
            Some(std::sync::Arc::new(self.autoload.clone()))
        }
        fn has_zeitwerk_autoload_conventions(&self) -> bool {
            false
        }
        fn zeitwerk_autoload_files(&self) -> std::sync::Arc<HashSet<ProjectFile>> {
            std::sync::Arc::new(self.empty.clone())
        }
        fn zeitwerk_consumer_files(&self) -> std::sync::Arc<HashSet<ProjectFile>> {
            std::sync::Arc::new(self.empty.clone())
        }
        fn zeitwerk_autoload_code_units(&self) -> std::sync::Arc<HashSet<CodeUnit>> {
            unimplemented!()
        }
        fn reverse_import_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
            unimplemented!()
        }
        fn mixin_relations(
            &self,
        ) -> std::sync::Arc<Vec<brokk_bifrost_core::analyzer::type_relations::TypeRelation>>
        {
            unimplemented!()
        }
        fn semantic_facts(&self) -> std::sync::Arc<crate::graph_support::RubySemanticFacts> {
            unimplemented!()
        }
        fn types_by_identifier(&self) -> std::sync::Arc<HashMap<String, Vec<CodeUnit>>> {
            std::sync::Arc::new(self.types.clone())
        }
        fn method_dispatch_mode(&self, unit: &CodeUnit) -> RubyMethodDispatchMode {
            self.parsed(unit.source())
                .ruby_method_dispatch_modes
                .get(unit)
                .copied()
                .unwrap_or(RubyMethodDispatchMode::Instance)
        }
        fn forward_owner_relation_facts(
            &self,
            unit: &CodeUnit,
        ) -> Vec<crate::mixins::RubyOwnerRelationFact> {
            let parsed = self.parsed(unit.source());
            parsed
                .raw_supertypes
                .get(unit)
                .into_iter()
                .flatten()
                .zip(
                    parsed
                        .supertype_lookup_paths
                        .get(unit)
                        .into_iter()
                        .flatten(),
                )
                .filter_map(|(raw, encoded)| crate::mixins::decode_owner_relation(encoded, raw))
                .collect()
        }
    }
    impl BoundedDefinitionLookup for Fixture {
        fn fqn(&self, name: &str) -> Vec<CodeUnit> {
            self.definitions(name).collect()
        }
        fn fqn_in_language(&self, name: &str, _: Language) -> Vec<CodeUnit> {
            self.fqn(name)
        }
        fn file_identifier(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
            self.parsed(file)
                .declarations()
                .iter()
                .filter(|unit| unit.identifier() == name)
                .cloned()
                .collect()
        }
        fn members_for_owner_name(&self, owner: &str, _: &str, name: &str) -> Vec<CodeUnit> {
            self.fqn(&format!("{owner}.{name}"))
        }
        fn fqn_direct_children(&self, _: &str) -> Vec<CodeUnit> {
            unimplemented!()
        }
        fn package_exists(&self, _: &str) -> bool {
            unimplemented!()
        }
        fn package_exists_in_language(&self, _: &str, _: Language) -> bool {
            unimplemented!()
        }
        fn fqn_prefix_exists(&self, _: &str) -> bool {
            unimplemented!()
        }
    }

    // No storage is involved in this grammar/reader fixture. The scope still
    // bounds the lifetime of every graph view, like the production scope.
    impl QueryScope for Fixture {}

    use brokk_bifrost_core::analyzer::memo_attribution::MemoCapability;

    struct TestAttribution;
    impl MemoAttribution for TestAttribution {
        type Key = ();
        fn is_capturing(&self) -> bool {
            false
        }
        fn capture_identity(
            &self,
        ) -> Option<brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity> {
            None
        }
        fn record_unattributed(&self) {
            panic!("fixture has no captures")
        }
        fn capture<T>(
            &self,
            build: impl FnOnce() -> T,
        ) -> (
            T,
            brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<()>,
            Option<brokk_bifrost_core::analyzer::memo_attribution::CaptureIdentity>,
        ) {
            (
                build(),
                brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads {
                    keys: Arc::from([]),
                    unattributed_reads: 0,
                    execution_dependences: 0,
                },
                None,
            )
        }
        fn capture_authority<T>(
            &self,
            build: impl FnOnce() -> T,
        ) -> (
            T,
            brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<()>,
        ) {
            let (value, reads, _) = self.capture(build);
            (value, reads)
        }
        fn replay(
            &self,
            _: &brokk_bifrost_core::analyzer::memo_attribution::CapturedMemoReads<()>,
        ) {
            panic!("fixture has no captures")
        }
    }
    fn with_semantic(
        fixture: &Fixture,
        read: impl FnOnce(&RubySemanticIndex<'_, TestAttribution>),
    ) {
        let definitions =
            |consumer: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| consumer(fixture);
        let attribution = MemoCapability::new(TestAttribution);
        let graph = RubyGraphSource {
            attribution: &attribution,
            token: fixture.token(),
            index: fixture,
            definitions: &definitions,
        };
        read(&RubySemanticIndex::build_for_lookup(graph, fixture));
    }

    #[test]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: lexical scalar constants must precede root classes"
    )]
    fn lexical_constant_and_qualified_prefix_resolution() {
        let mut fixture = Fixture::default();
        let file = fixture.add(
            "names.rb",
            "class Token; end; module Outer; Token = 7; end; module Left; class Same; end; end",
        );
        with_semantic(&fixture, |semantic| {
            let visible = [file.clone()].into_iter().collect();
            assert_eq!(
                semantic
                    .resolve_constant_name(&file, &visible, &["Outer".into()], "Token")
                    .unwrap()
                    .fq_name(),
                "Outer.Token"
            );
            let tree = crate::declarations::parse_ruby_tree("::Token").unwrap();
            assert_eq!(
                semantic
                    .resolve_constant(
                        &file,
                        &visible,
                        &["Outer".into()],
                        tree.root_node().named_child(0).unwrap(),
                        "::Token"
                    )
                    .unwrap()
                    .fq_name(),
                "Token"
            );
            assert_eq!(
                semantic.resolve_forward_owner_name(&fixture, &[file], "Client", "Missing$Same"),
                None
            );
            assert_eq!(
                crate::hierarchy::ruby_resolve_supertype(&fixture, "Missing$Same"),
                None
            );
        });
    }

    #[test]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: superclass usages must not resolve again inside the new class scope"
    )]
    fn superclass_reference_uses_enclosing_scope_only() {
        let source = "module Outer; class Base; end; class Child < Base; class Base; end; end; end";
        let mut fixture = Fixture::default();
        let file = fixture.add("superclass.rb", source);
        with_semantic(&fixture, |semantic| {
            let visible = [file.clone()].into_iter().collect();
            let tree = crate::declarations::parse_ruby_tree(source).unwrap();
            let mut stack = vec![tree.root_node()];
            let mut visited = 0;
            while let Some(node) = stack.pop() {
                if node.kind() == "class" && node.child_by_field_name("superclass").is_some() {
                    crate::graph::syntax::for_each_ruby_superclass_constant(node, |constant| {
                        if constant.kind() == "constant" {
                            visited += 1;
                            for lexical in [
                                vec!["Outer".into()],
                                vec!["Outer".into(), "Outer$Child".into()],
                            ] {
                                assert_eq!(
                                    resolve_constant_reference(
                                        semantic, &file, &visible, &lexical, constant, source
                                    )
                                    .unwrap()
                                    .unit
                                    .fq_name(),
                                    "Outer$Base"
                                );
                            }
                        }
                    });
                }
                for index in (0..node.named_child_count()).rev() {
                    stack.push(node.named_child(index).unwrap());
                }
            }
            assert_eq!(visited, 1);
        });
    }

    #[test]
    #[ignore = "finds real bug: persisted superclass facts lose absolute and lexical context, so ::Base and a nested Base resolve alike"]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: absolute and relative superclasses must retain distinct facts"
    )]
    fn superclass_facts_preserve_absolute_lookup() {
        let mut fixture = Fixture::default();
        fixture.add("parents.rb", "class Base; end; module Outer; class Base; end; class Relative < Base; end; class Absolute < ::Base; end; end");
        with_semantic(&fixture, |semantic| {
            let files = fixture.all_files();
            assert_eq!(
                semantic.forward_ancestor_lookup_order(&fixture, &files, "Outer$Relative"),
                ["Outer$Base"]
            );
            assert_eq!(
                semantic.forward_ancestor_lookup_order(&fixture, &files, "Outer$Absolute"),
                ["Base"]
            );
        });
    }

    #[test]
    fn project_local_visibility_excludes_autoload() {
        let mut fixture = Fixture::default();
        let file = fixture.add("consumer.rb", "module Widget; end");
        let lazy = fixture.add("lazy.rb", "module Widget; class Lazy; end; end");
        fixture
            .autoload
            .insert("Widget$Lazy".into(), [lazy].into_iter().collect());
        with_semantic(&fixture, |semantic| {
            let tree = crate::declarations::parse_ruby_tree("Widget::Lazy").unwrap();
            let node = tree.root_node().named_child(0).unwrap();
            let visible = [file.clone()].into_iter().collect();
            assert!(
                semantic
                    .resolve_constant(&file, &visible, &[], node, "Widget::Lazy")
                    .is_some()
            );
            assert!(
                semantic
                    .resolve_project_local_constant(&file, &visible, &[], node, "Widget::Lazy")
                    .is_none()
            );
        });
    }

    #[test]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: same-FQN reopenings share owner identity and relations"
    )]
    fn reopening_relation_reader_and_dispatch() {
        let mut fixture = Fixture::default();
        let first = fixture.add(
            "first.rb",
            "module M; def first; end; end; class Client; include M; end",
        );
        fixture.add(
            "second.rb",
            "module Helper; def extra; end; end; module M; include Helper; def second; end; end",
        );
        with_semantic(&fixture, |semantic| {
            let files = fixture.all_files();
            assert_eq!(
                semantic.resolve_forward_owner_name(&fixture, &files, "Client", "M"),
                Some("M".into())
            );
            let visible = files.into_iter().collect();
            let receiver = ReceiverType {
                owner_fq_name: "Client".into(),
                mode: ReceiverMode::Instance,
            };
            for (member, owner) in [("first", "M"), ("second", "M"), ("extra", "Helper")] {
                let mut find = None;
                let lookup_receiver = if member == "extra" {
                    ReceiverType {
                        owner_fq_name: "M".into(),
                        mode: ReceiverMode::Instance,
                    }
                } else {
                    receiver.clone()
                };
                let found = semantic.resolve_bare_method_candidates_traced(
                    &fixture,
                    &visible,
                    &lookup_receiver,
                    member,
                    &mut find,
                );
                assert_eq!(
                    found.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                    [format!("{owner}.{member}")]
                );
                assert_eq!(find.unwrap().owner, owner);
            }
            let target = fixture.fqn("M").pop().unwrap();
            let spec = RubyTargetSpec::from_target(&semantic.graph, &fixture, &target).unwrap();
            let for_target = RubySemanticIndex::build(semantic.graph, &fixture, &spec);
            for unit in fixture.fqn("M") {
                assert!(for_target.target_matches_constant(&unit));
            }
            assert!(
                semantic.declares_constant_anywhere(
                    &[],
                    crate::declarations::parse_ruby_tree("M")
                        .unwrap()
                        .root_node()
                        .named_child(0)
                        .unwrap(),
                    "M"
                )
            );
            assert!(
                !semantic.declares_constant_anywhere(
                    &[],
                    crate::declarations::parse_ruby_tree("NeverDefined")
                        .unwrap()
                        .root_node()
                        .named_child(0)
                        .unwrap(),
                    "NeverDefined"
                )
            );
            assert!(semantic.visible_files_from_bounded(&first, 1).is_some());
            assert!(semantic.visible_files_from_bounded(&first, 0).is_none());
        });
    }
}
