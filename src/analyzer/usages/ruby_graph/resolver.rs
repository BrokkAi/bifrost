use crate::analyzer::ruby::{RubyFieldScope, extract_name_path};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ProjectFile, RubyAnalyzer, RubyMethodDispatchMode, RubySemanticFacts,
    resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RubyTargetKind {
    TypeOrConstant,
    Method,
    Field(RubyFieldScope),
}

pub(crate) struct RubyTargetSpec {
    pub(crate) target: CodeUnit,
    pub(super) kind: RubyTargetKind,
    pub(crate) member_name: String,
    pub(super) field_owner: Option<String>,
}

pub(crate) struct RubyFieldTarget {
    pub(crate) owner: String,
    pub(crate) scope: RubyFieldScope,
    pub(crate) member: String,
}

impl RubyTargetSpec {
    pub(crate) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
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
            let class_side_declaration =
                resolve_analyzer::<RubyAnalyzer>(analyzer).is_some_and(|ruby| {
                    matches!(
                        ruby.method_dispatch_mode(target),
                        RubyMethodDispatchMode::Singleton | RubyMethodDispatchMode::ModuleFunction
                    )
                });
            if analyzer.parent_of(target).is_none() && class_side_declaration {
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

pub(crate) fn ruby_field_target(target: &CodeUnit) -> Option<RubyFieldTarget> {
    let member = target.identifier();
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
pub(crate) enum ReceiverMode {
    Instance,
    Class,
    TopLevel,
}

#[derive(Clone, Copy)]
pub(super) enum ExplicitReceiverLookup {
    Bare,
    ReceiverOnly,
}

#[derive(Clone)]
pub(crate) struct ReceiverType {
    pub(crate) owner_fq_name: String,
    pub(crate) mode: ReceiverMode,
}

pub(crate) struct RubySemanticIndex<'a> {
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) ruby: &'a RubyAnalyzer,
    facts: &'a RubySemanticFacts,
    target: Option<CodeUnit>,
    pub(super) factory_return_cache: RefCell<HashMap<FactoryInferenceKey, Option<String>>>,
}

impl<'a> RubySemanticIndex<'a> {
    pub(crate) fn build(
        analyzer: &'a dyn IAnalyzer,
        ruby: &'a RubyAnalyzer,
        spec: &RubyTargetSpec,
    ) -> Self {
        Self::build_with_target(analyzer, ruby, Some(spec.target.clone()))
    }

    pub(crate) fn build_for_lookup(analyzer: &'a dyn IAnalyzer, ruby: &'a RubyAnalyzer) -> Self {
        Self::build_with_target(analyzer, ruby, None)
    }

    fn build_with_target(
        analyzer: &'a dyn IAnalyzer,
        ruby: &'a RubyAnalyzer,
        target: Option<CodeUnit>,
    ) -> Self {
        Self {
            analyzer,
            ruby,
            facts: ruby.semantic_facts(),
            target,
            factory_return_cache: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn visible_files_from(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut visible = HashSet::default();
        visible.insert(file.clone());
        if let Some(zeitwerk_files) = self.ruby.zeitwerk_visible_files_for(file) {
            visible.extend(zeitwerk_files.iter().cloned());
        }
        let mut stack = self.ruby.required_files(file);
        while let Some(next) = stack.pop() {
            if !visible.insert(next.clone()) {
                continue;
            }
            stack.extend(self.ruby.required_files(&next));
        }
        visible
    }

    pub(crate) fn resolve_constant(
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
        )
    }

    pub(crate) fn resolve_constant_name(
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
        )
    }

    fn resolve_constant_path(
        &self,
        file: &ProjectFile,
        visible_files: &HashSet<ProjectFile>,
        lexical_stack: &[String],
        segments: &[String],
        absolute: bool,
    ) -> Option<CodeUnit> {
        let candidates = constant_lookup_candidates(lexical_stack, segments, absolute)?;

        candidates.into_iter().find_map(|candidate| {
            let autoload_files = self.ruby.autoload_visible_files_for_constant(&candidate);
            self.analyzer.definitions(&candidate).find(|unit| {
                visible_files.contains(unit.source())
                    || unit.source() == file
                    || autoload_files.contains(unit.source())
            })
        })
    }

    pub(super) fn target_matches_constant(&self, unit: &CodeUnit) -> bool {
        self.target
            .as_ref()
            .is_some_and(|target| unit == target || unit.fq_name() == target.fq_name())
    }

    pub(crate) fn resolve_method_candidates(
        &self,
        support: &dyn crate::analyzer::BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
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
                for owner in self.receiver_owner_lookup_order(&receiver.owner_fq_name) {
                    let mut prepended = Vec::new();
                    self.push_mixin_methods(
                        &owner,
                        &self.facts.mixin_prepended_owners,
                        &mut push_owner,
                        &mut prepended,
                    );
                    if !prepended.is_empty() {
                        return prepended;
                    }

                    let mut direct = Vec::new();
                    push_owner(&owner, RubyMethodLookupMode::InstanceMethod, &mut direct);
                    if !direct.is_empty() {
                        return direct;
                    }

                    let mut included = Vec::new();
                    self.push_mixin_methods(
                        &owner,
                        &self.facts.mixin_included_owners,
                        &mut push_owner,
                        &mut included,
                    );
                    if !included.is_empty() {
                        return included;
                    }
                }
                Vec::new()
            }
            ReceiverMode::Class => {
                for owner in self.receiver_owner_lookup_order(&receiver.owner_fq_name) {
                    let mut direct = Vec::new();
                    push_owner(&owner, RubyMethodLookupMode::SingletonMethod, &mut direct);
                    if !direct.is_empty() {
                        return direct;
                    }

                    let mut extended = Vec::new();
                    self.push_mixin_methods(
                        &owner,
                        &self.facts.mixin_class_owners,
                        &mut push_owner,
                        &mut extended,
                    );
                    if !extended.is_empty() {
                        return extended;
                    }
                }
                Vec::new()
            }
        }
    }

    pub(crate) fn resolve_bare_method_candidates(
        &self,
        support: &dyn crate::analyzer::BoundedDefinitionLookup,
        visible_files: &HashSet<ProjectFile>,
        receiver: &ReceiverType,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidates = self.resolve_method_candidates(support, visible_files, receiver, member);
        if !candidates.is_empty() || receiver.mode == ReceiverMode::TopLevel {
            return candidates;
        }
        let visible_files: Vec<ProjectFile> = visible_files.iter().cloned().collect();
        self.resolve_top_level_method_candidates(support, &visible_files, member)
    }

    fn resolve_top_level_method_candidates(
        &self,
        support: &dyn crate::analyzer::BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        member: &str,
    ) -> Vec<CodeUnit> {
        support
            .file_identifier_in_files(visible_files, member)
            .into_iter()
            .filter(|unit| {
                unit.is_function()
                    && unit.identifier() == member
                    && self.analyzer.parent_of(unit).is_none()
                    && !ruby_method_lookup_mode_matches(
                        self.ruby,
                        unit,
                        RubyMethodLookupMode::SingletonMethod,
                    )
            })
            .collect()
    }

    fn push_mixin_methods(
        &self,
        owner: &str,
        index: &HashMap<String, Vec<String>>,
        push_owner: &mut impl FnMut(&str, RubyMethodLookupMode, &mut Vec<CodeUnit>),
        out: &mut Vec<CodeUnit>,
    ) {
        if let Some(mixins) = index.get(owner) {
            for mixin in mixins.iter().rev() {
                push_owner(mixin, RubyMethodLookupMode::InstanceMethod, out);
                if !out.is_empty() {
                    break;
                }
            }
        }
    }

    fn receiver_owner_lookup_order(&self, owner: &str) -> Vec<String> {
        let mut out = vec![owner.to_string()];
        out.extend(self.ancestor_lookup_order(owner));
        out
    }

    pub(crate) fn ancestor_lookup_order(&self, owner: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut visited = HashSet::default();
        let mut stack: Vec<String> = self
            .facts
            .ancestors
            .get(owner)
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(candidate) = stack.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            out.push(candidate.clone());
            if let Some(next) = self.facts.ancestors.get(&candidate) {
                stack.extend(next.iter().cloned());
            }
        }
        out
    }
}

#[derive(Clone, Copy)]
pub(super) enum RubyMethodLookupMode {
    InstanceMethod,
    SingletonMethod,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct FactoryInferenceKey {
    pub(super) method: CodeUnit,
    pub(super) invocation_owner_fq_name: String,
}

pub(super) struct FactoryInferenceFrame {
    pub(super) method: CodeUnit,
    pub(super) invocation_owner_fq_name: String,
}

pub(super) enum FactoryMethodOutcome {
    Owner(String),
    Chain(Vec<FactoryInferenceFrame>),
    Unknown,
}

pub(super) fn ruby_method_lookup_mode_matches(
    ruby: &RubyAnalyzer,
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
