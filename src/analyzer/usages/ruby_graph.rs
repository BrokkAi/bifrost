//! Receiver-aware Ruby usage resolution.
//!
//! Ruby remains dynamic, so this strategy only emits graph hits when parser and
//! analyzer facts prove the target. Same-name calls with unknown receivers are
//! tracked as unsafe inference and surfaced through the existing query-level
//! graph diagnostic when no structured hits were found.

use crate::analyzer::ruby::parse_ruby_tree;
use crate::analyzer::type_relations::TypeRelationKind;
use crate::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, TreeWalkAction, language_for_target, usage_hit, walk_tree_iterative,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, Range, RubyAnalyzer, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, trimmed_snippet_around_line,
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use tree_sitter::Node;

const STRATEGY: &str = "RubyUsageGraphStrategy";

#[derive(Default)]
pub struct RubyUsageGraphStrategy;

impl RubyUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Ruby
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        if language_for_target(target) != Language::Ruby {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Ruby"),
                STRATEGY,
            );
        }
        let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability("Ruby analyzer is unavailable"),
                STRATEGY,
            );
        };
        let Some(spec) = RubyTargetSpec::from_target(analyzer, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                STRATEGY,
            );
        };

        let semantic = RubySemanticIndex::build(analyzer, ruby, &spec);
        let mut scan_files = candidate_files.clone();
        scan_files.insert(target.source().clone());
        scan_files.extend(ruby.zeitwerk_reference_files_for_identifier(&spec.member_name));

        let mut hits = BTreeSet::new();
        let mut saw_unproven_match = false;
        for file in &scan_files {
            if language_for_file(file) != Language::Ruby {
                continue;
            }
            let Ok(source) = analyzer.project().read_source(file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };
            let line_starts = compute_line_starts(&source);
            let visible_files = semantic.visible_files_from(file);
            let mut scan = RubyFileScan {
                analyzer,
                semantic: &semantic,
                support: analyzer.definition_lookup_index(),
                file,
                source: &source,
                line_starts: &line_starts,
                visible_files,
                spec: &spec,
                hits: &mut hits,
                saw_unproven_match: &mut saw_unproven_match,
            };
            scan.scan(tree.root_node());
        }

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| hit.enclosing != spec.target)
            .collect();

        if hits.is_empty() && saw_unproven_match && spec.kind == RubyTargetKind::Method {
            return GraphUsageOutcome::fallback_safe(
                spec.target.fq_name(),
                GraphFailureReason::UnsafeInference("no proven structured hits"),
                STRATEGY,
            );
        }

        if hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: spec.target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(spec.target.clone(), hits))
    }
}

impl UsageAnalyzer for RubyUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RubyTargetKind {
    TypeOrConstant,
    Method,
}

pub(crate) struct RubyTargetSpec {
    pub(crate) target: CodeUnit,
    kind: RubyTargetKind,
    pub(crate) member_name: String,
    singleton_declaration: bool,
}

impl RubyTargetSpec {
    pub(crate) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() || target.is_module() || target.is_field() {
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::TypeOrConstant,
                member_name: target.identifier().to_string(),
                singleton_declaration: false,
            });
        }
        if target.is_function() {
            analyzer.parent_of(target)?;
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::Method,
                member_name: target.identifier().to_string(),
                singleton_declaration: is_singleton_method_declaration(analyzer, target),
            });
        }
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverMode {
    Instance,
    Class,
}

#[derive(Clone)]
pub(crate) struct ReceiverType {
    pub(crate) owner_fq_name: String,
    pub(crate) mode: ReceiverMode,
}

pub(crate) struct RubySemanticIndex<'a> {
    analyzer: &'a dyn IAnalyzer,
    ruby: &'a RubyAnalyzer,
    target: Option<CodeUnit>,
    ancestors: HashMap<String, HashSet<String>>,
    mixin_included_owners: HashMap<String, Vec<String>>,
    mixin_prepended_owners: HashMap<String, Vec<String>>,
    mixin_class_owners: HashMap<String, Vec<String>>,
    factory_return_cache: RefCell<HashMap<FactoryInferenceKey, Option<String>>>,
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
        let mut ancestors = HashMap::default();
        let mut mixin_included_owners: HashMap<String, Vec<String>> = HashMap::default();
        let mut mixin_prepended_owners: HashMap<String, Vec<String>> = HashMap::default();
        let mut mixin_class_owners: HashMap<String, Vec<String>> = HashMap::default();

        for unit in analyzer
            .all_declarations()
            .filter(|unit| unit.is_class() || unit.is_module())
        {
            let mut direct = HashSet::default();
            if let Some(provider) = analyzer.type_hierarchy_provider() {
                direct.extend(
                    provider
                        .get_direct_ancestors(unit)
                        .into_iter()
                        .map(|ancestor| ancestor.fq_name()),
                );
            }
            ancestors.insert(unit.fq_name(), direct);
        }

        for relation in ruby.mixin_relations() {
            let entry = match relation.kind {
                TypeRelationKind::MixinInclude => &mut mixin_included_owners,
                TypeRelationKind::MixinPrepend => &mut mixin_prepended_owners,
                TypeRelationKind::MixinExtend => &mut mixin_class_owners,
                _ => continue,
            };
            push_ordered_mixin(entry, relation.from.fq_name(), relation.to.fq_name());
        }

        Self {
            analyzer,
            ruby,
            target,
            ancestors,
            mixin_included_owners,
            mixin_prepended_owners,
            mixin_class_owners,
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
        let name = qualified_internal_name(node, source)?;
        let mut candidates = Vec::new();
        if !is_absolute_scope_resolution(node) {
            for owner in lexical_stack.iter().rev() {
                candidates.push(format!("{owner}${name}"));
            }
        }
        candidates.push(name);

        candidates.into_iter().find_map(|candidate| {
            self.analyzer
                .definitions(&candidate)
                .find(|unit| visible_files.contains(unit.source()) || unit.source() == file)
                .cloned()
        })
    }

    fn target_matches_constant(&self, unit: &CodeUnit) -> bool {
        self.target
            .as_ref()
            .is_some_and(|target| unit == target || unit.fq_name() == target.fq_name())
    }

    pub(crate) fn resolve_method_candidates(
        &self,
        support: &crate::analyzer::DefinitionLookupIndex,
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
                    && ruby_method_lookup_mode_matches(self.analyzer, &unit, mode)
                    && seen.insert(unit.clone())
                {
                    out.push(unit);
                }
            }
        };

        match receiver.mode {
            ReceiverMode::Instance => {
                for owner in self.receiver_owner_lookup_order(&receiver.owner_fq_name) {
                    let mut prepended = Vec::new();
                    self.push_mixin_methods(
                        &owner,
                        &self.mixin_prepended_owners,
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
                        &self.mixin_included_owners,
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
                        &self.mixin_class_owners,
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

    fn ancestor_lookup_order(&self, owner: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut visited = HashSet::default();
        let mut stack: Vec<String> = self
            .ancestors
            .get(owner)
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(candidate) = stack.pop() {
            if !visited.insert(candidate.clone()) {
                continue;
            }
            out.push(candidate.clone());
            if let Some(next) = self.ancestors.get(&candidate) {
                stack.extend(next.iter().cloned());
            }
        }
        out
    }
}

fn push_ordered_mixin(index: &mut HashMap<String, Vec<String>>, from: String, to: String) {
    let owners = index.entry(from).or_default();
    if !owners.contains(&to) {
        owners.push(to);
    }
}

#[derive(Clone, Copy)]
enum RubyMethodLookupMode {
    InstanceMethod,
    SingletonMethod,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct FactoryInferenceKey {
    method: CodeUnit,
    invocation_owner_fq_name: String,
}

struct FactoryInferenceFrame {
    method: CodeUnit,
    invocation_owner_fq_name: String,
}

enum FactoryMethodOutcome {
    Owner(String),
    Chain(Vec<FactoryInferenceFrame>),
    Unknown,
}

fn ruby_method_lookup_mode_matches(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    mode: RubyMethodLookupMode,
) -> bool {
    let Some(spec) = RubyTargetSpec::from_target(analyzer, unit) else {
        return false;
    };
    match mode {
        RubyMethodLookupMode::InstanceMethod => !spec.singleton_declaration,
        RubyMethodLookupMode::SingletonMethod => spec.singleton_declaration,
    }
}

struct RubyFileScan<'a> {
    analyzer: &'a dyn IAnalyzer,
    semantic: &'a RubySemanticIndex<'a>,
    support: &'a crate::analyzer::DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    visible_files: HashSet<ProjectFile>,
    spec: &'a RubyTargetSpec,
    hits: &'a mut BTreeSet<UsageHit>,
    saw_unproven_match: &'a mut bool,
}

impl RubyFileScan<'_> {
    fn scan(&mut self, root: Node<'_>) {
        let mut state = RubyWalkState {
            scan: self,
            locals: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            exits: Vec::new(),
        };
        walk_tree_iterative(
            root,
            &mut state,
            |node, state| state.enter(node),
            |state| state.exit(),
        );
    }
}

enum RubyExit {
    Lexical,
    Method,
    LocalScope,
}

struct RubyWalkState<'a, 'b> {
    scan: &'a mut RubyFileScan<'b>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<ReceiverMode>,
    exits: Vec<RubyExit>,
}

impl RubyWalkState<'_, '_> {
    fn enter(&mut self, node: Node<'_>) -> TreeWalkAction {
        match node.kind() {
            "class" | "module" => {
                self.record_superclass_reference(node);
                if let Some(owner) = self.type_owner(node) {
                    self.lexical_stack.push(owner);
                    self.exits.push(RubyExit::Lexical);
                    self.record_reference(node);
                    return TreeWalkAction::DescendWithExit;
                }
            }
            "method" | "singleton_method" => {
                self.locals.enter_scope();
                self.seed_parameter_shadows(node);
                self.method_stack.push(method_receiver_mode(node));
                self.exits.push(RubyExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.locals.enter_scope();
                self.method_stack.push(ReceiverMode::Class);
                self.exits.push(RubyExit::Method);
                return TreeWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyExit::LocalScope);
                return TreeWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        self.record_reference(node);
        TreeWalkAction::Descend
    }

    fn exit(&mut self) {
        match self.exits.pop() {
            Some(RubyExit::Lexical) => {
                self.lexical_stack.pop();
            }
            Some(RubyExit::Method) => {
                self.method_stack.pop();
                self.locals.exit_scope();
            }
            Some(RubyExit::LocalScope) => {
                self.locals.exit_scope();
            }
            None => {}
        }
    }

    fn type_owner(&self, node: Node<'_>) -> Option<String> {
        ruby_type_owner(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.source,
        )
    }

    fn record_reference(&mut self, node: Node<'_>) {
        match self.scan.spec.kind {
            RubyTargetKind::TypeOrConstant => self.record_constant_reference(node),
            RubyTargetKind::Method => self.record_method_reference(node),
        }
    }

    fn record_superclass_reference(&mut self, node: Node<'_>) {
        if self.scan.spec.kind != RubyTargetKind::TypeOrConstant {
            return;
        }
        let Some(superclass) = node.child_by_field_name("superclass") else {
            return;
        };
        let mut stack = vec![superclass];
        while let Some(current) = stack.pop() {
            self.record_constant_reference(current);
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }

    fn record_constant_reference(&mut self, node: Node<'_>) {
        if !matches!(node.kind(), "constant" | "scope_resolution") || is_declaration_constant(node)
        {
            return;
        }
        if let Some(unit) = self.scan.semantic.resolve_constant(
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            node,
            self.scan.source,
        ) && self.scan.semantic.target_matches_constant(&unit)
        {
            self.record_hit(constant_hit_node(node));
        }
    }

    fn record_method_reference(&mut self, node: Node<'_>) {
        if node.kind() == "identifier" {
            self.record_bare_identifier_method_reference(node);
            return;
        }
        if node.kind() != "call" {
            return;
        }
        if self.dynamic_call_mentions_target(node) {
            *self.scan.saw_unproven_match = true;
            return;
        }
        let Some(method) = node.child_by_field_name("method") else {
            return;
        };
        if node_text(method, self.scan.source) != self.scan.spec.member_name {
            return;
        }
        let receiver = match node.child_by_field_name("receiver") {
            Some(receiver) => self.receiver_type(receiver),
            None => self.enclosing_receiver(),
        };
        match receiver {
            Some(receiver) => self.record_method_hit_for_receiver(&receiver, method),
            None => {
                *self.scan.saw_unproven_match = true;
            }
        }
    }

    fn record_bare_identifier_method_reference(&mut self, node: Node<'_>) {
        let name = node_text(node, self.scan.source);
        if name != self.scan.spec.member_name
            || self.locals.is_shadowed(name)
            || is_declaration_identifier(node)
            || is_call_method_identifier(node)
        {
            return;
        }
        match self.enclosing_receiver() {
            Some(receiver) => self.record_method_hit_for_receiver(&receiver, node),
            None => {
                *self.scan.saw_unproven_match = true;
            }
        }
    }

    fn record_method_hit_for_receiver(&mut self, receiver: &ReceiverType, hit_node: Node<'_>) {
        let candidates = self.scan.semantic.resolve_method_candidates(
            self.scan.support,
            &self.scan.visible_files,
            receiver,
            &self.scan.spec.member_name,
        );
        if candidates.iter().any(|candidate| {
            candidate == &self.scan.spec.target
                || candidate.fq_name() == self.scan.spec.target.fq_name()
        }) {
            self.record_hit(hit_node);
        } else if candidates.is_empty() {
            *self.scan.saw_unproven_match = true;
        }
    }

    fn receiver_type(&self, node: Node<'_>) -> Option<ReceiverType> {
        ruby_receiver_type(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            &self.locals,
            &self.method_stack,
            node,
            self.scan.source,
        )
    }

    fn enclosing_receiver(&self) -> Option<ReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack)
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        ruby_seed_assignment(
            self.scan.semantic,
            self.scan.file,
            &self.scan.visible_files,
            &self.lexical_stack,
            &self.method_stack,
            &mut self.locals,
            node,
            self.scan.source,
        );
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        ruby_seed_parameter_shadows(&mut self.locals, node, self.scan.source);
    }

    fn dynamic_call_mentions_target(&self, node: Node<'_>) -> bool {
        let Some(method) = node.child_by_field_name("method") else {
            return false;
        };
        if !is_dynamic_dispatch_method(method, self.scan.source) {
            return false;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return false;
        };
        let mut cursor = arguments.walk();
        arguments.named_children(&mut cursor).any(|arg| {
            symbol_or_string_value(arg, self.scan.source)
                .is_some_and(|value| value == self.scan.spec.member_name)
        })
    }

    fn record_hit(&mut self, node: Node<'_>) {
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        if start_byte >= end_byte {
            return;
        }
        let line_idx = find_line_index_for_offset(self.scan.line_starts, start_byte);
        let snippet = trimmed_snippet_around_line(
            self.scan.source,
            self.scan.line_starts,
            line_idx,
            SNIPPET_CONTEXT_LINES,
        );
        let range = Range {
            start_byte,
            end_byte,
            start_line: line_idx,
            end_line: line_idx,
        };
        let Some(enclosing) = self
            .scan
            .analyzer
            .enclosing_code_unit(self.scan.file, &range)
        else {
            return;
        };
        self.scan.hits.insert(usage_hit(
            self.scan.file,
            line_idx,
            start_byte,
            end_byte,
            enclosing,
            snippet,
        ));
    }
}

pub(crate) fn is_dynamic_dispatch_method(method: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(method, source),
        "send" | "__send__" | "public_send"
    )
}

fn language_for_file(file: &ProjectFile) -> Language {
    crate::analyzer::common::language_for_file(file)
}

pub(crate) fn first_precise(
    bindings: &LocalInferenceEngine<String>,
    symbol: &str,
) -> Option<String> {
    bindings
        .resolve_symbol(symbol)
        .as_precise()
        .and_then(|targets| targets.iter().next().cloned())
}

pub(crate) fn ruby_type_owner(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = node.child_by_field_name("name")?;
    semantic
        .resolve_constant(file, visible_files, lexical_stack, name, source)
        .filter(|unit| unit.is_class() || unit.is_module())
        .map(|unit| unit.fq_name())
        .or_else(|| {
            let mut segments = lexical_stack.to_vec();
            segments.extend(extract_name_segments(name, source));
            (!segments.is_empty()).then(|| segments.join("$"))
        })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    node: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    match node.kind() {
        "constant" | "scope_resolution" => {
            let unit =
                semantic.resolve_constant(file, visible_files, lexical_stack, node, source)?;
            (unit.is_class() || unit.is_module()).then(|| ReceiverType {
                owner_fq_name: unit.fq_name(),
                mode: ReceiverMode::Class,
            })
        }
        "identifier" => {
            first_precise(locals, node_text(node, source)).map(|owner_fq_name| ReceiverType {
                owner_fq_name,
                mode: ReceiverMode::Instance,
            })
        }
        "self" => ruby_enclosing_receiver(lexical_stack, method_stack),
        "call" => ruby_constructed_receiver_type(
            semantic,
            file,
            visible_files,
            lexical_stack,
            locals,
            method_stack,
            node,
            source,
        ),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_constructed_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    node: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    let method = node.child_by_field_name("method")?;
    let method_name = node_text(method, source);
    let receiver = node.child_by_field_name("receiver")?;

    if method_name == "new" {
        return ruby_new_receiver_type(
            semantic,
            file,
            visible_files,
            lexical_stack,
            locals,
            method_stack,
            receiver,
            source,
        );
    }

    let class = ruby_receiver_type(
        semantic,
        file,
        visible_files,
        lexical_stack,
        locals,
        method_stack,
        receiver,
        source,
    )?;
    ruby_factory_return_receiver_type(semantic, visible_files, &class, method_name)
}

#[allow(clippy::too_many_arguments)]
fn ruby_new_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    locals: &LocalInferenceEngine<String>,
    method_stack: &[ReceiverMode],
    receiver: Node<'_>,
    source: &str,
) -> Option<ReceiverType> {
    let class = ruby_receiver_type(
        semantic,
        file,
        visible_files,
        lexical_stack,
        locals,
        method_stack,
        receiver,
        source,
    )?;
    (class.mode == ReceiverMode::Class).then_some(ReceiverType {
        owner_fq_name: class.owner_fq_name,
        mode: ReceiverMode::Instance,
    })
}

fn ruby_factory_return_receiver_type(
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    class: &ReceiverType,
    method_name: &str,
) -> Option<ReceiverType> {
    if class.mode != ReceiverMode::Class {
        return None;
    }

    semantic
        .resolve_method_candidates(
            semantic.analyzer.definition_lookup_index(),
            visible_files,
            class,
            method_name,
        )
        .into_iter()
        .find_map(|candidate| {
            ruby_infer_method_return_instance_owner(
                semantic,
                candidate,
                class.owner_fq_name.clone(),
            )
            .map(|owner_fq_name| ReceiverType {
                owner_fq_name,
                mode: ReceiverMode::Instance,
            })
        })
}

fn ruby_infer_method_return_instance_owner(
    semantic: &RubySemanticIndex<'_>,
    method_unit: CodeUnit,
    invocation_owner_fq_name: String,
) -> Option<String> {
    let start = FactoryInferenceFrame {
        method: method_unit,
        invocation_owner_fq_name,
    };
    let start_key = start.key();
    if let Some(cached) = semantic.factory_return_cache.borrow().get(&start_key) {
        return cached.clone();
    }

    let mut stack = vec![start];
    let mut visited = HashSet::default();
    while let Some(frame) = stack.pop() {
        let key = frame.key();
        if let Some(cached) = semantic.factory_return_cache.borrow().get(&key) {
            if cached.is_some() {
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(start_key, cached.clone());
                return cached.clone();
            }
            continue;
        }
        if !visited.insert(key.clone()) {
            semantic.factory_return_cache.borrow_mut().insert(key, None);
            continue;
        }

        match ruby_factory_method_outcome(semantic, &frame) {
            FactoryMethodOutcome::Owner(owner) => {
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(key, Some(owner.clone()));
                semantic
                    .factory_return_cache
                    .borrow_mut()
                    .insert(start_key, Some(owner.clone()));
                return Some(owner);
            }
            FactoryMethodOutcome::Chain(next) => {
                if next.is_empty() {
                    semantic.factory_return_cache.borrow_mut().insert(key, None);
                } else {
                    stack.extend(next.into_iter().rev());
                }
            }
            FactoryMethodOutcome::Unknown => {
                semantic.factory_return_cache.borrow_mut().insert(key, None);
            }
        }
    }
    semantic
        .factory_return_cache
        .borrow_mut()
        .insert(start_key, None);
    None
}

impl FactoryInferenceFrame {
    fn key(&self) -> FactoryInferenceKey {
        FactoryInferenceKey {
            method: self.method.clone(),
            invocation_owner_fq_name: self.invocation_owner_fq_name.clone(),
        }
    }
}

fn ruby_factory_method_outcome(
    semantic: &RubySemanticIndex<'_>,
    frame: &FactoryInferenceFrame,
) -> FactoryMethodOutcome {
    let Some(owner) = semantic.analyzer.parent_of(&frame.method) else {
        return FactoryMethodOutcome::Unknown;
    };
    let Ok(source) = semantic
        .analyzer
        .project()
        .read_source(frame.method.source())
    else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(tree) = parse_ruby_tree(&source) else {
        return FactoryMethodOutcome::Unknown;
    };
    let ranges = semantic.analyzer.ranges(&frame.method);
    let Some(node) = ruby_method_node_for_ranges(tree.root_node(), ranges) else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(expression) = ruby_tail_expression(node) else {
        return FactoryMethodOutcome::Unknown;
    };
    let expression = if expression.kind() == "assignment" {
        let Some(right) = expression.child_by_field_name("right") else {
            return FactoryMethodOutcome::Unknown;
        };
        right
    } else {
        expression
    };
    if expression.kind() != "call"
        || expression
            .child_by_field_name("method")
            .is_none_or(|method| node_text(method, &source) != "new")
    {
        return FactoryMethodOutcome::Unknown;
    }
    let Some(receiver) = expression.child_by_field_name("receiver") else {
        return FactoryMethodOutcome::Unknown;
    };
    ruby_factory_new_receiver_outcome(
        semantic,
        frame.method.source(),
        &source,
        &owner.fq_name(),
        &frame.invocation_owner_fq_name,
        receiver,
    )
}

fn ruby_method_node_for_ranges<'tree>(root: Node<'tree>, ranges: &[Range]) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "method" | "singleton_method")
            && ranges.iter().any(|range| {
                range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
            })
        {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn ruby_factory_new_receiver_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    owner_fq_name: &str,
    invocation_owner_fq_name: &str,
    receiver: Node<'_>,
) -> FactoryMethodOutcome {
    let lexical_stack = ruby_lexical_stack_for_owner(owner_fq_name);
    match receiver.kind() {
        "self" => FactoryMethodOutcome::Owner(invocation_owner_fq_name.to_string()),
        "constant" | "scope_resolution" => {
            let visible_files = semantic.visible_files_from(file);
            semantic
                .resolve_constant(file, &visible_files, &lexical_stack, receiver, source)
                .filter(|unit| unit.is_class() || unit.is_module())
                .map(|unit| FactoryMethodOutcome::Owner(unit.fq_name()))
                .unwrap_or(FactoryMethodOutcome::Unknown)
        }
        "call" => ruby_factory_chained_call_outcome(
            semantic,
            file,
            source,
            &lexical_stack,
            invocation_owner_fq_name,
            receiver,
        ),
        _ => FactoryMethodOutcome::Unknown,
    }
}

fn ruby_factory_chained_call_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    lexical_stack: &[String],
    invocation_owner_fq_name: &str,
    call: Node<'_>,
) -> FactoryMethodOutcome {
    let Some(method) = call.child_by_field_name("method") else {
        return FactoryMethodOutcome::Unknown;
    };
    let method_name = node_text(method, source);
    let Some(receiver) = call.child_by_field_name("receiver") else {
        return FactoryMethodOutcome::Unknown;
    };
    let Some(owner_fq_name) = ruby_factory_class_receiver_owner(
        semantic,
        file,
        source,
        lexical_stack,
        invocation_owner_fq_name,
        receiver,
    ) else {
        return FactoryMethodOutcome::Unknown;
    };
    let visible_files = semantic.visible_files_from(file);
    let class = ReceiverType {
        owner_fq_name: owner_fq_name.clone(),
        mode: ReceiverMode::Class,
    };
    let frames = semantic
        .resolve_method_candidates(
            semantic.analyzer.definition_lookup_index(),
            &visible_files,
            &class,
            method_name,
        )
        .into_iter()
        .map(|method| FactoryInferenceFrame {
            method,
            invocation_owner_fq_name: owner_fq_name.clone(),
        })
        .collect();
    FactoryMethodOutcome::Chain(frames)
}

fn ruby_factory_class_receiver_owner(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    source: &str,
    lexical_stack: &[String],
    invocation_owner_fq_name: &str,
    receiver: Node<'_>,
) -> Option<String> {
    match receiver.kind() {
        "self" => Some(invocation_owner_fq_name.to_string()),
        "constant" | "scope_resolution" => {
            let visible_files = semantic.visible_files_from(file);
            semantic
                .resolve_constant(file, &visible_files, lexical_stack, receiver, source)
                .filter(|unit| unit.is_class() || unit.is_module())
                .map(|unit| unit.fq_name())
        }
        _ => None,
    }
}

fn ruby_tail_expression(node: Node<'_>) -> Option<Node<'_>> {
    let body = node.child_by_field_name("body")?;
    let mut cursor = body.walk();
    body.named_children(&mut cursor).last()
}

fn ruby_lexical_stack_for_owner(owner_fq_name: &str) -> Vec<String> {
    let segments: Vec<_> = owner_fq_name
        .split('$')
        .filter(|segment| !segment.is_empty())
        .collect();
    (1..=segments.len())
        .map(|end| segments[..end].join("$"))
        .collect()
}

pub(crate) fn ruby_enclosing_receiver(
    lexical_stack: &[String],
    method_stack: &[ReceiverMode],
) -> Option<ReceiverType> {
    let owner_fq_name = lexical_stack.last()?.clone();
    let mode = method_stack
        .last()
        .copied()
        .unwrap_or(ReceiverMode::Instance);
    Some(ReceiverType {
        owner_fq_name,
        mode,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ruby_seed_assignment(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    lexical_stack: &[String],
    method_stack: &[ReceiverMode],
    locals: &mut LocalInferenceEngine<String>,
    node: Node<'_>,
    source: &str,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let name = node_text(left, source);
    if name.is_empty() {
        return;
    }
    let resolved = node
        .child_by_field_name("right")
        .and_then(|right| {
            ruby_receiver_type(
                semantic,
                file,
                visible_files,
                lexical_stack,
                locals,
                method_stack,
                right,
                source,
            )
        })
        .filter(|receiver| receiver.mode == ReceiverMode::Instance)
        .map(|receiver| receiver.owner_fq_name);
    match resolved {
        Some(owner) => locals.seed_symbol(name.to_string(), owner),
        None => locals.declare_shadow(name.to_string()),
    }
}

pub(crate) fn ruby_seed_parameter_shadows(
    locals: &mut LocalInferenceEngine<String>,
    node: Node<'_>,
    source: &str,
) {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        let mut stack = vec![parameters];
        while let Some(current) = stack.pop() {
            if current.kind() == "identifier" {
                let name = node_text(current, source);
                if !name.is_empty() {
                    locals.declare_shadow(name.to_string());
                }
                continue;
            }
            for index in (0..current.named_child_count()).rev() {
                if let Some(child) = current.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }
}

pub(crate) fn is_singleton_method_declaration(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> bool {
    let Ok(source) = analyzer.project().read_source(target.source()) else {
        return false;
    };
    let Some(tree) = parse_ruby_tree(&source) else {
        return false;
    };
    let ranges = analyzer.ranges(target);
    if ranges.is_empty() {
        return false;
    }
    let Some(node) = ruby_method_node_for_ranges(tree.root_node(), ranges) else {
        return false;
    };
    if node.kind() == "singleton_method" {
        return true;
    }
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "singleton_class" {
            return true;
        }
        if matches!(current.kind(), "class" | "module") {
            break;
        }
        parent = current.parent();
    }
    false
}

pub(crate) fn is_declaration_constant(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "class" | "module")
        && parent.child_by_field_name("name") == Some(node)
    {
        return true;
    }
    if let Some(parent) = node.parent()
        && parent.kind() == "assignment"
        && parent.child_by_field_name("left") == Some(node)
    {
        return true;
    }
    false
}

pub(crate) fn method_receiver_mode(node: Node<'_>) -> ReceiverMode {
    if node.kind() == "singleton_method" {
        return ReceiverMode::Class;
    }
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "singleton_class" {
            return ReceiverMode::Class;
        }
        if matches!(current.kind(), "class" | "module") {
            break;
        }
        parent = current.parent();
    }
    ReceiverMode::Instance
}

pub(crate) fn is_declaration_identifier(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "method" | "singleton_method" | "assignment")
        && parent.child_by_field_name("name") == Some(node)
    {
        return true;
    }
    if let Some(parent) = node.parent()
        && parent.kind() == "assignment"
        && parent.child_by_field_name("left") == Some(node)
    {
        return true;
    }
    false
}

pub(crate) fn is_call_method_identifier(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call" && parent.child_by_field_name("method") == Some(node)
    })
}

fn qualified_internal_name(node: Node<'_>, source: &str) -> Option<String> {
    let segments = extract_name_segments(node, source);
    (!segments.is_empty()).then(|| segments.join("$"))
}

fn is_absolute_scope_resolution(node: Node<'_>) -> bool {
    node.kind() == "scope_resolution" && node.child_by_field_name("scope").is_none()
}

fn constant_hit_node(node: Node<'_>) -> Node<'_> {
    if node.kind() == "scope_resolution" {
        node.child_by_field_name("name").unwrap_or(node)
    } else {
        node
    }
}

pub(crate) fn extract_name_segments(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "scope_resolution" => {
            let mut segments = node
                .child_by_field_name("scope")
                .map(|scope| extract_name_segments(scope, source))
                .unwrap_or_default();
            if let Some(name) = node.child_by_field_name("name") {
                segments.extend(extract_name_segments(name, source));
            }
            segments
        }
        "constant" => {
            let text = node_text(node, source);
            if text.is_empty() {
                Vec::new()
            } else {
                vec![text.to_string()]
            }
        }
        _ => Vec::new(),
    }
}

pub(crate) fn symbol_or_string_value(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source);
    let stripped = text
        .strip_prefix(':')
        .unwrap_or(text)
        .trim_matches(['"', '\'']);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
