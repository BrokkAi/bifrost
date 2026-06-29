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

struct RubyTargetSpec {
    target: CodeUnit,
    kind: RubyTargetKind,
    owner: Option<CodeUnit>,
    member_name: String,
    singleton_declaration: bool,
}

impl RubyTargetSpec {
    fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() || target.is_module() || target.is_field() {
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::TypeOrConstant,
                owner: analyzer.parent_of(target),
                member_name: target.identifier().to_string(),
                singleton_declaration: false,
            });
        }
        if target.is_function() {
            let owner = analyzer.parent_of(target)?;
            return Some(Self {
                target: target.clone(),
                kind: RubyTargetKind::Method,
                owner: Some(owner),
                member_name: target.identifier().to_string(),
                singleton_declaration: is_singleton_method_declaration(analyzer, target),
            });
        }
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiverMode {
    Instance,
    Class,
}

#[derive(Clone)]
struct ReceiverType {
    owner_fq_name: String,
    mode: ReceiverMode,
}

struct RubySemanticIndex<'a> {
    analyzer: &'a dyn IAnalyzer,
    ruby: &'a RubyAnalyzer,
    target: CodeUnit,
    target_owner_fq_name: Option<String>,
    ancestors: HashMap<String, HashSet<String>>,
    mixin_instance_owners: HashMap<String, HashSet<String>>,
    mixin_class_owners: HashMap<String, HashSet<String>>,
}

impl<'a> RubySemanticIndex<'a> {
    fn build(analyzer: &'a dyn IAnalyzer, ruby: &'a RubyAnalyzer, spec: &RubyTargetSpec) -> Self {
        let mut ancestors = HashMap::default();
        let mut mixin_instance_owners: HashMap<String, HashSet<String>> = HashMap::default();
        let mut mixin_class_owners: HashMap<String, HashSet<String>> = HashMap::default();

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
                TypeRelationKind::MixinInclude | TypeRelationKind::MixinPrepend => {
                    &mut mixin_instance_owners
                }
                TypeRelationKind::MixinExtend => &mut mixin_class_owners,
                _ => continue,
            };
            entry
                .entry(relation.from.fq_name())
                .or_default()
                .insert(relation.to.fq_name());
        }

        Self {
            analyzer,
            ruby,
            target: spec.target.clone(),
            target_owner_fq_name: spec.owner.as_ref().map(CodeUnit::fq_name),
            ancestors,
            mixin_instance_owners,
            mixin_class_owners,
        }
    }

    fn visible_files_from(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
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

    fn resolve_constant(
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
        unit == &self.target || unit.fq_name() == self.target.fq_name()
    }

    fn method_matches_receiver(&self, receiver: &ReceiverType, spec: &RubyTargetSpec) -> bool {
        let Some(target_owner) = self.target_owner_fq_name.as_deref() else {
            return false;
        };
        match receiver.mode {
            ReceiverMode::Instance => {
                !spec.singleton_declaration
                    && (self.owner_or_ancestor_matches(&receiver.owner_fq_name, target_owner)
                        || self.mixin_matches(
                            &receiver.owner_fq_name,
                            target_owner,
                            &self.mixin_instance_owners,
                        ))
            }
            ReceiverMode::Class => {
                (spec.singleton_declaration
                    && self.owner_or_ancestor_matches(&receiver.owner_fq_name, target_owner))
                    || (!spec.singleton_declaration
                        && self.mixin_matches(
                            &receiver.owner_fq_name,
                            target_owner,
                            &self.mixin_class_owners,
                        ))
            }
        }
    }

    fn owner_or_ancestor_matches(&self, owner: &str, target_owner: &str) -> bool {
        if owner == target_owner {
            return true;
        }
        let mut visited = HashSet::default();
        let mut stack: Vec<String> = self
            .ancestors
            .get(owner)
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(candidate) = stack.pop() {
            if candidate == target_owner {
                return true;
            }
            if visited.insert(candidate.clone())
                && let Some(next) = self.ancestors.get(&candidate)
            {
                stack.extend(next.iter().cloned());
            }
        }
        false
    }

    fn mixin_matches(
        &self,
        owner: &str,
        target_owner: &str,
        index: &HashMap<String, HashSet<String>>,
    ) -> bool {
        let mut receiver_owners = vec![owner.to_string()];
        receiver_owners.extend(self.all_ancestors(owner));
        receiver_owners.iter().any(|receiver_owner| {
            index
                .get(receiver_owner)
                .is_some_and(|mixins| mixins.contains(target_owner))
        })
    }

    fn all_ancestors(&self, owner: &str) -> HashSet<String> {
        let mut out = HashSet::default();
        let mut stack: Vec<String> = self
            .ancestors
            .get(owner)
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(candidate) = stack.pop() {
            if out.insert(candidate.clone())
                && let Some(next) = self.ancestors.get(&candidate)
            {
                stack.extend(next.iter().cloned());
            }
        }
        out
    }
}

struct RubyFileScan<'a> {
    analyzer: &'a dyn IAnalyzer,
    semantic: &'a RubySemanticIndex<'a>,
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
        let name = node.child_by_field_name("name")?;
        self.scan
            .semantic
            .resolve_constant(
                self.scan.file,
                &self.scan.visible_files,
                &self.lexical_stack,
                name,
                self.scan.source,
            )
            .filter(|unit| unit.is_class() || unit.is_module())
            .map(|unit| unit.fq_name())
            .or_else(|| {
                let mut segments = self.lexical_stack.clone();
                segments.extend(extract_name_segments(name, self.scan.source));
                (!segments.is_empty()).then(|| segments.join("$"))
            })
    }

    fn record_reference(&mut self, node: Node<'_>) {
        match self.scan.spec.kind {
            RubyTargetKind::TypeOrConstant => self.record_constant_reference(node),
            RubyTargetKind::Method => self.record_method_reference(node),
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
            self.record_hit(node);
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
            Some(receiver)
                if self
                    .scan
                    .semantic
                    .method_matches_receiver(&receiver, self.scan.spec) =>
            {
                self.record_hit(method);
            }
            Some(_) | None => {
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
            Some(receiver)
                if self
                    .scan
                    .semantic
                    .method_matches_receiver(&receiver, self.scan.spec) =>
            {
                self.record_hit(node);
            }
            Some(_) | None => {
                *self.scan.saw_unproven_match = true;
            }
        }
    }

    fn receiver_type(&self, node: Node<'_>) -> Option<ReceiverType> {
        match node.kind() {
            "constant" | "scope_resolution" => {
                let unit = self.scan.semantic.resolve_constant(
                    self.scan.file,
                    &self.scan.visible_files,
                    &self.lexical_stack,
                    node,
                    self.scan.source,
                )?;
                (unit.is_class() || unit.is_module()).then(|| ReceiverType {
                    owner_fq_name: unit.fq_name(),
                    mode: ReceiverMode::Class,
                })
            }
            "identifier" => first_precise(&self.locals, node_text(node, self.scan.source)).map(
                |owner_fq_name| ReceiverType {
                    owner_fq_name,
                    mode: ReceiverMode::Instance,
                },
            ),
            "self" => self.enclosing_receiver(),
            "call" => self.constructed_receiver_type(node),
            _ => None,
        }
    }

    fn constructed_receiver_type(&self, node: Node<'_>) -> Option<ReceiverType> {
        let method = node.child_by_field_name("method")?;
        if node_text(method, self.scan.source) != "new" {
            return None;
        }
        let receiver = node.child_by_field_name("receiver")?;
        let class = self.receiver_type(receiver)?;
        (class.mode == ReceiverMode::Class).then_some(ReceiverType {
            owner_fq_name: class.owner_fq_name,
            mode: ReceiverMode::Instance,
        })
    }

    fn enclosing_receiver(&self) -> Option<ReceiverType> {
        let owner_fq_name = self.lexical_stack.last()?.clone();
        let mode = self
            .method_stack
            .last()
            .copied()
            .unwrap_or(ReceiverMode::Instance);
        Some(ReceiverType {
            owner_fq_name,
            mode,
        })
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if left.kind() != "identifier" {
            return;
        }
        let name = node_text(left, self.scan.source);
        if name.is_empty() {
            return;
        }
        let resolved = node
            .child_by_field_name("right")
            .and_then(|right| self.receiver_type(right))
            .filter(|receiver| receiver.mode == ReceiverMode::Instance)
            .map(|receiver| receiver.owner_fq_name);
        match resolved {
            Some(owner) => self.locals.seed_symbol(name.to_string(), owner),
            None => self.locals.declare_shadow(name.to_string()),
        }
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        if let Some(parameters) = node.child_by_field_name("parameters") {
            let mut stack = vec![parameters];
            while let Some(current) = stack.pop() {
                if current.kind() == "identifier" {
                    let name = node_text(current, self.scan.source);
                    if !name.is_empty() {
                        self.locals.declare_shadow(name.to_string());
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

    fn dynamic_call_mentions_target(&self, node: Node<'_>) -> bool {
        let Some(method) = node.child_by_field_name("method") else {
            return false;
        };
        if !matches!(
            node_text(method, self.scan.source),
            "send" | "__send__" | "public_send"
        ) {
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

fn language_for_file(file: &ProjectFile) -> Language {
    crate::analyzer::common::language_for_file(file)
}

fn first_precise(bindings: &LocalInferenceEngine<String>, symbol: &str) -> Option<String> {
    bindings
        .resolve_symbol(symbol)
        .as_precise()
        .and_then(|targets| targets.iter().next().cloned())
}

fn is_singleton_method_declaration(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> bool {
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
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "method" | "singleton_method")
            && ranges.iter().any(|range| {
                range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
            })
        {
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
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn is_declaration_constant(node: Node<'_>) -> bool {
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

fn method_receiver_mode(node: Node<'_>) -> ReceiverMode {
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

fn is_declaration_identifier(node: Node<'_>) -> bool {
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

fn is_call_method_identifier(node: Node<'_>) -> bool {
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

fn extract_name_segments(node: Node<'_>, source: &str) -> Vec<String> {
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

fn symbol_or_string_value(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source);
    let stripped = text
        .strip_prefix(':')
        .unwrap_or(text)
        .trim_matches(['"', '\'']);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
