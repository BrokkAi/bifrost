//! JavaScript / TypeScript receiver facts for bounded object-sensitive usage analysis.
//!
//! This provider intentionally starts with the small, structurally proven forms that
//! issue #394 needs first: local receivers assigned from `new Class()`, top-level
//! factory calls that return constructed values, and class factory methods whose body
//! returns a constructed value.

use crate::access_chain::{JsTsImportedMemberChainResolution, resolve_import_member_chain};
use crate::graph::common::{enclosing_function_scope, simple_identifier_text};
use crate::imports::{js_ts_module_identity, require_call_module_specifier};
use crate::imports::{
    resolve_js_ts_direct_import_candidates, resolve_js_ts_imported_member_chain,
    resolve_js_ts_module_binding_candidates, resolve_js_ts_module_specifier,
};
use crate::providers::{JsTsSource, compute_direct_ancestors};
use crate::source_facts::JsTsFileSourceFacts;
use crate::syntax::parse_js_ts_tree;
use crate::syntax::{
    JsTsImportBinder, JsTsImportBindingResolution, js_ts_is_class_scope_kind,
    pattern_binder_identifiers, slice, static_member_property,
};
use crate::ts_owners::{
    jsts_identifier_candidates, jsts_indexed_callable_node, ts_nodes_for_code_unit,
    ts_resolve_source_type_to_property_owner_outcome,
    ts_resolve_type_node_to_property_owner_outcome, ts_source_type_property_owners,
    ts_type_node_property_owners,
};
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::js_ts_facts::{
    JsTsComponentPropsFact, JsTsExportKind, JsTsSourceTypeId, JsTsTypeShape,
};
use brokk_bifrost_core::analyzer::model::CodeUnitType;
use brokk_bifrost_core::analyzer::tree_walk::{
    BoundedNamedTreeWalk, walk_named_tree_preorder_bounded,
};
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisBudgetTracker, ReceiverAnalysisCacheKey,
    ReceiverAnalysisOutcome, ReceiverAnalysisQuery, ReceiverAnalysisReport, ReceiverContext,
    ReceiverFactProvider, ReceiverFacts, ReceiverIdentityProof, ReceiverMemberTargetReport,
    ReceiverSummaryQuery, ReceiverValue,
};
use brokk_bifrost_core::analyzer::usages::reference_site::{
    node_range, smallest_named_node_covering,
};
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, Language, ProjectFile, Range,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::profiling;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

const MAX_JSTS_RECEIVER_RECURSION: usize = 8;
const MAX_JSTS_MEMBER_FRONTIER: usize = 512;

/// How many module or default-export steps a JSX component binding may take
/// before its props count as unproven. `lazy(() => import("./panel"))` costs
/// one step, and a module that re-exports another component's default costs the
/// next (#2041).
const MAX_JSX_COMPONENT_HOPS: usize = 3;

pub struct JsTsReceiverFactProvider<'tree, 'a> {
    host: &'a dyn JsTsSource,
    support: &'a dyn BoundedDefinitionLookup,
    language: Language,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    imports: JsTsImportBinder,
    aliases: Arc<AliasResolver>,
    syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    member_target_cache:
        RefCell<HashMap<ReceiverAnalysisCacheKey, ReceiverAnalysisOutcome<CodeUnit>>>,
    jsx_props_owner_cache: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
    /// Props owners by (enclosing scope, component name) in this file.
    jsx_component_owner_cache: RefCell<HashMap<(usize, String), Vec<CodeUnit>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexedNodeRange {
    start_byte: usize,
    end_byte: usize,
}

#[derive(Debug, Default)]
pub struct JsTsReceiverSyntaxIndex {
    function_declarations_by_name: HashMap<String, Vec<IndexedNodeRange>>,
    class_declarations_by_name: HashMap<String, Vec<IndexedNodeRange>>,
}

pub enum JsTsReceiverSyntaxIndexBuild {
    Complete {
        index: Arc<JsTsReceiverSyntaxIndex>,
        visited: usize,
    },
    ExceededScope {
        visited: usize,
    },
    Cancelled,
}

impl<'tree, 'a> JsTsReceiverFactProvider<'tree, 'a> {
    pub fn new(
        host: &'a dyn JsTsSource,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
    ) -> Self {
        let (syntax_index, _) =
            build_js_ts_receiver_syntax_index(root, source, None).expect("uncancelled index build");
        Self::new_with_syntax_index(
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            syntax_index,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_syntax_index(
        host: &'a dyn JsTsSource,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
        syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    ) -> Self {
        Self::new_with_batch_data(
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            Arc::clone(host.alias_resolver()),
            syntax_index,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_batch_data(
        host: &'a dyn JsTsSource,
        support: &'a dyn BoundedDefinitionLookup,
        language: Language,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        imports: JsTsImportBinder,
        aliases: Arc<AliasResolver>,
        syntax_index: Arc<JsTsReceiverSyntaxIndex>,
    ) -> Self {
        let imports = if imports.lexical_bindings().is_some() {
            imports
        } else {
            imports.with_lexical_bindings(
                root,
                crate::syntax::JsTsLexicalBindingIndex::build(root, source),
            )
        };
        Self {
            host,
            support,
            language,
            file,
            source,
            root,
            imports,
            aliases,
            syntax_index,
            member_target_cache: RefCell::new(HashMap::default()),
            jsx_props_owner_cache: RefCell::new(HashMap::default()),
            jsx_component_owner_cache: RefCell::new(HashMap::default()),
        }
    }

    pub fn resolve_receiver_node(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        self.resolve_receiver_node_report(node, budget).outcome
    }

    pub fn resolve_receiver_node_report(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_receiver_node");
        let (outcome, tracker) = self.resolve_receiver_with_tracker(node, budget);
        tracker.report(outcome)
    }

    fn resolve_receiver_with_tracker(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> (
        ReceiverAnalysisOutcome<ReceiverValue>,
        ReceiverAnalysisBudgetTracker,
    ) {
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        let outcome = self.resolve_expression(node, 0, budget, &mut tracker);
        (outcome, tracker)
    }

    pub fn resolve_iterable_element(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if self.language != Language::TypeScript {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let Some(name) = matches!(node.kind(), "identifier" | "type_identifier")
            .then(|| slice(node, self.source))
            .filter(|name| !name.is_empty())
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        for scope in lexical_scopes_for_node(node) {
            if let Some(outcome) = self.latest_iterable_element_binding_in_scope(
                scope,
                name,
                node.start_byte(),
                budget,
                &mut tracker,
            ) {
                return outcome;
            }
        }
        ReceiverAnalysisOutcome::Unknown
    }

    pub fn resolve_member_targets(
        &self,
        receiver: Node<'tree>,
        member: &str,
        _before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<CodeUnit> {
        self.resolve_member_targets_report(receiver, member, _before_byte, budget)
            .outcome
    }

    pub fn resolve_member_targets_report(
        &self,
        receiver: Node<'tree>,
        member: &str,
        _before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<CodeUnit> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_member_targets");
        let query = ReceiverAnalysisQuery {
            language: self.language,
            file: self.file,
            receiver_text: slice(receiver, self.source),
            receiver_range: Some(node_range(receiver)),
            member_name: Some(member),
            context: ReceiverContext::new(None, receiver.start_byte()),
            budget,
        };
        let cache_key = ReceiverAnalysisCacheKey::for_receiver(&query);
        if let Some(cached) = self.member_target_cache.borrow().get(&cache_key).cloned() {
            return ReceiverAnalysisReport::without_work(cached, budget);
        }
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        let outcome = match self.resolve_expression(receiver, 0, budget, &mut tracker) {
            ReceiverAnalysisOutcome::Precise(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets_for_value(value, member))
                    .collect::<Vec<_>>();
                ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget)
            }
            ReceiverAnalysisOutcome::Ambiguous(values) => {
                let targets = values
                    .iter()
                    .flat_map(|value| self.member_targets_for_value(value, member))
                    .collect::<Vec<_>>();
                let bounded = ReceiverAnalysisOutcome::single_precise_or_ambiguous(targets, budget);
                match bounded {
                    ReceiverAnalysisOutcome::Precise(targets)
                    | ReceiverAnalysisOutcome::Ambiguous(targets) => {
                        ReceiverAnalysisOutcome::Ambiguous(targets)
                    }
                    ReceiverAnalysisOutcome::Unknown => {
                        ReceiverAnalysisOutcome::Ambiguous(Vec::new())
                    }
                    other => other,
                }
            }
            ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
            ReceiverAnalysisOutcome::Unsupported { reason } => {
                ReceiverAnalysisOutcome::Unsupported { reason }
            }
            ReceiverAnalysisOutcome::ExceededBudget { limit } => {
                ReceiverAnalysisOutcome::ExceededBudget { limit }
            }
        };
        self.member_target_cache
            .borrow_mut()
            .insert(cache_key, outcome.clone());
        tracker.report(outcome)
    }

    pub fn resolve_member_targets_at_site(
        &self,
        site: Node<'tree>,
        expected_member: Option<&str>,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverMemberTargetReport> {
        let member_expression = member_expression_at_site(site)?;
        let (member, member_name) = static_member_property(member_expression, self.source)?;
        if member_name.is_empty() || expected_member.is_some_and(|expected| expected != member_name)
        {
            return None;
        }
        let receiver = member_expression.child_by_field_name("object")?;
        let receiver_analysis = self.resolve_receiver_node_report(receiver, budget);
        let receiver_identity = if matches!(
            &receiver_analysis.outcome,
            ReceiverAnalysisOutcome::Precise(values) if values.len() == 1
        ) && !receiver_analysis.candidates_truncated
        {
            ReceiverAnalysisReport::without_work(
                ReceiverAnalysisOutcome::Precise(vec![ReceiverIdentityProof::ExactValueAnalysis]),
                budget,
            )
        } else {
            self.immutable_identifier_binding_proof(receiver, budget)
        };
        Some(ReceiverMemberTargetReport {
            receiver_range: node_range(receiver),
            member_range: node_range(member),
            member_name: member_name.clone(),
            receiver_analysis,
            receiver_identity,
            analysis: self.resolve_member_targets_report(
                receiver,
                &member_name,
                before_byte,
                budget,
            ),
        })
    }

    fn immutable_identifier_binding_proof(
        &self,
        receiver: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverIdentityProof> {
        let Some(name) = simple_identifier_text(receiver, self.source) else {
            return ReceiverAnalysisReport::without_work(ReceiverAnalysisOutcome::Unknown, budget);
        };
        let mut tracker = ReceiverAnalysisBudgetTracker::new(budget);
        for scope in lexical_scopes_for_node(receiver) {
            match self.immutable_identifier_binding_in_scope(
                scope,
                name,
                receiver.start_byte(),
                &mut tracker,
            ) {
                IdentifierBindingProofSearch::NoBinding => {}
                IdentifierBindingProofSearch::Immutable(declaration_range) => {
                    return tracker.report(ReceiverAnalysisOutcome::Precise(vec![
                        ReceiverIdentityProof::ImmutableBinding {
                            file: self.file.clone(),
                            declaration_range,
                        },
                    ]));
                }
                IdentifierBindingProofSearch::NotImmutable => {
                    return tracker.report(ReceiverAnalysisOutcome::Unknown);
                }
                IdentifierBindingProofSearch::ExceededBudget => {
                    return tracker.report(ReceiverAnalysisOutcome::ExceededBudget {
                        limit: "max_scope_nodes",
                    });
                }
            }
        }
        tracker.report(ReceiverAnalysisOutcome::Unknown)
    }

    fn immutable_identifier_binding_in_scope(
        &self,
        scope: Node<'tree>,
        receiver: &str,
        before_byte: usize,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> IdentifierBindingProofSearch {
        let mut proof = IdentifierBindingProofSearch::NoBinding;
        let mut stack = vec![scope];
        while let Some(node) = stack.pop() {
            if tracker.record_scope_node().is_err() {
                return IdentifierBindingProofSearch::ExceededBudget;
            }
            if node.id() != scope.id() && is_scope_boundary(node.kind()) {
                continue;
            }

            if binding_node_shadows_receiver(node, self.source, receiver) {
                return IdentifierBindingProofSearch::NotImmutable;
            }
            if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                if node.start_byte() >= before_byte || !variable_declarator_is_const(node) {
                    return IdentifierBindingProofSearch::NotImmutable;
                }
                if !matches!(proof, IdentifierBindingProofSearch::NoBinding) {
                    return IdentifierBindingProofSearch::NotImmutable;
                }
                proof = IdentifierBindingProofSearch::Immutable(node_range(node));
            } else if node.start_byte() < before_byte
                && node.kind() == "assignment_expression"
                && let Some(left) = node.child_by_field_name("left")
                && matches!(left.kind(), "identifier" | "type_identifier")
                && node_text_matches(left, self.source, receiver)
            {
                return IdentifierBindingProofSearch::NotImmutable;
            }

            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        proof
    }

    /// The declarations that own `member` on ONE ELEMENT of `iterable`.
    ///
    /// `const [{ texture: frameTexture }] = frames` reads `texture` at the
    /// element type of `frames`, not at `frames` itself, so the element step
    /// happens before the member lookup that
    /// [`Self::resolve_member_targets`] performs for a whole value (#2039).
    pub fn resolve_iterable_element_member_targets(
        &self,
        iterable: Node<'tree>,
        member: &str,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<CodeUnit> {
        let ReceiverAnalysisOutcome::Precise(values) =
            self.resolve_iterable_element(iterable, budget)
        else {
            return Vec::new();
        };
        let mut targets = values
            .iter()
            .flat_map(|value| self.member_targets_for_value(value, member))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        targets
    }

    pub fn resolve_contextual_object_literal_key_targets(
        &self,
        key: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<CodeUnit> {
        if self.language != Language::TypeScript {
            return Vec::new();
        }
        let Some((property, object, member)) = object_literal_property_at_key(key, self.source)
        else {
            return Vec::new();
        };
        if !(property.start_byte() <= key.start_byte() && key.end_byte() <= property.end_byte()) {
            return Vec::new();
        }
        let owners = self.contextual_object_literal_receiver_values(object, budget);
        let mut targets = owners
            .iter()
            .flat_map(|value| self.member_targets_for_value(value, &member))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        targets
    }

    /// Resolves a JSX attribute name through the element's component declaration to
    /// the exact field on its props type. `None` means `node` is not an attribute
    /// name; `Some([])` is a recognized attribute whose owner cannot be proven.
    pub fn resolve_jsx_attribute_targets(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Option<Vec<CodeUnit>> {
        let (attribute_name, element_name) = jsx_attribute_site(node)?;
        if self.language != Language::TypeScript {
            return Some(Vec::new());
        }
        let attribute = slice(attribute_name, self.source);
        // A lower-case tag names an intrinsic element: the host environment
        // declares `div`'s attributes, not this workspace.
        let Some(component) = simple_identifier_text(element_name, self.source)
            .filter(|name| name.starts_with(|ch: char| ch.is_ascii_uppercase()))
        else {
            return Some(Vec::new());
        };

        let mut targets = self
            .jsx_component_props_owners(element_name, component)
            .iter()
            .flat_map(|owner| self.member_targets(owner, attribute))
            .collect::<Vec<_>>();
        sort_units(&mut targets);
        targets.dedup();
        targets.truncate(budget.max_targets.saturating_add(1));
        Some(targets)
    }

    /// The props owners of the component `name` names at `site`.
    ///
    /// A binding visible from the site *is* the component, so an import
    /// spelled the same way is shadowed by it and must not answer. Two visible
    /// bindings mean the name identifies no single declaration, and the site
    /// stays unresolved rather than merging both props types (#2041).
    ///
    /// The answer depends only on the name and the scope that asks, so it is
    /// memoized on that pair: one element usually carries several attributes,
    /// and each of them would otherwise repeat the scope walk and the module
    /// reads behind it.
    fn jsx_component_props_owners(&self, site: Node<'tree>, name: &str) -> Vec<CodeUnit> {
        let scope = enclosing_scope_id(site);
        if let Some(cached) = self
            .jsx_component_owner_cache
            .borrow()
            .get(&(scope, name.to_string()))
        {
            return cached.clone();
        }
        let owners = self.resolve_jsx_component_props_owners(site, name);
        self.jsx_component_owner_cache
            .borrow_mut()
            .insert((scope, name.to_string()), owners.clone());
        owners
    }

    fn resolve_jsx_component_props_owners(&self, site: Node<'tree>, name: &str) -> Vec<CodeUnit> {
        let bindings = visible_component_bindings(site, name, self.source);
        if bindings.len() > 1 {
            return Vec::new();
        }
        if let Some(binding) = bindings.first() {
            return jsx_binding_props_source(*binding, self.source)
                .map(|props| {
                    self.jsx_props_source_owners(
                        props,
                        self.file,
                        self.source,
                        &self.imports,
                        &self.aliases,
                        MAX_JSX_COMPONENT_HOPS,
                    )
                })
                .unwrap_or_default();
        }
        // Nothing in this file binds the name, so it is imported. Two direct
        // imports of one name leave the component unproven.
        if self.imports.has_competing_direct_imports(name) {
            return Vec::new();
        }
        let mut owners = self
            .jsx_component_candidates(name)
            .iter()
            .flat_map(|component| self.jsx_component_prop_owners(component))
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        owners
    }

    /// Resolves one binding's props evidence to the declarations that own the
    /// element's attributes. `hops` bounds the module and default-export steps
    /// the walk may still take, so the mutual recursion with
    /// [`Self::module_default_component_props_owners`] is depth-bounded.
    fn jsx_props_source_owners(
        &self,
        props: JsxPropsSource<'_>,
        file: &ProjectFile,
        source: &str,
        imports: &JsTsImportBinder,
        aliases: &AliasResolver,
        hops: usize,
    ) -> Vec<CodeUnit> {
        match props {
            JsxPropsSource::Type(type_node) => {
                self.type_node_property_owners(type_node, file, source, imports, aliases)
            }
            JsxPropsSource::ComponentTypeName(name) => {
                self.component_type_props_owners(&name, file, source, imports, aliases)
            }
            JsxPropsSource::Module(specifier) => {
                self.module_specifier_component_props_owners(file, &specifier, aliases, hops)
            }
            JsxPropsSource::TypeMember {
                owner_type,
                members,
            } => self.type_member_component_props_owners(
                owner_type, &members, file, source, imports, aliases,
            ),
        }
    }

    fn type_node_property_owners(
        &self,
        type_node: Node<'_>,
        file: &ProjectFile,
        source: &str,
        imports: &JsTsImportBinder,
        aliases: &AliasResolver,
    ) -> Vec<CodeUnit> {
        ts_type_node_property_owners(
            self.host,
            self.support,
            file,
            source,
            imports,
            aliases,
            type_node,
            0,
        )
    }

    fn source_type_property_owners(
        &self,
        type_id: JsTsSourceTypeId,
        file: &ProjectFile,
        facts: &JsTsFileSourceFacts,
    ) -> Vec<CodeUnit> {
        ts_source_type_property_owners(self.host, self.support, file, facts, type_id, 0)
    }

    fn canonical_props_source_owners(
        &self,
        props: &JsTsComponentPropsFact,
        file: &ProjectFile,
        facts: &JsTsFileSourceFacts,
        aliases: &AliasResolver,
        hops: usize,
    ) -> Vec<CodeUnit> {
        match props {
            JsTsComponentPropsFact::Type(id) => self.source_type_property_owners(*id, file, facts),
            JsTsComponentPropsFact::Named(name) => {
                let imports = JsTsImportBinder::from_source_facts(
                    &facts.facts,
                    &facts.imports,
                    &facts.source,
                );
                self.component_type_props_owners(name, file, "", &imports, aliases)
            }
            JsTsComponentPropsFact::Module(import) => {
                if hops == 0 {
                    return Vec::new();
                }
                let Some(path) = facts.imports[import.index()].path.as_ref() else {
                    return Vec::new();
                };
                let [specifier] = path.segments.as_slice() else {
                    return Vec::new();
                };
                self.module_specifier_component_props_owners(file, specifier, aliases, hops)
            }
            JsTsComponentPropsFact::TypeMember {
                owner_type,
                members,
            } => self.component_members_prop_owners(
                self.source_type_property_owners(*owner_type, file, facts),
                members,
            ),
        }
    }

    fn module_specifier_component_props_owners(
        &self,
        file: &ProjectFile,
        specifier: &str,
        aliases: &AliasResolver,
        hops: usize,
    ) -> Vec<CodeUnit> {
        if hops == 0 {
            return Vec::new();
        }
        resolve_js_ts_module_specifier(file, specifier, Language::TypeScript, Some(aliases))
            .iter()
            .flat_map(|module| {
                self.module_default_component_props_owners(module, aliases, hops - 1)
            })
            .collect()
    }

    /// The props a component *type* declares: `type DevtoolsComponentType =
    /// Component<QueryDevtoolsProps> & {...}` makes `QueryDevtoolsProps` the
    /// props of every variable annotated with it.
    fn component_type_props_owners(
        &self,
        name: &str,
        file: &ProjectFile,
        source: &str,
        imports: &JsTsImportBinder,
        aliases: &AliasResolver,
    ) -> Vec<CodeUnit> {
        let mut owners = Vec::new();
        for unit in jsts_identifier_candidates(
            self.host,
            self.support,
            Language::TypeScript,
            file,
            source,
            imports,
            aliases,
            name,
            false,
        ) {
            let Some(facts) = self.host.source_facts(unit.source()) else {
                continue;
            };
            for declaration in facts.facts.declarations.iter().filter(|declaration| {
                facts
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.contains(&unit))
            }) {
                let Some(argument) = declaration
                    .alias_type
                    .and_then(|id| source_component_wrapper_argument(&facts, id))
                else {
                    continue;
                };
                owners.extend(self.source_type_property_owners(argument, unit.source(), &facts));
            }
        }
        owners
    }

    /// The props of the component a module default-exports, which is what a
    /// `lazy(() => import("./panel"))` binding renders.
    fn module_default_component_props_owners(
        &self,
        file: &ProjectFile,
        aliases: &AliasResolver,
        hops: usize,
    ) -> Vec<CodeUnit> {
        let Some(facts) = self.host.source_facts(file) else {
            return Vec::new();
        };
        let Some(export) =
            facts.facts.exports.iter().find(|export| {
                export.is_esm && matches!(export.kind, JsTsExportKind::Default { .. })
            })
        else {
            return Vec::new();
        };
        let JsTsExportKind::Default { local_name } = &export.kind else {
            unreachable!()
        };
        let inline_declaration = facts.facts.declarations.iter().any(|declaration| {
            facts.source.declaration(declaration.declaration).occurrence == export.occurrence
        });
        let mut declarations = facts.facts.declarations.iter().filter(|declaration| {
            if inline_declaration {
                return facts.source.declaration(declaration.declaration).occurrence
                    == export.occurrence;
            }
            if let Some(name) = local_name {
                facts
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.iter().any(|unit| unit.identifier() == name))
            } else {
                facts.source.declaration(declaration.declaration).occurrence == export.occurrence
            }
        });
        let Some(declaration) = declarations.next() else {
            return Vec::new();
        };
        if declarations.next().is_some() {
            return Vec::new();
        }
        declaration
            .component_props
            .as_ref()
            .map(|props| self.canonical_props_source_owners(props, file, &facts, aliases, hops))
            .unwrap_or_default()
    }

    /// The props of a component read out of a typed value: `const { Box } =
    /// components` renders the component the enclosing type declares at
    /// `components.Box`.
    ///
    /// `members` names the properties to follow, outermost first. The chain is
    /// read inside the declaring type's own syntax, so a member whose type is
    /// declared in a third file ends the walk instead of guessing.
    #[allow(clippy::too_many_arguments)]
    fn type_member_component_props_owners(
        &self,
        owner_type: Node<'_>,
        members: &[String],
        file: &ProjectFile,
        source: &str,
        imports: &JsTsImportBinder,
        aliases: &AliasResolver,
    ) -> Vec<CodeUnit> {
        self.component_members_prop_owners(
            self.type_node_property_owners(owner_type, file, source, imports, aliases),
            members,
        )
    }

    fn component_members_prop_owners(
        &self,
        roots: Vec<CodeUnit>,
        members: &[String],
    ) -> Vec<CodeUnit> {
        let mut owners = Vec::new();
        for root in roots {
            let Some(facts) = self.host.source_facts(root.source()) else {
                continue;
            };
            for declaration in facts.facts.declarations.iter().filter(|declaration| {
                facts
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.contains(&root))
            }) {
                let Some(argument) = declaration
                    .alias_type
                    .or(declaration.declared_type)
                    .and_then(|id| source_type_member_component_argument(&facts, id, members))
                else {
                    continue;
                };
                owners.extend(self.source_type_property_owners(argument, root.source(), &facts));
            }
        }
        owners
    }

    fn jsx_component_candidates(&self, name: &str) -> Vec<CodeUnit> {
        let mut candidates = resolve_js_ts_direct_import_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &self.imports,
            name,
            Some(&self.aliases),
            true,
        )
        .unwrap_or_else(|| {
            self.support
                .file_identifier(self.file, name)
                .into_iter()
                .filter(|unit| unit.source() == self.file)
                .collect()
        });
        candidates.retain(|unit| unit.is_function() || unit.is_field() || unit.is_class());
        sort_units(&mut candidates);
        candidates.dedup();
        candidates
    }

    fn jsx_component_prop_owners(&self, component: &CodeUnit) -> Vec<CodeUnit> {
        let cache_key = (component.source().clone(), component.fq_name());
        if let Some(cached) = self.jsx_props_owner_cache.borrow().get(&cache_key) {
            return cached.clone();
        }
        let Some(facts) = self.host.source_facts(component.source()) else {
            return Vec::new();
        };
        let aliases = self.host.alias_resolver();
        let mut owners = facts
            .facts
            .declarations
            .iter()
            .filter(|declaration| {
                facts
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.contains(component))
            })
            .filter_map(|declaration| declaration.component_props.as_ref())
            .flat_map(|props| {
                self.canonical_props_source_owners(
                    props,
                    component.source(),
                    &facts,
                    aliases,
                    MAX_JSX_COMPONENT_HOPS,
                )
            })
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        self.jsx_props_owner_cache
            .borrow_mut()
            .insert(cache_key, owners.clone());
        owners
    }

    fn resolve_expression(
        &self,
        expression: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if depth > MAX_JSTS_RECEIVER_RECURSION {
            return ReceiverAnalysisOutcome::ExceededBudget {
                limit: "receiver_recursion",
            };
        }
        match expression.kind() {
            "new_expression" => self.resolve_new_expression(expression, budget),
            "object" if self.language == Language::JavaScript => {
                self.resolve_object_expression(expression, budget)
            }
            "object" if self.language == Language::TypeScript => {
                self.resolve_typescript_object_spreads(expression, depth + 1, budget, tracker)
            }
            "this" => self.resolve_this_expression(expression, budget),
            "call_expression" => self.summarize_call_node(
                expression,
                expression.start_byte(),
                depth,
                budget,
                tracker,
            ),
            "identifier" | "type_identifier" => {
                let name = slice(expression, self.source);
                if name.is_empty() {
                    ReceiverAnalysisOutcome::Unknown
                } else {
                    self.resolve_identifier_binding(expression, name, depth, budget, tracker)
                }
            }
            "conditional_expression" | "ternary_expression" => {
                let mut outcomes = Vec::new();
                for field in ["consequence", "alternative"] {
                    if let Some(branch) = expression.child_by_field_name(field) {
                        outcomes.push(self.resolve_expression(branch, depth + 1, budget, tracker));
                    }
                }
                ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
            }
            "parenthesized_expression" | "await_expression" => expression
                .named_child(0)
                .map(|child| self.resolve_expression(child, depth + 1, budget, tracker))
                .unwrap_or(ReceiverAnalysisOutcome::Unknown),
            _ => ReceiverAnalysisOutcome::Unknown,
        }
    }

    fn resolve_new_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(constructor) = expression.child_by_field_name("constructor") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name) = simple_identifier_text(constructor, self.source) else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_constructor_receiver",
            };
        };
        let values = self
            .class_units_named(name, expression)
            .into_iter()
            .map(|ty| ReceiverValue::AllocationSite {
                ty,
                file: self.file.clone(),
                range: node_range(expression),
            })
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_this_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(class_node) = enclosing_class_scope(expression) else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name_node) = class_node.child_by_field_name("name") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(name) = simple_identifier_text(name_node, self.source) else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let values = self
            .class_units_named(name, expression)
            .into_iter()
            .map(ReceiverValue::CurrentReceiver)
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_object_expression(
        &self,
        expression: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(declarator) = expression
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator")
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        if declarator
            .child_by_field_name("value")
            .is_none_or(|value| value.id() != expression.id())
        {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let Some(name) = declarator
            .child_by_field_name("name")
            .and_then(|name| simple_identifier_text(name, self.source))
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let values = self
            .support
            .file_identifier(self.file, name)
            .into_iter()
            .filter(|unit| unit.source() == self.file && unit.is_field())
            .map(ReceiverValue::ModuleOrExportObject)
            .collect::<Vec<_>>();
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(values, budget)
    }

    fn resolve_typescript_object_spreads(
        &self,
        expression: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let mut outcomes = Vec::new();
        let mut cursor = expression.walk();
        for child in expression.named_children(&mut cursor) {
            if child.kind() != "spread_element" {
                continue;
            }
            if let Some(value) = child.named_child(0) {
                outcomes.push(self.resolve_expression(value, depth + 1, budget, tracker));
            }
        }
        if outcomes.is_empty() {
            ReceiverAnalysisOutcome::Unknown
        } else {
            ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
        }
    }

    fn resolve_identifier_binding(
        &self,
        receiver_node: Node<'tree>,
        receiver: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let bindings = self
            .imports
            .lexical_bindings()
            .expect("receiver provider has lexical scopes");
        let function = enclosing_function_scope(receiver_node).map(|node| node.id());
        for byte in bindings.binding_write_sites_at(receiver, receiver_node.start_byte()) {
            if let Err(limit) = tracker.record_scope_node() {
                return limit.exceeded();
            }
            let write = self
                .root
                .named_descendant_for_byte_range(byte, byte + 1)
                .expect("a lexical write site names a source node");
            if enclosing_function_scope(write).map(|node| node.id()) != function {
                // Source ordering across callables is not execution ordering.
                // A captured write can run before this read even when its
                // declaration appears later; a type annotation cannot prove
                // one runtime owner in that case.
                return ReceiverAnalysisOutcome::Ambiguous(Vec::new());
            }
        }
        let before_byte = receiver_node.start_byte();
        let mut current = receiver_node;
        loop {
            if is_scope_boundary(current.kind())
                && let Some(outcome) = self.latest_identifier_binding_in_scope(
                    current,
                    receiver,
                    before_byte,
                    depth,
                    budget,
                    tracker,
                )
            {
                return outcome;
            }
            let Some(parent) = current.parent() else {
                break;
            };
            current = parent;
        }
        let class = self.resolve_static_object_expression(receiver_node, before_byte, budget);
        if !matches!(class, ReceiverAnalysisOutcome::Unknown) {
            return class;
        }
        self.imported_module_receiver_outcome(receiver, budget)
            .unwrap_or(ReceiverAnalysisOutcome::Unknown)
    }

    /// A uniquely bound package import is already a complete receiver identity;
    /// it does not need value-flow summary expansion to prove what module object
    /// the identifier denotes. Local bindings and assignments are handled by
    /// the lexical walk above and therefore take precedence over this fallback.
    fn imported_module_receiver_outcome(
        &self,
        receiver: &str,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        if self.imports.has_competing_static_imports(receiver)
            || self.imports.was_truncated(receiver)
        {
            return Some(ReceiverAnalysisOutcome::Ambiguous(Vec::new()));
        }
        let binding = self.imports.binding(receiver)?;
        let imported = js_ts_module_identity(&binding.module_specifier)?;
        let identity = match binding.kind {
            ImportKind::Default | ImportKind::Namespace | ImportKind::CommonJsRequire => {
                imported.specifier.to_owned()
            }
            ImportKind::Named => receiver.to_owned(),
            ImportKind::Glob => return None,
        };
        let module = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Module,
            "",
            identity,
            None,
            true,
        );
        Some(ReceiverAnalysisOutcome::single_precise_or_ambiguous(
            vec![ReceiverValue::ModuleOrExportObject(module)],
            budget,
        ))
    }

    fn latest_iterable_element_binding_in_scope(
        &self,
        scope: Node<'tree>,
        receiver: &str,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let mut latest = None;
        let mut stack = vec![scope];
        while let Some(node) = stack.pop() {
            if let Err(limit) = tracker.record_scope_node() {
                return Some(limit.exceeded());
            }
            if node.start_byte() >= before_byte {
                continue;
            }
            if node.id() != scope.id() && is_scope_boundary(node.kind()) {
                continue;
            }
            if matches!(node.kind(), "required_parameter" | "optional_parameter")
                && node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    .is_some_and(|name| node_text_matches(name, self.source, receiver))
                && let Some(type_node) = node.child_by_field_name("type")
            {
                latest = Some(self.iterable_element_type_outcome(type_node, budget));
            } else if binding_node_shadows_receiver(node, self.source, receiver) {
                latest = Some(ReceiverAnalysisOutcome::Unknown);
            } else if node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                latest = Some(
                    node.child_by_field_name("type")
                        .map(|type_node| self.iterable_element_type_outcome(type_node, budget))
                        .unwrap_or(ReceiverAnalysisOutcome::Unknown),
                );
            }

            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        latest
    }

    fn latest_identifier_binding_in_scope(
        &self,
        scope: Node<'tree>,
        receiver: &str,
        before_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let mut latest = None;
        let record = |latest: &mut Option<ReceiverAnalysisOutcome<ReceiverValue>>,
                      outcome: ReceiverAnalysisOutcome<ReceiverValue>| {
            // This source-order fold is not a CFG reachability proof. Once a
            // visible binding or write has unknown, ambiguous, unsupported, or
            // over-budget value evidence, a later precise write cannot erase
            // that uncertainty and manufacture an exact receiver (#2495).
            if !matches!(
                latest.as_ref(),
                Some(
                    ReceiverAnalysisOutcome::Unknown
                        | ReceiverAnalysisOutcome::Ambiguous(_)
                        | ReceiverAnalysisOutcome::Unsupported { .. }
                        | ReceiverAnalysisOutcome::ExceededBudget { .. }
                )
            ) {
                *latest = Some(outcome);
            }
        };
        // Each entry carries whether the node's nearest enclosing scope
        // boundary is `scope`, the answer `declaration_scope_id` gives.
        // Climbing `Node::parent` per node made this walk quadratic, because
        // tree-sitter finds a parent by descending from the root (#7724).
        let mut stack = vec![(scope, false)];
        while let Some((node, same_scope)) = stack.pop() {
            if let Err(limit) = tracker.record_scope_node() {
                return Some(limit.exceeded());
            }
            if node.start_byte() >= before_byte {
                continue;
            }
            if node.id() != scope.id() && is_declaration_boundary(node.kind()) {
                continue;
            }
            if same_scope
                && self.language == Language::TypeScript
                && matches!(node.kind(), "required_parameter" | "optional_parameter")
                && node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    .is_some_and(|name| node_text_matches(name, self.source, receiver))
                && let Some(type_node) = node.child_by_field_name("type")
            {
                record(
                    &mut latest,
                    self.type_annotation_receiver_outcome(type_node, budget),
                );
            } else if same_scope && binding_node_shadows_receiver(node, self.source, receiver) {
                record(&mut latest, ReceiverAnalysisOutcome::Unknown);
            } else if same_scope
                && node.kind() == "variable_declarator"
                && let Some(name) = node.child_by_field_name("name")
                && node_text_matches(name, self.source, receiver)
            {
                record(
                    &mut latest,
                    self.resolve_variable_declarator_binding(node, depth, budget, tracker),
                );
            } else if matches!(
                node.kind(),
                "assignment_expression" | "augmented_assignment_expression"
            ) && let Some(left) = node.child_by_field_name("left")
                && matches!(left.kind(), "identifier" | "type_identifier")
                && node_text_matches(left, self.source, receiver)
            {
                // A block-local declaration shadows the outer binding even
                // before its initializer (the lexical binding's TDZ).
                if lexical_scopes_for_node(node)
                    .into_iter()
                    .take_while(|s| s.id() != scope.id())
                    .any(|block| {
                        !component_bindings_in_scope(block, receiver, self.source).is_empty()
                    })
                {
                    continue;
                }
                if assignment_has_nonlinear_control_ancestor(node, scope, self.source)
                    || node.kind() == "augmented_assignment_expression"
                        && node.child_by_field_name("operator").is_some_and(|op| {
                            matches!(slice(op, self.source), "&&=" | "||=" | "??=")
                        })
                {
                    record(&mut latest, ReceiverAnalysisOutcome::Ambiguous(Vec::new()));
                } else if node.kind() == "augmented_assignment_expression" {
                    record(&mut latest, ReceiverAnalysisOutcome::Unknown);
                } else {
                    record(
                        &mut latest,
                        node.child_by_field_name("right")
                            .map(|right| self.resolve_expression(right, depth + 1, budget, tracker))
                            .unwrap_or(ReceiverAnalysisOutcome::Unknown),
                    );
                }
            }

            let children_same_scope = if is_scope_boundary(node.kind()) {
                node.id() == scope.id()
            } else {
                same_scope
            };
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push((child, children_same_scope));
                }
            }
        }
        latest
    }

    fn resolve_variable_declarator_binding(
        &self,
        declarator: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let mut initializer = None;
        if let (Some(name), Some(value)) = (
            declarator
                .child_by_field_name("name")
                .and_then(|name| simple_identifier_text(name, self.source)),
            declarator.child_by_field_name("value"),
        ) && require_call_module_specifier(value, self.source).is_some()
            && let Some(outcome) = self.imported_module_receiver_outcome(name, budget)
        {
            initializer = Some(outcome);
        }
        let initializer = initializer.or_else(|| {
            declarator
                .child_by_field_name("value")
                .map(|value| self.resolve_expression(value, depth + 1, budget, tracker))
        });
        if let Some(initialized) = initializer {
            return initialized;
        }
        if self.language == Language::TypeScript
            && let Some(type_node) = declarator.child_by_field_name("type")
        {
            return self.type_annotation_receiver_outcome(type_node, budget);
        }
        ReceiverAnalysisOutcome::Unknown
    }

    fn type_annotation_receiver_outcome(
        &self,
        type_node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        source_owner_receiver_outcome(
            ts_resolve_type_node_to_property_owner_outcome(
                self.host,
                self.support,
                self.file,
                self.source,
                &self.imports,
                &self.aliases,
                type_node,
                0,
                budget,
            ),
            budget,
        )
    }

    fn iterable_element_type_outcome(
        &self,
        type_node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        iterable_element_type(type_node, self.source)
            .map(|element_type| self.type_annotation_receiver_outcome(element_type, budget))
            .unwrap_or(ReceiverAnalysisOutcome::Unknown)
    }

    fn contextual_object_literal_receiver_values(
        &self,
        object: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> Vec<ReceiverValue> {
        if let Some(variable) = object
            .parent()
            .filter(|parent| parent.kind() == "variable_declarator")
            && variable
                .child_by_field_name("value")
                .is_some_and(|value| value.id() == object.id())
            && let Some(type_node) = variable.child_by_field_name("type")
        {
            return self
                .type_annotation_receiver_outcome(type_node, budget)
                .values()
                .map(|values| values.to_vec())
                .unwrap_or_default();
        }

        let Some(return_statement) = object
            .parent()
            .filter(|parent| parent.kind() == "return_statement")
        else {
            return Vec::new();
        };
        let mut cursor = return_statement.walk();
        if return_statement
            .named_children(&mut cursor)
            .next()
            .is_none_or(|value| value.id() != object.id())
        {
            return Vec::new();
        }
        let Some(function) = enclosing_function_scope(object) else {
            return Vec::new();
        };
        let Some(type_node) = function.child_by_field_name("return_type") else {
            return Vec::new();
        };
        self.type_annotation_receiver_outcome(type_node, budget)
            .values()
            .map(|values| values.to_vec())
            .unwrap_or_default()
    }

    fn resolve_static_object_expression(
        &self,
        expression: Node<'tree>,
        _call_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let Some(name) = simple_identifier_text(expression, self.source) else {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_static_factory_receiver",
            };
        };
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(
            self.class_units_named(name, expression)
                .into_iter()
                .map(ReceiverValue::ClassOrStaticObject),
            budget,
        )
    }

    fn summarize_call_node(
        &self,
        call: Node<'tree>,
        call_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if let Err(limit) = tracker.record_summary_expansion() {
            return limit.exceeded();
        }
        let function = call
            .child_by_field_name("function")
            .expect("call expressions have a function field");
        match function.kind() {
            "identifier" | "type_identifier" => {
                let name = slice(function, self.source);
                self.summarize_named_function(name, call, depth, budget, tracker)
            }
            "member_expression" | "subscript_expression" => {
                self.summarize_member_call(function, call_byte, depth, budget, tracker)
            }
            _ => ReceiverAnalysisOutcome::Unsupported {
                reason: "unsupported_call_callee",
            },
        }
    }

    fn summarize_named_function(
        &self,
        name: &str,
        site: Node<'tree>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if name.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let functions = self.visible_function_declarations_named(name, site);
        let mut outcomes: Vec<_> = functions
            .into_iter()
            .filter_map(|function| {
                let factory = self.function_unit_for_node(name, function)?;
                Some(wrap_factory_outcome(
                    self.summarize_function_body(function, &factory, depth + 1, budget, tracker),
                    &factory,
                ))
            })
            .collect();
        if let Some(imported) = self.summarize_imported_function(name, depth + 1, budget, tracker) {
            outcomes.push(imported);
        }
        if outcomes.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn summarize_imported_function(
        &self,
        name: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let functions = resolve_js_ts_direct_import_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &self.imports,
            name,
            Some(&self.aliases),
            true,
        )?;
        self.summarize_external_functions(functions, depth, budget, tracker)
    }

    fn summarize_external_functions(
        &self,
        functions: Vec<CodeUnit>,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let mut outcomes = Vec::new();
        for function in functions.into_iter().filter(CodeUnit::is_function) {
            let Ok(source) = function.source().read_to_string() else {
                continue;
            };
            let Some(tree) = parse_js_ts_tree(function.source(), &source, self.language) else {
                continue;
            };
            let Some(facts) = self.host.source_facts(function.source()) else {
                continue;
            };
            let imports = JsTsImportBinder::from_source_facts_with_lexical_bindings(
                &facts.facts,
                &facts.imports,
                &facts.source,
                tree.root_node(),
                crate::syntax::JsTsLexicalBindingIndex::build(tree.root_node(), &source),
            );
            let provider = JsTsReceiverFactProvider::new(
                self.host,
                self.support,
                self.language,
                function.source(),
                &source,
                tree.root_node(),
                imports,
            );
            let nodes = ts_nodes_for_code_unit(self.host, &function, tree.root_node());
            let implementation = crate::model::last_hoisted_function_implementation(&nodes);
            if nodes.len() > 1 && implementation.is_none() {
                // Redeclarations are not one binding snapshot. Equal declared
                // return types cannot turn their uncertainty into proof.
                outcomes.push(ReceiverAnalysisOutcome::Unknown);
            }
            for node in implementation
                .into_iter()
                .chain(nodes.into_iter().filter(|_| implementation.is_none()))
            {
                // The index holds the DECLARATION; `const f = () => ...` binds
                // its callable one level down, and the return type and returns
                // this summary reads both live on the callable.
                let callable = jsts_indexed_callable_node(node).unwrap_or(node);
                outcomes.push(wrap_factory_outcome(
                    provider.summarize_function_body(callable, &function, depth, budget, tracker),
                    &function,
                ));
            }
        }
        (!outcomes.is_empty())
            .then(|| ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget))
    }

    fn summarize_module_member_function(
        &self,
        object: Node<'tree>,
        member: &str,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        if self.language != Language::JavaScript {
            return None;
        }
        let module_specifier =
            require_call_module_specifier(object, self.source).or_else(|| {
                let binding_name = simple_identifier_text(object, self.source)?;
                let JsTsImportBindingResolution::Exact(binding) =
                    self.imports.binding_at(binding_name, object.start_byte())
                else {
                    return None;
                };
                let binding = &binding.binding;
                matches!(
                    binding.kind,
                    ImportKind::Namespace | ImportKind::CommonJsRequire
                )
                .then(|| binding.module_specifier.clone())
            })?;
        let functions = resolve_js_ts_module_binding_candidates(
            self.host,
            self.support,
            self.language,
            self.file,
            &module_specifier,
            member,
            Some(&self.aliases),
            true,
        );
        self.summarize_external_functions(functions, depth, budget, tracker)
    }

    fn summarize_member_call(
        &self,
        member_expression: Node<'tree>,
        call_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        if let Some(outcome) = self.summarize_imported_member_chain(
            member_expression,
            call_byte,
            depth,
            budget,
            tracker,
        ) {
            return outcome;
        }
        let Some(object) = member_expression.child_by_field_name("object") else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some((_, member)) = static_member_property(member_expression, self.source) else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        if member.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        if let Some(outcome) =
            self.summarize_module_member_function(object, &member, depth + 1, budget, tracker)
        {
            return outcome;
        }
        let class_values = self.resolve_static_object_expression(object, call_byte, budget);
        let ReceiverAnalysisOutcome::Precise(values) = class_values else {
            return class_values;
        };
        let mut methods = Vec::new();
        for value in values {
            for factory in self.member_targets_for_value(&value, &member) {
                methods.extend(
                    ts_nodes_for_code_unit(self.host, &factory, self.root)
                        .into_iter()
                        .map(|node| (node, factory.clone())),
                );
            }
        }
        if methods.is_empty() {
            return ReceiverAnalysisOutcome::Unknown;
        }
        let outcomes: Vec<_> = methods
            .into_iter()
            .map(|(method, factory)| {
                wrap_factory_outcome(
                    self.summarize_function_body(method, &factory, depth + 1, budget, tracker),
                    &factory,
                )
            })
            .collect();
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn summarize_imported_member_chain(
        &self,
        member_expression: Node<'tree>,
        call_byte: usize,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> Option<ReceiverAnalysisOutcome<ReceiverValue>> {
        let JsTsImportedMemberChainResolution::Exact(chain) =
            resolve_import_member_chain(member_expression, self.source)
        else {
            return None;
        };
        let JsTsImportBindingResolution::Exact(binding) = self
            .imports
            .binding_at(chain.root_name(self.source), call_byte)
        else {
            return None;
        };
        let resolved = resolve_js_ts_imported_member_chain(
            self.host,
            self.support,
            self.language,
            self.file,
            &binding.binding,
            &chain,
            Some(&self.aliases),
            true,
            budget,
        );
        match resolved {
            ReceiverAnalysisOutcome::Precise(endpoints) => {
                let functions = endpoints
                    .into_iter()
                    .map(|endpoint| endpoint.declaration)
                    .filter(|unit| unit.is_function())
                    .collect::<Vec<_>>();
                (!functions.is_empty())
                    .then(|| {
                        self.summarize_external_functions(functions, depth + 1, budget, tracker)
                    })
                    .flatten()
            }
            ReceiverAnalysisOutcome::Ambiguous(endpoints) => {
                Some(ReceiverAnalysisOutcome::Ambiguous(
                    endpoints
                        .into_iter()
                        .map(|endpoint| ReceiverValue::ClassOrStaticObject(endpoint.declaration))
                        .collect(),
                ))
            }
            ReceiverAnalysisOutcome::Unknown => Some(ReceiverAnalysisOutcome::Unknown),
            ReceiverAnalysisOutcome::Unsupported { reason } => {
                Some(ReceiverAnalysisOutcome::Unsupported { reason })
            }
            ReceiverAnalysisOutcome::ExceededBudget { limit } => {
                Some(ReceiverAnalysisOutcome::ExceededBudget { limit })
            }
        }
    }

    /// What a call of `callee` produces, read from `function`'s body.
    ///
    /// `callee` is the declaration the caller resolved the call to. It is the
    /// answer for one shape the body cannot supply: a return type written as an
    /// inline object type names no owner the index publishes under a type name,
    /// so the declaration walk publishes its members off the FUNCTION instead
    /// (#2159), and the function is therefore the owner a read through the call
    /// resolves against.
    fn summarize_function_body(
        &self,
        function: Node<'tree>,
        callee: &CodeUnit,
        depth: usize,
        budget: ReceiverAnalysisBudget,
        tracker: &mut ReceiverAnalysisBudgetTracker,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let function = jsts_indexed_callable_node(function).unwrap_or(function);
        if depth > MAX_JSTS_RECEIVER_RECURSION {
            return ReceiverAnalysisOutcome::ExceededBudget {
                limit: "receiver_recursion",
            };
        }
        if self.language == Language::TypeScript
            && let Some(facts) = self.host.source_facts(callee.source())
        {
            for declaration in &facts.facts.declarations {
                if !facts
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.contains(callee))
                {
                    continue;
                }
                let Some(type_id) = declaration.return_type else {
                    continue;
                };
                let outcome = ts_resolve_source_type_to_property_owner_outcome(
                    self.host,
                    self.support,
                    callee.source(),
                    &facts,
                    type_id,
                    0,
                    budget,
                );
                let outcome = source_owner_receiver_outcome(outcome, budget);
                if !matches!(outcome, ReceiverAnalysisOutcome::Unknown) {
                    return outcome;
                }
                let mut inner = type_id;
                while let JsTsTypeShape::Wrapped(child) = facts.facts.types[inner.index()].shape {
                    inner = child;
                }
                if matches!(
                    facts.facts.types[inner.index()].shape,
                    JsTsTypeShape::Object(_)
                ) {
                    return ReceiverAnalysisOutcome::Precise(vec![ReceiverValue::InstanceType(
                        callee.clone(),
                    )]);
                }
            }
        }
        let mut outcomes = Vec::new();
        let mut stack = vec![function];
        while let Some(node) = stack.pop() {
            if let Err(limit) = tracker.record_scope_node() {
                return limit.exceeded();
            }
            if node.id() != function.id() && is_summary_boundary(node.kind()) {
                continue;
            }
            if node.kind() == "return_statement" {
                let mut cursor = node.walk();
                if let Some(value) = node.named_children(&mut cursor).next() {
                    outcomes.push(self.resolve_expression(value, depth + 1, budget, tracker));
                } else {
                    outcomes.push(ReceiverAnalysisOutcome::Unknown);
                }
                continue;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        ReceiverAnalysisOutcome::merge_branch_outcomes(outcomes, budget)
    }

    fn class_units_named(&self, name: &str, site: Node<'tree>) -> Vec<CodeUnit> {
        let bindings = self
            .imports
            .lexical_bindings()
            .expect("receiver provider has lexical scopes");
        let ranges = bindings.binding_identifier_ranges_at(name, site.start_byte());
        let visible: Vec<_> = self
            .visible_class_declaration_nodes(name, site)
            .into_iter()
            .filter(|class| {
                class.child_by_field_name("name").is_some_and(|binder| {
                    ranges.iter().any(|range| {
                        range.start_byte == binder.start_byte()
                            && range.end_byte == binder.end_byte()
                    })
                })
            })
            .collect();
        let Some(scope) = lexical_scopes_for_node(site).into_iter().find(|scope| {
            visible
                .iter()
                .any(|node| declaration_scope_id(*node) == Some(scope.id()))
        }) else {
            return Vec::new();
        };
        let visible: Vec<_> = visible
            .into_iter()
            .filter(|node| declaration_scope_id(*node) == Some(scope.id()))
            .collect();
        let mut units = self
            .host
            .declarations(self.file)
            .into_iter()
            .filter(|unit| {
                unit.is_class()
                    && self.host.ranges(unit).iter().any(|range| {
                        visible.iter().any(|node| {
                            range.start_byte <= node.start_byte()
                                && node.end_byte() <= range.end_byte
                        })
                    })
                    && unit.identifier() == name
                    && brokk_bifrost_core::analyzer::common::language_for_file(unit.source())
                        == self.language
            })
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn member_targets(&self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let direct = self.member_targets_on_owner(owner, member);
        if !direct.is_empty() {
            return direct;
        }

        let mut seen = HashSet::default();
        seen.insert(owner.clone());
        let mut level = vec![owner.clone()];
        let mut visited = 0usize;
        while !level.is_empty() && visited < MAX_JSTS_MEMBER_FRONTIER {
            let mut next_level = Vec::new();
            let mut inherited = Vec::new();
            for current in level {
                for ancestor in compute_direct_ancestors(self.host, &current) {
                    if !seen.insert(ancestor.clone()) {
                        continue;
                    }
                    if visited == MAX_JSTS_MEMBER_FRONTIER {
                        break;
                    }
                    visited += 1;
                    let found = self.member_targets_on_owner(&ancestor, member);
                    if !found.is_empty() {
                        inherited.extend(found);
                    }
                    next_level.push(ancestor);
                }
            }
            if !inherited.is_empty() {
                sort_units(&mut inherited);
                inherited.dedup();
                return inherited;
            }
            level = next_level;
        }
        Vec::new()
    }

    fn member_targets_on_owner(&self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let fqn = format!("{}.{}", owner.fq_name(), member);
        let mut units = self
            .host
            .definitions(&fqn)
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| unit.is_function() || unit.is_field())
            .collect::<Vec<_>>();
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn member_targets_for_value(&self, receiver: &ReceiverValue, member: &str) -> Vec<CodeUnit> {
        let indexed_member = if matches!(receiver, ReceiverValue::ClassOrStaticObject(_)) {
            format!("{member}$static")
        } else {
            member.to_string()
        };
        self.member_targets(receiver.owner(), &indexed_member)
    }

    fn visible_function_declarations_named(
        &self,
        name: &str,
        site: Node<'tree>,
    ) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.syntax_index
            .function_declarations_by_name
            .get(name)
            .map(|functions| {
                functions
                    .iter()
                    .filter_map(|range| {
                        smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
                    })
                    .filter(|function| {
                        declaration_scope_id(*function)
                            .is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn function_unit_for_node(&self, name: &str, node: Node<'_>) -> Option<CodeUnit> {
        let target = IndexedNodeRange {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        };
        let syntax_ranges = self.syntax_index.function_declarations_by_name.get(name)?;
        self.support
            .file_identifier(self.file, name)
            .into_iter()
            .filter(|unit| unit.source() == self.file && unit.is_function())
            .filter_map(|unit| {
                let associated_syntax = self
                    .host
                    .ranges(&unit)
                    .into_iter()
                    .flat_map(|declaration_range| {
                        syntax_ranges
                            .iter()
                            .filter(move |syntax_range| {
                                declaration_range.start_byte < syntax_range.end_byte
                                    && syntax_range.start_byte < declaration_range.end_byte
                            })
                            .map(move |syntax_range| {
                                let boundary_distance = declaration_range
                                    .start_byte
                                    .abs_diff(syntax_range.start_byte)
                                    .saturating_add(
                                        declaration_range.end_byte.abs_diff(syntax_range.end_byte),
                                    );
                                let span_distance = declaration_range
                                    .end_byte
                                    .saturating_sub(declaration_range.start_byte)
                                    .abs_diff(
                                        syntax_range
                                            .end_byte
                                            .saturating_sub(syntax_range.start_byte),
                                    );
                                (boundary_distance, span_distance, *syntax_range)
                            })
                    })
                    .min_by_key(|(boundary_distance, span_distance, syntax_range)| {
                        (*boundary_distance, *span_distance, syntax_range.start_byte)
                    })?
                    .2;
                (associated_syntax == target).then_some(unit)
            })
            .min()
    }

    fn visible_class_declaration_nodes(&self, name: &str, site: Node<'tree>) -> Vec<Node<'tree>> {
        let visible_scopes = lexical_scope_ids_for_node(site);
        self.syntax_index
            .class_declarations_by_name
            .get(name)
            .map(|classes| {
                classes
                    .iter()
                    .filter_map(|range| {
                        smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
                    })
                    .filter(|class| {
                        declaration_scope_id(*class).is_some_and(|id| visible_scopes.contains(&id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn jsx_attribute_site(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let attribute = if node.kind() == "jsx_attribute" {
        node
    } else {
        node.parent()
            .filter(|parent| parent.kind() == "jsx_attribute")?
    };
    let attribute_name = attribute.named_child(0)?;
    if attribute_name.id() != node.id() && node.kind() != "jsx_attribute" {
        return None;
    }
    if attribute_name.kind() != "property_identifier" {
        return None;
    }
    let element = attribute.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "jsx_opening_element" | "jsx_self_closing_element"
        )
    })?;
    Some((attribute_name, element.child_by_field_name("name")?))
}

/// What a component binding proves about the props type its JSX attributes
/// name.
///
/// Every variant is evidence read off the binding's own syntax: a type
/// annotation, a dynamic import specifier, the name of a component type, or a
/// destructuring chain into a typed value. A binding that carries none of them
/// proves no owner, and its attributes stay unresolved (#2041).
pub(crate) enum JsxPropsSource<'tree> {
    /// The props type itself: a parameter's annotation, or the argument a
    /// component generic applies.
    Type(Node<'tree>),
    /// A component type name, whose own declaration applies the component
    /// generic (`let Devtools: DevtoolsComponentType`).
    ComponentTypeName(String),
    /// A dynamic `import(specifier)` inside a wrapper call
    /// (`lazy(() => import("./panel"))`): the module's default export is the
    /// component.
    Module(String),
    /// A component held in a property of a typed value (`const { Box } =
    /// components`). `members` names the properties to follow, outermost
    /// first.
    TypeMember {
        owner_type: Node<'tree>,
        members: Vec<String>,
    },
}

pub(crate) fn jsx_binding_props_source<'tree>(
    binding: Node<'tree>,
    source: &str,
) -> Option<JsxPropsSource<'tree>> {
    match binding.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "function_expression"
        | "arrow_function" => function_first_parameter_type(binding).map(JsxPropsSource::Type),
        "class_declaration" | "abstract_class_declaration" => {
            class_component_props_argument(binding, source).map(JsxPropsSource::Type)
        }
        "variable_declarator" => variable_binding_props_source(binding, source),
        "required_parameter" | "optional_parameter" => binding
            .child_by_field_name("type")
            .and_then(|annotation| component_type_props_source(annotation, source)),
        "shorthand_property_identifier_pattern" | "pair_pattern" => {
            destructured_binding_props_source(binding, source)
        }
        _ => None,
    }
}

fn variable_binding_props_source<'tree>(
    declarator: Node<'tree>,
    source: &str,
) -> Option<JsxPropsSource<'tree>> {
    let value = declarator.child_by_field_name("value");
    // `const Chip = ({ label }: ChipProps) => ...`: the value is the component.
    if let Some(props) = value
        .filter(|value| matches!(value.kind(), "function_expression" | "arrow_function"))
        .and_then(function_first_parameter_type)
    {
        return Some(JsxPropsSource::Type(props));
    }
    // `const Box: React.FC<IBox>`, `const Row: Component<RowProps>`.
    if let Some(props) = declarator
        .child_by_field_name("type")
        .and_then(|annotation| component_type_props_source(annotation, source))
    {
        return Some(props);
    }
    value
        .and_then(|value| wrapped_dynamic_import_specifier(value, source))
        .map(JsxPropsSource::Module)
}

/// The props evidence a *component-typed* annotation carries: either the
/// generic argument a component type applies, or the name of a type that
/// applies one itself.
fn component_type_props_source<'tree>(
    annotation: Node<'tree>,
    source: &str,
) -> Option<JsxPropsSource<'tree>> {
    if let Some(argument) = function_component_wrapper_argument(annotation, source) {
        return Some(JsxPropsSource::Type(argument));
    }
    let named = annotation
        .child_by_field_name("type")
        .or_else(|| annotation.named_child(0))
        .filter(|node| node.kind() == "type_identifier")?;
    Some(JsxPropsSource::ComponentTypeName(
        slice(named, source).to_string(),
    ))
}

/// The module a wrapper call defers to, as in `lazy(() => import("./panel"))`.
///
/// The wrapper itself is opaque -- `lazy`, `dynamic` and their re-exports are
/// all library functions this analyzer does not model -- but the dynamic
/// `import` inside its arguments names the module structurally.
fn wrapped_dynamic_import_specifier(value: Node<'_>, source: &str) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let mut stack = vec![value.child_by_field_name("arguments")?];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| function.kind() == "import")
        {
            return node
                .child_by_field_name("arguments")
                .and_then(|arguments| arguments.named_child(0))
                .filter(|argument| argument.kind() == "string")
                .and_then(|argument| argument.named_child(0))
                .map(|fragment| slice(fragment, source).to_string());
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

/// How deep a destructuring chain may be followed before the binding counts as
/// unproven.
const MAX_JSX_DESTRUCTURING_DEPTH: usize = 4;

/// The typed value a destructured component binding reads, and the property
/// chain that reaches the component inside it.
fn destructured_binding_props_source<'tree>(
    binding: Node<'tree>,
    source: &str,
) -> Option<JsxPropsSource<'tree>> {
    let mut members = Vec::new();
    let mut current = binding;
    for _ in 0..MAX_JSX_DESTRUCTURING_DEPTH {
        members.push(destructured_member_name(current, source)?);
        let pattern = current
            .parent()
            .filter(|parent| parent.kind() == "object_pattern")?;
        let owner = pattern.parent()?;
        match owner.kind() {
            // A nested pattern: the enclosing entry names the next property.
            "pair_pattern" => current = owner,
            "required_parameter" | "optional_parameter" => {
                let annotation = owner.child_by_field_name("type")?;
                members.reverse();
                return Some(JsxPropsSource::TypeMember {
                    owner_type: annotation,
                    members,
                });
            }
            "variable_declarator" => {
                if let Some(annotation) = owner.child_by_field_name("type") {
                    members.reverse();
                    return Some(JsxPropsSource::TypeMember {
                        owner_type: annotation,
                        members,
                    });
                }
                // `const { Box } = components`: continue at whatever binds
                // `components`, which carries the type this reads through.
                let value = owner.child_by_field_name("value")?;
                let name = simple_identifier_text(value, source)?;
                let bindings = visible_component_bindings(owner, name, source);
                let [next] = bindings.as_slice() else {
                    return None;
                };
                match next.kind() {
                    "shorthand_property_identifier_pattern" | "pair_pattern" => current = *next,
                    "variable_declarator" | "required_parameter" | "optional_parameter" => {
                        let annotation = next.child_by_field_name("type")?;
                        members.reverse();
                        return Some(JsxPropsSource::TypeMember {
                            owner_type: annotation,
                            members,
                        });
                    }
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    None
}

fn destructured_member_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "shorthand_property_identifier_pattern" => Some(slice(node, source).to_string()),
        "pair_pattern" => node
            .child_by_field_name("key")
            .map(|key| slice(key, source).to_string()),
        _ => None,
    }
}

/// The component generic a member chain reaches inside `declaration`.
///
/// The chain is followed through the declaration's own property signatures and
/// the inline object types nested in them; a member typed by a name declared
/// elsewhere ends the walk.
fn source_component_wrapper_argument(
    facts: &JsTsFileSourceFacts,
    root: JsTsSourceTypeId,
) -> Option<JsTsSourceTypeId> {
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        match &facts.facts.types[id.index()].shape {
            JsTsTypeShape::Generic { base, arguments } => {
                if let JsTsTypeShape::Named(path) = &facts.facts.types[base.index()].shape
                    && path.last().is_some_and(|name| {
                        matches!(
                            name.as_str(),
                            "FC" | "FunctionComponent"
                                | "ComponentType"
                                | "Component"
                                | "ParentComponent"
                                | "VoidComponent"
                                | "FlowComponent"
                        )
                    })
                {
                    return arguments.first().copied();
                }
            }
            JsTsTypeShape::Wrapped(child) => pending.push(*child),
            JsTsTypeShape::Union(children) | JsTsTypeShape::Intersection(children) => {
                pending.extend(children.iter().rev().copied());
            }
            _ => {}
        }
    }
    None
}

fn source_owner_receiver_outcome(
    outcome: ReceiverAnalysisOutcome<CodeUnit>,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<ReceiverValue> {
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) => ReceiverAnalysisOutcome::Precise(
            values
                .into_iter()
                .take(budget.max_targets)
                .map(ReceiverValue::InstanceType)
                .collect(),
        ),
        ReceiverAnalysisOutcome::Ambiguous(values) => ReceiverAnalysisOutcome::Ambiguous(
            values
                .into_iter()
                .take(budget.max_targets)
                .map(ReceiverValue::InstanceType)
                .collect(),
        ),
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

fn source_type_member_component_argument(
    facts: &JsTsFileSourceFacts,
    mut container: JsTsSourceTypeId,
    members: &[String],
) -> Option<JsTsSourceTypeId> {
    for (index, member) in members.iter().enumerate() {
        let JsTsTypeShape::Object(fields) = &facts.facts.types[container.index()].shape else {
            return None;
        };
        let (_, annotation) = fields.iter().find(|(name, _)| name == member)?;
        if index + 1 == members.len() {
            return source_component_wrapper_argument(facts, *annotation);
        }
        container = match &facts.facts.types[annotation.index()].shape {
            JsTsTypeShape::Wrapped(child) => *child,
            _ => return None,
        };
    }
    None
}

/// The scope a site resolves names in, which is the program when nothing
/// narrower encloses it.
fn enclosing_scope_id(site: Node<'_>) -> usize {
    let mut current = site;
    loop {
        if is_scope_boundary(current.kind()) {
            return current.id();
        }
        let Some(parent) = current.parent() else {
            return current.id();
        };
        current = parent;
    }
}

/// Every binding of `name` the site can see, from the nearest scope that binds
/// it at all.
///
/// Declaration order does not matter: a component declared below the JSX that
/// renders it is the same binding, so the scan reads the whole scope instead of
/// only the text before the site.
fn visible_component_bindings<'tree>(
    site: Node<'tree>,
    name: &str,
    source: &str,
) -> Vec<Node<'tree>> {
    let mut scope = Some(site);
    while let Some(current) = scope {
        if is_scope_boundary(current.kind()) {
            let bindings = component_bindings_in_scope(current, name, source);
            if !bindings.is_empty() {
                return bindings;
            }
        }
        scope = current.parent();
    }
    Vec::new()
}

fn component_bindings_in_scope<'tree>(
    scope: Node<'tree>,
    name: &str,
    source: &str,
) -> Vec<Node<'tree>> {
    let mut bindings = Vec::new();
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if let Some(binding) = binding_node_for_name(node, name, source) {
            bindings.push(binding);
            continue;
        }
        if node.id() != scope.id() && is_scope_boundary(node.kind()) {
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    bindings
}

/// The node that binds `name` at `node`, which is the declaration itself for a
/// plain binder and the pattern entry for a destructured one.
fn binding_node_for_name<'tree>(
    node: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    match node.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "class_declaration"
        | "abstract_class_declaration" => node
            .child_by_field_name("name")
            .filter(|declared| node_text_matches(*declared, source, name))
            .map(|_| node),
        "variable_declarator" | "required_parameter" | "optional_parameter" => {
            let pattern = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("pattern"))?;
            match pattern.kind() {
                "identifier" | "type_identifier" => {
                    node_text_matches(pattern, source, name).then_some(node)
                }
                "object_pattern" | "array_pattern" => {
                    destructured_pattern_entry(pattern, name, source)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn destructured_pattern_entry<'tree>(
    pattern: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![pattern];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "shorthand_property_identifier_pattern" if node_text_matches(node, source, name) => {
                return Some(node);
            }
            "pair_pattern"
                if node
                    .child_by_field_name("value")
                    .is_some_and(|value| node_text_matches(value, source, name)) =>
            {
                return Some(node);
            }
            _ => {}
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn function_first_parameter_type(function: Node<'_>) -> Option<Node<'_>> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .next()
        .and_then(|parameter| parameter.child_by_field_name("type"))
}

fn function_component_wrapper_argument<'tree>(
    type_annotation: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![type_annotation];
    while let Some(node) = stack.pop() {
        if node.kind() == "generic_type" {
            let Some(terminal) = node
                .child_by_field_name("name")
                .and_then(|name| type_reference_terminal(name, source))
            else {
                continue;
            };
            // React spells the props type as the argument of `FC`,
            // `FunctionComponent` or `ComponentType`; Solid spells the same
            // contract as `Component` and its arity variants.
            if matches!(
                terminal,
                "FC" | "FunctionComponent"
                    | "ComponentType"
                    | "Component"
                    | "ParentComponent"
                    | "VoidComponent"
                    | "FlowComponent"
            ) {
                return node
                    .child_by_field_name("type_arguments")
                    .and_then(|arguments| arguments.named_child(0));
            }
        }
        if matches!(
            node.kind(),
            "type_annotation" | "parenthesized_type" | "union_type" | "intersection_type"
        ) {
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
    }
    None
}

fn class_component_props_argument<'tree>(class: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut cursor = class.walk();
    let heritage = class
        .named_children(&mut cursor)
        .find(|child| child.kind() == "class_heritage")?;
    let mut cursor = heritage.walk();
    for extends in heritage
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "extends_clause")
    {
        let value = extends.child_by_field_name("value")?;
        let terminal = type_reference_terminal(value, source)?;
        if matches!(terminal, "Component" | "PureComponent") {
            return extends
                .child_by_field_name("type_arguments")
                .and_then(|arguments| arguments.named_child(0));
        }
    }
    None
}

fn type_reference_terminal<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        if let Some(name) = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("property"))
            && name.id() != node.id()
        {
            node = name;
            continue;
        }
        return match node.kind() {
            "identifier" | "type_identifier" | "property_identifier" => {
                let text = slice(node, source);
                (!text.is_empty()).then_some(text)
            }
            _ => None,
        };
    }
}

impl<'tree> ReceiverFacts<'tree> for JsTsReceiverFactProvider<'tree, '_> {
    fn member_expression_at_site(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        member_expression_at_site(node)
    }

    fn resolve_receiver(
        &self,
        node: Node<'tree>,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisReport<ReceiverValue> {
        self.resolve_receiver_node_report(node, budget)
    }

    fn resolve_member_targets_at_site(
        &self,
        site: Node<'tree>,
        expected_member: Option<&str>,
        before_byte: usize,
        budget: ReceiverAnalysisBudget,
    ) -> Option<ReceiverMemberTargetReport> {
        JsTsReceiverFactProvider::resolve_member_targets_at_site(
            self,
            site,
            expected_member,
            before_byte,
            budget,
        )
    }
}

impl ReceiverFactProvider for JsTsReceiverFactProvider<'_, '_> {
    fn resolve_receiver(
        &self,
        query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.resolve_receiver");
        let Some(range) = query.receiver_range else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(node) = smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let (outcome, _) = self.resolve_receiver_with_tracker(node, query.budget);
        outcome
    }

    fn summarize_call_result(
        &self,
        query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        let _scope = profiling::scope("jsts.receiver_analysis.summarize_call_result");
        let mut tracker = ReceiverAnalysisBudgetTracker::new(query.budget);
        let Some(range) = query.call_range else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        let Some(node) = smallest_named_node_covering(self.root, range.start_byte, range.end_byte)
        else {
            return ReceiverAnalysisOutcome::Unknown;
        };
        if node.kind() != "call_expression" {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "summary_query_not_call_expression",
            };
        }
        self.summarize_call_node(node, query.context.byte, 0, query.budget, &mut tracker)
    }
}

fn iterable_element_type<'tree>(type_node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut type_node = if type_node.kind() == "type_annotation" {
        type_node.named_child(0)?
    } else {
        type_node
    };
    loop {
        match type_node.kind() {
            "array_type" => return type_node.named_child(0),
            "generic_type" => {
                let name = type_node.child_by_field_name("name")?;
                if !matches!(
                    slice(name, source),
                    "Array"
                        | "ReadonlyArray"
                        | "Set"
                        | "ReadonlySet"
                        | "Iterable"
                        | "AsyncIterable"
                ) {
                    return None;
                }
                return type_node
                    .child_by_field_name("type_arguments")
                    .and_then(|arguments| arguments.named_child(0));
            }
            "parenthesized_type" | "readonly_type" => type_node = type_node.named_child(0)?,
            _ => return None,
        }
    }
}

fn lexical_scopes_for_node<'tree>(node: Node<'tree>) -> Vec<Node<'tree>> {
    let mut scopes = Vec::new();
    let mut current = node;
    loop {
        if is_scope_boundary(current.kind()) {
            scopes.push(current);
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    scopes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentifierBindingProofSearch {
    NoBinding,
    Immutable(Range),
    NotImmutable,
    ExceededBudget,
}

fn variable_declarator_is_const(declarator: Node<'_>) -> bool {
    let Some(declaration) = declarator.parent() else {
        return false;
    };
    if declaration.kind() != "lexical_declaration" {
        return false;
    }
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .any(|child| child.kind() == "const")
}

fn enclosing_class_scope<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    loop {
        if js_ts_is_class_scope_kind(node.kind()) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn object_literal_property_at_key<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>, String)> {
    crate::typescript::ts_object_literal_property_at_key(node, source)
}

fn lexical_scope_ids_for_node(node: Node<'_>) -> HashSet<usize> {
    lexical_scopes_for_node(node)
        .into_iter()
        .map(|scope| scope.id())
        .collect()
}

fn binding_node_shadows_receiver(node: Node<'_>, source: &str, receiver: &str) -> bool {
    match node.kind() {
        "formal_parameter" | "required_parameter" | "optional_parameter" | "rest_pattern"
        | "catch_clause" => node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("parameter"))
            .is_some_and(|pattern| binding_pattern_contains_name(pattern, source, receiver)),
        "variable_declarator" => node.child_by_field_name("name").is_some_and(|pattern| {
            !matches!(pattern.kind(), "identifier" | "type_identifier")
                && binding_pattern_contains_name(pattern, source, receiver)
        }),
        "identifier" | "type_identifier" => {
            node.parent()
                .is_some_and(|parent| matches!(parent.kind(), "formal_parameters" | "parameters"))
                && node_text_matches(node, source, receiver)
        }
        _ => false,
    }
}

fn binding_pattern_contains_name(node: Node<'_>, source: &str, receiver: &str) -> bool {
    pattern_binder_identifiers(node)
        .into_iter()
        .any(|binder| node_text_matches(binder, source, receiver))
}

fn declaration_scope_id(node: Node<'_>) -> Option<usize> {
    let mut current = node.parent()?;
    loop {
        if is_scope_boundary(current.kind()) {
            return Some(current.id());
        }
        current = current.parent()?;
    }
}

fn assignment_has_nonlinear_control_ancestor(
    assignment: Node<'_>,
    scope: Node<'_>,
    source: &str,
) -> bool {
    let mut current = assignment.parent();
    while let Some(node) = current {
        if node.id() == scope.id() || is_declaration_boundary(node.kind()) {
            return false;
        }
        if is_nonlinear_control_boundary(node.kind())
            || matches!(
                node.kind(),
                "binary_expression" | "augmented_assignment_expression"
            ) && node.child_by_field_name("operator").is_some_and(|op| {
                matches!(
                    slice(op, source),
                    "&&" | "||" | "??" | "&&=" | "||=" | "??="
                )
            })
        {
            return true;
        }
        current = node.parent();
    }
    false
}

fn is_nonlinear_control_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "ternary_expression"
            | "if_statement"
            | "else_clause"
            | "switch_statement"
            | "switch_case"
            | "for_statement"
            | "for_in_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "catch_clause"
    )
}

fn is_scope_boundary(kind: &str) -> bool {
    matches!(kind, "program" | "statement_block") || is_declaration_boundary(kind)
}

fn is_summary_boundary(kind: &str) -> bool {
    is_declaration_boundary(kind)
}

fn is_declaration_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "generator_function_declaration"
            | "generator_function"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
    )
}

pub fn build_js_ts_receiver_syntax_index<'tree>(
    root: Node<'tree>,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<(Arc<JsTsReceiverSyntaxIndex>, usize)> {
    match build_js_ts_receiver_syntax_index_bounded(root, source, cancellation, usize::MAX) {
        JsTsReceiverSyntaxIndexBuild::Complete { index, visited } => Some((index, visited)),
        JsTsReceiverSyntaxIndexBuild::Cancelled => None,
        JsTsReceiverSyntaxIndexBuild::ExceededScope { .. } => {
            unreachable!("an in-memory syntax tree cannot exceed usize::MAX nodes")
        }
    }
}

pub fn build_js_ts_receiver_syntax_index_bounded<'tree>(
    root: Node<'tree>,
    source: &str,
    cancellation: Option<&CancellationToken>,
    max_scope_nodes: usize,
) -> JsTsReceiverSyntaxIndexBuild {
    let mut functions: HashMap<String, Vec<IndexedNodeRange>> = HashMap::default();
    let mut classes: HashMap<String, Vec<IndexedNodeRange>> = HashMap::default();
    let traversal =
        walk_named_tree_preorder_bounded(root, true, max_scope_nodes, cancellation, |node| {
            let range = IndexedNodeRange {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            };
            if node.kind() == "function_declaration"
                && let Some(name_node) = node.child_by_field_name("name")
                && let Some(name) = simple_identifier_text(name_node, source)
            {
                functions.entry(name.to_string()).or_default().push(range);
            } else if matches!(
                node.kind(),
                "class_declaration" | "abstract_class_declaration"
            ) && let Some(name_node) = node.child_by_field_name("name")
                && let Some(name) = simple_identifier_text(name_node, source)
            {
                classes.entry(name.to_string()).or_default().push(range);
            }
        });
    let visited = match traversal {
        BoundedNamedTreeWalk::Complete { visited } => visited,
        BoundedNamedTreeWalk::Exceeded { visited } => {
            return JsTsReceiverSyntaxIndexBuild::ExceededScope { visited };
        }
        BoundedNamedTreeWalk::Cancelled => return JsTsReceiverSyntaxIndexBuild::Cancelled,
    };
    JsTsReceiverSyntaxIndexBuild::Complete {
        index: Arc::new(JsTsReceiverSyntaxIndex {
            function_declarations_by_name: functions,
            class_declarations_by_name: classes,
        }),
        visited,
    }
}

fn node_text_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    slice(node, source) == expected
}

fn wrap_factory_outcome(
    outcome: ReceiverAnalysisOutcome<ReceiverValue>,
    factory: &CodeUnit,
) -> ReceiverAnalysisOutcome<ReceiverValue> {
    let wrap = |value| ReceiverValue::FactoryReturn {
        factory: factory.clone(),
        value: Box::new(value),
    };
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) => {
            ReceiverAnalysisOutcome::Precise(values.into_iter().map(wrap).collect())
        }
        ReceiverAnalysisOutcome::Ambiguous(values) => {
            ReceiverAnalysisOutcome::Ambiguous(values.into_iter().map(wrap).collect())
        }
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

pub fn member_expression_at_site(mut node: Node<'_>) -> Option<Node<'_>> {
    for _ in 0..4 {
        if matches!(node.kind(), "member_expression" | "subscript_expression") {
            return Some(node);
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && matches!(
                function.kind(),
                "member_expression" | "subscript_expression"
            )
        {
            return Some(function);
        }
        node = node.parent()?;
    }
    None
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        left.source()
            .cmp(right.source())
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::parse_javascript;
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::capabilities::{
        ImportAnalysisProvider, TypeHierarchyProvider,
    };
    use brokk_bifrost_core::analyzer::model::ImportInfo;
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use brokk_bifrost_core::analyzer::query_token::QueryToken;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;

    #[test]
    #[hardwon("#4271: a default-value reference was mistaken for a destructuring binder")]
    fn destructuring_default_reference_is_not_a_binding() {
        let source = "const { a = b } = obj;\nconst later = b;\n";
        let tree = parse_javascript(source);
        let mut stack = vec![tree.root_node()];
        let mut pattern = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "object_pattern" {
                pattern = Some(node);
                break;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }

        let pattern = pattern.expect("destructuring pattern");
        assert!(!binding_pattern_contains_name(pattern, source, "b"));
    }
    struct FakeJsTsSource {
        project: Arc<TestProject>,
        aliases: Arc<AliasResolver>,
        file: ProjectFile,
        language: Language,
        declarations: Vec<(CodeUnit, Range)>,
        source_facts: Arc<JsTsFileSourceFacts>,
        additional_facts: HashMap<ProjectFile, Arc<JsTsFileSourceFacts>>,
        supertypes: HashMap<CodeUnit, Vec<String>>,
    }

    impl FakeJsTsSource {
        fn new_in(root: &std::path::Path, path: &str, source: &str) -> Self {
            let file = ProjectFile::new(root, path);
            std::fs::write(file.abs_path(), source).expect("write fixture");
            let language = brokk_bifrost_core::analyzer::common::language_for_file(&file);
            let project = Arc::new(TestProject::new(root, language));
            let aliases = Arc::new(AliasResolver::new(project.clone() as Arc<dyn Project>));

            let tree = parse_js_ts_tree(&file, source, language).expect("parse");
            let parsed = match language {
                Language::JavaScript => {
                    crate::javascript::parse_javascript_file(&file, source, &tree)
                }
                Language::TypeScript => {
                    crate::typescript::parse_typescript_file(&file, source, &tree)
                }
                _ => unreachable!("JS/TS fixture"),
            };
            let declarations = parsed
                .ranges
                .iter()
                .flat_map(|(unit, ranges)| ranges.iter().map(|range| (unit.clone(), *range)))
                .collect();
            let mut declaration_units: HashMap<_, Vec<_>> = HashMap::default();
            for (declaration, unit) in parsed.source_declaration_units {
                declaration_units.entry(declaration).or_default().push(unit);
            }
            let publication = parsed.source_facts.expect("primary source publication");
            let source_facts = Arc::new(JsTsFileSourceFacts {
                source: publication.occurrences,
                imports: publication.imports,
                facts: publication.js_ts.expect("JS/TS source family"),
                declaration_units,
            });
            Self {
                project,
                aliases,
                file,
                language,
                declarations,
                source_facts,
                additional_facts: HashMap::default(),
                supertypes: parsed.raw_supertypes,
            }
        }
    }

    impl CodeUnitIndex for FakeJsTsSource {
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
            self.declarations
                .iter()
                .filter(|(u, _)| u.source() == file)
                .map(|(u, _)| u.clone())
                .collect()
        }
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
            self.declarations(file).into_iter().collect()
        }
        fn definitions(&self, fqn: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            let fqn = fqn.to_owned();
            Box::new(
                self.declarations
                    .iter()
                    .filter(move |(u, _)| u.fq_name() == fqn)
                    .map(|(u, _)| u.clone()),
            )
        }
        fn project(&self) -> &dyn Project {
            self.project.as_ref()
        }

        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([self.language])
        }

        fn analyzed_files(&self) -> Vec<ProjectFile> {
            self.all_files()
        }

        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.declarations.iter().map(|(unit, _)| unit.clone()))
        }

        fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
            self.declarations
                .iter()
                .filter(|(unit, _)| unit == code_unit)
                .map(|(_, range)| *range)
                .collect()
        }

        // These surfaces are outside the parser/publication/receiver boundary
        // exercised here; fail if a test unexpectedly reaches one.
        fn search_definitions(&self, _pattern: &str, _case_sensitive: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }

        fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
            unimplemented!()
        }

        fn enclosing_code_unit_for_lines(
            &self,
            _file: &ProjectFile,
            _start_line: usize,
            _end_line: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }

        fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }

        fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }

        fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
            unimplemented!()
        }

        fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }

    impl ImportAnalysisProvider for FakeJsTsSource {
        fn imported_code_units_of(
            &self,
            _file: &ProjectFile,
        ) -> Arc<brokk_bifrost_core::hash::HashSet<CodeUnit>> {
            Arc::new(brokk_bifrost_core::hash::HashSet::default())
        }

        fn referencing_files_of(
            &self,
            _file: &ProjectFile,
        ) -> brokk_bifrost_core::hash::HashSet<ProjectFile> {
            brokk_bifrost_core::hash::HashSet::default()
        }
    }

    impl TypeHierarchyProvider for FakeJsTsSource {
        fn get_direct_ancestors(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
            Vec::new()
        }

        fn get_direct_descendants(
            &self,
            _code_unit: &CodeUnit,
        ) -> brokk_bifrost_core::hash::HashSet<CodeUnit> {
            brokk_bifrost_core::hash::HashSet::default()
        }
    }

    impl JsTsSource for FakeJsTsSource {
        fn source_file_inventory(
            &self,
        ) -> brokk_bifrost_core::analyzer::query_batch::QueryBatch<ProjectFile> {
            let files = self.all_files();
            let count = files.len();
            brokk_bifrost_core::analyzer::query_batch::QueryBatch::complete(files, count)
        }

        fn source_facts(&self, file: &ProjectFile) -> Option<Arc<JsTsFileSourceFacts>> {
            if file == &self.file {
                Some(self.source_facts.clone())
            } else {
                self.additional_facts.get(file).cloned()
            }
        }
        fn alias_resolver(&self) -> &Arc<AliasResolver> {
            &self.aliases
        }

        fn language(&self) -> Language {
            self.language
        }

        fn all_files(&self) -> Vec<ProjectFile> {
            std::iter::once(self.file.clone())
                .chain(self.additional_facts.keys().cloned())
                .collect()
        }

        fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
            Vec::new()
        }

        fn bulk_import_infos(
            &self,
            _files: &[ProjectFile],
        ) -> HashMap<ProjectFile, Vec<ImportInfo>> {
            HashMap::default()
        }

        fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
            self.supertypes.get(code_unit).cloned().unwrap_or_default()
        }

        fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
            self.source_facts.facts.declarations.iter().any(|d| {
                d.alias_type.is_some()
                    && self
                        .source_facts
                        .declaration_units
                        .get(&d.declaration)
                        .is_some_and(|units| units.contains(code_unit))
            })
        }

        fn raw_signatures(&self, _code_unit: &CodeUnit) -> Vec<String> {
            Vec::new()
        }

        fn with_usage_definitions(
            &self,
            _token: QueryToken<'_>,
            read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
        ) {
            read(self);
        }

        fn usage_index(
            &self,
            _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        ) -> Option<Arc<crate::graph::resolver::JsTsUsageIndex>> {
            crate::graph::resolver::build_jsts_usage_index(
                self,
                &self.aliases,
                self.language,
                false,
            )
            .map(Arc::new)
        }
    }

    impl BoundedDefinitionLookup for FakeJsTsSource {
        fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.declarations
                .iter()
                .filter(|(unit, _)| unit.fq_name() == fqn)
                .map(|(unit, _)| unit.clone())
                .collect()
        }

        fn fqn_in_language(&self, fqn: &str, _language: Language) -> Vec<CodeUnit> {
            self.fqn(fqn)
        }

        fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
            self.declarations
                .iter()
                .filter(|(unit, _)| unit.source() == file && unit.identifier() == ident)
                .map(|(unit, _)| unit.clone())
                .collect()
        }

        fn package_exists(&self, _package: &str) -> bool {
            false
        }

        fn package_exists_in_language(&self, _package: &str, _language: Language) -> bool {
            false
        }

        fn fqn_prefix_exists(&self, _prefix: &str) -> bool {
            false
        }

        fn fqn_direct_children(&self, _fqn: &str) -> Vec<CodeUnit> {
            Vec::new()
        }
    }

    fn with_provider<R>(
        source: &str,
        run: impl FnOnce(&JsTsReceiverFactProvider<'_, '_>) -> R,
    ) -> R {
        with_workspace(source, &[], run)
    }
    fn with_workspace<R>(
        source: &str,
        modules: &[(&str, &str)],
        run: impl FnOnce(&JsTsReceiverFactProvider<'_, '_>) -> R,
    ) -> R {
        with_sources("receiver.tsx", source, modules, run)
    }
    fn with_sources<R>(
        path: &str,
        source: &str,
        modules: &[(&str, &str)],
        run: impl FnOnce(&JsTsReceiverFactProvider<'_, '_>) -> R,
    ) -> R {
        let root = tempfile::tempdir().expect("fixture root");
        let mut host = FakeJsTsSource::new_in(root.path(), path, source);
        for (path, text) in modules {
            let module = FakeJsTsSource::new_in(root.path(), path, text);
            host.declarations.extend(module.declarations);
            host.supertypes.extend(module.supertypes);
            host.additional_facts
                .insert(module.file, module.source_facts);
        }
        let tree = parse_js_ts_tree(&host.file, source, host.language).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let imports = crate::syntax::compute_import_binder(source, &tree);
        let provider = JsTsReceiverFactProvider::new(
            &host,
            &host,
            host.language,
            &host.file,
            source,
            tree.root_node(),
            imports,
        );
        run(&provider)
    }

    fn nodes<'t>(root: Node<'t>, kind: &str) -> Vec<Node<'t>> {
        let mut found = Vec::new();
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == kind {
                found.push(node);
            }
            for i in (0..node.named_child_count()).rev() {
                pending.push(node.named_child(i).unwrap());
            }
        }
        found
    }

    #[test]
    #[hardwon("#7218: review: bare return did not add factory uncertainty")]
    fn bare_factory_return_stays_uncertain() {
        with_provider(
            "class A {m(){}} function make() {if (flag) return; return new A();} make().m();",
            |p| {
                let member = nodes(p.root, "member_expression")[0];
                let result = p.resolve_receiver_node(
                    member.child_by_field_name("object").unwrap(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    matches!(result, ReceiverAnalysisOutcome::Ambiguous(_)),
                    "{result:?}"
                );
            },
        );
    }

    #[test]
    #[hardwon("#7218: review: constructor lookup ignored nearer value binder")]
    fn constructor_respects_value_shadow() {
        for binding in [
            "function f(C) {new C().m();}",
            "function f() {const C = external; new C().m();}",
        ] {
            let source = format!("class C {{m(){{}}}} {binding}");
            with_provider(&source, |p| {
                let new = nodes(p.root, "new_expression")[0];
                let result = p.resolve_receiver_node(new, ReceiverAnalysisBudget::default());
                assert!(
                    !matches!(result, ReceiverAnalysisOutcome::Precise(_)),
                    "{binding}: {result:?}"
                );
            });
        }
    }

    #[test]
    #[hardwon("#7218: review: generator body treated as caller scope write")]
    fn generator_write_cannot_prove_receiver() {
        with_provider(
            "class A {m(){}} class B {m(){}} let x = new A(); function* later() {x = new B();} x.m();",
            |p| {
                let member = nodes(p.root, "member_expression")[0];
                let result = p.resolve_receiver_node(
                    member.child_by_field_name("object").unwrap(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    !matches!(result, ReceiverAnalysisOutcome::Precise(ref v) if v[0].owner().identifier() == "B"),
                    "{result:?}"
                );
            },
        );
    }

    #[test]
    #[hardwon("#7218: review: redeclared variable factory selected last value after export")]
    fn redeclared_factory_is_ambiguous() {
        with_sources(
            "receiver.cjs",
            "const {make} = require('./factory'); make().m();",
            &[(
                "factory.cjs",
                "class A {m(){}} class B {m(){}} var make = () => {return new A();}; exports.make = make; var make = () => {return new B();};",
            )],
            |p| {
                let functions = p
                    .host
                    .all_declarations()
                    .filter(|u| u.identifier() == "make")
                    .collect();
                let budget = ReceiverAnalysisBudget::default();
                let result = p
                    .summarize_external_functions(
                        functions,
                        0,
                        budget,
                        &mut ReceiverAnalysisBudgetTracker::new(budget),
                    )
                    .unwrap();
                assert!(
                    matches!(result, ReceiverAnalysisOutcome::Ambiguous(_)),
                    "{result:?}"
                );
            },
        );
    }

    // Overload signatures share the implementation's binding and have no
    // body, so they must not turn the one implementation into a redeclaration.
    #[test]
    fn overloaded_factory_uses_its_implementation() {
        with_sources(
            "receiver.ts",
            "import {make} from './factory'; make('a').m();",
            &[(
                "factory.ts",
                "export class A {m(){}} export function make(x: string): A; export function make(x: number): A; export function make(x: any): A {return new A();}",
            )],
            |p| {
                let functions = p
                    .host
                    .all_declarations()
                    .filter(|u| u.identifier() == "make")
                    .collect();
                let budget = ReceiverAnalysisBudget::default();
                let result = p
                    .summarize_external_functions(
                        functions,
                        0,
                        budget,
                        &mut ReceiverAnalysisBudgetTracker::new(budget),
                    )
                    .unwrap();
                assert!(
                    matches!(result, ReceiverAnalysisOutcome::Precise(_)),
                    "{result:?}"
                );
            },
        );
    }

    #[test]
    #[hardwon("#7218: review: equal return annotations erased variable redeclaration ambiguity")]
    fn redeclared_typed_factory_is_ambiguous() {
        with_sources(
            "receiver.ts",
            "import {make} from './factory'; make().m();",
            &[(
                "factory.ts",
                "class A {m(){}} var make = (): A => {return new A();}; export {make}; var make = (): A => {return new A();};",
            )],
            |p| {
                let functions = p
                    .host
                    .all_declarations()
                    .filter(|u| u.identifier() == "make")
                    .collect();
                let budget = ReceiverAnalysisBudget::default();
                let result = p
                    .summarize_external_functions(
                        functions,
                        0,
                        budget,
                        &mut ReceiverAnalysisBudgetTracker::new(budget),
                    )
                    .unwrap();
                assert!(
                    matches!(result, ReceiverAnalysisOutcome::Ambiguous(_)),
                    "{result:?}"
                );
            },
        );
    }

    #[test]
    #[hardwon("#7218: review: conditional expression and augmented writes retained exact proof")]
    fn expression_writes_invalidate_receiver() {
        for control in [
            "false ? x = new B() : 0;",
            "false && (x = new B());",
            "true || (x = new B());",
            "x ?? (x = new B());",
            "x &&= new B();",
            "x ||= new B();",
            "x ??= new B();",
            "x += 1;",
        ] {
            let source = format!(
                "class A {{m(){{}}}} class B {{m(){{}}}} let x = new A(); {control} x.m();"
            );
            with_provider(&source, |p| {
                let member = nodes(p.root, "member_expression")[0];
                let result = p.resolve_receiver_node(
                    member.child_by_field_name("object").unwrap(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    !matches!(result, ReceiverAnalysisOutcome::Precise(_)),
                    "{control}: {result:?}"
                );
            });
        }
    }

    #[test]
    #[hardwon("#7218: review: heritage qualifier ignored enclosing namespace")]
    fn heritage_resolves_in_enclosing_namespace() {
        with_provider(
            "namespace M {export class Base {outer(){}}} namespace N {export namespace M {export class Base {inner(){}}} class Child extends M.Base {} new Child().inner();}",
            |p| {
                let child = p
                    .host
                    .declarations(p.file)
                    .into_iter()
                    .find(|u| u.fq_name() == "N.Child")
                    .unwrap();
                let ancestors = crate::hierarchy::resolve_direct_ancestors(
                    p.host,
                    &crate::graph::resolver::JsTsUsageIndex::default(),
                    p.language,
                    &p.aliases,
                    &child,
                    &["M.Base".to_string()],
                );
                assert_eq!(
                    ancestors.iter().map(|u| u.fq_name()).collect::<Vec<_>>(),
                    ["N.M.Base"]
                );
            },
        );
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: nested component containers are not components"
    )]
    fn component_container_annotations_do_not_prove_props() {
        for annotation in [
            "Holder<FC<A>, FC<B>>",
            "FC<A>[]",
            "(callback: FC<A>) => void",
            "{ panel: FC<A> }",
        ] {
            let source = format!(
                "interface A {{ a: string }} interface B {{ b: string }} type Holder<T,U> = {{ left:T; right:U }}; type Bad = {annotation}; let Panel: Bad; let Direct: {annotation}; <Panel a='x' />; <Direct a='x' />;"
            );
            with_provider(&source, |provider| {
                let attributes = nodes(provider.root, "jsx_attribute");
                assert_eq!(attributes.len(), 2);
                for attribute in attributes {
                    assert!(
                        provider
                            .resolve_jsx_attribute_targets(
                                attribute,
                                ReceiverAnalysisBudget::default()
                            )
                            .unwrap()
                            .is_empty(),
                        "{annotation}"
                    );
                }
            });
        }
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: class receiver ignores lexical shadowing"
    )]
    fn class_receivers_obey_lexical_scope() {
        with_provider(
            "class C { outer() {} } namespace N { export class C { inner() {} } new C().inner(); } new C().outer();",
            |p| {
                for (node, expected) in nodes(p.root, "new_expression")
                    .into_iter()
                    .zip(["N.C", "C"])
                {
                    let result = p.resolve_receiver_node(node, ReceiverAnalysisBudget::default());
                    let ReceiverAnalysisOutcome::Precise(values) = result else {
                        panic!("{result:?}")
                    };
                    assert_eq!(
                        values
                            .iter()
                            .map(|v| v.owner().fq_name())
                            .collect::<Vec<_>>(),
                        [expected]
                    );
                }
            },
        );
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: unknown factory branches cannot prove a member target"
    )]
    fn uncertain_factory_member_stays_uncertain() {
        with_provider(
            "class A { m() {} } function make() { return flag ? new A() : unknownValue; } make().m();",
            |p| {
                let member = nodes(p.root, "member_expression")[0];
                let receiver = member.child_by_field_name("object").unwrap();
                let outcome = p.resolve_member_targets(
                    receiver,
                    "m",
                    member.start_byte(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    matches!(outcome, ReceiverAnalysisOutcome::Ambiguous(ref v) if v.len() == 1),
                    "{outcome:?}"
                );
                let missing = p.resolve_member_targets(
                    receiver,
                    "missing",
                    member.start_byte(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    matches!(missing, ReceiverAnalysisOutcome::Ambiguous(ref v) if v.is_empty()),
                    "{missing:?}"
                );
            },
        );
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: writes in conditional blocks were skipped"
    )]
    fn conditional_writes_cannot_prove_an_exact_receiver() {
        for control in [
            "if (flag) x = new B();",
            "if (flag) { x = new B(); }",
            "while (flag) { x = new B(); }",
            "{ x = new B(); }",
        ] {
            let source = format!(
                "class A {{ m() {{}} }} class B {{ m() {{}} }} let x = new A(); {control} x.m();"
            );
            with_provider(&source, |p| {
                let member = nodes(p.root, "member_expression")[0];
                let receiver = member.child_by_field_name("object").unwrap();
                let result = p.resolve_receiver_node(receiver, ReceiverAnalysisBudget::default());
                if control.starts_with('{') {
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::Precise(ref v) if v[0].owner().identifier() == "B"),
                        "{control}: {result:?}"
                    );
                } else {
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::Ambiguous(_)),
                        "{control}: {result:?}"
                    );
                }
            });
        }
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: imported duplicate declarations bind the last implementation"
    )]
    fn duplicate_factory_uses_last_implementation() {
        with_sources(
            "receiver.cjs",
            "const {make} = require('./factory'); make().b();",
            &[(
                "factory.cjs",
                "class A { a() {} } class B { b() {} } function make() { return new A(); } function make() { return new B(); } exports.make = make;",
            )],
            |p| {
                let member = nodes(p.root, "member_expression")[0];
                let receiver = member.child_by_field_name("object").unwrap();
                let result = p.resolve_receiver_node(receiver, ReceiverAnalysisBudget::default());
                let ReceiverAnalysisOutcome::Precise(values) = result else {
                    panic!("{result:?}")
                };
                assert_eq!(
                    values
                        .iter()
                        .map(|v| v.owner().identifier())
                        .collect::<Vec<_>>(),
                    ["B"]
                );
                let targets = p.resolve_member_targets(
                    receiver,
                    "b",
                    member.start_byte(),
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    matches!(targets, ReceiverAnalysisOutcome::Precise(ref v) if v.len() == 1 && v[0].fq_name() == "B.b"),
                    "{targets:?}"
                );
            },
        );
    }

    // Grammar boundary: binders use the value of a renamed property and the
    // key still supplies the property path. Defaults are expressions, not names.
    #[test]
    fn binding_and_focus_grammar_matrix() {
        for (pattern, bound, absent) in [
            ("{service, other}", "service", "missing"),
            ("{Box: Renamed, Renamed: Other}", "Renamed", "Box"),
            ("{a = fallback}", "a", "fallback"),
            ("{}", "missing", "service"),
        ] {
            let source = format!("const {pattern} = value;");
            let tree = parse_javascript(&source);
            let pattern_node = nodes(tree.root_node(), "object_pattern")[0];
            assert_eq!(
                binding_pattern_contains_name(pattern_node, &source, bound),
                pattern != "{}"
            );
            assert!(!binding_pattern_contains_name(
                pattern_node,
                &source,
                absent
            ));
            if pattern.contains("Box:") {
                let entry = destructured_pattern_entry(pattern_node, "Renamed", &source).unwrap();
                assert_eq!(
                    destructured_member_name(entry, &source),
                    Some("Box".to_owned())
                );
            }
        }
        for source in ["value.member;", "value['member'];", "((value)).member;"] {
            let tree = parse_javascript(source);
            let receiver = nodes(tree.root_node(), "identifier")[0];
            let enclosing = member_expression_at_site(receiver).expect(source);
            let (_, member) = static_member_property(enclosing, source).unwrap();
            assert_eq!(member, "member");
            assert_eq!(enclosing.start_byte(), 0);
            assert_eq!(enclosing.end_byte(), source.len() - 1);
        }
    }

    // Grammar-to-publication contract: every component annotation uses the first
    // argument as props, in both the AST and the canonical source fact route.
    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: lexical walks skipped local class components"
    )]
    fn component_annotation_grammar_matrix() {
        let source = "interface Props { label: string; count: number } interface State { decoy: boolean }\n\
            type Kind = FlowComponent<Props, State>; const Kind = 0;\n\
            const Panel: FlowComponent<Props, State> = impl;\n\
            let Alias: Kind;\n\
            class ClassPanel extends React.Component<Props, State> {}\n\
            class PurePanel extends React.PureComponent<Props> {}\n\
            function render(Parameter: FC<Props>, Optional?: FlowComponent<Props>) {\n\
                return <><Parameter label='x' /><Optional label='x' /><Panel label='x' count={1}/><Panel label='y'/><Alias label='x'/><ClassPanel label='x'/><PurePanel label='x'/></>; }";
        with_provider(source, |p| {
            for class in nodes(p.root, "class_declaration") {
                assert!(
                    class_component_props_argument(class, source).is_some(),
                    "{}",
                    class.to_sexp()
                );
            }
            for attribute in nodes(p.root, "jsx_attribute") {
                let name = slice(attribute.named_child(0).unwrap(), source);
                let targets = p
                    .resolve_jsx_attribute_targets(attribute, ReceiverAnalysisBudget::default())
                    .unwrap();
                assert_eq!(
                    targets.iter().map(|u| u.fq_name()).collect::<Vec<_>>(),
                    [format!("Props.{name}")],
                    "{}",
                    slice(attribute.parent().unwrap(), source)
                );
            }
            let facts = p.host.source_facts(p.file).unwrap();
            let alias = facts
                .facts
                .declarations
                .iter()
                .find_map(|d| d.alias_type)
                .unwrap();
            let props = source_component_wrapper_argument(&facts, alias).unwrap();
            assert!(
                matches!(&facts.facts.types[props.index()].shape, JsTsTypeShape::Named(path) if path == &["Props"])
            );
            for class in nodes(p.root, "class_declaration") {
                assert_eq!(
                    slice(
                        class_component_props_argument(class, source).unwrap(),
                        source
                    ),
                    "Props"
                );
            }
        });
    }

    #[test]
    fn contextual_object_key_grammar_matrix() {
        with_provider(
            "interface P { first: number; second: number } interface Q { first: string; second: string } const p: P = { first: 1, second: 2 }; function make(): P { return { first: 3, second: 4 }; }",
            |p| {
                let keys = nodes(p.root, "pair");
                assert_eq!(keys.len(), 4);
                for pair in keys {
                    let key = pair.child_by_field_name("key").unwrap();
                    let targets = p.resolve_contextual_object_literal_key_targets(
                        key,
                        ReceiverAnalysisBudget::default(),
                    );
                    assert_eq!(
                        targets.iter().map(|u| u.fq_name()).collect::<Vec<_>>(),
                        [format!("P.{}", slice(key, p.source))]
                    );
                }
            },
        );
    }

    #[test]
    fn receiver_expression_budget_boundary() {
        for parentheses in [7, 8, 9] {
            let source = format!(
                "class C {{}} {}new C(){};",
                "(".repeat(parentheses),
                ")".repeat(parentheses)
            );
            with_provider(&source, |p| {
                let expression = nodes(p.root, "expression_statement")[0]
                    .named_child(0)
                    .unwrap();
                let result = p.resolve_receiver_node(expression, ReceiverAnalysisBudget::default());
                if parentheses <= 8 {
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::Precise(_)),
                        "{parentheses}: {result:?}"
                    );
                } else {
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::ExceededBudget { .. }),
                        "{result:?}"
                    );
                }
            });
        }
    }

    #[test]
    fn imported_component_and_factory_matrix() {
        let modules = [
            (
                "panel.tsx",
                "export interface Props { label: string } interface State { unused: number } export class Panel extends React.Component<Props, State> {} export default function DefaultPanel(props: Props) { return null; }",
            ),
            (
                "deferred.tsx",
                "export const Deferred = lazy(() => import('./panel'));",
            ),
            (
                "factory.ts",
                "export interface make { decoy: number } class Result { m() {} } export function make() { return new Result(); }",
            ),
        ];
        with_workspace(
            "import {Panel} from './panel'; import {Deferred} from './deferred'; import {make} from './factory'; import * as ns from './factory'; <Panel label='x'/>; <Deferred label='x'/>; make().m(); ns.make().m();",
            &modules,
            |p| {
                for attribute in nodes(p.root, "jsx_attribute") {
                    let targets = p
                        .resolve_jsx_attribute_targets(attribute, ReceiverAnalysisBudget::default())
                        .unwrap();
                    assert_eq!(
                        targets.iter().map(|u| u.fq_name()).collect::<Vec<_>>(),
                        ["Props.label"],
                        "{}; candidates {:?}; facts {:?}",
                        slice(attribute.parent().unwrap(), p.source),
                        p.jsx_component_candidates("Panel"),
                        p.host
                            .all_declarations()
                            .map(|u| (u.fq_name(), u.source().rel_path().to_owned()))
                            .collect::<Vec<_>>()
                    );
                }
                for member in nodes(p.root, "member_expression").into_iter().filter(|n| {
                    static_member_property(*n, p.source).is_some_and(|(_, name)| name == "m")
                }) {
                    let receiver = member.child_by_field_name("object").unwrap();
                    let result = p.resolve_member_targets(
                        receiver,
                        "m",
                        member.start_byte(),
                        ReceiverAnalysisBudget::default(),
                    );
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::Precise(ref v) if v.len() == 1 && v[0].fq_name() == "Result.m"),
                        "{}: {result:?}",
                        slice(member, p.source)
                    );
                }
            },
        );
    }

    #[test]
    fn jsx_module_hop_budget_matrix() {
        let modules = [
            (
                "one.tsx",
                "export default function Panel(props: Props) { return null; } export interface Props { label: string }",
            ),
            (
                "two.tsx",
                "const Panel = lazy(() => import('./one')); export default Panel;",
            ),
            (
                "three.tsx",
                "const Panel = lazy(() => import('./two')); export default Panel;",
            ),
            (
                "four.tsx",
                "const Panel = lazy(() => import('./three')); export default Panel;",
            ),
            (
                "cycle.tsx",
                "const Panel = lazy(() => import('./cycle')); export default Panel;",
            ),
        ];
        with_workspace(
            "const One = lazy(() => import('./one')); const Three = lazy(() => import('./three')); const Four = lazy(() => import('./four')); const Cycle = lazy(() => import('./cycle')); <One label='x'/>; <Three label='x'/>; <Four label='x'/>; <Cycle label='x'/>;",
            &modules,
            |p| {
                let attributes = nodes(p.root, "jsx_attribute");
                for (attribute, expected) in attributes.into_iter().zip([true, true, false, false])
                {
                    let targets = p
                        .resolve_jsx_attribute_targets(attribute, ReceiverAnalysisBudget::default())
                        .unwrap();
                    assert_eq!(
                        !targets.is_empty(),
                        expected,
                        "{}: {targets:?}",
                        slice(attribute.parent().unwrap(), p.source)
                    );
                }
            },
        );
    }

    #[test]
    fn destructured_component_grammar_matrix() {
        for depth in [1, 3, 4, 5] {
            let annotation = format!(
                "{}Box: FlowComponent<Props, Decoy>{}",
                "nested: { ".repeat(depth - 1),
                " }".repeat(depth - 1)
            );
            let annotation = format!("{{ {annotation} }}");
            let pattern = format!(
                "{}Box: Renamed{}",
                "nested: { ".repeat(depth - 1),
                " }".repeat(depth - 1)
            );
            let pattern = format!("{{ {pattern} }}");
            // The binding's annotation selects a named, nested container.
            let source = format!(
                "interface Props {{ label: string }} interface Decoy {{ decoy: string }} type Components = {annotation}; function render({pattern}: Components) {{ return <Renamed label='x'/>; }}"
            );
            with_provider(&source, |p| {
                let attribute = nodes(p.root, "jsx_attribute")[0];
                let targets = p
                    .resolve_jsx_attribute_targets(attribute, ReceiverAnalysisBudget::default())
                    .unwrap();
                assert_eq!(
                    !targets.is_empty(),
                    depth <= 4,
                    "depth {depth}: {targets:?}"
                );
                if depth <= 4 {
                    assert_eq!(targets[0].fq_name(), "Props.label");
                }
            });
        }
        with_provider(
            "interface Props { label: string } interface Decoy { decoy: string } type Container = { Box: FlowComponent<Props, Decoy> };",
            |p| {
                let facts = p.host.source_facts(p.file).unwrap();
                let container = facts
                    .facts
                    .declarations
                    .iter()
                    .find_map(|d| d.alias_type)
                    .unwrap();
                let props =
                    source_type_member_component_argument(&facts, container, &["Box".to_owned()])
                        .unwrap();
                assert!(
                    matches!(&facts.facts.types[props.index()].shape, JsTsTypeShape::Named(path) if path == &["Props"])
                );
            },
        );
    }

    #[test]
    fn receiver_type_and_factory_budget_grammar_matrix() {
        with_provider(
            "interface P { m(): void } function render(p: P) { p.m(); } function factory(): P { return unknownValue; }",
            |p| {
                let annotation = nodes(p.root, "required_parameter")[0]
                    .child_by_field_name("type")
                    .unwrap();
                // A declared return type can resolve at the last admitted
                // factory depth without expanding a return expression.
                let outcome = p.type_annotation_receiver_outcome(
                    annotation,
                    ReceiverAnalysisBudget::default(),
                );
                assert!(
                    !matches!(outcome, ReceiverAnalysisOutcome::Unknown),
                    "{outcome:?}"
                );
                let function = nodes(p.root, "function_declaration")[1];
                let unit = p
                    .host
                    .declarations(p.file)
                    .into_iter()
                    .find(|u| u.identifier() == "factory")
                    .unwrap();
                for depth in [8, 9] {
                    let mut tracker =
                        ReceiverAnalysisBudgetTracker::new(ReceiverAnalysisBudget::default());
                    let result = p.summarize_function_body(
                        function,
                        &unit,
                        depth,
                        ReceiverAnalysisBudget::default(),
                        &mut tracker,
                    );
                    assert_eq!(
                        matches!(result, ReceiverAnalysisOutcome::ExceededBudget { .. }),
                        depth == 9,
                        "{result:?}"
                    );
                }
            },
        );
    }
    #[test]
    fn inherited_receiver_member_matrix() {
        with_provider(
            "class Grand { m() {} } class Parent extends Grand {} class Child extends Parent {} class Override extends Child { m() {} } class Decoy { m() {} } new Child().m(); new Override().m();",
            |p| {
                for (member, target) in nodes(p.root, "member_expression")
                    .into_iter()
                    .zip(["Grand.m", "Override.m"])
                {
                    let result = p.resolve_member_targets(
                        member.child_by_field_name("object").unwrap(),
                        "m",
                        member.start_byte(),
                        ReceiverAnalysisBudget::default(),
                    );
                    assert!(
                        matches!(result, ReceiverAnalysisOutcome::Precise(ref v) if v.len() == 1 && v[0].fq_name() == target),
                        "{target}: {result:?}"
                    );
                }
            },
        );
    }

    #[test]
    fn receiver_type_depth_boundary_matrix() {
        for depth in [5, 6, 7] {
            let source = format!(
                "interface P {{ m(): void }} function render(p: {}P{}) {{ p.m(); }}",
                "(".repeat(depth),
                ")".repeat(depth)
            );
            with_provider(&source, |p| {
                let annotation = nodes(p.root, "required_parameter")[0]
                    .child_by_field_name("type")
                    .unwrap();
                let result = p.type_annotation_receiver_outcome(
                    annotation,
                    ReceiverAnalysisBudget::default(),
                );
                assert_eq!(
                    matches!(result, ReceiverAnalysisOutcome::Precise(_)),
                    depth <= 6,
                    "depth {depth}: {result:?}"
                );
            });
        }
    }

    #[test]
    fn component_union_intersection_storage_boundary() {
        with_provider(
            "interface P { p: string } interface Q { q: string } type Either = FC<P> | FC<Q>; type Both = FC<P> & FC<Q>;",
            |p| {
                assert_eq!(nodes(p.root, "union_type").len(), 1);
                assert_eq!(nodes(p.root, "intersection_type").len(), 1);
                let facts = p.host.source_facts(p.file).unwrap();
                let shapes = facts
                    .facts
                    .declarations
                    .iter()
                    .filter_map(|d| d.alias_type)
                    .map(|id| &facts.facts.types[id.index()].shape)
                    .collect::<Vec<_>>();
                assert_eq!(shapes.len(), 2);
                assert!(
                    shapes.iter().any(
                        |s| matches!(s, JsTsTypeShape::Union(children) if children.len() == 2)
                    )
                );
                assert!(shapes.iter().any(
                    |s| matches!(s, JsTsTypeShape::Intersection(children) if children.len() == 2)
                ));
            },
        );
    }

    #[test]
    fn receiver_recursion_budget_includes_its_boundary() {
        for (depth, precise) in [(8, true), (9, false)] {
            let source = format!(
                "class A {{}} const value = {}new A(){};",
                "(".repeat(depth),
                ")".repeat(depth)
            );
            with_provider(&source, |provider| {
                let expression = nodes(provider.root, "parenthesized_expression")
                    .into_iter()
                    .max_by_key(|node| node.end_byte() - node.start_byte())
                    .expect("outer expression");
                let outcome =
                    provider.resolve_receiver_node(expression, ReceiverAnalysisBudget::default());
                if precise {
                    assert!(
                        matches!(outcome, ReceiverAnalysisOutcome::Precise(ref values) if values.len() == 1 && values[0].owner().identifier() == "A"),
                        "{outcome:?}"
                    );
                } else {
                    assert!(
                        matches!(
                            outcome,
                            ReceiverAnalysisOutcome::ExceededBudget {
                                limit: "receiver_recursion"
                            }
                        ),
                        "{outcome:?}"
                    );
                }
            });
        }
    }

    #[test]
    fn factory_member_call_grammar_matrix() {
        for callee in ["makers.make", "makers['make']", "makers[\"make\"]"] {
            let source = format!("const makers = require('./factory'); {callee}().m();");
            with_sources(
                "receiver.cjs",
                &source,
                &[(
                    "factory.cjs",
                    "class A { m() {} } function make() { return new A(); } exports.make = make;",
                )],
                |provider| {
                    let call = nodes(provider.root, "call_expression")
                        .into_iter()
                        .find(|node| slice(*node, provider.source) == format!("{callee}()"))
                        .expect("factory call");
                    let outcome = provider.resolve_member_targets(
                        call,
                        "m",
                        call.end_byte(),
                        ReceiverAnalysisBudget::default(),
                    );
                    assert!(
                        matches!(outcome, ReceiverAnalysisOutcome::Precise(ref values) if values.len() == 1 && values[0].identifier() == "m"),
                        "{callee}: {outcome:?}"
                    );
                },
            );
        }
    }

    #[test]
    fn call_grammar_always_supplies_function_field() {
        for parse in [
            crate::test_support::parse_javascript,
            crate::test_support::parse_typescript,
        ] {
            for source in ["f()", "f?.()", "(f)()", "object['f']()", "f(", "f(,"] {
                let tree = parse(source);
                let calls = nodes(tree.root_node(), "call_expression");
                // Recovery may produce ERROR instead of a call; a real call
                // still has its grammar-required function field.
                if !tree.root_node().has_error() {
                    assert!(!calls.is_empty(), "{source}");
                }
                for call in calls {
                    assert!(
                        call.child_by_field_name("function").is_some(),
                        "{source}: {}",
                        tree.root_node().to_sexp()
                    );
                }
            }
        }
    }
}
