use super::*;
use crate::analyzer::AnalyzerDefinitionLookup;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::RubyMethodDispatchMode;
use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;
use crate::analyzer::ruby::constant_identity::RubyOverlayConstants;
use crate::analyzer::ruby::{RubyFieldScope, RubyNamePath, ruby_field_short_name};
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::tree_walk::push_named_children_reversed_as;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::usages::reference_site::node_range as ruby_node_range;
use brokk_bifrost_ruby::graph::resolver::{
    RubyMethodFind, RubyMethodLookupMode, ruby_dispatch_matches_lookup_mode,
};
use brokk_bifrost_ruby::graph::scope::{RubyScopeExit, exit_scope};
use brokk_bifrost_ruby::hierarchy::ruby_direct_ancestors;
use brokk_bifrost_ruby::mixins::{ruby_forward_mixin_specs, ruby_forward_superclass_targets};

mod instance_fields;
use brokk_bifrost_ruby::local_bindings::{LocalBindingBudget, collect_local_write};

pub(crate) struct RubyDefinitionProvider<'a> {
    ruby: &'a RubyAnalyzer,
    session: &'a ResolutionSession,
    overlay: Option<&'a crate::analyzer::semantic_model::SemanticModelOverlay>,
}

impl<'a> RubyDefinitionProvider<'a> {
    pub(crate) fn new(ruby: &'a RubyAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            ruby,
            session,
            overlay: None,
        }
    }

    pub(crate) fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        super::query_limited_definition_units(self.session, |limit| {
            self.ruby
                .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                    self.session.observe_cancellation()
                })
        })
    }

    fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.ruby.ranges_limited(unit, limit))
    }

    fn parent(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        if !self.scope_step() {
            return None;
        }
        let fq_name = unit.fq_name();
        let owner_fqn = fq_name.strip_suffix(unit.identifier())?.strip_suffix('.')?;
        if owner_fqn.is_empty() {
            return None;
        }
        let mut owners = self
            .fqn(owner_fqn)
            .into_iter()
            .filter(|owner| owner.is_class() || owner.is_module())
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        let [owner] = owners.as_slice() else {
            return None;
        };
        self.members_for_owner_name(owner_fqn, unit.identifier())
            .iter()
            .any(|candidate| candidate == unit)
            .then(|| owner.clone())
    }

    fn method_dispatch_mode(&self, unit: &CodeUnit) -> Option<RubyMethodDispatchMode> {
        let modes = self
            .session
            .query_limited_rows(|limit| self.ruby.method_dispatch_modes_limited(unit, limit));
        let [mode] = modes.as_slice() else {
            return None;
        };
        Some(*mode)
    }

    fn scope_step(&self) -> bool {
        self.session.scope_step()
    }

    fn visible_files_from(
        &self,
        semantic: &RubySemanticIndex<'_>,
        file: &ProjectFile,
    ) -> Option<HashSet<ProjectFile>> {
        let files = self.session.query_limited_rows(|limit| {
            let Some(files) = semantic.visible_files_from_bounded(file, limit) else {
                return LimitedQueryRows::incomplete(Vec::new(), limit);
            };
            let inspected = files.len();
            LimitedQueryRows::complete(files.into_iter().collect(), inspected)
        });
        (!files.is_empty()).then(|| files.into_iter().collect())
    }
}

impl BoundedDefinitionLookup for RubyDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.ruby
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language == Language::Ruby {
            self.fqn(fqn)
        } else {
            self.session.mark_scope_incomplete();
            Vec::new()
        }
    }

    fn members_for_owner_name(
        &self,
        owner_fqn: &str,
        _normalized_owner_fqn: &str,
        name: &str,
    ) -> Vec<CodeUnit> {
        RubyDefinitionProvider::members_for_owner_name(self, owner_fqn, name)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        let units = self
            .session
            .query_limited_rows(|limit| {
                self.ruby
                    .declaration_candidates_by_identifier_limited(ident, limit, || {
                        self.session.observe_cancellation()
                    })
            })
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect::<Vec<_>>();
        crate::analyzer::definition_lookup::sort_dedup_units(units)
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        super::fqn_direct_children(
            self.fqn(fqn),
            |owner| {
                self.session
                    .query_limited_rows(|limit| self.ruby.direct_children_limited(owner, limit))
            },
            || self.session.observe_cancellation(),
        )
    }

    fn package_exists(&self, _package: &str) -> bool {
        false
    }

    fn package_exists_in_language(&self, _package: &str, language: Language) -> bool {
        if language != Language::Ruby {
            self.session.mark_scope_incomplete();
        }
        false
    }

    fn fqn_prefix_exists(&self, _prefix: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RubyTypeLookupResolution {
    pub(crate) fqn: String,
    pub(crate) target_kind: TypeLookupTargetKind,
}

pub(crate) enum RubyBoundedPreflight<'a> {
    Ready {
        ruby: &'a RubyAnalyzer,
        tree: &'a Tree,
    },
    AnalyzerUnavailable,
    ParseFailed,
    SourceFactsUnavailable,
}

pub(crate) fn ruby_bounded_preflight<'a>(
    analyzer: &'a dyn IAnalyzer,
    tree: Option<&'a Tree>,
    session: &ResolutionSession,
) -> RubyBoundedPreflight<'a> {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return RubyBoundedPreflight::AnalyzerUnavailable;
    };
    let Some(tree) = tree else {
        return RubyBoundedPreflight::ParseFailed;
    };
    if !session.observe_cancellation() || !ruby.canonical_sources_ready() {
        return RubyBoundedPreflight::SourceFactsUnavailable;
    }
    RubyBoundedPreflight::Ready { ruby, tree }
}

fn ruby_unshadowed_external_type<'a>(
    ruby: &RubyAnalyzer,
    session: &ResolutionSession,
    constants: RubyOverlayConstants<'a>,
    qualified_name: &str,
) -> Option<&'a crate::analyzer::semantic_model::SemanticModelSymbol> {
    let result = constants.unique_type(qualified_name)?;
    let workspace_owners = session.query_limited_rows(|limit| {
        ruby.declaration_candidates_by_identifier_limited(&result.name, limit, || {
            session.observe_cancellation()
        })
    });
    if workspace_owners
        .iter()
        .any(|unit| unit.fq_segment_texts().join("::") == result.qualified_name)
    {
        return None;
    }
    Some(result)
}

pub(crate) fn resolve_ruby_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let (ruby, tree) = match ruby_bounded_preflight(analyzer, tree, &session) {
        RubyBoundedPreflight::Ready { ruby, tree } => (ruby, tree),
        RubyBoundedPreflight::AnalyzerUnavailable => {
            return session.finish(no_definition(
                "ruby_analyzer_unavailable",
                "Ruby analyzer is unavailable",
            ));
        }
        RubyBoundedPreflight::ParseFailed => {
            return session.finish(no_definition(
                "ruby_parse_failed",
                "Ruby source could not be parsed",
            ));
        }
        RubyBoundedPreflight::SourceFactsUnavailable => {
            return session.finish(no_definition(
                "ruby_source_facts_unavailable",
                "Canonical Ruby source facts are unavailable",
            ));
        }
    };
    let provider = RubyDefinitionProvider::new(ruby, &session);
    let outcome = resolve_ruby_bounded_in_session(&provider, file, source, tree.root_node(), site);
    session.finish(outcome)
}

pub(crate) fn ruby_site_for_focus(
    mut site: ResolvedReferenceSite,
    tree: &Tree,
    source: &str,
) -> ResolvedReferenceSite {
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return site;
    };
    match ruby_reference_node(node, source) {
        Some(RubyReferenceNode::Constant(constant)) => {
            site.text = ruby_node_text(constant, source)
                .trim_start_matches("::")
                .to_owned();
            site.range = ruby_node_range(constant);
            site.focus_start_byte = constant.start_byte();
            site.focus_end_byte = constant.end_byte();
        }
        Some(RubyReferenceNode::Method {
            call: Some(call),
            method,
        }) => {
            let receiver = call.child_by_field_name("receiver");
            let (owner, instance_receiver) = receiver.map_or((None, false), |receiver| {
                if matches!(receiver.kind(), "constant" | "scope_resolution") {
                    return (
                        Some(
                            ruby_node_text(receiver, source)
                                .trim_start_matches("::")
                                .to_owned(),
                        ),
                        false,
                    );
                }
                if receiver.kind() == "call"
                    && receiver
                        .child_by_field_name("method")
                        .is_some_and(|method| ruby_node_text(method, source) == "new")
                    && let Some(constructor_owner) = receiver.child_by_field_name("receiver")
                    && matches!(constructor_owner.kind(), "constant" | "scope_resolution")
                {
                    return (
                        Some(
                            ruby_node_text(constructor_owner, source)
                                .trim_start_matches("::")
                                .to_owned(),
                        ),
                        true,
                    );
                }
                (None, false)
            });
            let member = ruby_node_text(method, source);
            site.text = owner.map_or_else(
                || member.to_owned(),
                |owner| {
                    if instance_receiver {
                        format!("{owner}#{member}")
                    } else {
                        format!("{owner}.{member}")
                    }
                },
            );
            site.range = ruby_node_range(method);
            site.focus_start_byte = method.start_byte();
            site.focus_end_byte = method.end_byte();
        }
        _ => {}
    }
    site
}

fn resolve_ruby_bounded_in_session(
    provider: &RubyDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(node) = ruby_smallest_named_node_covering_bounded(
        provider,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Ruby definition",
                site.text
            ),
        );
    };
    match ruby_reference_node(node, source) {
        Some(RubyReferenceNode::Constant(constant)) => {
            if ruby_is_declaration_constant(constant) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            let Some(receiver) = context.constant_receiver_type(constant) else {
                return no_definition(
                    "no_indexed_definition",
                    format!(
                        "`{}` did not resolve to an exact indexed Ruby constant",
                        site.text
                    ),
                );
            };
            candidates_outcome(provider.fqn(&receiver.owner_fq_name))
        }
        Some(RubyReferenceNode::Method { call, method }) => {
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            ruby_bounded_method_outcome(provider, &context, call, method, source)
        }
        Some(RubyReferenceNode::Identifier(identifier)) => {
            if ruby_is_declaration_identifier(identifier) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            let context = BoundedRubyLookupContext::build(
                provider,
                file,
                source,
                root,
                site.focus_start_byte,
            );
            if context
                .local_receiver_type(ruby_node_text(identifier, source))
                .is_some()
            {
                return no_definition(
                    "local_variable_reference",
                    format!("`{}` is a local Ruby value", site.text),
                );
            }
            ruby_bounded_method_outcome(provider, &context, None, identifier, source)
        }
        Some(RubyReferenceNode::AutoloadSymbol(_)) => no_definition(
            "ruby_autoload_scope_unproven",
            "bounded Ruby lookup does not expand project-wide autoload conventions",
        ),
        Some(RubyReferenceNode::Variable(_)) => no_definition(
            "unsupported_ruby_receiver",
            "bounded Ruby field lookup requires heap/member refinement",
        ),
        None => no_definition(
            "unsupported_ruby_reference_shape",
            format!(
                "`{}` is a Ruby `{}` reference shape that bounded get_definition does not resolve",
                site.text,
                node.kind()
            ),
        ),
    }
}

pub(crate) fn ruby_type_lookup_resolution_bounded(
    provider: &RubyDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<RubyTypeLookupResolution> {
    let node = ruby_smallest_named_node_covering_bounded(
        provider,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let context =
        BoundedRubyLookupContext::build(provider, file, source, root, site.focus_start_byte);
    let receiver = context.expression_receiver_type(node)?;
    let target_kind = if receiver.mode == RubyReceiverMode::Class
        && matches!(node.kind(), "constant" | "scope_resolution")
    {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    Some(RubyTypeLookupResolution {
        fqn: receiver.owner_fq_name,
        target_kind,
    })
}

/// Retain an activated declaration's result identity for class-set propagation.
/// This proves the result of this expression, never the types of its callers'
/// parameters or a closed Ruby dispatch universe.
pub(crate) fn ruby_modeled_result_class_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    call: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<Option<crate::analyzer::semantic::ClassIdentity>> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let result = (|| {
        let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer)?;
        let overlay = analyzer.semantic_model_overlay()?;
        let mut provider = RubyDefinitionProvider::new(ruby, &session);
        provider.overlay = Some(&overlay);
        let context = BoundedRubyLookupContext::build(
            &provider,
            file,
            source,
            tree.root_node(),
            call.start_byte(),
        );
        let receiver = context.call_result_receiver_type(call, 0)?;
        if receiver.mode != RubyReceiverMode::Instance
            || !provider.fqn(&receiver.owner_fq_name).is_empty()
        {
            return None;
        }
        let constants = RubyOverlayConstants::new(Some(&overlay));
        let result =
            ruby_unshadowed_external_type(ruby, &session, constants, &receiver.owner_fq_name)?;
        crate::analyzer::semantic::type_flow::external_class_identity(
            Some(&overlay),
            Language::Ruby,
            &result.qualified_name,
            Some(&result.id),
            &mut crate::analyzer::semantic::type_flow::ExternalClassCache::default(),
        )
    })();
    session.finish(result)
}

fn ruby_bounded_method_outcome(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    call: Option<Node<'_>>,
    method: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    if call.is_some_and(|call| ruby_is_dynamic_dispatch(call, source)) {
        return no_definition(
            "unsupported_ruby_dynamic_dispatch",
            "Ruby send/public_send dispatch remains explicitly unsupported",
        );
    }
    let member = ruby_node_text(method, source);
    if member.is_empty() {
        return no_definition("no_reference_text", "Ruby method reference is blank");
    }
    let receiver = match call.and_then(|call| call.child_by_field_name("receiver")) {
        Some(receiver) => context.expression_receiver_type(receiver),
        None => context.enclosing_receiver(),
    };
    let Some(receiver) = receiver else {
        return no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby method `{member}` is not structurally resolved"),
        );
    };
    let Some(candidates) = ruby_bounded_method_candidates(provider, context, &receiver, member)
    else {
        return no_definition(
            "ruby_resolution_budget_exhausted",
            "Ruby visible-file resolution exceeded its bounded scope",
        );
    };
    if candidates.is_empty() {
        return no_definition(
            "ruby_inherited_or_dynamic_dispatch_unproven",
            format!(
                "Ruby method `{member}` has no exact direct declaration on `{}`; mixins, inheritance, refinements, monkeypatching, and method_missing remain open",
                receiver.owner_fq_name
            ),
        );
    }
    candidates_outcome(candidates)
}

fn ruby_bounded_method_candidates(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    receiver: &RubyReceiverType,
    member: &str,
) -> Option<Vec<CodeUnit>> {
    let bounded_definitions = AnalyzerDefinitionLookup::new(provider.ruby, Language::Ruby);
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&bounded_definitions);
    };
    let scope = AnalyzerQueryScope::new(provider.ruby);
    let semantic = RubySemanticIndex::build_for_lookup(
        RubyGraphSource {
            token: scope.token(),
            index: provider.ruby,
            definitions: &definitions,
        },
        provider.ruby,
    );
    let mut visible_files = provider.visible_files_from(&semantic, context.file)?;
    // Exact indexed owner declarations remain candidates without an explicit
    // require edge. Admit only their bounded source set alongside the require
    // closure; the semantic index still selects dispatch mode and precedence.
    // Otherwise the visibility filter would erase direct-owner evidence that
    // the bounded declaration lookup has already established.
    visible_files.extend(
        provider
            .members_for_owner_name(&receiver.owner_fq_name, member)
            .into_iter()
            .map(|unit| unit.source().clone()),
    );
    if receiver.mode == RubyReceiverMode::Class && member == "new" {
        visible_files.extend(
            provider
                .fqn(&receiver.owner_fq_name)
                .into_iter()
                .filter(CodeUnit::is_class)
                .map(|unit| unit.source().clone()),
        );
    }
    let mut candidates =
        semantic.resolve_method_candidates(provider, &visible_files, receiver, member);
    if candidates.is_empty() {
        candidates = ruby_default_constructor_candidates(
            provider,
            &semantic,
            &visible_files,
            receiver,
            member,
        );
    }
    Some(candidates)
}

fn ruby_dispatch_mode_matches(
    declaration: RubyMethodDispatchMode,
    receiver: RubyReceiverMode,
) -> bool {
    let mode = match receiver {
        RubyReceiverMode::Instance | RubyReceiverMode::TopLevel => {
            RubyMethodLookupMode::InstanceMethod
        }
        RubyReceiverMode::Class => RubyMethodLookupMode::SingletonMethod,
    };
    ruby_dispatch_matches_lookup_mode(declaration, mode)
}

fn ruby_default_constructor_candidates(
    support: &dyn BoundedDefinitionLookup,
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    receiver: &RubyReceiverType,
    member: &str,
) -> Vec<CodeUnit> {
    if member != "new" || receiver.mode != RubyReceiverMode::Class {
        return Vec::new();
    }
    let mut candidates = support
        .fqn(&receiver.owner_fq_name)
        .into_iter()
        .filter(|unit| {
            unit.is_class()
                && unit.fq_name() == receiver.owner_fq_name
                && visible_files.contains(unit.source())
        })
        .collect::<Vec<_>>();
    let initializer_receiver = RubyReceiverType {
        owner_fq_name: receiver.owner_fq_name.clone(),
        mode: RubyReceiverMode::Instance,
    };
    let inherited_initializers = semantic
        .resolve_method_candidates(support, visible_files, &initializer_receiver, "initialize")
        .into_iter()
        .filter(|initializer| {
            initializer
                .fq_name()
                .strip_suffix(initializer.identifier())
                .and_then(|owner| owner.strip_suffix('.'))
                .is_some_and(|owner| owner != receiver.owner_fq_name)
        })
        .collect::<Vec<_>>();
    if !inherited_initializers.is_empty() {
        return inherited_initializers;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

// Completed controls share one transfer walk. Only locals written inside the
// control are snapshotted; all other lexical and receiver context stays put.
trait RubyCompletedLocals {
    fn step(&self) -> bool;
    fn source(&self) -> &str;
    fn local(&self, name: &str) -> Option<RubyReceiverType>;
    fn set_local(&mut self, name: &str, value: Option<RubyReceiverType>);
    fn assign(&mut self, node: Node<'_>);
}

struct RubyWriteBudget<'a, C>(&'a C);

impl<C: RubyCompletedLocals> LocalBindingBudget for RubyWriteBudget<'_, C> {
    type Error = ();

    fn enter_node(&mut self) -> Result<(), Self::Error> {
        self.0.step().then_some(()).ok_or(())
    }

    fn before_insert(&mut self) -> Result<(), Self::Error> {
        self.enter_node()
    }

    fn charge_name(&mut self, _name: &str) -> Result<(), Self::Error> {
        self.enter_node()
    }
}

fn ruby_completed_writes(
    context: &impl RubyCompletedLocals,
    root: Node<'_>,
) -> Option<(Vec<String>, bool)> {
    let mut names = HashSet::default();
    let mut abrupt = false;
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if !context.step() {
            return None;
        }
        if matches!(
            node.kind(),
            "method" | "singleton_method" | "class" | "module" | "singleton_class" | "lambda"
        ) {
            continue;
        }
        abrupt |= matches!(node.kind(), "return" | "break" | "next" | "redo" | "retry");
        let Ok(writes) = collect_local_write(context.source(), node, &mut RubyWriteBudget(context))
        else {
            return None;
        };
        for (name, _) in writes.activations() {
            if !context.step() {
                return None;
            }
            names.insert(name.to_owned());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !context.step() {
                return None;
            }
            pending.push(child);
        }
    }
    Some((names.into_iter().collect(), abrupt))
}

fn ruby_invalidate_completed(context: &mut impl RubyCompletedLocals, root: Node<'_>) -> bool {
    let Some((names, _)) = ruby_completed_writes(context, root) else {
        return false;
    };
    for name in names {
        if !context.step() {
            return false;
        }
        context.set_local(&name, None);
    }
    true
}

fn ruby_local_snapshot(
    context: &impl RubyCompletedLocals,
    names: &[String],
) -> Option<Vec<Option<RubyReceiverType>>> {
    let mut values = Vec::with_capacity(names.len());
    for name in names {
        if !context.step() {
            return None;
        }
        values.push(context.local(name));
    }
    Some(values)
}

fn ruby_restore_locals(
    context: &mut impl RubyCompletedLocals,
    names: &[String],
    values: &[Option<RubyReceiverType>],
) -> bool {
    assert_eq!(names.len(), values.len());
    for (name, value) in names.iter().zip(values) {
        if !context.step() {
            return false;
        }
        context.set_local(name, value.clone());
    }
    true
}

fn ruby_transfer_completed(context: &mut impl RubyCompletedLocals, root: Node<'_>) {
    let Some((names, abrupt)) = ruby_completed_writes(context, root) else {
        return;
    };
    if names.is_empty() {
        return;
    }
    if abrupt || root.has_error() {
        // This local analysis does not prove abrupt-edge reachability. Do not
        // let an assignment following an exit establish a receiver at the join.
        for name in names {
            if !context.step() {
                return;
            }
            context.set_local(&name, None);
        }
        return;
    }
    enum Frame<'tree> {
        Eval(Node<'tree>),
        Child(Node<'tree>, usize),
        Split(Vec<Option<Node<'tree>>>),
        Case(Node<'tree>),
        Branch {
            arms: Vec<Option<Node<'tree>>>,
            next: usize,
            incoming: Vec<Option<RubyReceiverType>>,
            merged: Option<Vec<Option<RubyReceiverType>>>,
        },
    }
    let mut pending = vec![Frame::Eval(root)];
    while let Some(frame) = pending.pop() {
        if !context.step() {
            return;
        }
        match frame {
            Frame::Eval(node) => match node.kind() {
                "assignment" => {
                    if let Some(right) = node.child_by_field_name("right")
                        && !ruby_invalidate_completed(context, right)
                    {
                        return;
                    }
                    if node
                        .child_by_field_name("left")
                        .is_some_and(|left| left.kind() == "identifier")
                    {
                        context.assign(node);
                    } else if !ruby_invalidate_completed(context, node) {
                        return;
                    }
                }
                "if" | "unless" | "elsif" => {
                    pending.push(Frame::Split(vec![
                        node.child_by_field_name("consequence"),
                        node.child_by_field_name("alternative"),
                    ]));
                    if let Some(condition) = node.child_by_field_name("condition") {
                        pending.push(Frame::Eval(condition));
                    }
                }
                "if_modifier" | "unless_modifier" => {
                    pending.push(Frame::Split(vec![node.child_by_field_name("body"), None]));
                    if let Some(condition) = node.child_by_field_name("condition") {
                        pending.push(Frame::Eval(condition));
                    }
                }
                "case" => {
                    pending.push(Frame::Case(node));
                    if let Some(value) = node.child_by_field_name("value") {
                        pending.push(Frame::Eval(value));
                    }
                }
                "begin" | "body_statement" => {
                    let mut has_handlers = false;
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if !context.step() {
                            return;
                        }
                        has_handlers |= matches!(child.kind(), "rescue" | "else" | "ensure");
                    }
                    if has_handlers {
                        if !ruby_invalidate_completed(context, node) {
                            return;
                        }
                    } else {
                        pending.push(Frame::Child(node, 0));
                    }
                }
                "then" | "else" | "parenthesized_statements" => {
                    pending.push(Frame::Child(node, 0));
                }
                _ => {
                    // Loops, deferred calls/blocks, pattern matching and other
                    // unsupported expressions cannot establish a reaching value.
                    if !ruby_invalidate_completed(context, node) {
                        return;
                    }
                }
            },
            Frame::Child(node, index) => {
                if index < node.named_child_count() {
                    pending.push(Frame::Child(node, index + 1));
                    if let Some(child) = node.named_child(index) {
                        pending.push(Frame::Eval(child));
                    }
                }
            }
            Frame::Case(node) => {
                let mut arms = Vec::new();
                let mut has_else = false;
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !context.step() {
                        return;
                    }
                    match child.kind() {
                        "when" => {
                            // Patterns are evaluated in order and may stop at a
                            // match. Conservatively forget their possible writes
                            // before branching, rather than execute them eagerly.
                            let mut patterns = child.walk();
                            for pattern in child.children_by_field_name("pattern", &mut patterns) {
                                if !context.step() || !ruby_invalidate_completed(context, pattern) {
                                    return;
                                }
                            }
                            arms.push(child.child_by_field_name("body"));
                        }
                        "else" => {
                            has_else = true;
                            arms.push(Some(child));
                        }
                        _ => {}
                    }
                }
                if !has_else {
                    arms.push(None);
                }
                pending.push(Frame::Split(arms));
            }
            Frame::Split(arms) => {
                let Some(incoming) = ruby_local_snapshot(context, &names) else {
                    return;
                };
                pending.push(Frame::Branch {
                    arms,
                    next: 0,
                    incoming,
                    merged: None,
                });
            }
            Frame::Branch {
                arms,
                next,
                incoming,
                mut merged,
            } => {
                if next > 0 {
                    let Some(values) = ruby_local_snapshot(context, &names) else {
                        return;
                    };
                    if let Some(merged) = merged.as_mut() {
                        for (agreed, value) in merged.iter_mut().zip(values) {
                            if !context.step() {
                                return;
                            }
                            if !matches!((&*agreed, &value), (Some(left), Some(right))
                                if left.owner_fq_name == right.owner_fq_name && left.mode == right.mode)
                            {
                                *agreed = None;
                            }
                        }
                    } else {
                        merged = Some(values);
                    }
                }
                if next == arms.len() {
                    let values = merged.expect("a control join has at least one path");
                    if !ruby_restore_locals(context, &names, &values) {
                        return;
                    }
                } else {
                    if !ruby_restore_locals(context, &names, &incoming) {
                        return;
                    }
                    let arm = arms[next];
                    pending.push(Frame::Branch {
                        arms,
                        next: next + 1,
                        incoming,
                        merged,
                    });
                    if let Some(arm) = arm {
                        pending.push(Frame::Eval(arm));
                    }
                }
            }
        }
    }
}

struct RubyInstanceFields {
    owner: String,
    types: HashMap<Box<str>, Option<RubyReceiverType>>,
}

struct BoundedRubyLookupContext<'a, 'tree> {
    provider: &'a RubyDefinitionProvider<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    lexical_stack: Vec<String>,
    method_stack: Vec<RubyReceiverMode>,
    receiver_context: Vec<RubyReceiverMode>,
    local_scopes: Vec<HashMap<Box<str>, Option<RubyReceiverType>>>,
    instance_fields: Option<RubyInstanceFields>,
    exits: Vec<BoundedRubyExit>,
    focus_start: usize,
    inference_depth: usize,
}

impl<'a, 'tree> BoundedRubyLookupContext<'a, 'tree> {
    fn new(
        provider: &'a RubyDefinitionProvider<'a>,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        focus_start: usize,
    ) -> Self {
        Self {
            provider,
            file,
            source,
            root,
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            receiver_context: Vec::new(),
            local_scopes: vec![HashMap::default()],
            instance_fields: None,
            exits: Vec::new(),
            focus_start,
            inference_depth: 0,
        }
    }

    fn build(
        provider: &'a RubyDefinitionProvider<'a>,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'tree>,
        focus_start: usize,
    ) -> Self {
        let mut context = Self::new(provider, file, source, root, focus_start);
        context.walk_to_focus(root);
        context
    }

    fn walk_to_focus(&mut self, root: Node<'_>) {
        let mut stack = vec![BoundedRubyFrame::Enter(root)];
        let mut reached_focus = false;
        while let Some(frame) = stack.pop() {
            if reached_focus || !self.provider.scope_step() {
                break;
            }
            match frame {
                BoundedRubyFrame::Enter(node) => match self.enter(node) {
                    BoundedRubyWalkAction::Descend => {
                        stack.push(BoundedRubyFrame::NextChild { node, index: 0 });
                    }
                    BoundedRubyWalkAction::DescendWithExit => {
                        stack.push(BoundedRubyFrame::Exit);
                        stack.push(BoundedRubyFrame::NextChild { node, index: 0 });
                    }
                    BoundedRubyWalkAction::Skip => {
                        reached_focus = node.start_byte() >= self.focus_start;
                    }
                },
                BoundedRubyFrame::NextChild { node, index } => {
                    if index < node.named_child_count() {
                        stack.push(BoundedRubyFrame::NextChild {
                            node,
                            index: index + 1,
                        });
                        if let Some(child) = node.named_child(index) {
                            stack.push(BoundedRubyFrame::Enter(child));
                        }
                    }
                }
                BoundedRubyFrame::Exit => self.exit(),
            }
        }
    }

    fn enter(&mut self, node: Node<'_>) -> BoundedRubyWalkAction {
        if node.start_byte() >= self.focus_start {
            return BoundedRubyWalkAction::Skip;
        }
        if node.end_byte() <= self.focus_start {
            ruby_transfer_completed(self, node);
            return BoundedRubyWalkAction::Skip;
        }
        match node.kind() {
            "class" | "module" => {
                let owner = node
                    .child_by_field_name("name")
                    .and_then(|name| self.resolve_constant_owner(name));
                if let Some(owner) = owner.as_ref() {
                    self.lexical_stack.push(owner.clone());
                }
                self.receiver_context.push(RubyReceiverMode::Instance);
                self.exits.push(BoundedRubyExit::Type {
                    has_lexical_owner: owner.is_some(),
                });
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "method" | "singleton_method" => {
                self.method_stack.push(ruby_method_receiver_mode(
                    node,
                    self.receiver_context.last().copied(),
                ));
                self.local_scopes.push(HashMap::default());
                self.seed_parameter_shadows(node);
                self.exits.push(BoundedRubyExit::Method);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.method_stack.push(RubyReceiverMode::Class);
                self.receiver_context.push(RubyReceiverMode::Class);
                self.local_scopes.push(HashMap::default());
                self.exits.push(BoundedRubyExit::SingletonClass);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                let inherited = self.local_scopes.last().cloned().unwrap_or_default();
                self.local_scopes.push(inherited);
                self.seed_parameter_shadows(node);
                self.exits.push(BoundedRubyExit::LocalScope);
                return BoundedRubyWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        BoundedRubyWalkAction::Descend
    }

    fn exit(&mut self) {
        match self.exits.pop() {
            Some(BoundedRubyExit::Type { has_lexical_owner }) => {
                assert!(
                    matches!(
                        self.receiver_context.pop(),
                        Some(RubyReceiverMode::Instance)
                    ),
                    "type receiver context must match its exit"
                );
                if has_lexical_owner {
                    self.lexical_stack.pop();
                }
            }
            Some(BoundedRubyExit::Method) => {
                self.method_stack.pop();
                self.local_scopes.pop();
            }
            Some(BoundedRubyExit::SingletonClass) => {
                assert!(
                    matches!(self.receiver_context.pop(), Some(RubyReceiverMode::Class)),
                    "singleton-class receiver context must match its exit"
                );
                self.method_stack.pop();
                self.local_scopes.pop();
            }
            Some(BoundedRubyExit::LocalScope) => {
                self.local_scopes.pop();
            }
            None => {}
        }
    }

    fn seed_parameter_shadows(&mut self, callable: Node<'_>) {
        let provider = self.provider;
        let layout =
            formal_parameter_slots_for_owner_bounded(Language::Ruby, callable, self.source, || {
                provider.scope_step()
            })
            .unwrap_or_default();
        let Some(locals) = self.local_scopes.last_mut() else {
            return;
        };
        for slot in layout.slots {
            for name in slot.names {
                locals.insert(name.into_boxed_str(), None);
            }
        }
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        if left.kind() != "identifier" {
            if self.provider.overlay.is_some() {
                ruby_invalidate_completed(self, node);
            }
            return;
        }
        let name = ruby_node_text(left, self.source);
        if name.is_empty() {
            return;
        }
        // Ruby introduces the LHS binding before evaluating its RHS.
        if let Some(locals) = self.local_scopes.last_mut() {
            locals.entry(name.into()).or_insert(None);
        }
        let value = node
            .child_by_field_name("right")
            .and_then(|right| self.expression_receiver_type(right));
        if let Some(locals) = self.local_scopes.last_mut() {
            locals.insert(name.into(), value);
        }
    }

    fn local_receiver_type(&self, name: &str) -> Option<RubyReceiverType> {
        self.local_scopes
            .last()
            .and_then(|locals| locals.get(name))
            .cloned()
            .flatten()
    }

    fn enclosing_receiver(&self) -> Option<RubyReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack)
    }

    fn constant_receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        self.resolve_constant_owner(node)
            .or_else(|| self.modeled_constant_owner(node))
            .map(|owner_fq_name| RubyReceiverType {
                owner_fq_name,
                mode: RubyReceiverMode::Class,
            })
    }

    fn modeled_constant_owner(&self, node: Node<'_>) -> Option<String> {
        let constants = RubyOverlayConstants::new(Some(self.provider.overlay?));
        let path = self.constant_name_path(node)?;
        // A workspace declaration of any prefix can shadow this external
        // path, even when the declaring file is not required by this file.
        for end in 1..=path.segments.len() {
            let relative = path.segments[..end].join("$");
            if !self.provider.fqn(&relative).is_empty() {
                return None;
            }
            if !path.absolute {
                for lexical in &self.lexical_stack {
                    if !self
                        .provider
                        .fqn(&format!("{lexical}${relative}"))
                        .is_empty()
                    {
                        return None;
                    }
                }
            }
        }
        constants
            .unique_type(&path.segments.join("::"))
            .map(|owner| owner.qualified_name.clone())
    }

    fn expression_receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        self.expression_receiver_type_at_depth(node, self.inference_depth)
    }

    fn expression_receiver_type_at_depth(
        &self,
        mut node: Node<'_>,
        depth: usize,
    ) -> Option<RubyReceiverType> {
        if depth >= 12 || !self.provider.scope_step() {
            return None;
        }
        while matches!(node.kind(), "parenthesized_statements") {
            if !self.provider.scope_step() {
                return None;
            }
            if node.named_child_count() != 1 {
                return None;
            }
            node = ruby_first_named_child(node)?;
        }
        match node.kind() {
            "string" | "string_content" => Some(RubyReceiverType {
                owner_fq_name: "String".to_owned(),
                mode: RubyReceiverMode::Instance,
            }),
            "constant" | "scope_resolution" => self.constant_receiver_type(node),
            "self" => self.enclosing_receiver(),
            "identifier" => {
                let name = ruby_node_text(node, self.source);
                if self
                    .local_scopes
                    .last()
                    .is_some_and(|locals| locals.contains_key(name))
                {
                    self.local_receiver_type(name)
                } else {
                    let receiver = self.enclosing_receiver()?;
                    self.workspace_method_result(&receiver, name, depth + 1)
                }
            }
            "instance_variable" => {
                let fields = self.instance_fields.as_ref()?;
                let receiver = self.enclosing_receiver()?;
                if receiver.mode != RubyReceiverMode::Instance
                    || receiver.owner_fq_name != fields.owner
                {
                    return None;
                }
                fields
                    .types
                    .get(ruby_node_text(node, self.source))
                    .cloned()
                    .flatten()
            }
            "call" => self.call_result_receiver_type(node, depth + 1),
            _ => None,
        }
    }

    fn call_result_receiver_type(&self, call: Node<'_>, depth: usize) -> Option<RubyReceiverType> {
        if depth >= 12 || !self.provider.scope_step() {
            return None;
        }
        let method = call.child_by_field_name("method")?;
        let method_name = ruby_node_text(method, self.source);
        if method_name.is_empty() || matches!(method_name, "send" | "public_send") {
            return None;
        }
        let receiver = match call.child_by_field_name("receiver") {
            Some(receiver) => self.expression_receiver_type_at_depth(receiver, depth + 1)?,
            None => self.enclosing_receiver()?,
        };
        let constants = RubyOverlayConstants::new(self.provider.overlay);
        if let Some(owner) = constants.unique_type(&receiver.owner_fq_name)
            && self.provider.fqn(&receiver.owner_fq_name).is_empty()
        {
            let member =
                constants.callable(owner, method_name, ruby_positional_argument_count(call)?)?;
            if member.is_static() != (receiver.mode == RubyReceiverMode::Class) {
                return None;
            }
            let result = constants.declared_result(member)?;
            return Some(RubyReceiverType {
                owner_fq_name: result.qualified_name.clone(),
                mode: RubyReceiverMode::Instance,
            });
        }
        if method_name == "new" {
            return (receiver.mode == RubyReceiverMode::Class).then_some(RubyReceiverType {
                owner_fq_name: receiver.owner_fq_name,
                mode: RubyReceiverMode::Instance,
            });
        }
        self.workspace_method_result(&receiver, method_name, depth + 1)
    }

    fn workspace_method_result(
        &self,
        receiver: &RubyReceiverType,
        method_name: &str,
        depth: usize,
    ) -> Option<RubyReceiverType> {
        if depth >= 12 || !self.provider.scope_step() {
            return None;
        }
        let mut candidates =
            ruby_bounded_method_candidates(self.provider, self, receiver, method_name)?;
        candidates.retain(|unit| {
            unit.is_function()
                && self
                    .provider
                    .method_dispatch_mode(unit)
                    .is_some_and(|mode| ruby_dispatch_mode_matches(mode, receiver.mode))
        });
        sort_units(&mut candidates);
        candidates.dedup();
        let method = (candidates.len() == 1).then(|| candidates.remove(0))?;
        self.factory_method_return_receiver_type(&method, receiver, depth + 1)
    }

    fn factory_method_return_receiver_type(
        &self,
        method: &CodeUnit,
        invocation_receiver: &RubyReceiverType,
        depth: usize,
    ) -> Option<RubyReceiverType> {
        if depth >= 12 || method.source() != self.file || !self.provider.scope_step() {
            return None;
        }
        let owner = self.provider.parent(method)?;
        if owner.fq_name() != invocation_receiver.owner_fq_name {
            return None;
        }
        let ranges = self.provider.ranges(method);
        let range = (ranges.len() == 1).then(|| ranges[0])?;
        let method_node = self.method_node_for_range(&range)?;
        if method_node.has_error() {
            return None;
        }
        let body = method_node.child_by_field_name("body")?;
        let tail = self.tail_expression(method_node)?;
        // A tail value is not a return summary when another exit can bypass it.
        // Keep unsupported control-flow returns open instead of picking a branch.
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            if !self.provider.scope_step() {
                return None;
            }
            if matches!(
                node.kind(),
                "method" | "singleton_method" | "class" | "module" | "lambda"
            ) {
                continue;
            }
            if matches!(
                node.kind(),
                "return" | "break" | "next" | "redo" | "retry" | "rescue" | "ensure"
            ) && !(node == tail && node.kind() == "return")
            {
                return None;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !self.provider.scope_step() {
                    return None;
                }
                pending.push(child);
            }
        }
        // Evaluate in the factory's lexical/local scope, never the caller's.
        let mut context = Self::new(
            self.provider,
            self.file,
            self.source,
            self.root,
            tail.start_byte(),
        );
        context.inference_depth = depth;
        context.walk_to_focus(self.root);
        if context
            .enclosing_receiver()
            .as_ref()
            .is_none_or(|receiver| {
                receiver.owner_fq_name != invocation_receiver.owner_fq_name
                    || receiver.mode != invocation_receiver.mode
            })
        {
            return None;
        }
        let mut expression = tail;
        if expression.kind() == "assignment" {
            let left = expression.child_by_field_name("left")?;
            if left.kind() != "identifier" {
                return None;
            }
            context.seed_assignment(expression);
            return context.local_receiver_type(ruby_node_text(left, self.source));
        } else if expression.kind() == "return" {
            let arguments = ruby_first_named_child(expression)?;
            expression = if arguments.kind() == "argument_list" {
                if arguments.named_child_count() != 1 {
                    return None;
                }
                ruby_first_named_child(arguments)?
            } else {
                arguments
            };
        }
        context.expression_receiver_type_at_depth(expression, depth + 1)
    }

    fn method_node_for_range(&self, range: &Range) -> Option<Node<'tree>> {
        let mut node = self.root;
        loop {
            if !self.provider.scope_step() {
                return None;
            }
            if range.start_byte == node.start_byte()
                && range.end_byte == node.end_byte()
                && matches!(node.kind(), "method" | "singleton_method")
            {
                return Some(node);
            }
            let mut next = None;
            for index in 0..node.named_child_count() {
                if !self.provider.scope_step() {
                    return None;
                }
                let child = node.named_child(index)?;
                if child.start_byte() <= range.start_byte && range.end_byte <= child.end_byte() {
                    next = Some(child);
                    break;
                }
            }
            node = next?;
        }
    }

    fn tail_expression(&self, method: Node<'tree>) -> Option<Node<'tree>> {
        let body = method.child_by_field_name("body")?;
        let mut tail = None;
        for index in 0..body.named_child_count() {
            if !self.provider.scope_step() {
                return None;
            }
            tail = body.named_child(index);
        }
        tail
    }

    fn resolve_constant_owner(&self, node: Node<'_>) -> Option<String> {
        let path = self.constant_name_path(node)?;
        if path.segments.is_empty() {
            return None;
        }
        let relative = path.segments.join("$");
        let mut candidates = Vec::new();
        if !path.absolute {
            candidates.extend(
                self.lexical_stack
                    .iter()
                    .rev()
                    .map(|owner| format!("{owner}${relative}")),
            );
        }
        candidates.push(relative);
        candidates.into_iter().find(|candidate| {
            self.provider
                .fqn(candidate)
                .into_iter()
                .any(|unit| unit.fq_name() == *candidate && (unit.is_class() || unit.is_module()))
        })
    }

    /// Interpret a Ruby constant path from tree-sitter fields while charging
    /// every visited path node to this bounded lookup. Ruby nests
    /// `scope_resolution` nodes to the left, so an explicit stack preserves
    /// source order without an unmetered recursive descent.
    fn constant_name_path(&self, node: Node<'_>) -> Option<RubyNamePath> {
        let mut stack = vec![node];
        let mut segments = Vec::new();
        let mut absolute = false;
        while let Some(current) = stack.pop() {
            if !self.provider.scope_step() {
                return None;
            }
            match current.kind() {
                "scope_resolution" => {
                    let name = current.child_by_field_name("name")?;
                    stack.push(name);
                    if let Some(scope) = current.child_by_field_name("scope") {
                        stack.push(scope);
                    } else {
                        absolute = true;
                    }
                }
                "constant" => {
                    let segment = ruby_node_text(current, self.source);
                    if segment.is_empty() {
                        return None;
                    }
                    segments.push(segment.to_string());
                }
                _ => return None,
            }
        }
        Some(RubyNamePath { segments, absolute })
    }
}

impl RubyCompletedLocals for BoundedRubyLookupContext<'_, '_> {
    fn step(&self) -> bool {
        self.provider.scope_step()
    }

    fn source(&self) -> &str {
        self.source
    }

    fn local(&self, name: &str) -> Option<RubyReceiverType> {
        self.local_receiver_type(name)
    }

    fn set_local(&mut self, name: &str, value: Option<RubyReceiverType>) {
        self.local_scopes
            .last_mut()
            .expect("Ruby lookup always has a local scope")
            .insert(name.into(), value);
    }

    fn assign(&mut self, node: Node<'_>) {
        self.seed_assignment(node);
    }
}

enum BoundedRubyFrame<'tree> {
    Enter(Node<'tree>),
    NextChild { node: Node<'tree>, index: usize },
    Exit,
}

enum BoundedRubyWalkAction {
    Descend,
    DescendWithExit,
    Skip,
}

enum BoundedRubyExit {
    Type { has_lexical_owner: bool },
    Method,
    SingletonClass,
    LocalScope,
}

fn ruby_smallest_named_node_covering_bounded<'tree>(
    provider: &RubyDefinitionProvider<'_>,
    node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if start > end || start < node.start_byte() || end > node.end_byte() {
        return None;
    }
    brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        node,
        start,
        end,
        || provider.scope_step(),
    )
}

fn ruby_first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::first_named_child(node)
}

pub(super) fn resolve_ruby(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return no_definition("ruby_analyzer_unavailable", "Ruby analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("ruby_parse_failed", "Ruby source could not be parsed");
    };
    if !ruby.canonical_sources_ready() {
        return no_definition(
            "ruby_source_facts_unavailable",
            "Canonical Ruby source facts are unavailable",
        );
    }
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Ruby definition",
                site.text
            ),
        );
    };

    let bounded_definitions = AnalyzerDefinitionLookup::new(analyzer, Language::None);
    let definitions = |consume: &mut dyn FnMut(&dyn BoundedDefinitionLookup)| {
        consume(&bounded_definitions);
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let semantic = RubySemanticIndex::build_for_lookup(
        RubyGraphSource {
            token: scope.token(),
            index: analyzer,
            definitions: &definitions,
        },
        ruby,
    );
    let Some(visible_files) = semantic.visible_files_from(file) else {
        return no_definition(
            "ruby_source_facts_unavailable",
            "Canonical Ruby load closure is unavailable",
        );
    };
    let context = RubyLookupContext::build(
        analyzer,
        &semantic,
        file,
        source,
        &visible_files,
        root,
        site.focus_start_byte,
    );

    match ruby_reference_node(node, source) {
        Some(RubyReferenceNode::Constant(constant)) => {
            if ruby_is_declaration_constant(constant) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            ruby_constant_outcome(&semantic, file, &visible_files, &context, constant, source)
        }
        Some(RubyReferenceNode::AutoloadSymbol(symbol)) => {
            ruby_autoload_symbol_outcome(&semantic, file, &visible_files, &context, symbol, source)
        }
        Some(RubyReferenceNode::Method { call, method }) => ruby_method_outcome(
            support,
            &semantic,
            &visible_files,
            &context,
            call,
            method,
            source,
        ),
        Some(RubyReferenceNode::Identifier(identifier)) => {
            if ruby_is_declaration_identifier(identifier) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a Ruby reference site", site.text),
                );
            }
            if context
                .locals
                .is_shadowed(ruby_node_text(identifier, source))
            {
                return no_definition(
                    "local_variable_reference",
                    format!("`{}` is a local Ruby value", site.text),
                );
            }
            ruby_method_outcome(
                support,
                &semantic,
                &visible_files,
                &context,
                None,
                identifier,
                source,
            )
        }
        Some(RubyReferenceNode::Variable(variable)) => {
            ruby_field_outcome(analyzer, support, &semantic, &context, variable, source)
        }
        None => no_definition(
            "unsupported_ruby_reference_shape",
            format!(
                "`{}` is a Ruby `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

enum RubyReferenceNode<'tree> {
    Constant(Node<'tree>),
    AutoloadSymbol(Node<'tree>),
    Method {
        call: Option<Node<'tree>>,
        method: Node<'tree>,
    },
    Identifier(Node<'tree>),
    Variable(Node<'tree>),
}

fn ruby_reference_node<'tree>(node: Node<'tree>, source: &str) -> Option<RubyReferenceNode<'tree>> {
    match node.kind() {
        "constant" => Some(RubyReferenceNode::Constant(ruby_focused_constant_path(
            node,
        ))),
        "simple_symbol"
            if crate::analyzer::ruby::is_ruby_autoload_symbol_argument(node, source) =>
        {
            Some(RubyReferenceNode::AutoloadSymbol(node))
        }
        "scope_resolution" => Some(RubyReferenceNode::Constant(node)),
        "instance_variable" | "class_variable" => Some(RubyReferenceNode::Variable(node)),
        "identifier" => {
            if ruby_is_call_method_identifier(node) {
                return Some(RubyReferenceNode::Method {
                    call: node.parent(),
                    method: node,
                });
            }
            Some(RubyReferenceNode::Identifier(node))
        }
        "call" => node
            .child_by_field_name("method")
            .map(|method| RubyReferenceNode::Method {
                call: Some(node),
                method,
            }),
        _ => {
            let parent = node.parent()?;
            match parent.kind() {
                "call" if parent.child_by_field_name("method") == Some(node) => {
                    Some(RubyReferenceNode::Method {
                        call: Some(parent),
                        method: node,
                    })
                }
                _ => None,
            }
        }
    }
}

/// Resolve a constant path *up to and including* the focused segment: clicking
/// `Foo` in `Foo::Bar::Baz` targets `Foo`, `Bar` targets `Foo::Bar`, and `Baz`
/// targets the whole path. tree-sitter nests `scope_resolution` to the left, so a
/// segment's enclosing path is its parent `scope_resolution` exactly when the
/// segment is that node's terminal `name` (a left `scope` segment resolves to just
/// the constant). This also covers assignment-LHS chains, whose leftmost scope
/// segment naturally resolves to itself.
fn ruby_focused_constant_path(node: Node<'_>) -> Node<'_> {
    if let Some(parent) = node.parent()
        && parent.kind() == "scope_resolution"
        && parent.child_by_field_name("name") == Some(node)
    {
        parent
    } else {
        node
    }
}

fn ruby_constant_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    if let Some(unit) =
        semantic.resolve_constant(file, visible_files, &context.lexical_stack, node, source)
    {
        return candidates_outcome(vec![unit]);
    }
    // `ruby_constant_path_leaves_the_workspace` fuses the qualified-path shape
    // with the workspace-declaration check, so its negation is the
    // workspace-internal gate.
    gated_boundary(
        || !ruby_constant_path_leaves_the_workspace(semantic, context, node, source),
        format!("`{raw}` appears to cross a Ruby gem boundary not indexed in this workspace"),
        UnindexedClaim::external_boundary(raw, ClaimSubjectRole::Any),
        "no_indexed_definition",
        format!("`{raw}` did not resolve to an indexed Ruby definition"),
    )
}

/// Whether an unresolved constant reference routes out of the workspace.
///
/// Only an explicitly qualified path whose owner is itself written as constants
/// (`Widget::Config`) can say so, which is the same candidate shape Ruby's
/// proof-gated diagnostics judge. Ruby's top-level constant surface includes the
/// core library, everything `Object` inherits, and whatever every loaded gem
/// defined as a side effect, none of which Bifrost publishes, so a bare constant
/// that misses proves nothing about where the name lives (#1624). An owner that
/// is an arbitrary expression (`registry.current::Config`) names its namespace
/// only while the program runs, so nothing static can place it either.
///
/// The owner is then checked against the workspace's own declarations
/// regardless of which files this one can reach. That is the #1089
/// workspace-namespace gate: a project file may declare `Widget` without this
/// file requiring it, and an unreached workspace declaration is a plain miss,
/// never a route out of the workspace.
fn ruby_constant_path_leaves_the_workspace(
    semantic: &RubySemanticIndex<'_>,
    context: &RubyLookupContext<'_>,
    node: Node<'_>,
    source: &str,
) -> bool {
    let Some(owner) = node
        .child_by_field_name("scope")
        .filter(|owner| matches!(owner.kind(), "constant" | "scope_resolution"))
    else {
        return false;
    };
    !semantic.declares_constant_anywhere(&context.lexical_stack, owner, source)
}

fn ruby_autoload_symbol_outcome(
    semantic: &RubySemanticIndex<'_>,
    file: &ProjectFile,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    let Some(name) = crate::analyzer::ruby::ruby_symbol_name(node, source) else {
        return no_definition(
            "unsupported_ruby_reference_shape",
            format!("`{raw}` is not a Ruby autoload constant symbol"),
        );
    };
    let Some(unit) =
        semantic.resolve_constant_name(file, visible_files, &context.lexical_stack, &name)
    else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to an indexed Ruby definition"),
        );
    };
    candidates_outcome(vec![unit])
}

fn ruby_field_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    semantic: &RubySemanticIndex<'_>,
    context: &RubyLookupContext,
    node: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    let raw = ruby_node_text(node, source);
    let Some((owner, scope)) =
        ruby_field_reference_owner_and_scope(&context.lexical_stack, &context.method_stack, node)
    else {
        return no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby field `{raw}` is not resolved"),
        );
    };

    let owners: Vec<String> = match scope {
        RubyFieldScope::ClassVariable => std::iter::once(owner.clone())
            .chain(semantic.forward_ancestor_lookup_order(
                support,
                &context.visible_files.iter().cloned().collect::<Vec<_>>(),
                &owner,
            ))
            .collect(),
        RubyFieldScope::Instance | RubyFieldScope::SingletonClass => vec![owner],
    };

    let mut candidates = Vec::new();
    for owner in owners {
        let segments: Vec<String> = owner
            // fqname-M4: `owner` is a `&str` owner name from an import/reference chain, not a CodeUnit; ruby joins its whole type chain with `$`
            .split('$')
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect();
        if let Some(fqn) = ruby_field_short_name(&segments, node, source, scope) {
            candidates.extend(support.fqn(&fqn));
        }
    }
    candidates.retain(|unit| {
        unit.is_field()
            && unit.identifier() == raw
            && context.visible_files.contains(unit.source())
            && ruby_field_target_from_code_unit(unit).is_some_and(|target| target.scope == scope)
    });
    sort_units(&mut candidates);
    candidates.dedup();

    if candidates
        .iter()
        .any(|candidate| ruby_is_indexed_field_declaration_site(analyzer, candidate, node))
    {
        return no_definition(
            "declaration_or_import_site",
            format!("`{raw}` is not a Ruby reference site"),
        );
    }

    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("Ruby field `{raw}` did not resolve to an indexed definition"),
        );
    }
    candidates_outcome(candidates)
}

fn ruby_is_indexed_field_declaration_site(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    node: Node<'_>,
) -> bool {
    if !ruby_is_plain_assignment_left_variable(node) {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    analyzer
        .ranges(target)
        .iter()
        .any(|range| range.start_byte == parent.start_byte() && range.end_byte == parent.end_byte())
}

fn ruby_method_outcome(
    support: &dyn BoundedDefinitionLookup,
    semantic: &RubySemanticIndex<'_>,
    visible_files: &HashSet<ProjectFile>,
    context: &RubyLookupContext,
    call: Option<Node<'_>>,
    method: Node<'_>,
    source: &str,
) -> DefinitionLookupOutcome {
    if call.is_some_and(|call| ruby_is_dynamic_dispatch(call, source)) {
        return no_definition(
            "unsupported_ruby_dynamic_dispatch",
            "Ruby dynamic dispatch is not resolved by get_definition",
        );
    }

    let member = ruby_node_text(method, source);
    if member.is_empty() {
        return no_definition("no_reference_text", "Ruby method reference is blank");
    }

    let receiver_node = call.and_then(|call| call.child_by_field_name("receiver"));
    let receiver = match receiver_node {
        Some(receiver) => context.receiver_type(receiver),
        None => context.enclosing_receiver(),
    };
    let Some(receiver) = receiver else {
        return ruby_unresolved_receiver_outcome(semantic, context, receiver_node, member, source);
    };

    let bare = call
        .and_then(|call| call.child_by_field_name("receiver"))
        .is_none();
    // The traced entry points report where the winning group was found
    // (#1477). An untraced lookup takes the plain ones and records nothing.
    let mut find = None;
    let mut candidates = match (bare, trace::recording()) {
        (true, true) => semantic.resolve_bare_method_candidates_traced(
            support,
            visible_files,
            &receiver,
            member,
            &mut find,
        ),
        (true, false) => {
            semantic.resolve_bare_method_candidates(support, visible_files, &receiver, member)
        }
        (false, true) => semantic.resolve_method_candidates_traced(
            support,
            visible_files,
            &receiver,
            member,
            &mut find,
        ),
        (false, false) => {
            semantic.resolve_method_candidates(support, visible_files, &receiver, member)
        }
    };
    if candidates.is_empty() {
        candidates = ruby_default_constructor_candidates(
            support,
            semantic,
            visible_files,
            &receiver,
            member,
        );
    }

    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("Ruby method `{member}` did not resolve to an indexed definition"),
        );
    }
    if let Some(find) = find {
        ruby_stage_member_attribution(
            semantic,
            support,
            visible_files,
            &receiver,
            &find,
            &candidates,
        );
    }
    candidates_outcome(candidates)
}

/// A method call whose receiver is written as a constant path names its owner
/// as a class or module (`ENV.fetch`, `Widget::Config.fetch`). When workspace
/// receiver typing answered nothing above, the receiver path is not one of the
/// workspace's declarations; this helper decides whether the call's owner is
/// nevertheless a workspace name.
///
/// [`RubySemanticIndex::declares_constant_anywhere`] is the same
/// visibility-blind workspace gate the constant-reference boundary uses
/// (#1089): a project file that declares the path without being required still
/// makes this a workspace-internal miss, and the report stays
/// `unsupported_ruby_receiver`. Only once no workspace file declares the path
/// does the written constant become the structured fact that places the
/// method's owner outside the indexed workspace (#3466). The published
/// identity is the call's own `<receiver>.<member>` spelling -- the same one
/// `call_bindings` reports for the call site.
fn ruby_unresolved_receiver_outcome(
    semantic: &RubySemanticIndex<'_>,
    context: &RubyLookupContext<'_>,
    receiver: Option<Node<'_>>,
    member: &str,
    source: &str,
) -> DefinitionLookupOutcome {
    let unresolved = || {
        no_definition(
            "unsupported_ruby_receiver",
            format!("receiver for Ruby method `{member}` is not resolved"),
        )
    };
    let Some(receiver) =
        receiver.filter(|receiver| matches!(receiver.kind(), "constant" | "scope_resolution"))
    else {
        return unresolved();
    };
    if semantic.declares_constant_anywhere(&context.lexical_stack, receiver, source) {
        return unresolved();
    }
    let receiver_text = ruby_node_text(receiver, source);
    if receiver_text.is_empty() {
        return unresolved();
    }
    let reference = format!("{receiver_text}.{member}");
    trace::record_named_boundary(reference.clone());
    // gated upstream: `declares_constant_anywhere` answered the workspace
    // half above, over every file, before this boundary is published.
    boundary_unchecked(
        format!(
            "`{reference}` is a member of `{receiver_text}`, a Ruby class or module declared outside the indexed workspace"
        ),
        UnindexedClaim::external_boundary(receiver_text, ClaimSubjectRole::Any),
    )
}

/// Bind external constant and constructed-instance receivers to the activated
/// declaration model. The bounded AST context propagates constructor results
/// through local assignments; workspace declarations always take precedence.
pub(super) fn exact_ruby_external_call(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer)?;
    let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), cancellation);
    let overlay = analyzer.semantic_model_overlay();
    let mut provider = RubyDefinitionProvider::new(ruby, &session);
    provider.overlay = overlay.as_deref();
    let root = tree.root_node();
    let callee = ruby_smallest_named_node_covering_bounded(
        &provider,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    if callee.kind() != "identifier" {
        return None;
    }
    let call = callee.parent()?;
    if call.kind() != "call"
        || call
            .child_by_field_name("method")
            .is_none_or(|method| method.id() != callee.id())
    {
        return None;
    }
    let context =
        BoundedRubyLookupContext::build(&provider, file, source, root, site.focus_start_byte);
    let receiver_node = call.child_by_field_name("receiver");
    let member_name = ruby_node_text(callee, source);
    let parameter_count = ruby_positional_argument_count(call)?;

    if receiver_node.is_none() && member_name == "system" {
        if !ruby_bare_core_method_is_proven(&provider, &context, call, source) {
            return None;
        }
        let constants = RubyOverlayConstants::new(overlay.as_deref());
        let owner = ruby_unshadowed_external_type(ruby, &session, constants, "Kernel")?;
        let member = constants.callable(owner, "system", parameter_count)?;
        let proof = ExactExternalCallProof::ruby_bound_external_member(
            &owner.qualified_name,
            &member.name,
            u32::try_from(parameter_count).ok()?,
        );
        let identity = ResolverOwnedExternalCalleeIdentity::new(
            Language::Ruby,
            owner.qualified_name.clone(),
            member.name.clone(),
        );
        return match session.finish((proof, identity)) {
            BoundedResolution::Complete { value, .. } => Some(value),
            _ => None,
        };
    }

    let receiver_node = receiver_node?;
    let receiver = context
        .expression_receiver_type(receiver_node)
        .or_else(|| {
            let types = context.infer_instance_fields();
            if !types.values().any(Option::is_some) {
                return None;
            }
            let owner = context.enclosing_receiver()?.owner_fq_name;
            // Replay local assignments with the class postcondition available, so
            // aliases of an instance field retain the same declared model type.
            // Ordinary build() remains field-free, including census RHS contexts.
            let mut seeded =
                BoundedRubyLookupContext::new(&provider, file, source, root, site.focus_start_byte);
            seeded.instance_fields = Some(RubyInstanceFields { owner, types });
            seeded.walk_to_focus(root);
            seeded.expression_receiver_type(receiver_node)
        })?;
    if !provider.fqn(&receiver.owner_fq_name).is_empty() {
        return None;
    }
    let constants = RubyOverlayConstants::new(overlay.as_deref());
    // The declared result can name a different class from the constructor's
    // owner, so check this result identity independently.
    let owner = ruby_unshadowed_external_type(ruby, &session, constants, &receiver.owner_fq_name)?;
    let member = constants.callable(owner, member_name, parameter_count)?;
    if member.is_static() != (receiver.mode == RubyReceiverMode::Class) {
        return None;
    }
    let proof = ExactExternalCallProof::ruby_bound_external_member(
        &owner.qualified_name,
        &member.name,
        u32::try_from(parameter_count).ok()?,
    );
    let identity = ResolverOwnedExternalCalleeIdentity::new(
        Language::Ruby,
        owner.qualified_name.clone(),
        member.name.clone(),
    );
    match session.finish((proof, identity)) {
        BoundedResolution::Complete { value, .. } => Some(value),
        _ => None,
    }
}

/// Bare Ruby calls use the enclosing receiver and can fall through to Kernel.
/// The fallback is deliberately narrower than the ordinary method resolver:
/// unknown class ancestry, workspace dynamic hooks, or a lexical refinement
/// means that `system` may select something other than Kernel#system.
fn ruby_bare_core_method_is_proven(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    call: Node<'_>,
    source: &str,
) -> bool {
    if ruby_has_active_refinement(context.root, call, source)
        || ruby_has_dynamic_bare_dispatch(context.root, &context.lexical_stack, call, source)
        || ruby_has_unknown_receiver_ancestry(provider, context, call, source)
    {
        return false;
    }
    let Some(receiver) = context.enclosing_receiver() else {
        return false;
    };
    let Some(system_candidates) =
        ruby_bare_method_candidates(provider, context, &receiver, "system")
    else {
        return false;
    };
    if !system_candidates.is_empty() {
        return false;
    }
    let Some(method_missing_candidates) =
        ruby_bare_method_candidates(provider, context, &receiver, "method_missing")
    else {
        return false;
    };
    method_missing_candidates.is_empty()
}

fn ruby_bare_method_candidates(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    receiver: &RubyReceiverType,
    member: &str,
) -> Option<Vec<CodeUnit>> {
    let mut candidates = ruby_bounded_method_candidates(provider, context, receiver, member)?;
    if receiver.mode != RubyReceiverMode::TopLevel {
        return Some(candidates);
    }

    // The normal Ruby graph keeps a top-level bare call separate from the
    // Object/Kernel ancestry. A workspace can still reopen either owner and
    // change the implicit-self lookup, so inspect those structured owners
    // before accepting the builtin fall-through.
    let object = RubyReceiverType {
        owner_fq_name: "Object".to_owned(),
        mode: RubyReceiverMode::Instance,
    };
    let object_candidates = ruby_bounded_method_candidates(provider, context, &object, member)?;
    candidates.extend(object_candidates);
    for owner in ["BasicObject", "Kernel"] {
        candidates.extend(
            provider
                .members_for_owner_name(owner, member)
                .into_iter()
                .filter(|unit| {
                    unit.is_function()
                        && matches!(
                            provider.method_dispatch_mode(unit),
                            Some(
                                RubyMethodDispatchMode::Instance
                                    | RubyMethodDispatchMode::ModuleFunction
                            )
                        )
                }),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates)
}

fn ruby_has_active_refinement(root: Node<'_>, call: Node<'_>, source: &str) -> bool {
    let mut ancestor = call;
    while let Some(parent) = ancestor.parent() {
        if parent.kind() == "call"
            && parent
                .child_by_field_name("method")
                .is_some_and(|method| ruby_node_text(method, source) == "refine")
        {
            return true;
        }
        ancestor = parent;
    }

    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.start_byte() >= call.start_byte() {
            continue;
        }
        if node.kind() == "call"
            && node.end_byte() <= call.start_byte()
            && node
                .child_by_field_name("method")
                .is_some_and(|method| ruby_node_text(method, source) == "using")
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            pending.push(node.named_child(index).expect("named child exists"));
        }
    }
    false
}

fn ruby_has_dynamic_bare_dispatch(
    root: Node<'_>,
    lexical_stack: &[String],
    call: Node<'_>,
    source: &str,
) -> bool {
    let mut enclosing_types = Vec::new();
    let mut ancestor = call;
    while let Some(parent) = ancestor.parent() {
        if matches!(parent.kind(), "class" | "module" | "singleton_class") {
            enclosing_types.push(parent);
        }
        ancestor = parent;
    }
    if enclosing_types.is_empty() && lexical_stack.is_empty() {
        return ruby_type_contains_dynamic_dispatch(root, source);
    }
    enclosing_types
        .into_iter()
        .any(|owner| ruby_type_contains_dynamic_dispatch(owner, source))
}

fn ruby_type_contains_dynamic_dispatch(root: Node<'_>, source: &str) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node != root && matches!(node.kind(), "class" | "module" | "singleton_class") {
            continue;
        }
        if matches!(node.kind(), "method" | "singleton_method")
            && node
                .child_by_field_name("name")
                .is_some_and(|name| ruby_node_text(name, source) == "method_missing")
        {
            return true;
        }
        if node.kind() == "call"
            && node.child_by_field_name("method").is_some_and(|method| {
                matches!(
                    ruby_node_text(method, source),
                    "define_method" | "define_singleton_method"
                )
            })
        {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            pending.push(node.named_child(index).expect("named child exists"));
        }
    }
    false
}

fn ruby_has_unknown_receiver_ancestry(
    provider: &RubyDefinitionProvider<'_>,
    context: &BoundedRubyLookupContext<'_, '_>,
    call: Node<'_>,
    source: &str,
) -> bool {
    let mut enclosing_types = Vec::new();
    let mut ancestor = call;
    while let Some(parent) = ancestor.parent() {
        if parent.kind() == "class" {
            enclosing_types.push(parent);
        }
        ancestor = parent;
    }
    for owner in enclosing_types {
        if owner.kind() == "singleton_class" {
            return true;
        }
        let Some(owner_name) = owner
            .child_by_field_name("name")
            .and_then(|name| context.resolve_constant_owner(name))
        else {
            return true;
        };
        if ruby_owner_ancestry_is_unknown(provider, &owner_name) {
            return true;
        }
        if let Some(superclass) = owner.child_by_field_name("superclass")
            && !ruby_known_core_ancestor(superclass, context)
            && context.resolve_constant_owner(superclass).is_none()
        {
            return true;
        }
        let mut pending = vec![owner];
        while let Some(node) = pending.pop() {
            if node != owner && matches!(node.kind(), "class" | "module" | "singleton_class") {
                continue;
            }
            if node.kind() == "call"
                && node.child_by_field_name("method").is_some_and(|method| {
                    matches!(
                        ruby_node_text(method, source),
                        "include" | "prepend" | "extend"
                    )
                })
            {
                let Some(arguments) = node.child_by_field_name("arguments") else {
                    return true;
                };
                let Some(argument) = arguments.named_child(0) else {
                    return true;
                };
                if context.resolve_constant_owner(argument).is_none() {
                    return true;
                }
            }
            for index in (0..node.named_child_count()).rev() {
                pending.push(node.named_child(index).expect("named child exists"));
            }
        }
    }
    false
}

fn ruby_owner_ancestry_is_unknown(provider: &RubyDefinitionProvider<'_>, owner: &str) -> bool {
    let mut pending = vec![owner.to_owned()];
    let mut visited = HashSet::default();
    while let Some(owner) = pending.pop() {
        if !provider.scope_step() {
            return true;
        }
        if !visited.insert(owner.clone()) {
            continue;
        }
        let mut declarations = provider
            .fqn(&owner)
            .into_iter()
            .filter(|unit| unit.is_class() || unit.is_module())
            .collect::<Vec<_>>();
        sort_units(&mut declarations);
        declarations.dedup();
        let [declaration] = declarations.as_slice() else {
            return true;
        };
        let raw_ancestors = ruby_forward_superclass_targets(provider.ruby, declaration);
        if raw_ancestors.len() > 1 {
            return true;
        }
        let resolved_ancestors = ruby_direct_ancestors(provider.ruby, declaration);
        if raw_ancestors.is_empty() {
            continue;
        }
        let raw = &raw_ancestors[0];
        if ruby_known_core_superclass(raw) {
        } else {
            let [ancestor] = resolved_ancestors.as_slice() else {
                return true;
            };
            pending.push(ancestor.fq_name().to_owned());
        }
        let raw_mixins = ruby_forward_mixin_specs(provider.ruby, declaration);
        let resolved_mixins = provider
            .ruby
            .mixin_relations()
            .iter()
            .filter(|relation| relation.from == *declaration)
            .map(|relation| relation.to.fq_name().to_owned())
            .collect::<Vec<_>>();
        if resolved_mixins.len() != raw_mixins.len() {
            return true;
        }
        pending.extend(resolved_mixins);
    }
    false
}

fn ruby_known_core_superclass(raw: &str) -> bool {
    matches!(raw, "Object" | "BasicObject" | "Kernel" | "String")
}

fn ruby_known_core_ancestor(node: Node<'_>, context: &BoundedRubyLookupContext<'_, '_>) -> bool {
    let Some(path) = context.constant_name_path(node) else {
        return false;
    };
    path.segments.len() == 1
        && matches!(
            path.segments[0].as_str(),
            "Object" | "BasicObject" | "Kernel" | "String"
        )
        && !path.absolute
}

/// A splat, keyword group or block argument does not prove written positional
/// arity. Keep that call open instead of counting the group as one argument.
fn ruby_positional_argument_count(call: Node<'_>) -> Option<usize> {
    if call.child_by_field_name("block").is_some() {
        return None;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Some(0);
    };
    let mut cursor = arguments.walk();
    let mut count = 0;
    for argument in arguments.named_children(&mut cursor) {
        if argument.is_extra() {
            continue;
        }
        if matches!(
            argument.kind(),
            "splat_argument"
                | "hash_splat_argument"
                | "block_argument"
                | "pair"
                | "forward_argument"
        ) {
            return None;
        }
        count += 1;
    }
    Some(count)
}

/// The route the Ruby method walk took from the receiver's own owner to the
/// owner it found the winning group on (#1477).
///
/// `forward_ancestor_lookup_order` flattens its walk to a lookup order that no
/// longer says which owner reached which. This repeats that walk over the same
/// direct-ancestor edges, in the same order and with the same visited-set
/// deduplication, and retains the first-discovery parent. It decides nothing:
/// the production lookup consumed its own order unchanged.
#[derive(Default)]
struct RubyOwnerRoutes {
    parents: HashMap<String, String>,
}

impl RubyOwnerRoutes {
    fn build(
        semantic: &RubySemanticIndex<'_>,
        support: &dyn BoundedDefinitionLookup,
        visible_files: &[ProjectFile],
        base: &str,
    ) -> Self {
        let mut routes = Self::default();
        let mut visited: HashSet<String> = HashSet::default();
        visited.insert(base.to_owned());
        let mut stack: Vec<(String, String)> = semantic
            .direct_ancestor_owners(support, visible_files, base)
            .into_iter()
            .rev()
            .map(|ancestor| (ancestor, base.to_owned()))
            .collect();
        while let Some((owner, parent)) = stack.pop() {
            if !visited.insert(owner.clone()) {
                continue;
            }
            routes.parents.insert(owner.clone(), parent);
            let mut next = semantic.direct_ancestor_owners(support, visible_files, &owner);
            next.reverse();
            stack.extend(next.into_iter().map(|ancestor| (ancestor, owner.clone())));
        }
        routes
    }

    /// The owner chain from `base` to `owner`, `base` first. `None` when the
    /// walk never reached `owner`, which leaves the candidates unattributed
    /// rather than attributed to a route this seam cannot name.
    fn chain(&self, base: &str, owner: &str) -> Option<Vec<String>> {
        let mut chain = vec![owner.to_owned()];
        while chain.last().is_some_and(|last| last != base) {
            let parent = self
                .parents
                .get(chain.last().expect("chain is never empty"))?;
            chain.push(parent.clone());
        }
        chain.reverse();
        Some(chain)
    }
}

/// Stage the attribution for the group the Ruby method lookup returned.
///
/// The lookup returns the first non-empty group it reaches, so one owner, one
/// hop distance and one bucket describe every candidate in it.
fn ruby_stage_member_attribution(
    semantic: &RubySemanticIndex<'_>,
    support: &dyn BoundedDefinitionLookup,
    visible_files: &HashSet<ProjectFile>,
    receiver: &RubyReceiverType,
    find: &RubyMethodFind,
    winners: &[CodeUnit],
) {
    use crate::analyzer::structural::{HierarchyRelation, MemberDispatchTier, PrecedenceTier};
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    let visible: Vec<ProjectFile> = visible_files.iter().cloned().collect();
    let routes = RubyOwnerRoutes::build(semantic, support, &visible, &receiver.owner_fq_name);
    let Some(mut chain) = routes.chain(&receiver.owner_fq_name, &find.reached_from) else {
        return;
    };
    // A mixin is one further edge off the ancestor the walk had reached.
    if find.mixin.is_some() {
        chain.push(find.owner.clone());
    }
    let mut units = Vec::with_capacity(chain.len());
    for name in &chain {
        let Some(unit) = semantic.owner_unit(support, &visible, name) else {
            return;
        };
        units.push(unit);
    }
    let owner = units
        .last()
        .expect("the chain always names its owner")
        .clone();
    let mixin_hop = find.mixin.is_some().then(|| units.len() - 2);
    let route: Vec<trace::HierarchyHopRecord> = units
        .windows(2)
        .enumerate()
        .map(|(hop, pair)| trace::HierarchyHopRecord {
            hop,
            from: pair[0].clone(),
            to: pair[1].clone(),
            // A superclass edge is an extension. The hierarchy vocabulary has
            // no mixin edge, so a composed-in module takes the
            // undifferentiated one rather than claiming to be something else.
            relation: if mixin_hop == Some(hop) {
                HierarchyRelation::Supertype
            } else {
                HierarchyRelation::Extends
            },
        })
        .collect();
    let depth = route.len();
    // A module composed in through include/prepend/extend is Ruby's
    // trait/interface seam whichever side it was reached from; a class-side
    // lookup that found the method on the class itself is the companion seam.
    let dispatch_tier = match find.mixin {
        Some(_) => MemberDispatchTier::TraitOrInterface,
        None if find.class_side => MemberDispatchTier::StaticOrCompanion,
        None if depth == 0 => MemberDispatchTier::InherentOrDirect,
        None => MemberDispatchTier::InheritedOrPromoted,
    };
    trace::stage_tier(
        if depth == 0 {
            PrecedenceTier::OwnMember
        } else {
            PrecedenceTier::InheritedMember
        },
        winners.iter().map(CodeUnit::fq_name).collect(),
    );
    trace::stage_member_context(
        winners
            .iter()
            .map(|unit| {
                (
                    unit.fq_name(),
                    trace::MemberEnrichment {
                        owner: owner.clone(),
                        hierarchy_depth: depth,
                        dispatch_tier,
                        // The Ruby method lookup selects by owner, name and
                        // dispatch mode and never inspects the call shape, so
                        // the callable axis (#1478) stays unclaimed.
                        applicability: ApplicabilityVerdict::Unknown,
                        route: route.clone(),
                    },
                )
            })
            .collect(),
    );
}

struct RubyLookupContext<'a> {
    semantic: &'a RubySemanticIndex<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    visible_files: &'a HashSet<ProjectFile>,
    locals: LocalInferenceEngine<String>,
    lexical_stack: Vec<String>,
    method_stack: Vec<RubyReceiverMode>,
    receiver_context: Vec<RubyReceiverMode>,
    exits: Vec<RubyScopeExit>,
    focus_start: usize,
}

impl<'a> RubyLookupContext<'a> {
    fn build(
        _analyzer: &'a dyn IAnalyzer,
        semantic: &'a RubySemanticIndex<'a>,
        file: &'a ProjectFile,
        source: &'a str,
        visible_files: &'a HashSet<ProjectFile>,
        root: Node<'_>,
        focus_start: usize,
    ) -> Self {
        let mut context = Self {
            semantic,
            file,
            source,
            visible_files,
            locals: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            lexical_stack: Vec::new(),
            method_stack: Vec::new(),
            receiver_context: Vec::new(),
            exits: Vec::new(),
            focus_start,
        };
        context.walk_to_focus(root);
        context
    }

    fn walk_to_focus(&mut self, root: Node<'_>) {
        let mut stack = vec![RubyFrame::Enter(root)];
        let mut reached_focus = false;
        while let Some(frame) = stack.pop() {
            if reached_focus {
                break;
            }
            match frame {
                RubyFrame::Enter(node) => match self.enter(node) {
                    RubyWalkAction::Descend => {
                        push_named_children_reversed_as(node, &mut stack, |child| {
                            RubyFrame::Enter(child)
                        });
                    }
                    RubyWalkAction::DescendWithExit => {
                        stack.push(RubyFrame::Exit);
                        push_named_children_reversed_as(node, &mut stack, |child| {
                            RubyFrame::Enter(child)
                        });
                    }
                    RubyWalkAction::Skip => {
                        reached_focus = node.start_byte() >= self.focus_start;
                    }
                },
                RubyFrame::Exit => self.exit(),
            }
        }
    }

    fn enter(&mut self, node: Node<'_>) -> RubyWalkAction {
        if node.start_byte() >= self.focus_start {
            return RubyWalkAction::Skip;
        }
        if node.end_byte() <= self.focus_start {
            ruby_transfer_completed(self, node);
            return RubyWalkAction::Skip;
        }

        match node.kind() {
            "class" | "module" => {
                let owner = self.type_owner(node);
                if let Some(owner) = owner.as_ref() {
                    self.lexical_stack.push(owner.clone());
                }
                self.receiver_context.push(RubyReceiverMode::Instance);
                self.exits.push(RubyScopeExit::Type {
                    has_lexical_owner: owner.is_some(),
                });
                return RubyWalkAction::DescendWithExit;
            }
            "method" | "singleton_method" => {
                self.locals.enter_scope();
                self.seed_parameter_shadows(node);
                self.method_stack.push(ruby_method_receiver_mode(
                    node,
                    self.receiver_context.last().copied(),
                ));
                self.exits.push(RubyScopeExit::Method);
                return RubyWalkAction::DescendWithExit;
            }
            "singleton_class" => {
                self.locals.enter_scope();
                self.method_stack.push(RubyReceiverMode::Class);
                self.receiver_context.push(RubyReceiverMode::Class);
                self.exits.push(RubyScopeExit::SingletonClass);
                return RubyWalkAction::DescendWithExit;
            }
            "block" | "do_block" => {
                self.locals.enter_scope();
                self.exits.push(RubyScopeExit::LocalScope);
                return RubyWalkAction::DescendWithExit;
            }
            "assignment" => self.seed_assignment(node),
            _ => {}
        }
        RubyWalkAction::Descend
    }

    fn exit(&mut self) {
        exit_scope(
            self.exits.pop(),
            &mut self.receiver_context,
            &mut self.lexical_stack,
            &mut self.method_stack,
            &mut self.locals,
        );
    }

    fn type_owner(&self, node: Node<'_>) -> Option<String> {
        ruby_type_owner(
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            node,
            self.source,
        )
    }

    fn receiver_type(&self, node: Node<'_>) -> Option<RubyReceiverType> {
        ruby_receiver_type(
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            &self.locals,
            &self.method_stack,
            node,
            self.source,
        )
    }

    fn enclosing_receiver(&self) -> Option<RubyReceiverType> {
        ruby_enclosing_receiver(&self.lexical_stack, &self.method_stack)
    }

    fn seed_assignment(&mut self, node: Node<'_>) {
        ruby_seed_assignment(
            self.semantic,
            self.file,
            self.visible_files,
            &self.lexical_stack,
            &self.method_stack,
            &mut self.locals,
            node,
            self.source,
        );
    }

    fn seed_parameter_shadows(&mut self, node: Node<'_>) {
        ruby_seed_parameter_shadows(&mut self.locals, node, self.source);
    }
}

impl RubyCompletedLocals for RubyLookupContext<'_> {
    fn step(&self) -> bool {
        true
    }

    fn source(&self) -> &str {
        self.source
    }

    fn local(&self, name: &str) -> Option<RubyReceiverType> {
        let targets = self.locals.resolve_symbol_ref(name)?.as_precise()?;
        if targets.len() != 1 {
            return None;
        }
        Some(RubyReceiverType {
            owner_fq_name: targets.iter().next()?.clone(),
            mode: RubyReceiverMode::Instance,
        })
    }

    fn set_local(&mut self, name: &str, value: Option<RubyReceiverType>) {
        match value {
            Some(receiver) if receiver.mode == RubyReceiverMode::Instance => {
                self.locals
                    .seed_symbol(name.to_owned(), receiver.owner_fq_name);
            }
            _ => self.locals.declare_shadow(name.to_owned()),
        }
    }

    fn assign(&mut self, node: Node<'_>) {
        self.seed_assignment(node);
    }
}

enum RubyFrame<'tree> {
    Enter(Node<'tree>),
    Exit,
}

enum RubyWalkAction {
    Descend,
    DescendWithExit,
    Skip,
}

fn ruby_is_dynamic_dispatch(call: Node<'_>, source: &str) -> bool {
    let Some(method) = call.child_by_field_name("method") else {
        return false;
    };
    if !ruby_is_dynamic_dispatch_method(method, source) {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .any(|arg| ruby_symbol_or_string_value(arg, source).is_some())
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::ruby::parse_ruby_tree;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

    use crate::analyzer::usages::traits::{GraphUsageAnalyzer, UsageScanScope};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    fn ruby_site(
        source: &str,
        file: &ProjectFile,
        needle: &str,
        member: &str,
    ) -> ResolvedReferenceSite {
        let expression_start = source.find(needle).expect("Ruby expression");
        let member_start =
            expression_start + needle.rfind(member).expect("Ruby member within expression");
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        crate::test_support::resolved_reference_site(
            rel_path_string(file),
            member.to_string(),
            Range {
                start_byte: member_start,
                end_byte: member_start + member.len(),
                start_line: line,
                end_line: line,
            },
        )
    }

    #[test]
    #[hardwon(
        "#4271: a class-body call must resolve a singleton method through the implicit class receiver"
    )]
    fn class_body_call_resolves_singleton_method_in_lookup_and_graph() {
        let source = "class Widget\n  def self.helper; end\n  helper\nend\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("class_body.rb", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = analyzer
            .analyzed_files()
            .into_iter()
            .next()
            .expect("fixture Ruby file");
        let tree = parse_ruby_tree(source).expect("Ruby tree");
        let site = ruby_site(source, &file, "helper\nend", "helper");
        let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);

        let legacy = resolve_ruby(analyzer, &support, &file, source, Some(&tree), &site);
        let lookup_resolved = legacy.status == DefinitionLookupStatus::Resolved
            && legacy
                .definitions
                .iter()
                .any(|unit| unit.fq_name() == "Widget.helper");

        let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer).expect("Ruby analyzer");
        let target = ruby
            .get_definitions("Widget.helper")
            .into_iter()
            .find(CodeUnit::is_function)
            .expect("class-side helper");
        let candidates = analyzer.analyzed_files().into_iter().collect();
        let usages = crate::analyzer::usages::ruby_graph::RubyUsageGraphStrategy::new()
            .find_graph_usages(analyzer, &[target], &UsageScanScope::new(&candidates), 100);
        let graph_resolved = matches!(
            &usages,
            crate::analyzer::usages::outcome::GraphUsageOutcome::Resolved(
                crate::analyzer::usages::model::FuzzyResult::Success { hits_by_overload, .. }
            ) if hits_by_overload.values().any(|hits| !hits.is_empty())
        );
        assert!(
            lookup_resolved && graph_resolved,
            "legacy lookup: {legacy:#?}; graph extraction: {usages:#?}"
        );
    }

    #[test]
    #[hardwon(
        "#3529: Ruby conditional-flow fixture requires receiver alternatives to agree before publishing one method target"
    )]
    fn completed_conditional_locals_require_agreeing_receivers() {
        for (alternative, expected) in [("Service.new", true), ("Other.new", false)] {
            let source = format!(
                "class Service\n def run; end\nend\nclass Other\n def run; end\nend\n\
                 def invoke(flag)\n if flag\n service = Service.new\n else\n service = {alternative}\n end\n service.run\nend\n"
            );
            let fixture =
                AnalyzerFixture::new_for_language(Language::Ruby, &[("conditional.rb", &source)]);
            let file = ProjectFile::new(fixture.project_root(), "conditional.rb");
            let tree = parse_ruby_tree(&source).expect("Ruby tree");
            let site = ruby_site(&source, &file, "service.run", "run");
            let outcome = resolve_ruby_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("conditional lookup should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status == DefinitionLookupStatus::Resolved,
                expected,
                "{source}: {value:#?}"
            );
            let support =
                AnalyzerDefinitionLookup::new(fixture.analyzer.analyzer(), Language::None);
            let legacy = resolve_ruby(
                fixture.analyzer.analyzer(),
                &support,
                &file,
                &source,
                Some(&tree),
                &site,
            );
            assert_eq!(
                legacy.status == DefinitionLookupStatus::Resolved,
                expected,
                "legacy lookup: {source}: {legacy:#?}"
            );
            if expected {
                assert!(
                    matches!(value.definitions.as_slice(), [definition]
                    if definition.fq_name() == "Service.run"),
                    "{value:#?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#3529: Checks a completed conditional-flow join does not erase an earlier traversal-budget stop"
    )]
    fn completed_conditional_join_preserves_budget_exhaustion() {
        let source = format!(
            "class Service\n def run; end\nend\ndef invoke(flag)\n{}service.run\nend\n",
            "if flag\n service = Service.new\nelse\n service = Service.new\nend\n".repeat(32)
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("bounded_join.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "bounded_join.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let site = ruby_site(&source, &file, "service.run", "run");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 128,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );
        assert!(
            matches!(outcome, BoundedResolution::Exceeded {
            limit: ReceiverBudgetLimit::ScopeNodes, work,
        } if work.scope_nodes == budget.max_scope_nodes),
            "{outcome:#?}"
        );
    }

    fn parenthesized_receiver_outcome(
        depth: usize,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> BoundedResolution<bool> {
        let expression = format!("{}Service{}", "(".repeat(depth), ")".repeat(depth));
        let source = format!("class Service\nend\n{expression}\n");
        let fixture = AnalyzerFixture::new_for_language(
            Language::Ruby,
            &[("parenthesized_receiver.rb", &source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "parenthesized_receiver.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let expression_node = tree
            .root_node()
            .named_child(tree.root_node().named_child_count().saturating_sub(1))
            .expect("parenthesized receiver expression");
        let session = ResolutionSession::bounded(budget, cancellation);
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context = BoundedRubyLookupContext::build(
            &support,
            &file,
            &source,
            tree.root_node(),
            expression_node.start_byte(),
        );
        let resolved = context.expression_receiver_type(expression_node).is_some();
        session.finish(resolved)
    }

    #[test]
    fn bounded_factory_return_uses_exact_limited_parent_owner() {
        let source = r#"
    module Outer
      class Factory
        class Product
          def run
          end
        end

        def self.make
          Product.new
        end
      end
    end

    module Unrelated
      class Factory
        class Product
          def run
          end
        end
      end
    end

    def invoke
      Outer::Factory.make.run
    end
    "#
        .to_string();
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("nested_factory.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "nested_factory.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");
        let methods = ruby.get_definitions("Outer$Factory.make");
        let [method] = methods.as_slice() else {
            panic!("expected nested factory method: {methods:#?}");
        };
        assert_eq!(method.fq_name(), "Outer$Factory.make");
        assert_eq!(method.identifier(), "make");
        let owners = ruby.get_definitions("Outer$Factory");
        assert!(
            owners
                .iter()
                .any(|owner| owner.fq_name() == "Outer$Factory"),
            "expected nested factory owner: {owners:#?}"
        );
        let parent_session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let parent_provider = RubyDefinitionProvider::new(ruby, &parent_session);
        let parent = parent_provider.parent(method);
        let parent_outcome = parent_session.finish(parent);
        let BoundedResolution::Complete {
            value: Some(parent),
            ..
        } = parent_outcome
        else {
            panic!("bounded nested factory parent was not proven: {parent_outcome:#?}");
        };
        assert_eq!(parent.fq_name(), "Outer$Factory");
        let call_start = source
            .rfind("Outer::Factory.make.run")
            .expect("nested factory call");
        let member_start = call_start + "Outer::Factory.make.".len();
        let line = source[..member_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte: member_start,
                end_byte: member_start + "run".len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: member_start,
            focus_end_byte: member_start + "run".len(),
        };

        let outcome = resolve_ruby_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("nested Ruby factory lookup should complete: {outcome:#?}");
        };
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Outer$Factory$Product.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn parenthesized_receiver_unwrap_is_fully_budgeted_and_cancellable() {
        let BoundedResolution::Complete {
            value: true,
            work: shallow_work,
        } = parenthesized_receiver_outcome(1, ReceiverAnalysisBudget::default(), None)
        else {
            panic!("shallow parenthesized Ruby receiver should resolve");
        };
        let BoundedResolution::Complete {
            value: true,
            work: deep_work,
        } = parenthesized_receiver_outcome(256, ReceiverAnalysisBudget::default(), None)
        else {
            panic!("deep parenthesized Ruby receiver should resolve iteratively");
        };
        assert!(
            deep_work.scope_nodes >= shallow_work.scope_nodes + 255,
            "each parenthesis transition must be charged: shallow={shallow_work:?}, deep={deep_work:?}"
        );

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: deep_work.scope_nodes.saturating_sub(1),
            ..ReceiverAnalysisBudget::default()
        };
        assert!(matches!(
            parenthesized_receiver_outcome(256, budget, None),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));

        let cancellation =
            CancellationToken::cancel_after_checks_for_test(shallow_work.scope_nodes + 16);
        assert!(matches!(
            parenthesized_receiver_outcome(
                256,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn bounded_constant_path_walk_is_iterative_and_budgeted() {
        let expected = (0..128)
            .map(|index| format!("Namespace{index}"))
            .collect::<Vec<_>>();
        let source = format!("{}\n", expected.join("::"));
        let fixture =
            AnalyzerFixture::new_for_language(Language::Ruby, &[("deep_constant.rb", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "deep_constant.rb");
        let tree = parse_ruby_tree(&source).expect("Ruby tree");
        let path_node = tree
            .root_node()
            .named_child(0)
            .expect("qualified constant expression");
        assert_eq!(path_node.kind(), "scope_resolution");
        let ruby =
            resolve_analyzer::<RubyAnalyzer>(fixture.analyzer.analyzer()).expect("Ruby analyzer");

        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context =
            BoundedRubyLookupContext::build(&support, &file, &source, tree.root_node(), 0);
        let path = context
            .constant_name_path(path_node)
            .expect("deep path should fit the ordinary receiver budget");
        assert_eq!(path.segments, expected);
        assert!(!path.absolute);
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { .. }
        ));

        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 32,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);
        let support = RubyDefinitionProvider::new(ruby, &session);
        let context =
            BoundedRubyLookupContext::build(&support, &file, &source, tree.root_node(), 0);
        assert!(context.constant_name_path(path_node).is_none());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }
}
