#[cfg(test)]
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::usages::get_definition::*;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile,
    Range, resolve_analyzer,
};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalBindingsSnapshot;
use brokk_bifrost_core::analyzer::usages::model::{ImportBinder, ImportKind};
use brokk_bifrost_core::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
pub(crate) use brokk_bifrost_python::syntax::{
    python_attribute_callee_uses_self_or_cls_bounded,
    python_attribute_names_nested_class_through_current_receiver_bounded,
};
use std::sync::{Arc, OnceLock};
#[cfg(test)]
use tree_sitter::Parser;
use tree_sitter::{Node, Tree};

use crate::analyzer::PythonAnalyzer;

use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause;

pub(crate) fn definition_value_identity(
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<ResolvedValueIdentity>, DerivationExecutionCause> {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)
        .expect("Python identity hook requires Python analyzer");
    let cancel = cancellation.cloned().unwrap_or_default();
    let mut retained =
        crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest::open(
            python, &cancel,
        );
    let scope = AnalyzerQueryScope::new(analyzer);
    let Some(tree) = definition_tree(analyzer, scope.token(), file, Language::Python, source)
    else {
        return Ok(None);
    };
    match python_external_value_identity_at_range(
        &mut retained,
        analyzer,
        request,
        file,
        source,
        &tree,
        cancellation,
    )? {
        Some(identity) => Ok(Some(identity)),
        None => python_attribute_value_identity_at_range(
            &mut retained,
            analyzer,
            request,
            file,
            source,
            &tree,
            cancellation,
        ),
    }
}

fn python_attribute_value_identity_at_range(
    retained: &mut crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest<'_>,
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<ResolvedValueIdentity>, DerivationExecutionCause> {
    let (Some(start_byte), Some(end_byte)) = (request.start_byte, request.end_byte) else {
        return Ok(None);
    };
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return Ok(None);
    };
    let Some((terminal_start_byte, terminal_end_byte)) =
        crate::analyzer::python::python_attribute_value_terminal_range(
            python, file, source, start_byte, end_byte,
        )
    else {
        return Ok(None);
    };
    let Some((outcome, _)) = crate::analyzer::python::native_request::definition_lookup::definition_at_range_with_request(retained, analyzer, file, source, tree, terminal_start_byte..terminal_end_byte, cancellation)? else { return Ok(None); };
    match outcome.status {
        DefinitionLookupStatus::Cancelled => return Err(DerivationExecutionCause::Cancelled),
        DefinitionLookupStatus::ExceededBudget(_) => return Err(DerivationExecutionCause::Budget),
        DefinitionLookupStatus::Unavailable | DefinitionLookupStatus::Incomplete => {
            return Err(DerivationExecutionCause::Provider);
        }
        _ => {}
    }
    if outcome.status != DefinitionLookupStatus::Resolved {
        return Ok(None);
    }
    let mut definitions = outcome.definitions;
    definitions.sort_by_key(|definition| definition.declaration_id());
    definitions.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
    let mut modeled = outcome.modeled_definitions;
    modeled.sort_by(|left, right| left.id.cmp(&right.id));
    modeled.dedup_by(|left, right| left.id == right.id);
    Ok(match (definitions.as_slice(), modeled.as_slice()) {
        ([definition], []) => Some(ResolvedValueIdentity {
            kind: ResolvedValueIdentityKind::WorkspaceDeclaration,
            identity: definition.declaration_id().to_string(),
            aliases: Vec::new(),
        }),
        ([], [symbol]) if exact_semantic_model_value_identity(symbol) => {
            Some(ResolvedValueIdentity {
                kind: ResolvedValueIdentityKind::ActiveSemanticModel,
                identity: symbol.id.clone(),
                aliases: symbol.aliases.clone(),
            })
        }
        _ => None,
    })
}

fn python_external_value_identity_at_range(
    retained: &mut crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest<'_>,
    analyzer: &dyn IAnalyzer,
    request: &DefinitionLookupRequest,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<ResolvedValueIdentity>, DerivationExecutionCause> {
    let (Some(start_byte), Some(end_byte)) = (request.start_byte, request.end_byte) else {
        return Ok(None);
    };
    let Some((outcome, _)) =
        crate::analyzer::python::native_request::definition_lookup::definition_at_range_with_request(
            retained,
            analyzer,
            file,
            source,
            tree,
            start_byte..end_byte,
            cancellation,
        )?
    else {
        return Ok(None);
    };
    match outcome.status {
        DefinitionLookupStatus::Cancelled => return Err(DerivationExecutionCause::Cancelled),
        DefinitionLookupStatus::ExceededBudget(_) => return Err(DerivationExecutionCause::Budget),
        DefinitionLookupStatus::Unavailable | DefinitionLookupStatus::Incomplete => {
            return Err(DerivationExecutionCause::Provider);
        }
        _ => {}
    }
    if outcome.status != DefinitionLookupStatus::Resolved
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
    {
        return Ok(None);
    }
    let [symbol] = outcome.modeled_definitions.as_slice() else {
        return Ok(None);
    };
    if symbol.language != Language::Python.config_label()
        || !exact_semantic_model_value_identity(symbol)
    {
        return Ok(None);
    }
    Ok(Some(ResolvedValueIdentity {
        kind: ResolvedValueIdentityKind::ActiveSemanticModel,
        identity: symbol.id.clone(),
        aliases: symbol.aliases.clone(),
    }))
}

pub(crate) fn definition_tree(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    // Reuse only the exact analyzer snapshot matching the caller's source.
    if let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer)
        && let Some(prepared) = py.prepared_syntax(token, file)
        && prepared.source() == source
    {
        return Some(prepared.tree().clone());
    }
    parse_tree_for_language(file, language, source)
}

pub(crate) fn release_definition_file(
    context: &mut DefinitionBatchContext<'_, '_>,
    file: &ProjectFile,
) {
    context
        .language_state::<PythonDefinitionState>()
        .python_contexts
        .remove(file);
}

#[derive(Default)]
pub(crate) struct PythonDefinitionState {
    python_contexts: HashMap<ProjectFile, Arc<PythonDefinitionContext>>,
}

use brokk_bifrost_python::graph::extractor::collect_scope_facts_from_parsed_source;

use brokk_bifrost_python::graph::extractor::enclosing_scope_facts;

use brokk_bifrost_python::graph::extractor::slice as python_slice;

use brokk_bifrost_python::graph::resolver::resolve_receiver_type as resolve_python_receiver_type;

use crate::analyzer::usages::python_graph::with_python_graph_source;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_analysis::analyzer::lexical_definitions::PythonMethodBinding;

use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded;

use crate::analyzer::python::lexical_scope::python_lexical_scope_inventory_bounded;

use brokk_bifrost_python::syntax::python_deferred_annotation_identifier_ranges;

use brokk_bifrost_python::syntax::python_node_is_in_annotation;

use brokk_bifrost_core::analyzer::usages::model::ExportEntry;

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

use brokk_bifrost_python::imports::resolve_fqn_candidates;

use brokk_bifrost_python::graph_support::resolve_module_code_unit;

use brokk_bifrost_python::graph_support::retain_modules_for_importer;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_python::bindings::{
    PythonClassReferenceScope, PythonDirectScopeBindingKind, PythonLexicalNameResolution,
    PythonLexicalScopeBindings, python_comprehension_binds_name_at,
    python_comprehension_binds_name_at_bounded, python_direct_scope_bindings_bounded,
    python_executable_scope_children, python_global_binding_is_untouched_bounded,
    python_type_parameter_binds_name_at_bounded, python_unambiguous_module_binding_node_bounded,
    python_unambiguous_module_class_binding_bounded,
};
use brokk_bifrost_python::graph::extractor::python_first_function_definition;
use brokk_bifrost_python::graph_support::PythonSource;
use brokk_bifrost_python::imports::{
    PythonImportBinding, PythonImportDetails, python_import_bindings_from_imports_bounded,
    python_import_details, python_import_infos_from_node, python_local_module_alias_path_before,
    resolve_python_relative_module,
};
use brokk_bifrost_python::source_facts::{PythonModuleMutationFacts, PythonSourceFactProvider};
pub(crate) use brokk_bifrost_python::syntax::{
    python_keyword_argument_label, python_static_attribute_path_bounded,
};
use std::cell::Cell;
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

const PYTHON_RECEIVER_TYPE_CACHE_LIMIT: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PythonDefinitionContextKey {
    // The request memo lives on one Python analyzer generation. The remaining
    // identity axes distinguish exact-source calls and concurrent query
    // contexts that selected different semantic-model publications.
    file: ProjectFile,
    source: brokk_bifrost_analysis::analyzer::semantic::StableDigest,
    semantic_overlay: Option<Box<str>>,
}

struct Replayable<T> {
    value: T,
    reads: Arc<brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger>,
    receipt: brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
}

#[derive(Default)]
pub(crate) struct PythonDefinitionContextRequestMemo {
    contexts:
        KeyedPoolSafeMemo<PythonDefinitionContextKey, Replayable<Arc<PythonDefinitionContext>>>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

fn definition_context_key(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    prepared: Option<&brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>,
) -> PythonDefinitionContextKey {
    let semantic_overlay = analyzer
        .semantic_model_overlay()
        .map(|overlay| Box::<str>::from(overlay.active_model_set_hash()));
    let source = match prepared {
        Some(prepared) if prepared.source().as_bytes() == source.as_bytes() => {
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array(
                prepared.source_sha256(),
            )
        }
        _ => brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(source),
    };
    PythonDefinitionContextKey {
        file: file.clone(),
        source,
        semantic_overlay,
    }
}

pub(crate) fn request_definition_context(
    py: &PythonAnalyzer,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
) -> Arc<PythonDefinitionContext> {
    let prepared = py.prepared_syntax(token, file);
    let key = definition_context_key(analyzer, file, source, prepared.as_deref());
    let memo = py
        .active_query_request_memo::<PythonDefinitionContextRequestMemo>()
        .expect("Python definition context requires an active query scope");
    let cell = memo.contexts.cell(&key);
    let built_here = Cell::new(false);
    let entry = cell.get_or_build_pool_independent(|| {
        built_here.set(true);
        let _scope = brokk_bifrost_core::profiling::scope("get_definition::python::batch_context");
        #[cfg(test)]
        memo.build_counters
            .context_builds
            .fetch_add(1, Ordering::Relaxed);
        let ((context, reads), receipt) =
            brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(analyzer, || {
                brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                    PythonDefinitionContext::build(
                        py,
                        analyzer,
                        token,
                        file,
                        *key.source.as_bytes(),
                        #[cfg(test)]
                        Arc::clone(&memo.build_counters),
                    )
                })
            });
        Replayable {
            value: Arc::new(context),
            reads,
            receipt,
        }
    });
    if !built_here.get() {
        entry.receipt.replay();
        debug_assert!(entry.reads.keys_satisfy(|key| {
            brokk_bifrost_analysis::analyzer::i_analyzer::read_key_recorded_on_active_ledgers(
                analyzer, key,
            )
        }));
    }
    Arc::clone(&entry.value)
}

#[cfg(test)]
pub(crate) fn request_definition_build_counts(py: &PythonAnalyzer) -> (usize, usize, usize, usize) {
    let counters = &py
        .active_query_request_memo::<PythonDefinitionContextRequestMemo>()
        .expect("Python definition build counts require an active query scope")
        .build_counters;
    (
        counters.context_builds.load(Ordering::Relaxed),
        counters.scope_fact_builds.load(Ordering::Relaxed),
        counters.receiver_type_cache_misses.load(Ordering::Relaxed),
        counters
            .generic_receiver_type_fallbacks
            .load(Ordering::Relaxed),
    )
}

/// Complete syntax facts live for one active query, or one provider when no
/// outer query exists. Owners and selected reads are deliberately not cached.
#[derive(Default)]
struct PythonModuleMutationRequestMemo {
    facts: Mutex<HashMap<[u8; 32], Arc<PythonModuleMutationFacts>>>,
    #[cfg(test)]
    collections: AtomicUsize,
}

impl PythonModuleMutationRequestMemo {
    fn facts(
        &self,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        session: &ResolutionSession,
    ) -> Option<Arc<PythonModuleMutationFacts>> {
        if !session.scope_step() {
            return None;
        }
        let key = prepared.source_sha256();
        let cached = self
            .facts
            .lock()
            .expect("module mutation memo lock poisoned")
            .get(&key)
            .cloned();
        if let Some(cached) = cached {
            return session.scope_step().then_some(cached);
        }
        #[cfg(test)]
        self.collections.fetch_add(1, Ordering::Relaxed);
        // Collection never holds the map lock and uses this caller's session.
        let collected = Arc::new(PythonModuleMutationFacts::collect_bounded(
            prepared.tree().root_node(),
            prepared.source(),
            || session.scope_step(),
        )?);
        if !session.scope_step() {
            return None;
        }
        let facts = {
            let mut facts = self
                .facts
                .lock()
                .expect("module mutation memo lock poisoned");
            // A concurrent fill cannot repair this caller's stop while waiting.
            if !session.scope_step() {
                return None;
            }
            Arc::clone(facts.entry(key).or_insert(collected))
        };
        session.scope_step().then_some(facts)
    }
}

pub(crate) struct PythonDefinitionProvider<'a> {
    python: &'a PythonAnalyzer,
    session: &'a ResolutionSession,
    source_facts_unavailable: Cell<bool>,
    module_mutations: Arc<PythonModuleMutationRequestMemo>,
}

impl<'a> PythonDefinitionProvider<'a> {
    pub(crate) fn new(python: &'a PythonAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            python,
            session,
            source_facts_unavailable: Cell::new(false),
            // Choose once, before nested per-base scopes can change the registry.
            module_mutations: python
                .active_query_request_memo::<PythonModuleMutationRequestMemo>()
                .unwrap_or_else(|| Arc::new(PythonModuleMutationRequestMemo::default())),
        }
    }

    pub(crate) fn analyzer(&self) -> &PythonAnalyzer {
        self.python
    }

    pub(crate) fn session(&self) -> &ResolutionSession {
        self.session
    }

    pub(crate) fn source_facts_unavailable(&self) -> bool {
        self.source_facts_unavailable.get()
    }

    fn module_mutation_owner_syntax(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>> {
        if !self.scope_step() {
            return None;
        }
        let scope = AnalyzerQueryScope::new(self.python);
        // This read occurs for every owner, including byte-identical memo hits.
        let prepared = self
            .session
            .query(|| self.python.prepared_syntax(scope.token(), file))??;
        if prepared.source() != source || !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(prepared)
    }

    pub(crate) fn module_binding_unmutated_at_bounded(
        &self,
        file: &ProjectFile,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        self.module_binding_unmutated_from_source_bounded(
            file,
            prepared.tree().root_node(),
            prepared.source(),
            name,
            reference,
        )
    }

    fn module_binding_unmutated_from_source_bounded(
        &self,
        file: &ProjectFile,
        root: Node<'_>,
        source: &str,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        let prepared = self.module_mutation_owner_syntax(file, source)?;
        let facts = self.module_mutations.facts(&prepared, self.session)?;
        let answer =
            facts.binding_unmutated_at_bounded(root, name, reference, || self.scope_step())?;
        if !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(answer)
    }

    /// Syntax-only builtin callers already own their current prepared read.
    /// This does not establish a workspace class or an exported owner identity.
    pub(crate) fn module_binding_unmutated_in_prepared_bounded(
        &self,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
        reference: Node<'_>,
    ) -> Option<bool> {
        let facts = self.module_mutations.facts(prepared, self.session)?;
        let answer = facts.binding_unmutated_at_bounded(
            prepared.tree().root_node(),
            name,
            reference,
            || self.scope_step(),
        )?;
        self.scope_step().then_some(answer)
    }

    fn module_export_unmutated_bounded(
        &self,
        file: &ProjectFile,
        prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        name: &str,
    ) -> Option<bool> {
        let source = prepared.source();
        let current = self.module_mutation_owner_syntax(file, source)?;
        let facts = self.module_mutations.facts(&current, self.session)?;
        let answer = facts.export_unmutated_bounded(name, || self.scope_step())?;
        if !self.python.indexed_source_matches(file, source) {
            return None;
        }
        self.scope_step().then_some(answer)
    }

    fn callable_source_facts(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<brokk_bifrost_python::source_facts::PythonFileSourceFacts>> {
        let facts = self.session.query(|| {
            self.python
                .python_source_facts(token, file, &|| self.scope_step())
        })?;
        if facts.is_none() {
            self.source_facts_unavailable.set(true);
        }
        facts
    }

    pub(crate) fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_fqn_limited(fqn, limit, || {
                    self.session.observe_cancellation()
                })
        });
        brokk_bifrost_core::analyzer::definition_lookup::sort_dedup_units(units)
    }

    fn workspace_fqn_prefix_exists(&self, prefix: &str) -> Option<bool> {
        self.session
            .query(|| self.python.workspace_fqn_prefix_exists(prefix))
    }

    fn workspace_module_prefix_exists(&self, prefix: &str) -> Option<bool> {
        if prefix.is_empty() {
            return Some(false);
        }
        if self.workspace_fqn_prefix_exists(prefix)? {
            return Some(true);
        }
        self.session.query(|| {
            self.python
                .project()
                .has_directory(std::path::Path::new(prefix))
        })
    }

    pub(crate) fn identifier(&self, identifier: &str) -> Vec<CodeUnit> {
        let units = self.session.query_limited_rows(|limit| {
            self.python
                .declaration_candidates_by_identifier_limited(identifier, limit, || {
                    self.session.observe_cancellation()
                })
        });
        brokk_bifrost_core::analyzer::definition_lookup::sort_dedup_units(units)
    }

    pub(crate) fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        self.identifier(identifier)
            .into_iter()
            .filter(|unit| unit.source() == file)
            .collect()
    }

    /// Resolve one module identity through the request session. The source
    /// module surface is path-backed. An incomplete bounded path query must
    /// remain a session stop, not launch an allocating definition fallback.
    ///
    /// `importer` is the file whose import named `module`. Two sibling source
    /// roots can spell one module name, so the root that owns the importer is
    /// what says which of them its import means (#3475); a module no
    /// containing root owns keeps every candidate and therefore no unique
    /// identity, which is the honest answer for an interactive lookup.
    fn module_code_unit(&self, importer: &ProjectFile, module: &str) -> Option<CodeUnit> {
        let mut candidates = self.module_candidates(module);
        retain_modules_for_importer(
            self.python.project(),
            importer,
            &mut candidates,
            CodeUnit::source,
        );
        let candidate = unique_python_candidate(candidates)?;
        candidate.is_module().then_some(candidate)
    }

    fn module_candidates(&self, module: &str) -> Vec<CodeUnit> {
        self.session.query_limited_rows(|limit| {
            self.python
                .module_candidates_by_fqn_limited(module, limit, || {
                    self.session.observe_cancellation()
                })
        })
    }

    pub(crate) fn members_for_owner(&self, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
        brokk_bifrost_analysis::analyzer::usages::get_definition::query_limited_definition_units(
            self.session,
            |limit| {
                self.python
                    .member_candidates_for_owner_limited(owner, name, limit, || {
                        self.session.observe_cancellation()
                    })
            },
        )
    }

    pub(crate) fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.python.ranges_limited(unit, limit))
    }

    /// The import bindings `file` declares, charged as one indexed query.
    fn import_binder(
        &self,
        token: QueryToken<'_>,
        file: &ProjectFile,
    ) -> Option<Arc<ImportBinder>> {
        self.session
            .query(|| self.python.import_binder_of(token, file))
    }

    fn scope_step(&self) -> bool {
        self.session.scope_step()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PythonTypeLookupTarget {
    Workspace(CodeUnit),
    External { qualified_name: String },
}

#[derive(Debug, Clone)]
pub(crate) struct PythonTypeLookupResolution {
    pub(crate) target: PythonTypeLookupTarget,
    pub(crate) target_kind: TypeLookupTargetKind,
}

pub(crate) fn python_type_lookup_resolution_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<PythonTypeLookupResolution> {
    let node = python_smallest_named_node_covering_bounded(
        support,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let expression = python_type_expression_node_bounded(support, node)?;
    let target_kind = if expression.kind() == "identifier"
        && !python_has_lexical_binding_bounded(support, expression, source)
        && python_class_candidate_for_name(
            support,
            token,
            file,
            source,
            expression,
            python_slice(expression, source),
        )
        .is_some()
    {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    if let Some(qualified_name) =
        python_external_class_reference_fqn_bounded(support, token, file, source, root, expression)
    {
        return Some(PythonTypeLookupResolution {
            target: PythonTypeLookupTarget::External { qualified_name },
            target_kind,
        });
    }
    let unit =
        python_type_for_expression_bounded(support, token, file, source, root, expression, 0)?;
    Some(PythonTypeLookupResolution {
        target: PythonTypeLookupTarget::Workspace(unit),
        target_kind,
    })
}

fn python_external_class_reference_fqn_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<String> {
    let reference = if expression.kind() == "call" {
        expression.child_by_field_name("function")?
    } else {
        expression
    };
    let (module, member) =
        python_external_imported_symbol_bounded(support, token, file, source, root, reference)?;
    let qualified_name = format!("{module}.{member}");
    let overlay = support.python.semantic_model_overlay()?;
    let matched = overlay.symbols_named_for(&qualified_name, "python");
    matched
        .records
        .iter()
        .any(|symbol| {
            symbol.language == brokk_bifrost_core::analyzer::model::Language::Python.config_label()
                && symbol.owner_id.is_none()
                && symbol.kind == brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Class
                && (symbol.qualified_name == qualified_name
                    || symbol.aliases.iter().any(|alias| alias == &qualified_name))
        })
        .then_some(qualified_name)
}

/// The expression whose type the caret asks for.
///
/// A caret on the member of `value.paint` covers the `paint` identifier alone,
/// but the type owed is the attribute expression's, so climb to the outermost
/// `attribute` the caret's node is the member of. A caret on the receiver stays
/// where it is: `value` in `value.paint` still asks for `value`'s own type.
fn python_type_expression_node_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if parent.kind() != "attribute" || parent.child_by_field_name("attribute") != Some(current)
        {
            break;
        }
        current = parent;
    }
    Some(current)
}

fn python_smallest_named_node_covering_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope(
        node,
        start,
        end,
        || support.scope_step(),
    )
}

fn python_named_children_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Vec<Node<'tree>>> {
    let mut children = Vec::new();
    let mut cursor = node.walk();
    brokk_bifrost_core::analyzer::tree_walk::push_bounded_nodes(
        node.named_children(&mut cursor),
        &mut children,
        || support.scope_step(),
    )
    .then_some(children)
}

fn python_keyword_argument_with_step<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonReferenceNode<'tree>> {
    if !scope_step() || node.kind() != "identifier" {
        return None;
    }
    let kwarg = node.parent()?;
    if !scope_step() || !python_keyword_argument_label(node) {
        return None;
    }
    let arguments = kwarg.parent()?;
    if !scope_step() || arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if !scope_step() || call.kind() != "call" {
        return None;
    }
    Some(PythonReferenceNode::KeywordArgument)
}

fn python_reference_node_with_step<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonReferenceNode<'tree>> {
    if let Some(keyword) = python_keyword_argument_with_step(node, &mut scope_step) {
        return Some(keyword);
    }
    if !scope_step() {
        return None;
    }
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if !scope_step() {
            return None;
        }
        if parent.kind() != "attribute" {
            break;
        }
        if parent.child_by_field_name("attribute") == Some(node)
            || parent.child_by_field_name("attribute") == Some(original)
        {
            node = parent;
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            Some(PythonReferenceNode::Attribute { object })
        }
        "identifier" => Some(PythonReferenceNode::Identifier),
        "string_content" if python_node_is_in_annotation(node) => {
            Some(PythonReferenceNode::Identifier)
        }
        _ => None,
    }
}

fn python_namespace_imported_class_candidate_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<CodeUnit> {
    let fqn = python_namespace_imported_class_name_bounded(
        support, token, file, source, root, expression,
    )?;
    if let Some(candidate) = unique_python_candidate(
        support
            .fqn(&fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect(),
    ) {
        return Some(candidate);
    }

    let (module, member) = fqn.rsplit_once('.')?;
    python_imported_class_from_module(support, token, file, module.to_owned(), member.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PythonAttributeCalleeKind {
    Class,
    Function,
    Value,
}

/// Classify the declaration named by an attribute call.
///
/// A type lookup answers the same way for three different shapes.
/// `Parameter` in `Holder.Parameter()` names a class, so the lookup's class is
/// what the call constructs. `make` in `Holder().make()` names a method, so
/// the lookup's class is that method's return type. `_regex` in
/// `self._regex()` names a field, so the lookup's class is the class of the
/// stored value; calling it runs that value's `__call__` and produces
/// something else. `None` means the receiver or the member did not resolve.
pub(crate) fn python_attribute_callee_kind_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callee: Node<'_>,
) -> Option<PythonAttributeCalleeKind> {
    if python_namespace_imported_class_candidate_bounded(support, token, file, source, root, callee)
        .is_some()
    {
        return Some(PythonAttributeCalleeKind::Class);
    }
    let object = callee.child_by_field_name("object")?;
    let member = python_slice(callee.child_by_field_name("attribute")?, source);
    if member.is_empty() {
        return None;
    }
    let receiver =
        python_type_for_expression_bounded(support, token, file, source, root, object, 1)?;
    let declaration = unique_python_candidate(support.members_for_owner(&receiver, member))?;
    Some(if declaration.is_class() {
        PythonAttributeCalleeKind::Class
    } else if declaration.is_function() {
        PythonAttributeCalleeKind::Function
    } else {
        PythonAttributeCalleeKind::Value
    })
}

/// Whether an attribute callee reads a stored value rather than naming a
/// class or a callable declaration.
pub(crate) fn python_attribute_callee_reads_a_field_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callee: Node<'_>,
) -> Option<bool> {
    python_attribute_callee_kind_bounded(support, token, file, source, root, callee)
        .map(|kind| kind == PythonAttributeCalleeKind::Value)
}

pub(crate) fn python_namespace_imported_class_name_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<String> {
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    if path.len() < 2 {
        return None;
    }
    let local_name = python_slice(path[0], source);
    if local_name.is_empty() {
        return None;
    }
    if let Some(module_path) = python_namespace_imported_module_path_bounded(
        support, token, file, source, root, expression,
    ) {
        return Some(module_path.join("."));
    }
    let mut support_context = support;
    let module_path = python_local_module_alias_path_before(
        expression,
        local_name,
        source,
        &mut support_context,
        |module_expression, support| {
            Ok(python_namespace_imported_module_path_bounded(
                support,
                token,
                file,
                source,
                root,
                module_expression,
            ))
        },
        |support| {
            if support.scope_step() {
                Ok(())
            } else {
                Err(())
            }
        },
    )
    .ok()?;
    let mut canonical = module_path?.to_vec();
    canonical.extend(
        path.into_iter()
            .skip(1)
            .map(|attribute| python_slice(attribute, source).to_owned().into_boxed_str()),
    );
    Some(
        canonical
            .iter()
            .map(Box::as_ref)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn python_namespace_imported_module_path_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<Box<[Box<str>]>> {
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    let local_name = python_slice(*path.first()?, source);
    if local_name.is_empty()
        || python_namespace_root_shadowed_bounded(support, local_name, expression, source)?
    {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(local_name)?;
    if binding.kind != ImportKind::Namespace
        || !python_namespace_import_binding_is_unique_bounded(
            support,
            root,
            local_name,
            expression.start_byte(),
            source,
        )?
    {
        return None;
    }
    let mut canonical = binding
        .module_specifier
        .split('.')
        .map(str::to_owned)
        .map(String::into_boxed_str)
        .collect::<Vec<_>>();
    canonical.extend(
        path.into_iter()
            .skip(1)
            .map(|attribute| python_slice(attribute, source).to_owned().into_boxed_str()),
    );
    Some(canonical.into_boxed_slice())
}

/// Prove one imported external symbol's owner and member without requiring a
/// call node. Decorator applications have an implicit argument, so their bare
/// callee must use the same import and shadowing proofs as explicit calls.
pub(crate) fn python_external_imported_symbol_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<(String, String)> {
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    if let Some(selected) =
        python_local_imported_symbol_bounded(support, token, file, source, root, expression)?
    {
        return selected
            .external_symbol_bounded(support)
            .filter(|_| support.python.indexed_source_matches(file, source));
    }
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    let local_name = python_slice(*path.first()?, source);
    if !support
        .module_binding_unmutated_from_source_bounded(file, root, source, local_name, expression)?
    {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(local_name)?;
    let (module, member) = match binding.kind {
        ImportKind::Named if path.len() == 1 => (
            binding.module_specifier.clone(),
            binding.imported_name.as_ref()?.clone(),
        ),
        ImportKind::Namespace if path.len() >= 2 => {
            let mut module = binding.module_specifier.clone();
            if path.len() > 2 {
                python_complete_external_module(support, &module)?;
                for segment in &path[1..path.len() - 1] {
                    module.push('.');
                    module.push_str(python_slice(*segment, source));
                    python_complete_external_module(support, &module)?;
                }
            }
            (module, python_slice(*path.last()?, source).to_owned())
        }
        ImportKind::Named if path.len() >= 2 => {
            // A from-import can bind a submodule alias. Every additional
            // attribute before the callable must also be an activated,
            // complete module; otherwise a dotted value chain could borrow a
            // package identity from its spelling.
            let imported_name = binding.imported_name.as_ref()?;
            let mut module = format!("{}.{imported_name}", binding.module_specifier);
            python_complete_external_module(support, &module)?;
            for segment in &path[1..path.len() - 1] {
                module.push('.');
                module.push_str(python_slice(*segment, source));
                python_complete_external_module(support, &module)?;
            }
            (module, python_slice(*path.last()?, source).to_owned())
        }
        _ => return None,
    };
    if local_name.is_empty()
        || python_namespace_root_shadowed_bounded(support, local_name, expression, source)?
    {
        return None;
    }
    // An activated external model cannot stand in for a workspace module with
    // the same name, even when that module does not declare the requested member.
    let unique = python_import_binding_is_unique_bounded(
        support,
        root,
        local_name,
        expression.start_byte(),
        source,
    )?;
    if !unique
        && (!python_import_binding_is_unique_without_wildcards_bounded(
            support,
            root,
            local_name,
            expression.start_byte(),
            source,
        )? || !python_wildcard_imports_reexport_same_external_bounded(
            support, token, file, local_name, &module, &member,
        )?)
    {
        return None;
    }
    if !python_external_model_namespace_available(support, &module, &member)
        || !support.python.indexed_source_matches(file, source)
    {
        return None;
    }
    Some((module, member))
}

/// A model cannot replace a workspace module/member whose source does not
/// establish the requested external class object.
pub(crate) fn python_external_model_namespace_available(
    support: &PythonDefinitionProvider<'_>,
    module: &str,
    member: &str,
) -> bool {
    support.module_candidates(module).is_empty()
        && support.fqn(module).is_empty()
        && support.fqn(&format!("{module}.{member}")).is_empty()
        && support.scope_step()
}

/// Whether a class base expression is rooted in one unshadowed, unmutated,
/// module-level import of a module that the workspace does not contain.
///
/// Such a base names a class outside the analyzed program. When no active
/// model covers it, the base is an unknown external endpoint rather than a
/// workspace lookup that failed. Imports of workspace modules, relative imports
/// (resolved into the importing package), wildcard-shadowed names and any
/// other binding keep the caller's failed-resolution answer. `None` is a
/// stopped walk.
pub(crate) fn python_base_imported_from_external_module_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<bool> {
    let path = python_static_attribute_path_bounded(expression, || support.scope_step())?;
    let local_name = python_slice(*path.first()?, source);
    if local_name.is_empty()
        || !support.module_binding_unmutated_from_source_bounded(
            file, root, source, local_name, expression,
        )?
        || python_namespace_root_shadowed_bounded(support, local_name, expression, source)?
        || !python_import_binding_is_unique_bounded(
            support,
            root,
            local_name,
            expression.start_byte(),
            source,
        )?
    {
        return Some(false);
    }
    let binder = support.import_binder(token, file)?;
    let Some(binding) = binder.bindings.get(local_name) else {
        return Some(false);
    };
    let (module, member) = match binding.kind {
        ImportKind::Named => {
            let Some(member) = binding.imported_name.as_deref() else {
                return Some(false);
            };
            (binding.module_specifier.clone(), member.to_owned())
        }
        // An unaliased `import pkg.child` binds `pkg`, while the expression
        // continues through `child`; append those segments so the full module
        // is checked rather than only the bound root.
        ImportKind::Namespace if path.len() >= 2 => {
            let mut module = binding.module_specifier.clone();
            for segment in &path[1..path.len() - 1] {
                module.push('.');
                module.push_str(python_slice(*segment, source));
            }
            (module, python_slice(*path.last()?, source).to_owned())
        }
        _ => return Some(false),
    };
    // The binder resolves relative imports to absolute module names, so a
    // workspace package root rejects both `from .missing import X` and an
    // absolute import of a workspace module that does not declare the class.
    let package = module.split('.').next().unwrap_or(module.as_str());
    // A namespace package has no module unit or declaration of its own, so
    // exact symbol lookups cannot see its descendants. Its directory still
    // keeps `from nspkg import Missing` and relative imports beside
    // `nspkg/sub.py` inside the workspace.
    let package_exists = support.workspace_module_prefix_exists(package)?;
    let external =
        !package_exists && python_external_model_namespace_available(support, &module, &member);
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    Some(external)
}

fn python_complete_external_module(
    support: &PythonDefinitionProvider<'_>,
    module: &str,
) -> Option<()> {
    let overlay = support.python.semantic_model_overlay()?;
    let matched = overlay.symbols_named_for(module, "python");
    let [symbol] = matched.records.as_slice() else {
        return None;
    };
    if matched.disposition
        != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        || symbol.kind
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Module
        || symbol.language != brokk_bifrost_core::analyzer::model::Language::Python.config_label()
        || symbol.qualified_name != module
        || symbol.provenance.ambiguous
        || symbol.provenance.completeness
            != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCompleteness::Complete
    {
        return None;
    }
    let workspace_modules = support
        .session
        .query(|| support.python.path_module_fqn(module))??;
    if !workspace_modules.is_empty() || !support.fqn(module).is_empty() || !support.scope_step() {
        return None;
    }
    Some(())
}

fn python_namespace_root_shadowed_bounded(
    support: &PythonDefinitionProvider<'_>,
    name: &str,
    reference: Node<'_>,
    source: &str,
) -> Option<bool> {
    if python_comprehension_binds_name_at_bounded(name, reference, source, || support.scope_step())?
        || python_type_parameter_binds_name_at_bounded(name, reference, source, || {
            support.scope_step()
        })?
    {
        return Some(true);
    }
    let mut current = reference;
    let mut crossed_callable_body = false;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        let body = parent.child_by_field_name("body");
        let inside_body = body.is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(parent, source, || support.scope_step())?;
            let resolution =
                inventory.name_resolution_at_bounded(name, reference, || support.scope_step())?;
            if resolution == PythonLexicalNameResolution::Global {
                return Some(!python_global_binding_is_untouched_bounded(
                    name,
                    reference,
                    parent,
                    source,
                    || support.scope_step(),
                )?);
            }
            if inventory
                .has_runtime_callable_binding_at_bounded(name, reference, || support.scope_step())?
                || matches!(
                    resolution,
                    PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
                )
            {
                return Some(true);
            }
            crossed_callable_body = true;
        } else if parent.kind() == "class_definition" && !crossed_callable_body && inside_body {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, reference, || support.scope_step())?;
            let inventory = class_scope.collect_bounded(source, || support.scope_step())?;
            let resolution =
                inventory.name_resolution_at_bounded(name, reference, || support.scope_step())?;
            if resolution == PythonLexicalNameResolution::Global {
                return Some(!python_global_binding_is_untouched_bounded(
                    name,
                    reference,
                    parent,
                    source,
                    || support.scope_step(),
                )?);
            }
            if resolution == PythonLexicalNameResolution::Nonlocal
                || class_scope.binds_name_bounded(name, source, || support.scope_step())?
            {
                return Some(true);
            }
            // Nested classes do not capture their enclosing class namespace.
            crossed_callable_body = true;
        }
        current = parent;
    }
    Some(false)
}

fn python_import_binding_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = false;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
                || matched_import
            {
                return Some(false);
            }
            matched_import = true;
        }
        for child in python_executable_scope_children(node)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            stack.push(child);
        }
    }
    Some(matched_import)
}

/// Prove a namespace local is imported only by top-level imports that Python
/// binds to the same unaliased root. Repeating `import pkg` before or after
/// `import pkg.sub` still binds the same namespace root; the dotted import
/// facts below retain the longer path needed to qualify a class reference.
fn python_namespace_import_binding_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut declarations = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
            {
                return Some(false);
            }
            if !declarations
                .iter()
                .any(|existing: &Node<'_>| existing.id() == declaration.id())
            {
                declarations.push(declaration);
            }
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    if declarations.is_empty() {
        return Some(false);
    }
    let repeated_declarations = declarations.len() > 1;
    for declaration in declarations {
        let matching = python_import_infos_from_node(declaration, source)
            .into_iter()
            .filter(|import| import.local_name() == Some(name))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Some(false);
        }
        if matching.len() == 1 && !repeated_declarations {
            continue;
        }
        if declaration.kind() != "import_statement"
            || matching.iter().any(|import| {
                import.alias.is_some()
                    || import.path.as_ref().is_none_or(|path| {
                        path.kind
                    != Some(
                        brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace,
                    )
                    || path.segments.first().is_none_or(|root| root != name)
                    })
            })
        {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether the explicit import remains the same external binding through every
/// workspace wildcard import in the module. A wildcard is open evidence unless
/// its structured export surface proves that it reexports this exact symbol.
fn python_wildcard_imports_reexport_same_external_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    local_name: &str,
    expected_module: &str,
    expected_member: &str,
) -> Option<bool> {
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let mut saw_wildcard = false;
    for import in imports.iter().filter(|import| import.is_wildcard) {
        let Some(PythonImportDetails::FromImport {
            module,
            wildcard: true,
            ..
        }) = python_import_details(import)
        else {
            return Some(false);
        };
        let Some(module) = resolve_python_relative_module(support.python.project(), file, &module)
        else {
            return Some(false);
        };
        let Some(module_unit) = support
            .session
            .query(|| resolve_module_code_unit(support.python, Some(file), &module))?
        else {
            return Some(false);
        };
        let exports = support
            .session
            .query(|| support.python.export_index_of(token, module_unit.source()))?;
        if !exports.reexport_stars.is_empty()
            || !matches!(
                exports.exports_by_name.get(local_name),
                Some(ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                }) if module_specifier == expected_module && imported_name == expected_member
            )
        {
            return Some(false);
        }
        saw_wildcard = true;
    }
    Some(saw_wildcard)
}

/// The ordinary import uniqueness check rejects every wildcard. This variant
/// proves the explicit binding independently so the caller can validate each
/// wildcard's actual export through `ExportIndex` instead of treating unrelated
/// stars as an automatic shadow.
fn python_import_binding_is_unique_without_wildcards_bounded(
    support: &PythonDefinitionProvider<'_>,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = false;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            continue;
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                if parent.kind() == "module" {
                    return Some(false);
                }
                declaration = parent;
            }
            if declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "module")
                || declaration.start_byte() > reference_start
                || matched_import
            {
                return Some(false);
            }
            matched_import = true;
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    Some(matched_import)
}

fn python_type_for_expression_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match node.kind() {
        "identifier" => {
            let name = python_slice(node, source);
            if let Some(receiver) =
                python_current_receiver_class(support, token, file, source, node, name)
            {
                Some(receiver)
            } else if python_has_lexical_binding_bounded(support, node, source) {
                python_bound_type_for_identifier(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    name,
                    depth + 1,
                )
            } else {
                python_class_candidate_for_name(support, token, file, source, node, name)
            }
        }
        "call" => {
            let function = node.child_by_field_name("function")?;
            let callable = match function.kind() {
                "identifier" => {
                    let name = python_slice(function, source);
                    let lexical_binding = python_lexical_binding_bounded(support, function, source);
                    match lexical_binding {
                        PythonLexicalBinding::Other | PythonLexicalBinding::LocalClass(_) => {
                            return None;
                        }
                        PythonLexicalBinding::LocalFunction(declaration) => {
                            return python_function_return_type_from_node_bounded(
                                support,
                                token,
                                file,
                                source,
                                root,
                                declaration,
                                depth + 1,
                            );
                        }
                        PythonLexicalBinding::UnboundOrGlobal => {
                            if let Some(class) = python_class_candidate_for_name(
                                support, token, file, source, function, name,
                            ) {
                                return Some(class);
                            }
                        }
                    }
                    unique_python_candidate(
                        support
                            .file_identifier(file, name)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .filter(|candidate| {
                                python_same_file_function_visible_at(
                                    support, source, function, candidate,
                                )
                                .unwrap_or(false)
                            })
                            .collect(),
                    )
                }
                "attribute" => {
                    if let Some(class) = python_namespace_imported_class_candidate_bounded(
                        support, token, file, source, root, function,
                    ) {
                        return Some(class);
                    }
                    let object = function.child_by_field_name("object")?;
                    let member = python_slice(function.child_by_field_name("attribute")?, source);
                    let receiver = python_type_for_expression_bounded(
                        support,
                        token,
                        file,
                        source,
                        root,
                        object,
                        depth + 1,
                    )?;
                    unique_python_candidate(
                        support
                            .members_for_owner(&receiver, member)
                            .into_iter()
                            .filter(CodeUnit::is_function)
                            .collect(),
                    )
                }
                _ => None,
            }?;
            python_callable_return_type_in_tree(
                support,
                token,
                file,
                source,
                root,
                &callable,
                depth + 1,
            )
        }
        // `value.paint` outside a call: the receiver's type owns the member, so
        // the member declaration's own type is the expression's type.
        "attribute" => {
            if let Some(class) = python_namespace_imported_class_candidate_bounded(
                support, token, file, source, root, node,
            ) {
                return Some(class);
            }
            let object = node.child_by_field_name("object")?;
            let member = python_slice(node.child_by_field_name("attribute")?, source);
            if member.is_empty() {
                return None;
            }
            let receiver = python_type_for_expression_bounded(
                support,
                token,
                file,
                source,
                root,
                object,
                depth + 1,
            )?;
            let declaration =
                unique_python_candidate(support.members_for_owner(&receiver, member))?;
            python_member_declared_type_bounded(
                support,
                token,
                file,
                source,
                root,
                &declaration,
                depth + 1,
            )
        }
        "parenthesized_expression" => {
            let child = node.named_child(0)?;
            python_type_for_expression_bounded(support, token, file, source, root, child, depth + 1)
        }
        _ => None,
    }
}

/// The type a resolved member declaration carries: a nested class is its own
/// type, a method's is its return type, and an attribute's is its annotation or
/// the type of the value bound to it.
///
/// The syntax routes read the site's own tree, so a member declared in another
/// file has no bounded answer here. That is the same in-file rule
/// [`python_callable_return_type_in_tree`] applies to a resolved callable: the
/// bounded core answers from the tree the caller already parsed and never
/// cold-parses a second file to finish a step.
fn python_member_declared_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    member: &CodeUnit,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    if member.is_class() {
        return Some(member.clone());
    }
    if member.source() != file {
        return None;
    }
    let mut types = Vec::new();
    for range in support.ranges(member) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if !support.scope_step() {
                return None;
            }
            if node.kind() == "function_definition"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == member.identifier())
            {
                types.extend(python_function_return_type_from_node_bounded(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    depth + 1,
                ));
                break;
            }
            // `name: T = ..` at class level and `self.name = ..` in a method are
            // both assignments whose bound name is the member's identifier.
            let bound = (node.kind() == "assignment")
                .then(|| node.child_by_field_name("left"))
                .flatten()
                .and_then(|left| match left.kind() {
                    "identifier" => Some(left),
                    "attribute" => left.child_by_field_name("attribute"),
                    _ => None,
                });
            if bound.is_some_and(|bound| python_slice(bound, source) == member.identifier()) {
                let declared = python_assignment_bound_type_bounded(
                    support,
                    token,
                    file,
                    source,
                    root,
                    node,
                    depth + 1,
                );
                types.extend(declared);
                break;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
    }
    unique_python_candidate(types)
}

fn python_assignment_bound_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    assignment: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    match assignment.child_by_field_name("type") {
        Some(annotation) => {
            python_type_from_annotation_bounded(support, token, file, source, annotation, depth)
        }
        None => assignment.child_by_field_name("right").and_then(|value| {
            python_type_for_expression_bounded(support, token, file, source, root, value, depth)
        }),
    }
}

/// Runtime-only transport within the caller's prepared tree and session.
/// Ordinary declaration navigation never follows these assignment nodes.
pub(crate) enum PythonRuntimeClassCandidate<'tree> {
    WorkspaceClass(CodeUnit),
    AliasRhs {
        assignment: Node<'tree>,
        rhs: Node<'tree>,
    },
}

/// A selected runtime base must name the class object itself. Type inference
/// for an instance/call/annotation is deliberately not used here.
pub(crate) fn python_class_object_base_candidate<'tree>(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    prepared: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
    base: Node<'tree>,
) -> Option<PythonRuntimeClassCandidate<'tree>> {
    let source = prepared.source();
    if let Some(selected) = python_local_imported_symbol_bounded(
        support,
        token,
        file,
        source,
        prepared.tree().root_node(),
        base,
    )? {
        // A path-backed module with this spelling does not prove that a
        // from-imported value is that module. Keep such attribute chains
        // unknown until source export ownership can establish that fact.
        if selected.import_kind
            == brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom
            && selected.requires_imported_module
        {
            return None;
        }
        return python_runtime_imported_class_from_module(
            support,
            token,
            file,
            selected.module.join("."),
            selected.member,
        )
        .map(PythonRuntimeClassCandidate::WorkspaceClass);
    }
    if base.kind() == "attribute" {
        let path = python_static_attribute_path_bounded(base, || support.scope_step())?;
        let root = *path.first()?;
        if !support.module_binding_unmutated_at_bounded(
            file,
            prepared,
            python_slice(root, source),
            base,
        )? {
            return None;
        }
        if python_type_parameter_binds_name_at_bounded(
            python_slice(root, source),
            root,
            source,
            || support.scope_step(),
        )? {
            return None;
        }
        let canonical = python_namespace_imported_class_name_bounded(
            support,
            token,
            file,
            source,
            prepared.tree().root_node(),
            base,
        )?;
        let (module, member) = canonical.rsplit_once('.')?;
        return python_runtime_imported_class_from_module(
            support,
            token,
            file,
            module.into(),
            member.into(),
        )
        .map(PythonRuntimeClassCandidate::WorkspaceClass);
    }
    if base.kind() != "identifier" {
        return None;
    }
    let name = python_slice(base, source);
    // Only the nearest executing class body participates. C's own header
    // executes outside C's body, and methods/lambdas do not capture a class
    // namespace. Inspect this scope before an enclosing callable's bindings.
    let mut current = base;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        let inside_body = parent.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= base.start_byte() && base.end_byte() <= body.end_byte()
        });
        if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            break;
        }
        if inside_body && parent.kind() == "class_definition" {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, base, || support.scope_step())?;
            let inventory = class_scope.collect_bounded(source, || support.scope_step())?;
            let binds = class_scope.binds_name_bounded(name, source, || support.scope_step())?;
            match inventory.name_resolution_at_bounded(name, base, || support.scope_step())? {
                PythonLexicalNameResolution::Global => {
                    // Skip outer locals, but never skip known writes to this
                    // same global namespace in enclosing executing scopes.
                    return if python_global_binding_is_untouched_bounded(
                        name,
                        base,
                        parent,
                        source,
                        || support.scope_step(),
                    )? {
                        python_runtime_module_class_candidate_bounded(
                            support, token, file, source, base, name,
                        )
                    } else {
                        None
                    };
                }
                PythonLexicalNameResolution::Nonlocal => return None,
                PythonLexicalNameResolution::Local => {
                    let declaration =
                        inventory
                            .local_class_declaration_bounded(name, base, || support.scope_step())?;
                    if declaration.parent() != parent.child_by_field_name("body")
                        || declaration.end_byte() > base.start_byte()
                    {
                        return None;
                    }
                    return python_unit_for_class_declaration(
                        support,
                        file,
                        source,
                        base,
                        declaration,
                    )
                    .map(PythonRuntimeClassCandidate::WorkspaceClass);
                }
                PythonLexicalNameResolution::Unbound if binds => return None,
                PythonLexicalNameResolution::Unbound => break,
            }
        }
        current = parent;
    }
    if python_type_parameter_binds_name_at_bounded(name, base, source, || support.scope_step())? {
        return None;
    }
    match python_lexical_declaration_binding_bounded(support, base, source) {
        PythonLexicalBinding::LocalClass(declaration) => {
            python_unit_for_class_declaration(support, file, source, base, declaration)
                .map(PythonRuntimeClassCandidate::WorkspaceClass)
        }
        PythonLexicalBinding::UnboundOrGlobal => {
            python_runtime_module_class_candidate_bounded(support, token, file, source, base, name)
        }
        PythonLexicalBinding::LocalFunction(_) | PythonLexicalBinding::Other => None,
    }
}

/// Runtime class admission has mutation obligations beyond ordinary navigation.
fn python_runtime_module_class_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    reference: Node<'tree>,
    name: &str,
) -> Option<PythonRuntimeClassCandidate<'tree>> {
    let mut root = reference;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !support.module_binding_unmutated_from_source_bounded(file, root, source, name, reference)? {
        return None;
    }
    // A positive assignment witness requires the COMPLETE module inventory;
    // an early Other kind is not evidence that later writes are absent.
    let binding = python_unambiguous_module_binding_node_bounded(root, source, name, || {
        support.scope_step()
    })??;
    if binding.kind == PythonDirectScopeBindingKind::Other {
        let target = binding.declaration;
        let assignment = target.parent()?;
        let statement = assignment.parent()?;
        if target.kind() != "identifier"
            || assignment.kind() != "assignment"
            || assignment.child_by_field_name("left") != Some(target)
            || assignment.child_by_field_name("type").is_some()
            || assignment.child_by_field_name("annotation").is_some()
            || statement.kind() != "expression_statement"
            || statement.parent() != Some(root)
            || assignment.end_byte() > reference.start_byte()
            || assignment.has_error()
        {
            return None;
        }
        let rhs = assignment.child_by_field_name("right")?;
        if rhs.kind() == "assignment" || rhs.has_error() || rhs.is_missing() {
            return None;
        }
        // Transport syntax, never an inferred instance/type or a cached answer.
        // The hierarchy rechecks the RHS binding at THIS source occurrence.
        return (support.python.indexed_source_matches(file, source) && support.scope_step())
            .then_some(PythonRuntimeClassCandidate::AliasRhs { assignment, rhs });
    }
    python_class_candidate_for_name_with_import_admission(
        support,
        token,
        file,
        source,
        reference,
        name,
        |owner, prepared, imported_name| {
            support.module_export_unmutated_bounded(owner, prepared, imported_name)
        },
    )
    .filter(|_| support.python.indexed_source_matches(file, source))
    .map(PythonRuntimeClassCandidate::WorkspaceClass)
}

fn python_unit_for_class_declaration(
    support: &PythonDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    base: Node<'_>,
    declaration: Node<'_>,
) -> Option<CodeUnit> {
    let name = python_slice(declaration.child_by_field_name("name")?, source);
    let mut selected = None;
    for candidate in support.file_identifier(file, name) {
        if !support.scope_step() {
            return None;
        }
        if candidate.is_class()
            && python_class_node_for_candidate_bounded(support, source, base, &candidate)
                == Some(declaration)
        {
            if selected.is_some() {
                return None;
            }
            selected = Some(candidate);
        }
    }
    selected
}

pub(crate) fn python_class_candidate_for_name(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    python_class_candidate_for_name_with_import_admission(
        support,
        token,
        file,
        source,
        site,
        name,
        |_, _, _| Some(true),
    )
}

fn python_class_candidate_for_name_with_import_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
    mut admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    if name.is_empty() {
        return None;
    }
    let mut file_candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    file_candidates.retain(|candidate| {
        python_same_file_class_visible_at(support, source, site, candidate).unwrap_or(false)
    });
    if let Some(candidate) = unique_python_candidate(file_candidates) {
        return Some(candidate);
    }
    // A same-file declaration shadows an import, so the binder is consulted only
    // after the file's own classes cannot answer the name.
    if let Some(candidate) = python_imported_class_candidate_with_admission(
        support,
        token,
        file,
        source,
        site,
        name,
        &mut admit_export,
    ) {
        return Some(candidate);
    }
    if !name.contains('.') {
        return None;
    }
    let exact_candidates = support
        .fqn(name)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    unique_python_candidate(exact_candidates)
}

/// Resolve a class imported exclusively under `if TYPE_CHECKING:` for use in
/// static type bounds. Runtime expression resolution must continue to ignore
/// this import because the name is not bound when the module executes.
pub(crate) fn python_type_checking_imported_class_candidate(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if name.is_empty() || !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(name)?;
    if binding.kind != ImportKind::Named {
        return None;
    }
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !python_type_checking_import_is_unique_bounded(
        support,
        token,
        file,
        root,
        name,
        site.start_byte(),
        source,
    )? {
        return None;
    }
    python_imported_class_from_module(
        support,
        token,
        file,
        binding.module_specifier.clone(),
        binding.imported_name.as_ref()?.clone(),
    )
}

fn python_type_checking_import_is_unique_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    name: &str,
    reference_start: usize,
    source: &str,
) -> Option<bool> {
    let mut matched_import = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "wildcard_import" {
            return Some(false);
        }
        for direct in python_direct_scope_bindings_bounded(node, source, || support.scope_step())? {
            if python_slice(direct.declaration, source) != name {
                continue;
            }
            let mut declaration = direct.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                let Some(parent) = declaration.parent() else {
                    return Some(false);
                };
                declaration = parent;
            }
            if declaration.kind() != "import_from_statement"
                || declaration.start_byte() > reference_start
                || matched_import.is_some()
            {
                return Some(false);
            }
            let Some(block) = declaration.parent() else {
                return Some(false);
            };
            let Some(guard) = block.parent() else {
                return Some(false);
            };
            if block.kind() != "block"
                || guard.kind() != "if_statement"
                || guard
                    .child_by_field_name("consequence")
                    .map(|body| body.id())
                    != Some(block.id())
                || guard.parent().map(|parent| parent.kind()) != Some("module")
            {
                return Some(false);
            }
            let Some(condition) = guard.child_by_field_name("condition") else {
                return Some(false);
            };
            if !python_type_checking_condition_is_imported(
                support, token, file, root, condition, source,
            )? {
                return Some(false);
            }
            matched_import = Some(declaration);
        }
        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if Some(child.id()) != excluded_body {
                stack.push(child);
            }
        }
    }
    Some(matched_import.is_some())
}

fn python_type_checking_condition_is_imported(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    root: Node<'_>,
    condition: Node<'_>,
    source: &str,
) -> Option<bool> {
    if condition.kind() != "identifier" {
        return Some(false);
    }
    let name = python_slice(condition, source);
    let binding = support
        .import_binder(token, file)?
        .bindings
        .get(name)?
        .clone();
    if binding.kind != ImportKind::Named
        || binding.module_specifier != "typing"
        || binding.imported_name.as_deref() != Some("TYPE_CHECKING")
    {
        return Some(false);
    }
    python_import_binding_is_unique_bounded(support, root, name, condition.start_byte(), source)
}

/// The class an imported local name binds to.
///
/// A named import may point directly at a class declaration or at a package
/// facade that re-exports it. Resolve that structured export identity before
/// applying the uniqueness/class gate. Namespace imports name modules, not
/// class declarations.
fn python_imported_class_candidate_with_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    site: Node<'_>,
    name: &str,
    admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    let binder = support.import_binder(token, file)?;
    let binding = binder.bindings.get(name)?;
    if binding.kind != ImportKind::Named || !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let imported = binding.imported_name.as_ref()?;
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    if !python_import_binding_is_unique_bounded(support, root, name, site.start_byte(), source)? {
        return None;
    }
    python_imported_class_from_module_with_admission(
        support,
        token,
        file,
        binding.module_specifier.clone(),
        imported.clone(),
        admit_export,
    )
}

fn python_imported_class_from_module(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    module: String,
    imported_name: String,
) -> Option<CodeUnit> {
    python_imported_class_from_module_with_admission(
        support,
        token,
        importer,
        module,
        imported_name,
        |_, _, _| Some(true),
    )
}

fn python_runtime_imported_class_from_module(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    module: String,
    imported_name: String,
) -> Option<CodeUnit> {
    python_imported_class_from_module_with_admission(
        support,
        token,
        importer,
        module,
        imported_name,
        |owner, prepared, name| support.module_export_unmutated_bounded(owner, prepared, name),
    )
}

fn python_imported_class_from_module_with_admission(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    importer: &ProjectFile,
    mut module: String,
    mut imported_name: String,
    mut admit_export: impl FnMut(
        &ProjectFile,
        &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
        &str,
    ) -> Option<bool>,
) -> Option<CodeUnit> {
    let mut importer = importer.clone();
    let mut visited = HashSet::default();

    loop {
        if !support.scope_step() || !visited.insert((module.clone(), imported_name.clone())) {
            return None;
        }
        let module_unit = support.module_code_unit(&importer, &module)?;
        let prepared = support
            .session
            .query(|| support.python.prepared_syntax(token, module_unit.source()))??;
        if !matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_))
            || !support
                .python
                .indexed_source_matches(module_unit.source(), prepared.source())
        {
            return None;
        }
        let target_root = prepared.tree().root_node();
        let target_source = prepared.source();
        // Runtime imports require mutation admission at every actual owner;
        // ordinary navigation retains its declaration-based export contract.
        if !admit_export(module_unit.source(), &prepared, &imported_name)? {
            return None;
        }
        let target_binder = support.import_binder(token, module_unit.source())?;

        if let Some(target_binding) = target_binder.bindings.get(&imported_name) {
            // A facade hop is safe only when the target module's complete
            // module-scope inventory proves one unconditional named import.
            // The ordinary binder is collapsed and therefore cannot establish
            // source order or reject a conditional/rebound import by itself.
            if target_binding.kind != ImportKind::Named
                || !python_import_binding_is_unique_bounded(
                    support,
                    target_root,
                    &imported_name,
                    usize::MAX,
                    target_source,
                )?
                || !support
                    .python
                    .indexed_source_matches(module_unit.source(), target_source)
            {
                return None;
            }
            importer = module_unit.source().clone();
            module = target_binding.module_specifier.clone();
            imported_name = target_binding.imported_name.as_ref()?.clone();
            continue;
        }

        // No import means this module must provide exactly one unconditional
        // class declaration. Keep all indexed declarations through the
        // uniqueness check so a class/function collision cannot be treated as
        // a type proof.
        if !python_unambiguous_module_class_binding_bounded(
            target_root,
            target_source,
            &imported_name,
            || support.scope_step(),
        )? {
            return None;
        }
        // The module's own module-scope inventory has already proven one
        // unconditional binding for this name, so the indexed lookup only has
        // to hand back that declaration's unit. Two sibling roots can share
        // one module FQN, so the uniqueness question is which declaration
        // *this* module file owns, not how many the workspace spells that way.
        let fqn = format!("{}.{}", module_unit.fq_name(), imported_name);
        let candidate = unique_python_candidate(
            support
                .fqn(&fqn)
                .into_iter()
                .filter(|candidate| candidate.source() == module_unit.source())
                .collect(),
        )?;
        if !support
            .python
            .indexed_source_matches(module_unit.source(), prepared.source())
        {
            return None;
        }
        return candidate.is_class().then_some(candidate);
    }
}

#[derive(Clone, Copy)]
struct PythonReferenceVisibility<'tree> {
    class_scope: Option<Node<'tree>>,
    deferred_body: bool,
}

#[derive(Clone, Copy)]
enum PythonClassDeclarationScope<'tree> {
    Module,
    Class(Node<'tree>),
    Other,
}

#[derive(Clone, Copy)]
enum PythonFunctionDeclarationScope<'tree> {
    Module,
    Function(Node<'tree>),
    Other,
}

#[derive(Clone, Copy)]
enum PythonDeclarationScope<'tree> {
    Module,
    Class(Node<'tree>),
    Function(Node<'tree>),
    Other,
}

fn python_same_file_class_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let visibility = python_reference_visibility_bounded(support, site)?;
    let declaration = python_class_node_for_candidate_bounded(support, source, site, candidate)?;
    if !visibility.deferred_body && declaration.start_byte() > site.start_byte() {
        return Some(false);
    }
    let declaration_scope = python_class_declaration_scope_bounded(support, declaration)?;
    let visible = match declaration_scope {
        PythonClassDeclarationScope::Module => {
            let mut root = site;
            while let Some(parent) = root.parent() {
                if !support.scope_step() {
                    return None;
                }
                root = parent;
            }
            python_unambiguous_module_class_binding_bounded(
                root,
                source,
                candidate.identifier(),
                || support.scope_step(),
            )?
        }
        PythonClassDeclarationScope::Class(scope) => visibility
            .class_scope
            .is_some_and(|visible| visible == scope),
        PythonClassDeclarationScope::Other => false,
    };
    Some(visible)
}

fn python_reference_visibility_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    site: Node<'tree>,
) -> Option<PythonReferenceVisibility<'tree>> {
    let site_start = site.start_byte();
    let site_end = site.end_byte();
    let mut class_scope = None;
    let mut current = site;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return Some(PythonReferenceVisibility {
                class_scope: None,
                deferred_body: true,
            });
        }
        if class_scope.is_none() && parent.kind() == "class_definition" {
            class_scope = Some(parent);
        }
        current = parent;
    }
    Some(PythonReferenceVisibility {
        class_scope,
        deferred_body: false,
    })
}

fn python_class_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    python_declaration_node_for_candidate_bounded(
        support,
        source,
        site,
        candidate,
        "class_definition",
    )
}

fn python_declaration_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
    declaration_kind: &str,
) -> Option<Node<'tree>> {
    let mut root = site;
    while let Some(parent) = root.parent() {
        if !support.scope_step() {
            return None;
        }
        root = parent;
    }
    for range in support.ranges(candidate) {
        if range.start_byte >= range.end_byte || range.end_byte > source.len() {
            continue;
        }
        let Some(mut node) = python_smallest_named_node_covering_bounded(
            support,
            root,
            range.start_byte,
            range.end_byte,
        ) else {
            continue;
        };
        loop {
            if node.kind() == declaration_kind
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| python_slice(name, source) == candidate.identifier())
            {
                return Some(node);
            }
            if node.kind() == "decorated_definition" {
                for child in python_named_children_bounded(support, node)? {
                    if child.kind() == declaration_kind
                        && child.child_by_field_name("name").is_some_and(|name| {
                            python_slice(name, source) == candidate.identifier()
                        })
                    {
                        return Some(child);
                    }
                }
            }
            let Some(parent) = node.parent() else {
                break;
            };
            if !support.scope_step() {
                return None;
            }
            node = parent;
        }
    }
    None
}

fn python_class_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonClassDeclarationScope<'tree>> {
    match python_declaration_scope_bounded(support, declaration)? {
        PythonDeclarationScope::Module => Some(PythonClassDeclarationScope::Module),
        PythonDeclarationScope::Class(owner) => Some(PythonClassDeclarationScope::Class(owner)),
        PythonDeclarationScope::Function(_) | PythonDeclarationScope::Other => {
            Some(PythonClassDeclarationScope::Other)
        }
    }
}

fn python_same_file_function_visible_at(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'_>,
    candidate: &CodeUnit,
) -> Option<bool> {
    let declaration = python_function_node_for_candidate_bounded(support, source, site, candidate)?;
    let visibility = python_reference_visibility_bounded(support, site)?;
    match python_function_declaration_scope_bounded(support, declaration)? {
        PythonFunctionDeclarationScope::Module => {
            Some(visibility.deferred_body || declaration.start_byte() <= site.start_byte())
        }
        PythonFunctionDeclarationScope::Function(owner) => {
            let nearest = python_enclosing_callable_bounded(support, site)?;
            let mut inside_owner = false;
            let mut current = Some(site);
            while let Some(node) = current {
                if !support.scope_step() {
                    return None;
                }
                if node == owner {
                    inside_owner = true;
                    break;
                }
                current = node.parent();
            }
            Some(
                inside_owner && (nearest != owner || declaration.start_byte() <= site.start_byte()),
            )
        }
        PythonFunctionDeclarationScope::Other => Some(false),
    }
}

fn python_function_node_for_candidate_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    source: &str,
    site: Node<'tree>,
    candidate: &CodeUnit,
) -> Option<Node<'tree>> {
    python_declaration_node_for_candidate_bounded(
        support,
        source,
        site,
        candidate,
        "function_definition",
    )
}

fn python_function_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonFunctionDeclarationScope<'tree>> {
    match python_declaration_scope_bounded(support, declaration)? {
        PythonDeclarationScope::Module => Some(PythonFunctionDeclarationScope::Module),
        PythonDeclarationScope::Function(owner) => {
            Some(PythonFunctionDeclarationScope::Function(owner))
        }
        PythonDeclarationScope::Class(_) | PythonDeclarationScope::Other => {
            Some(PythonFunctionDeclarationScope::Other)
        }
    }
}

fn python_declaration_scope_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    declaration: Node<'tree>,
) -> Option<PythonDeclarationScope<'tree>> {
    let mut current = declaration;
    while let Some(parent) = current.parent() {
        if !support.scope_step() {
            return None;
        }
        match parent.kind() {
            "module" => return Some(PythonDeclarationScope::Module),
            "class_definition" => return Some(PythonDeclarationScope::Class(parent)),
            "function_definition" | "lambda" => {
                return Some(PythonDeclarationScope::Function(parent));
            }
            "decorated_definition" => current = parent,
            "if_statement" | "for_statement" | "while_statement" | "try_statement"
            | "with_statement" | "match_statement" | "case_clause" => {
                return Some(PythonDeclarationScope::Other);
            }
            _ => current = parent,
        }
    }
    Some(PythonDeclarationScope::Other)
}

fn unique_python_candidate(mut candidates: Vec<CodeUnit>) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn python_current_receiver_class(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    if !matches!(name, "self" | "cls") {
        return None;
    }
    let function = python_enclosing_callable_bounded(support, node)?;
    let layout =
        formal_parameter_slots_for_owner_bounded(Language::Python, function, source, || {
            support.scope_step()
        })?;
    if matches!(layout.python_binding, Some(PythonMethodBinding::Static))
        || layout
            .slots
            .first()
            .is_none_or(|slot| !slot.names.iter().any(|candidate| candidate == name))
    {
        return None;
    }
    let mut parent = function.parent();
    while let Some(candidate) = parent {
        if !support.scope_step() {
            return None;
        }
        if candidate.kind() == "class_definition" {
            let class_name = candidate.child_by_field_name("name")?;
            return python_class_candidate_for_name(
                support,
                token,
                file,
                source,
                node,
                python_slice(class_name, source),
            );
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") {
            return None;
        }
        parent = candidate.parent();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn python_bound_type_for_identifier(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    identifier: Node<'_>,
    name: &str,
    depth: usize,
) -> Option<CodeUnit> {
    let function = python_enclosing_callable_bounded(support, identifier)?;
    if let Some(parameters) = function.child_by_field_name("parameters")
        && let Some(annotation) =
            python_parameter_annotation_bounded(support, parameters, source, name)
    {
        return python_type_from_annotation_bounded(
            support,
            token,
            file,
            source,
            annotation,
            depth + 1,
        );
    }
    let body = function.child_by_field_name("body")?;
    let mut best: Option<Node<'_>> = None;
    let mut stack = vec![body];
    while let Some(candidate) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if candidate.start_byte() >= identifier.start_byte() {
            continue;
        }
        if candidate != body
            && matches!(
                candidate.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if candidate.kind() == "assignment"
            && let Some(left) = candidate.child_by_field_name("left")
            && left.kind() == "identifier"
            && python_slice(left, source) == name
            && best.is_none_or(|previous| previous.start_byte() < candidate.start_byte())
        {
            best = Some(candidate);
        }
        let children = python_named_children_bounded(support, candidate)?;
        stack.extend(children.into_iter().rev());
    }
    let assignment = best?;
    python_assignment_bound_type_bounded(support, token, file, source, root, assignment, depth + 1)
}

fn python_parameter_annotation_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    parameters: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if matches!(node.kind(), "typed_parameter" | "typed_default_parameter") {
            let binding = node.child_by_field_name("name").or_else(|| {
                node.named_child(0)
                    .filter(|candidate| candidate.kind() == "identifier")
            });
            if binding.is_some_and(|binding| python_slice(binding, source) == name) {
                if let Some(annotation) = node.child_by_field_name("type") {
                    return Some(annotation);
                }
                for candidate in python_named_children_bounded(support, node)? {
                    if candidate.kind() != "identifier" {
                        return Some(candidate);
                    }
                }
                return None;
            }
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    None
}

fn python_type_from_annotation_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    annotation: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth >= 12 || !support.scope_step() {
        return None;
    }
    match annotation.kind() {
        "identifier" | "string_content" => python_class_candidate_for_name(
            support,
            token,
            file,
            source,
            annotation,
            python_slice(annotation, source),
        ),
        "attribute" => {
            let exact = python_slice(annotation, source);
            unique_python_candidate(
                support
                    .fqn(exact)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect(),
            )
        }
        "string" => {
            let content = python_named_children_bounded(support, annotation)?
                .into_iter()
                .find(|child| child.kind() == "string_content")?;
            python_type_from_annotation_bounded(support, token, file, source, content, depth + 1)
        }
        // The grammar wraps an annotation, a PEP 695 bound and a `*Ts` unpack
        // around the type they carry, and the type is the first named child.
        "type" | "constrained_type" | "splat_type" | "type_parameter" => {
            let inner = python_named_children_bounded(support, annotation)?
                .into_iter()
                .next()?;
            python_type_from_annotation_bounded(support, token, file, source, inner, depth + 1)
        }
        // A subscripted annotation names its outer class, never a type
        // argument: `list[int]` is a `list` and `Generator[Result, None,
        // None]` is a generator, not a `Result`. `Optional[X]` and
        // `Union[...]` are the two forms that name their arguments instead.
        "generic_type" | "subscript" => {
            let parts = python_subscripted_annotation_parts(support, annotation)?;
            if python_annotation_names_its_arguments(parts.base, source) {
                let mut candidates = Vec::new();
                for argument in parts.arguments {
                    if let Some(candidate) = python_type_from_annotation_bounded(
                        support,
                        token,
                        file,
                        source,
                        argument,
                        depth + 1,
                    ) {
                        candidates.push(candidate);
                    }
                }
                unique_python_candidate(candidates)
            } else {
                python_type_from_annotation_bounded(
                    support,
                    token,
                    file,
                    source,
                    parts.base,
                    depth + 1,
                )
            }
        }
        // A PEP 604 `X | Y` names each member of the union. The grammar
        // spells it `union_type` in a type position and `binary_operator`
        // where the annotation is read as an expression.
        "union_type" | "binary_operator"
            if annotation.kind() == "union_type"
                || annotation
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "|") =>
        {
            let mut candidates = Vec::new();
            for member in python_named_children_bounded(support, annotation)? {
                if let Some(candidate) = python_type_from_annotation_bounded(
                    support,
                    token,
                    file,
                    source,
                    member,
                    depth + 1,
                ) {
                    candidates.push(candidate);
                }
            }
            unique_python_candidate(candidates)
        }
        _ => None,
    }
}

/// The outer type and the type arguments of a subscripted annotation.
struct PythonSubscriptedAnnotation<'tree> {
    base: Node<'tree>,
    arguments: Vec<Node<'tree>>,
}

fn python_subscripted_annotation_parts<'tree>(
    support: &PythonDefinitionProvider<'_>,
    annotation: Node<'tree>,
) -> Option<PythonSubscriptedAnnotation<'tree>> {
    match annotation.kind() {
        // `list[int]` in an annotation: the outer name comes first and the
        // bracketed arguments follow as one `type_parameter` list.
        "generic_type" => {
            let mut children = python_named_children_bounded(support, annotation)?.into_iter();
            let base = children.next()?;
            let mut arguments = Vec::new();
            for list in children {
                arguments.extend(python_named_children_bounded(support, list)?);
            }
            Some(PythonSubscriptedAnnotation { base, arguments })
        }
        // The same shape reached through expression syntax carries its
        // arguments in one or more `subscript` fields.
        "subscript" => {
            let base = annotation.child_by_field_name("value")?;
            let mut arguments = Vec::new();
            let mut cursor = annotation.walk();
            for child in annotation.children_by_field_name("subscript", &mut cursor) {
                if !support.scope_step() {
                    return None;
                }
                if child.kind() == "tuple" {
                    arguments.extend(python_named_children_bounded(support, child)?);
                } else {
                    arguments.push(child);
                }
            }
            Some(PythonSubscriptedAnnotation { base, arguments })
        }
        _ => None,
    }
}

/// Whether a subscripted annotation's outer name is one of the two forms whose
/// type arguments are the annotated classes rather than parameters of an outer
/// class: `Optional[X]` and `Union[...]`.
fn python_annotation_names_its_arguments(base: Node<'_>, source: &str) -> bool {
    let name = match base.kind() {
        "identifier" => python_slice(base, source),
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                base.child_by_field_name("object"),
                base.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            if object.kind() != "identifier"
                || attribute.kind() != "identifier"
                || !matches!(python_slice(object, source), "typing" | "typing_extensions")
            {
                return false;
            }
            python_slice(attribute, source)
        }
        _ => return false,
    };
    matches!(name, "Optional" | "Union")
}

fn python_callable_return_type_in_tree(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    callable: &CodeUnit,
    depth: usize,
) -> Option<CodeUnit> {
    if callable.source() != file || depth >= 12 {
        return None;
    }
    let ranges = support.ranges(callable);
    let mut functions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "function_definition"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| python_slice(name, source) == callable.identifier())
            && ranges.iter().any(|range| {
                range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte
            })
        {
            functions.push(node);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    let function = (functions.len() == 1).then(|| functions.remove(0))?;
    python_function_return_type_from_node_bounded(
        support, token, file, source, root, function, depth,
    )
}

/// Whether a function definition is a coroutine function.
///
/// The grammar marks it with an `async` token before `def` rather than with a
/// distinct node kind or a field.
fn python_function_is_async(function: Node<'_>) -> bool {
    let mut cursor = function.walk();
    function
        .children(&mut cursor)
        .any(|child| !child.is_named() && child.kind() == "async")
}

fn python_function_return_type_from_node_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    // Calling an `async def` produces a coroutine. Its annotation describes
    // what awaiting that coroutine yields, so it is not the call's own type,
    // and the body's `return` values are not either.
    if python_function_is_async(function) {
        return None;
    }
    let facts = support.callable_source_facts(token, file)?;
    let declaration = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .unwrap_or(function);
    let Some(fact) =
        facts.callable_return_for_range(declaration.start_byte(), declaration.end_byte(), &|| {
            support.scope_step()
        })
    else {
        support.source_facts_unavailable.set(true);
        return None;
    };
    if fact.return_annotation.is_some() {
        return python_captured_return_type_bounded(
            support,
            token,
            file,
            source,
            root,
            &facts,
            fact,
            depth + 1,
        );
    }

    let body = function.child_by_field_name("body")?;
    let mut returns = Vec::new();
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if !support.scope_step() {
            return None;
        }
        if node != body
            && matches!(
                node.kind(),
                "function_definition" | "lambda" | "class_definition"
            )
        {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
            && let Some(candidate) = python_type_for_expression_bounded(
                support,
                token,
                file,
                source,
                root,
                value,
                depth + 1,
            )
        {
            returns.push(candidate);
            continue;
        }
        let children = python_named_children_bounded(support, node)?;
        stack.extend(children.into_iter().rev());
    }
    unique_python_candidate(returns)
}

/// Resolve source-owned annotation candidates in the active lexical scope.
/// Their ordering and attribute fallback structure were selected by the primary
/// producer; this walk does not interpret declaration annotation syntax.
#[allow(clippy::too_many_arguments)]
fn python_captured_return_type_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    facts: &brokk_bifrost_python::source_facts::PythonFileSourceFacts,
    fact: &brokk_bifrost_core::analyzer::python_facts::PythonCallableReturnFact,
    depth: usize,
) -> Option<CodeUnit> {
    use brokk_bifrost_core::analyzer::python_facts::PythonAnnotationReferenceName;
    let mut candidates = Vec::new();
    let mut index = 0;
    while let Some(reference) = fact.annotation_references.get(index) {
        if !support.scope_step() {
            return None;
        }
        if depth.saturating_add(usize::from(reference.lookup_depth)) >= 12 {
            index += 1;
            continue;
        }
        let candidate = match &reference.name {
            PythonAnnotationReferenceName::Lexical(name) => {
                let range = facts.occurrences.occurrence(reference.occurrence).range;
                let focus = root.descendant_for_byte_range(range.start_byte, range.end_byte);
                let Some(focus) = focus.filter(|focus| {
                    focus.start_byte() == range.start_byte && focus.end_byte() == range.end_byte
                }) else {
                    support.source_facts_unavailable.set(true);
                    return None;
                };
                python_class_candidate_for_name(support, token, file, source, focus, name)
            }
            PythonAnnotationReferenceName::Qualified(path) => unique_python_candidate(
                support
                    .fqn(&path.join("."))
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect(),
            ),
            PythonAnnotationReferenceName::Unavailable => None,
        };
        if let Some(candidate) = candidate {
            candidates.push(candidate);
            index = reference.subtree_end;
        } else {
            index += 1;
        }
    }
    unique_python_candidate(candidates)
}

fn python_enclosing_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    python_nearest_enclosing_callable(node, || support.scope_step(), |_| true)
}

fn python_nearest_enclosing_callable<'tree>(
    node: Node<'tree>,
    mut scope_step: impl FnMut() -> bool,
    mut accepts: impl FnMut(Node<'tree>) -> bool,
) -> Option<Node<'tree>> {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if !scope_step() {
            return None;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda") && accepts(candidate) {
            return Some(candidate);
        }
        parent = candidate.parent();
    }
    None
}

fn python_has_lexical_binding_bounded(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'_>,
    source: &str,
) -> bool {
    !matches!(
        python_lexical_binding_bounded(support, identifier, source),
        PythonLexicalBinding::UnboundOrGlobal
    )
}

#[derive(Clone, Copy, Debug)]
enum PythonLexicalBinding<'tree> {
    UnboundOrGlobal,
    LocalFunction(Node<'tree>),
    LocalClass(Node<'tree>),
    Other,
}

fn python_lexical_binding_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'tree>,
    source: &str,
) -> PythonLexicalBinding<'tree> {
    match python_lexical_declaration_binding_bounded(support, identifier, source) {
        PythonLexicalBinding::LocalClass(_) => PythonLexicalBinding::Other,
        binding => binding,
    }
}

fn python_lexical_declaration_binding_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    identifier: Node<'tree>,
    source: &str,
) -> PythonLexicalBinding<'tree> {
    let name = python_slice(identifier, source);
    let reference_start = identifier.start_byte();
    let reference_end = identifier.end_byte();
    let mut current = identifier;
    let mut unresolved_nonlocal = false;
    while let Some(candidate) = current.parent() {
        if !support.scope_step() {
            // Exhausted or cancelled binding discovery must never reopen the
            // module-level class fallback.
            return PythonLexicalBinding::Other;
        }
        if matches!(candidate.kind(), "function_definition" | "lambda")
            && candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        {
            let Some(inventory) =
                python_lexical_scope_inventory_bounded(candidate, source, || support.scope_step())
            else {
                return PythonLexicalBinding::Other;
            };
            let Some(resolution) =
                inventory.name_resolution_at_bounded(name, identifier, || support.scope_step())
            else {
                return PythonLexicalBinding::Other;
            };
            match resolution {
                PythonLexicalNameResolution::Local => {
                    let declaration = if let Some(declaration) = inventory
                        .local_function_declaration_bounded(name, identifier, || {
                            support.scope_step()
                        }) {
                        declaration
                    } else if let Some(declaration) =
                        inventory.local_class_declaration_bounded(name, identifier, || {
                            support.scope_step()
                        })
                    {
                        // Class bases execute now. Prove a preceding class in
                        // the identical immediate statement container; never
                        // turn a parameter/assignment/conditional into a class.
                        let mut statement = identifier;
                        while statement.parent().is_some_and(|parent| {
                            parent.kind() != "block" && parent.kind() != "module"
                        }) {
                            if !support.scope_step() {
                                return PythonLexicalBinding::Other;
                            }
                            statement = statement.parent().expect("parent checked");
                        }
                        return if declaration.parent() == statement.parent()
                            && declaration.end_byte() <= statement.start_byte()
                            && declaration.parent() == candidate.child_by_field_name("body")
                        {
                            PythonLexicalBinding::LocalClass(declaration)
                        } else {
                            PythonLexicalBinding::Other
                        };
                    } else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(PythonFunctionDeclarationScope::Function(owner)) =
                        python_function_declaration_scope_bounded(support, declaration)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    let Some(nearest) = python_enclosing_body_callable_bounded(support, identifier)
                    else {
                        return PythonLexicalBinding::Other;
                    };
                    return if owner == candidate
                        && (nearest != owner || declaration.start_byte() <= identifier.start_byte())
                    {
                        PythonLexicalBinding::LocalFunction(declaration)
                    } else {
                        PythonLexicalBinding::Other
                    };
                }
                PythonLexicalNameResolution::Nonlocal => unresolved_nonlocal = true,
                PythonLexicalNameResolution::Global => {
                    return if python_global_binding_is_untouched_bounded(
                        name,
                        identifier,
                        candidate,
                        source,
                        || support.scope_step(),
                    ) == Some(true)
                    {
                        PythonLexicalBinding::UnboundOrGlobal
                    } else {
                        PythonLexicalBinding::Other
                    };
                }
                PythonLexicalNameResolution::Unbound => {}
            }
        }
        current = candidate;
    }
    if unresolved_nonlocal {
        PythonLexicalBinding::Other
    } else {
        PythonLexicalBinding::UnboundOrGlobal
    }
}

fn python_enclosing_body_callable_bounded<'tree>(
    support: &PythonDefinitionProvider<'_>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    let reference_start = node.start_byte();
    let reference_end = node.end_byte();
    python_nearest_enclosing_callable(
        node,
        || support.scope_step(),
        |candidate| {
            candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference_start && reference_end <= body.end_byte()
            })
        },
    )
}

/// Restore the exact synthetic identifier selected inside a deferred annotation.
///
/// Tree-sitter represents the contents of `"Widget | Gadget"` as one
/// `string_content` leaf. The generic reference-site resolver therefore widens
/// either structured occurrence range to that whole leaf, even though the
/// Python adapter has parsed and validated two distinct identifier ranges
/// inside it. Narrow only ranges reproduced by that structured parser; ordinary
/// strings and arbitrary subranges retain the generic fail-closed behavior.
pub(crate) fn python_site_for_focus(
    mut site: ResolvedReferenceSite,
    tree: &Tree,
    source: &str,
    requested_start: Option<usize>,
    requested_end: Option<usize>,
) -> ResolvedReferenceSite {
    let (Some(start), Some(end)) = (requested_start, requested_end) else {
        return site;
    };
    let Some(node) = smallest_named_node_covering(tree.root_node(), start, end) else {
        return site;
    };
    if node.kind() != "string_content" {
        return site;
    }
    let Some(string) = node.parent() else {
        return site;
    };
    let exact_deferred_identifier =
        python_deferred_annotation_identifier_ranges(string, source, None).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|range| range.start_byte == start && range.end_byte == end)
        });
    if !exact_deferred_identifier {
        return site;
    }
    let Some(text) = source.get(start..end) else {
        return site;
    };
    let line_starts = compute_line_starts(source);
    site.text = text.to_owned();
    site.range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start) + 1,
        end_line: find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1,
    };
    site.focus_start_byte = start;
    site.focus_end_byte = end;
    site
}

/// Exact external callable selected by one explicit Python import.
///
/// Identity comes from the tree-sitter import binder and call expression, not
/// from the local spelling. A proof exists only when that import is the one
/// unconditional, module- or function-scoped binding visible at a static call.
/// Rebinding, competing bindings, wildcard/class-local uncertainty, and the
/// wrong attribute depth intentionally return no proof.
// No production caller since #5658 M8 step 1a; tests still exercise it until the legacy resolver is deleted (#5658).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct PythonImportedCallSelection {
    pub(crate) proof: ExactExternalCallProof,
    pub(crate) module: Vec<String>,
    pub(crate) member: String,
}

/// An import path is not yet a class or callable declaration proof.
pub(crate) struct PythonImportedSymbolSelection {
    pub(crate) module: Vec<String>,
    pub(crate) member: String,
    // No production caller since #5658 M8 step 1a; tests still exercise it until the legacy resolver is deleted (#5658).
    #[cfg_attr(not(test), allow(dead_code))]
    canonical_name: String,
    import_kind: brokk_bifrost_core::analyzer::model::StructuredImportPathKind,
    // Selected structured namespace segments consumed before the final member.
    consumed_attributes: usize,
    requires_imported_module: bool,
}

impl PythonImportedSymbolSelection {
    /// Import selection alone cannot turn an imported value into a module.
    /// Share the original external intermediate-module admission across local
    /// class bases, decorators and other exact imported-symbol consumers.
    pub(crate) fn external_symbol_bounded(
        self,
        support: &PythonDefinitionProvider<'_>,
    ) -> Option<(String, String)> {
        let first_module = match self.import_kind {
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom
                if self.requires_imported_module =>
            {
                Some(self.module.len())
            }
            brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace
                if self.consumed_attributes > 0 =>
            {
                Some(self.module.len().checked_sub(self.consumed_attributes)?)
            }
            _ => None,
        };
        if let Some(first) = first_module {
            for end in first..=self.module.len() {
                if !support.scope_step() {
                    return None;
                }
                python_complete_external_module(support, &self.module[..end].join("."))?;
            }
        }
        let module = self.module.join(".");
        python_external_model_namespace_available(support, &module, &self.member)
            .then_some((module, self.member))
    }
}

enum PythonFunctionImportSelection<'a> {
    Selected(&'a PythonImportBinding),
    NotLocal,
    Blocked,
}

/// Shared import-binding proof for a selected expression, before source or
/// external declaration admission. None is a stopped walk, not an empty proof.
pub(crate) fn python_local_imported_symbol_bounded(
    support: &PythonDefinitionProvider<'_>,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
) -> Option<Option<PythonImportedSymbolSelection>> {
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    let Some(path) = python_static_attribute_path_bounded(expression, || support.scope_step())
    else {
        return if support.session.observe_cancellation() {
            Some(None)
        } else {
            None
        };
    };
    let reference = *path.first()?;
    // Module/class-body-only references keep their existing module gates;
    // no function-local import projection is needed for that route.
    let owner = python_nearest_enclosing_callable(
        reference,
        || support.scope_step(),
        |candidate| {
            candidate.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= reference.start_byte()
                    && reference.end_byte() <= body.end_byte()
            })
        },
    );
    if owner.is_none() {
        return if support.session.observe_cancellation() {
            Some(None)
        } else {
            None
        };
    }
    let imports = support
        .session
        .query(|| support.python.import_info_of(token, file))?;
    let bindings =
        python_import_bindings_from_imports_bounded(&imports, root, source.len(), || {
            support.scope_step()
        })?;
    let binding = match python_visible_function_import_binding_bounded(
        &bindings,
        python_slice(reference, source),
        reference,
        source,
        || support.scope_step(),
    )? {
        PythonFunctionImportSelection::Selected(binding) => binding,
        PythonFunctionImportSelection::NotLocal | PythonFunctionImportSelection::Blocked => {
            return Some(None);
        }
    };
    let selected =
        python_imported_symbol_for_binding_bounded(binding, &path, &imports, source, || {
            support.scope_step()
        });
    if !support.python.indexed_source_matches(file, source) {
        return None;
    }
    if !support.session.observe_cancellation() {
        return None;
    }
    Some(selected)
}

fn python_imported_symbol_for_binding_bounded(
    binding: &PythonImportBinding,
    path: &[Node<'_>],
    imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonImportedSymbolSelection> {
    let local_name = python_slice(*path.first()?, source);
    let final_segment = python_slice(*path.last()?, source);
    let canonical_name = if path.len() == 1 {
        (binding.consumed_attributes == 0).then(|| binding.qualified_name.clone())?
    } else {
        (path.len() - 1 == binding.consumed_attributes + 1)
            .then(|| format!("{}.{}", binding.qualified_name, final_segment))?
    };
    let mut matched = None;
    for import in imports {
        if !scope_step() {
            return None;
        }
        let Some(import_path) = &import.path else {
            continue;
        };
        for _ in &import_path.segments {
            if !scope_step() {
                return None;
            }
        }
        if import_path.declaration_start_byte == binding.start_byte
            && import_path.render_segments(".") == binding.qualified_name
            && import.local_name() == Some(local_name)
        {
            if matched.is_some() {
                return None;
            }
            matched = Some(import_path);
        }
    }
    let import = matched?;
    // An unaliased dotted namespace import consumes those exact receiver
    // segments, not any receiver prefix of the same length. Aliases consume
    // no attributes; their local token was checked against ImportInfo above.
    if binding.consumed_attributes > 0 {
        if import.kind
            != Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::Namespace)
            || import.segments.len() != binding.consumed_attributes + 1
        {
            return None;
        }
        for (node, segment) in path.iter().zip(&import.segments) {
            if !scope_step() || python_slice(*node, source) != segment {
                return None;
            }
        }
    }
    if path.len() == 1
        && import.kind
            != Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ImportFrom)
    {
        return None;
    }
    let (module, member) = if path.len() == 1 {
        let (member, module) = import.segments.split_last()?;
        (module.to_vec(), member.clone())
    } else {
        (import.segments.clone(), final_segment.to_owned())
    };
    if !scope_step() {
        return None;
    }
    Some(PythonImportedSymbolSelection {
        module,
        member,
        canonical_name,
        import_kind: import.kind?,
        consumed_attributes: binding.consumed_attributes,
        requires_imported_module: path.len() > 1,
    })
}

// No production caller since #5658 M8 step 1a; tests still exercise it until the legacy resolver is deleted (#5658).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn exact_python_imported_call_selection(
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &[brokk_bifrost_core::analyzer::model::ImportInfo],
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonImportedCallSelection> {
    let root = tree.root_node();
    let (path, call) = crate::analyzer::python::external_authority::python_imported_callee_shape(
        tree,
        site.focus_start_byte,
        site.focus_end_byte,
        &mut scope_step,
    )?;
    let bindings =
        python_import_bindings_from_imports_bounded(imports, root, source.len(), &mut scope_step)?;
    let reference = *path.first()?;
    let name = python_slice(reference, source);
    let binding = match python_visible_function_import_binding_bounded(
        &bindings,
        name,
        reference,
        source,
        &mut scope_step,
    )? {
        PythonFunctionImportSelection::Selected(binding) => binding,
        PythonFunctionImportSelection::Blocked => return None,
        PythonFunctionImportSelection::NotLocal => python_visible_module_import_binding_bounded(
            root,
            &bindings,
            name,
            reference,
            source,
            &mut scope_step,
        )??,
    };
    let selected = python_imported_symbol_for_binding_bounded(
        binding,
        &path,
        imports,
        source,
        &mut scope_step,
    )?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut parameter_count = 0u32;
    let mut cursor = arguments.walk();
    for _ in arguments.named_children(&mut cursor) {
        if !scope_step() {
            return None;
        }
        parameter_count = parameter_count.checked_add(1)?;
    }
    Some(PythonImportedCallSelection {
        proof: ExactExternalCallProof::python_imported_call(
            selected.canonical_name,
            parameter_count,
        ),
        module: selected.module,
        member: selected.member,
    })
}

fn python_visible_function_import_binding_bounded<'a>(
    bindings: &'a [PythonImportBinding],
    local_name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<PythonFunctionImportSelection<'a>> {
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, try_walk_named_tree_preorder};
    if python_comprehension_binds_name_at_bounded(local_name, reference, source, &mut scope_step)?
        || python_type_parameter_binds_name_at_bounded(
            local_name,
            reference,
            source,
            &mut scope_step,
        )?
    {
        return Some(PythonFunctionImportSelection::Blocked);
    }
    let mut current = reference;
    let mut crossed_callable = false;
    let mut crossed_class_namespace = false;
    while let Some(parent) = current.parent() {
        if !scope_step() {
            return None;
        }
        let inside_body = parent.child_by_field_name("body").is_some_and(|body| {
            body.start_byte() <= reference.start_byte() && reference.end_byte() <= body.end_byte()
        });
        if parent.kind() == "class_definition"
            && inside_body
            && !crossed_callable
            && !crossed_class_namespace
        {
            let class_scope =
                PythonClassReferenceScope::new_bounded(parent, reference, &mut scope_step)?;
            let inventory = class_scope.collect_bounded(source, &mut scope_step)?;
            match inventory.name_resolution_at_bounded(local_name, reference, &mut scope_step)? {
                PythonLexicalNameResolution::Global => {
                    return Some(
                        if python_global_binding_is_untouched_bounded(
                            local_name,
                            reference,
                            parent,
                            source,
                            &mut scope_step,
                        )? {
                            PythonFunctionImportSelection::NotLocal
                        } else {
                            PythonFunctionImportSelection::Blocked
                        },
                    );
                }
                PythonLexicalNameResolution::Nonlocal | PythonLexicalNameResolution::Local => {
                    return Some(PythonFunctionImportSelection::Blocked);
                }
                PythonLexicalNameResolution::Unbound => {
                    if class_scope.binds_name_bounded(local_name, source, &mut scope_step)? {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    // A nested class does not capture an outer class namespace.
                    crossed_class_namespace = true;
                }
            }
        } else if inside_body && matches!(parent.kind(), "function_definition" | "lambda") {
            let inventory =
                python_lexical_scope_inventory_bounded(parent, source, &mut scope_step)?;
            match inventory.name_resolution_at_bounded(local_name, reference, &mut scope_step)? {
                PythonLexicalNameResolution::Global => {
                    return Some(
                        if python_global_binding_is_untouched_bounded(
                            local_name,
                            reference,
                            parent,
                            source,
                            &mut scope_step,
                        )? {
                            PythonFunctionImportSelection::NotLocal
                        } else {
                            PythonFunctionImportSelection::Blocked
                        },
                    );
                }
                PythonLexicalNameResolution::Nonlocal => {
                    return Some(PythonFunctionImportSelection::Blocked);
                }
                PythonLexicalNameResolution::Unbound => crossed_callable = true,
                PythonLexicalNameResolution::Local => {
                    if crossed_callable {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    let Some(declaration) = inventory.unique_import_declaration_bounded(
                        local_name,
                        reference,
                        &mut scope_step,
                    )?
                    else {
                        return Some(PythonFunctionImportSelection::Blocked);
                    };
                    let mut selected = None;
                    for binding in bindings {
                        if !scope_step() {
                            return None;
                        }
                        if binding.is_function_scoped()
                            && binding.local_name == local_name
                            && binding.scope_start_byte == parent.start_byte()
                            && binding.scope_end_byte == parent.end_byte()
                        {
                            if selected.is_some() {
                                return Some(PythonFunctionImportSelection::Blocked);
                            }
                            selected = Some(binding);
                        }
                    }
                    let Some(binding) = selected else {
                        return Some(PythonFunctionImportSelection::Blocked);
                    };
                    if !python_function_import_is_unconditional_bounded(
                        parent,
                        binding,
                        declaration,
                        reference,
                        &mut scope_step,
                    )? {
                        return Some(PythonFunctionImportSelection::Blocked);
                    }
                    // Nonlocal declarations expose this cell. A preceding
                    // nested callable can also capture it without a nonlocal
                    // statement; refuse that uncertainty without interpreting
                    // calls, closure objects or cell_contents writes. Bodies
                    // created by the selected class after its header are not
                    // preceding captures.
                    let mut exposed_cell = false;
                    try_walk_named_tree_preorder(
                        parent.child_by_field_name("body")?,
                        true,
                        |node| {
                            if !scope_step() {
                                return Err(());
                            }
                            if node.kind() != "identifier"
                                || python_slice(node, source) != local_name
                            {
                                return Ok(WalkControl::Continue);
                            }
                            let nonlocal = node
                                .parent()
                                .is_some_and(|p| p.kind() == "nonlocal_statement");
                            let preceding_capture = if !nonlocal
                                && node.start_byte() < reference.start_byte()
                            {
                                let owner = python_nearest_enclosing_callable(
                                    node,
                                    &mut scope_step,
                                    |candidate| {
                                        candidate.child_by_field_name("body").is_some_and(|body| {
                                            body.start_byte() <= node.start_byte()
                                                && node.end_byte() <= body.end_byte()
                                        })
                                    },
                                )
                                .ok_or(())?;
                                owner != parent
                            } else {
                                false
                            };
                            if nonlocal || preceding_capture {
                                exposed_cell = true;
                                return Ok(WalkControl::Break);
                            }
                            Ok(WalkControl::Continue)
                        },
                    )
                    .ok()?;
                    return Some(if exposed_cell {
                        PythonFunctionImportSelection::Blocked
                    } else {
                        PythonFunctionImportSelection::Selected(binding)
                    });
                }
            }
        }
        current = parent;
    }
    Some(PythonFunctionImportSelection::NotLocal)
}

fn python_function_import_is_unconditional_bounded(
    function: Node<'_>,
    binding: &PythonImportBinding,
    declaration: Node<'_>,
    reference: Node<'_>,
    mut scope_step: impl FnMut() -> bool,
) -> Option<bool> {
    let mut current = declaration;
    while !matches!(current.kind(), "import_statement" | "import_from_statement") {
        if !scope_step() {
            return None;
        }
        let Some(parent) = current.parent() else {
            return Some(false);
        };
        if parent == function {
            return Some(false);
        }
        current = parent;
    }
    if current.start_byte() != binding.start_byte || current.end_byte() > reference.start_byte() {
        return Some(false);
    }
    let Some(body) = function.child_by_field_name("body") else {
        return Some(false);
    };
    Some(current.parent() == Some(body) && body.parent() == Some(function))
}

// No production caller since #5658 M8 step 1a; tests still exercise it until the legacy resolver is deleted (#5658).
#[cfg_attr(not(test), allow(dead_code))]
fn python_visible_module_import_binding_bounded<'a>(
    root: Node<'_>,
    bindings: &'a [PythonImportBinding],
    local_name: &str,
    reference: Node<'_>,
    source: &str,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Option<&'a PythonImportBinding>> {
    let mut selected = None;
    for binding in bindings {
        if !scope_step() {
            return None;
        }
        if !binding.is_function_scoped()
            && binding.local_name == local_name
            && binding.start_byte <= reference.start_byte()
        {
            if selected.is_some() {
                return Some(None);
            }
            selected = Some(binding);
        }
    }
    let Some(binding) = selected else {
        return Some(None);
    };
    // Preserve the module selector's preceding-event contract; this is not
    // the function-local uniqueness proof and cannot admit a class-body import.
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, try_walk_named_tree_preorder};
    let mut matched = false;
    let mut valid = true;
    try_walk_named_tree_preorder(root, true, |node| {
        if !scope_step() {
            return Err(());
        }
        if node.start_byte() >= reference.start_byte()
            || node.parent().is_some_and(|owner| {
                matches!(
                    owner.kind(),
                    "function_definition" | "lambda" | "class_definition"
                ) && owner.child_by_field_name("body") == Some(node)
            })
        {
            return Ok(WalkControl::SkipChildren);
        }
        if node.kind() == "wildcard_import" {
            valid = false;
            return Ok(WalkControl::Break);
        }
        for event in python_direct_scope_bindings_bounded(node, source, &mut scope_step).ok_or(())?
        {
            if python_slice(event.declaration, source) != local_name {
                continue;
            }
            let mut declaration = event.declaration;
            while !matches!(
                declaration.kind(),
                "import_statement" | "import_from_statement"
            ) {
                if !scope_step() {
                    return Err(());
                }
                let Some(parent) = declaration.parent() else {
                    valid = false;
                    return Ok(WalkControl::Break);
                };
                if parent.kind() == "module" {
                    valid = false;
                    return Ok(WalkControl::Break);
                }
                declaration = parent;
            }
            if declaration.parent() != Some(root)
                || declaration.start_byte() != binding.start_byte
                || matched
            {
                valid = false;
                return Ok(WalkControl::Break);
            }
            matched = true;
        }
        Ok(WalkControl::Continue)
    })
    .ok()?;
    Some((matched && valid).then_some(binding))
}

/// Which same-file declarations a bare Python name written at `node` can bind
/// to: a binding of the class body the name is written in, otherwise a
/// module-level declaration. A method or an attribute of some other class is
/// absent, because Python has no implicit receiver -- `list(values)` inside a
/// class that declares `def list(self, ...)` is the builtin, never `self.list`.
///
/// The forward resolver answers same-file lookups with this, and the reference
/// census grades against the same notion of scope (#2054): a same-file
/// declaration this rejects is not evidence that forward lookup missed a target.
pub fn python_visible_same_file_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let class_candidates =
        python_visible_class_binding_candidates(analyzer, file, node, candidates);
    if !class_candidates.is_empty() {
        return class_candidates;
    }
    candidates
        .iter()
        .filter(|candidate| {
            !candidate.is_module()
                && analyzer
                    .parent_of(candidate)
                    .is_some_and(|parent| parent.is_module())
        })
        .cloned()
        .collect()
}

fn python_visible_class_binding_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing_class = analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|mut scope| {
            if scope.is_function() && !python_function_declaration_expression_is_class_scoped(node)
            {
                return None;
            }
            loop {
                if scope.is_class() {
                    break Some(scope);
                }
                if scope.is_module() {
                    break None;
                }
                scope = analyzer.parent_of(&scope)?;
            }
        });
    let Some(enclosing_class) = enclosing_class else {
        return Vec::new();
    };
    let latest_end = candidates
        .iter()
        .filter(|candidate| {
            analyzer
                .parent_of(candidate)
                .is_some_and(|parent| parent == enclosing_class)
        })
        .flat_map(|candidate| analyzer.ranges(candidate))
        .filter(|range| range.end_byte <= node.start_byte())
        .map(|range| range.end_byte)
        .max();
    let Some(latest_end) = latest_end else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter(|candidate| {
            analyzer
                .parent_of(candidate)
                .is_some_and(|parent| parent == enclosing_class)
                && analyzer
                    .ranges(candidate)
                    .iter()
                    .any(|range| range.end_byte == latest_end)
        })
        .cloned()
        .collect()
}

fn python_function_declaration_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            return parent.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= site_start && site_end <= body.end_byte())
            });
        }
        if parent.kind() == "decorated_definition" {
            return current.kind() == "decorator";
        }
        if parent.kind() == "class_definition" {
            break;
        }
        current = parent;
    }
    false
}

#[cfg(test)]
pub(crate) fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

type PythonScopeFacts = HashMap<CodeUnit, LocalBindingsSnapshot<String>>;

pub(crate) struct PythonDefinitionContext {
    file: ProjectFile,
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
    scope_facts: OnceLock<Replayable<Arc<PythonScopeFacts>>>,
    lexical_scopes: Mutex<HashMap<(usize, usize), PythonLexicalScopeBindings>>,
    source_sha256: [u8; 32],
    receiver_types: Mutex<PythonReceiverTypeCache>,
    #[cfg(test)]
    build_counters: Arc<PythonDefinitionBuildCounters>,
}

struct PythonReceiverTypeCache {
    limit: usize,
    values: HashMap<(String, bool), Replayable<Option<CodeUnit>>>,
}

impl PythonReceiverTypeCache {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            values: HashMap::default(),
        }
    }
}

impl PythonDefinitionContext {
    fn name_shadowed_at(&self, name: &str, reference: Node<'_>, source: &str) -> bool {
        debug_assert!({
            let keys = brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(source);
            keys.as_bytes() == &self.source_sha256
        });
        // The context key already names the exact source. Cached inventories
        // contain owned binding facts, never nodes borrowed from another tree.
        let mut scopes = self
            .lexical_scopes
            .lock()
            .expect("Python lexical scope cache poisoned");
        python_name_shadowed_at(name, reference, source, &mut scopes)
    }

    pub(crate) fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        source_sha256: [u8; 32],
        #[cfg(test)] build_counters: Arc<PythonDefinitionBuildCounters>,
    ) -> Self {
        let binder = py.import_binder_of(token, file);
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        named.insert(
                            local.clone(),
                            format!("{}.{}", binding.module_specifier, imported),
                        );
                    }
                }
                ImportKind::Namespace => {
                    namespace.insert(local.clone(), binding.module_specifier.clone());
                }
                ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
            }
        }
        let mut same_file: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in same_file.values_mut() {
            sort_units(units);
        }
        Self {
            file: file.clone(),
            source_sha256,
            named,
            namespace,
            same_file,
            scope_facts: OnceLock::new(),
            lexical_scopes: Mutex::default(),
            receiver_types: Mutex::new(PythonReceiverTypeCache::new(
                PYTHON_RECEIVER_TYPE_CACHE_LIMIT,
            )),
            #[cfg(test)]
            build_counters,
        }
    }

    fn namespace_module_for_node(&self, object: Node<'_>, source: &str) -> Option<String> {
        let mut attributes = Vec::new();
        let mut current = object;
        while current.kind() == "attribute" {
            let attribute = current.child_by_field_name("attribute")?;
            let text = python_slice(attribute, source);
            if text.is_empty() {
                return None;
            }
            attributes.push(text);
            current = current.child_by_field_name("object")?;
        }
        if current.kind() != "identifier" {
            return None;
        }
        let root = python_slice(current, source);
        let mut module = self.namespace.get(root)?.clone();
        for attribute in attributes.into_iter().rev() {
            module.push('.');
            module.push_str(attribute);
        }
        Some(module)
    }

    fn receiver_type_for_object(
        &self,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        object: &str,
    ) -> Option<CodeUnit> {
        if let Some(fqn) = self.named.get(object) {
            return python_class_for_fqn(py, support, &self.file, fqn);
        }
        self.same_file
            .get(object)?
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    }

    fn receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        let raw_type = raw_type.trim();
        if &self.file != file {
            return self.generic_receiver_type(analyzer, py, file, raw_type, target_self_file);
        }

        let key = (raw_type.to_string(), target_self_file);
        if let Some(cached) = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned")
            .values
            .get(&key)
        {
            debug_assert_eq!(
                cached.reads.digest(),
                brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(
                    &cached.reads.keys()
                )
            );
            cached.receipt.replay();
            return cached.value.clone();
        }

        #[cfg(test)]
        self.build_counters
            .receiver_type_cache_misses
            .fetch_add(1, Ordering::Relaxed);

        let ((resolved, reads), receipt) =
            brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(analyzer, || {
                brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                    self.receiver_type_for_object(py, support, raw_type)
                        .or_else(|| {
                            self.generic_receiver_type(
                                analyzer,
                                py,
                                file,
                                raw_type,
                                target_self_file,
                            )
                        })
                })
            });

        let mut cache = self
            .receiver_types
            .lock()
            .expect("Python receiver type cache mutex poisoned");
        if cache.values.len() < cache.limit {
            cache.values.insert(
                key,
                Replayable {
                    value: resolved.clone(),
                    reads,
                    receipt,
                },
            );
        }
        resolved
    }

    fn generic_receiver_type(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        raw_type: &str,
        target_self_file: bool,
    ) -> Option<CodeUnit> {
        #[cfg(test)]
        self.build_counters
            .generic_receiver_type_fallbacks
            .fetch_add(1, Ordering::Relaxed);
        with_python_graph_source(analyzer, |graph| {
            resolve_python_receiver_type(&graph, py, file, raw_type, target_self_file)
        })
    }

    fn scope_facts(
        &self,
        analyzer: &dyn IAnalyzer,
        py: &PythonAnalyzer,
        file: &ProjectFile,
        source: &str,
        root: Node<'_>,
    ) -> Option<Arc<PythonScopeFacts>> {
        if let Some(entry) = self.scope_facts.get() {
            debug_assert_eq!(
                entry.reads.digest(),
                brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest(&entry.reads.keys())
            );
            entry.receipt.replay();
            return Some(Arc::clone(&entry.value));
        }
        let _scope = brokk_bifrost_core::profiling::scope("get_definition::python::scope_facts");
        #[cfg(test)]
        self.build_counters
            .scope_fact_builds
            .fetch_add(1, Ordering::Relaxed);
        let ((facts, reads), receipt) =
            brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(analyzer, || {
                brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                    with_python_graph_source(analyzer, |graph| {
                        collect_scope_facts_from_parsed_source(&graph, py, file, source, root)
                    })
                })
            });
        let Some(facts) = facts else {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "Canonical Python callable annotations are unavailable for {file:?}"
                )),
            );
            return None;
        };
        let entry = self.scope_facts.get_or_init(|| Replayable {
            value: Arc::new(facts),
            reads,
            receipt,
        });
        entry.receipt.replay();
        Some(Arc::clone(&entry.value))
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct PythonDefinitionBuildCounters {
    pub(crate) context_builds: AtomicUsize,
    pub(crate) scope_fact_builds: AtomicUsize,
    pub(crate) receiver_type_cache_misses: AtomicUsize,
    pub(crate) generic_receiver_type_fallbacks: AtomicUsize,
}

enum PythonReferenceNode<'tree> {
    Identifier,
    Attribute {
        object: Node<'tree>,
    },
    /// A keyword argument `name=value` in a call `Callee(name=..)`: `name` resolves
    /// to the callee type's member/parameter (e.g. a dataclass field `Foo.a`), not
    /// a name in scope.
    KeywordArgument,
}

/// A keyword-argument identifier (`a` in `Foo(a=3)`): the `name` of a
/// `keyword_argument` inside a call's `argument_list`.
fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    python_reference_node_with_step(node, || true)
}

/// Declarations indexed at exactly `fqn` in a language other than Python.
fn python_cross_language_declarations(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
) -> Vec<CodeUnit> {
    cross_language_declarations(support, fqn, Language::Python)
}

fn python_class_for_fqn(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    importer: &ProjectFile,
    fqn: &str,
) -> Option<CodeUnit> {
    resolve_fqn_candidates(py, Some(importer), fqn, |name| support.fqn(name))
        .into_iter()
        .find(|unit| unit.is_class())
        .or_else(|| {
            // An imported CLR/JVM type used as a receiver: the class is indexed
            // at this exact fq in another language (#1174).
            python_cross_language_declarations(support, fqn)
                .into_iter()
                .find(|unit| unit.is_class())
        })
}

#[allow(clippy::too_many_arguments)]
fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "identifier" => {
            let receiver = python_slice(object, source);
            if let Some(unit) =
                python_self_receiver_type(analyzer, py, file, root, object, receiver)
            {
                return Some(unit);
            }
            // A typed-variable receiver: use the local/parameter's inferred type.
            let facts_by_scope = context.scope_facts(analyzer, py, file, source, root)?;
            if let Some(facts) = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)
                && let Some(raw_type) = facts
                    .resolution_for(receiver)
                    .as_precise()
                    .and_then(|targets| targets.iter().next().cloned())
                && let Some(unit) =
                    context.receiver_type(analyzer, py, support, file, &raw_type, false)
            {
                return Some(unit);
            }
            // A class-name receiver: `ClassName.Nested` / `ClassName.member`
            // accesses a member on the class itself.
            let class = context.receiver_type(analyzer, py, support, file, receiver, false);
            if class.is_some() {
                return class;
            }
            let binder = py.import_binder_of(token, file);
            let binding = binder.bindings.get(receiver)?;
            let imported = binding.imported_name.as_ref()?;
            let fqn = format!("{}.{}", binding.module_specifier, imported);
            python_class_for_fqn(py, support, file, &fqn)
        }
        // A call receiver: `Foo().bar` (construction) or `make().bar` (the
        // called function/method's return type).
        "call" => python_call_result_type(
            analyzer, token, py, support, context, file, source, root, object,
        ),
        _ => None,
    }
}

/// Resolve the instance class for one exact Python bound-method call. A
/// class-qualified call is excluded because an instance's `__getattribute__`
/// does not intercept lookup on the class object.
pub(crate) fn python_bound_receiver_class_for_method_call(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    callee_start_byte: usize,
) -> Option<CodeUnit> {
    let py = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    let context = request_definition_context(py, analyzer, token, file, source);
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);
    let focus = tree
        .root_node()
        .named_descendant_for_byte_range(callee_start_byte, callee_start_byte.saturating_add(1))?;
    let PythonReferenceNode::Attribute { object, .. } = python_reference_node(focus)? else {
        return None;
    };
    let callee = match focus.kind() {
        "attribute" => focus,
        _ => {
            let mut current = focus;
            loop {
                let parent = current.parent()?;
                if parent.kind() != "attribute"
                    || parent.child_by_field_name("attribute") != Some(current)
                {
                    return None;
                }
                current = parent;
                if let Some(call) = current.parent()
                    && call.kind() == "call"
                    && call.child_by_field_name("function") == Some(current)
                {
                    break current;
                }
            }
        }
    };
    let call = callee.parent()?;
    if call.kind() != "call" || call.child_by_field_name("function") != Some(callee) {
        return None;
    }
    if python_receiver_is_class_qualified(py, &support, &context, object, source) {
        return None;
    }
    python_receiver_type_unit(
        analyzer,
        token,
        py,
        &support,
        &context,
        file,
        source,
        tree.root_node(),
        object,
    )
}

fn python_receiver_is_class_qualified(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    receiver: Node<'_>,
    source: &str,
) -> bool {
    match receiver.kind() {
        "identifier" => {
            let name = python_slice(receiver, source);
            !context.name_shadowed_at(name, receiver, source)
                && context
                    .receiver_type_for_object(py, support, name)
                    .is_some()
        }
        "attribute" => context
            .namespace_module_for_node(receiver, source)
            .is_some(),
        _ => false,
    }
}

/// The type produced by a call expression: the class for a construction
/// (`Foo()`), or the resolved return type of the called function/method
/// (`make()`, `obj.make()`).
#[allow(clippy::too_many_arguments)]
fn python_call_result_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<CodeUnit> {
    let function = call.child_by_field_name("function")?;
    let callee = python_resolve_callable(
        analyzer, token, py, support, context, file, source, root, function,
    )?;
    if callee.is_class() {
        return Some(callee);
    }
    python_callable_return_type(analyzer, py, support, context, &callee)
}

/// Resolve a call's callee expression to the class or function/method being
/// called.
#[allow(clippy::too_many_arguments)]
fn python_resolve_callable(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
) -> Option<CodeUnit> {
    match function.kind() {
        "identifier" => {
            let name = python_slice(function, source);
            if let Some(class) = context.receiver_type(analyzer, py, support, file, name, false) {
                return Some(class);
            }
            analyzer
                .declarations(file)
                .into_iter()
                .find(|unit| unit.identifier() == name && unit.is_function())
        }
        "attribute" => {
            let receiver = function.child_by_field_name("object")?;
            let method = python_slice(function.child_by_field_name("attribute")?, source);
            let receiver_type = python_receiver_type_unit(
                analyzer, token, py, support, context, file, source, root, receiver,
            )?;
            analyzer
                .definitions(&format!("{}.{}", receiver_type.fq_name(), method))
                .next()
        }
        _ => None,
    }
}

/// The declared or inferred return type of a Python function/method: read a
/// `-> T` annotation, else infer from a `return T(...)` / `return T` in the
/// body. Resolved in the callable's own file.
fn python_callable_return_type(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    context: &PythonDefinitionContext,
    callable: &CodeUnit,
) -> Option<CodeUnit> {
    let file = callable.source();
    let metadata = analyzer.signature_metadata(callable);
    let first = metadata.first()?;
    if let Some(nominal) = first
        .return_type_identity()
        .and_then(|identity| identity.nominal_name())
        && let Some(class) =
            context.receiver_type(analyzer, py, support, file, &nominal.path().join("."), true)
    {
        return Some(class);
    }
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let prepared = brokk_bifrost_python::graph_support::PythonSource::prepared_syntax(
        py,
        query_scope.token(),
        file,
    )?;
    let source = prepared.source();
    let root = prepared.tree().root_node();
    let mut ranges = analyzer.ranges(callable);
    ranges.sort_by_key(|range| range.start_byte);
    let function = ranges.into_iter().find_map(|range| {
        let declaration = root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
        python_first_function_definition(declaration)
    })?;

    let body = function.child_by_field_name("body")?;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        // Don't descend into nested functions/classes — their returns are theirs.
        if matches!(node.kind(), "function_definition" | "class_definition") {
            continue;
        }
        if node.kind() == "return_statement"
            && let Some(value) = node.named_child(0)
        {
            let name = match value.kind() {
                "call" => value
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|f| python_slice(f, source)),
                "identifier" => Some(python_slice(value, source)),
                _ => None,
            };
            let class = name
                .and_then(|name| context.receiver_type(analyzer, py, support, file, name, true));
            if let Some(class) = class {
                return Some(class);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn python_self_receiver_type(
    analyzer: &dyn IAnalyzer,
    _py: &PythonAnalyzer,
    file: &ProjectFile,
    _root: Node<'_>,
    object: Node<'_>,
    receiver: &str,
) -> Option<CodeUnit> {
    if receiver != "self" && receiver != "cls" {
        return None;
    }
    let range = Range {
        start_byte: object.start_byte(),
        end_byte: object.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .filter(|unit| unit.is_class())
}

fn python_name_shadowed_at(
    name: &str,
    reference: Node<'_>,
    source: &str,
    scopes: &mut HashMap<(usize, usize), PythonLexicalScopeBindings>,
) -> bool {
    if python_comprehension_binds_name_at(name, reference, source) {
        return true;
    }
    let mut current = reference;
    while let Some(parent) = current.parent() {
        current = parent;
        if !matches!(current.kind(), "function_definition" | "lambda") {
            continue;
        }
        let bindings = match scopes.entry((current.start_byte(), current.end_byte())) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let Some(inventory) =
                    python_lexical_scope_inventory_bounded(current, source, || true)
                else {
                    return true;
                };
                entry.insert(inventory.into_bindings())
            }
        };
        match bindings.name_resolution_at(name, reference) {
            PythonLexicalNameResolution::Local => return true,
            PythonLexicalNameResolution::Global => return false,
            PythonLexicalNameResolution::Nonlocal | PythonLexicalNameResolution::Unbound => {}
        }
    }
    false
}

pub(crate) fn python_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call" if parent.child_by_field_name("function") == Some(current) => return true,
            "attribute" if parent.child_by_field_name("attribute") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

/// One selected native operation kept across the points of a batch or file
/// window, as the Rust and Go batch operations keep theirs. It opens on first
/// use, inside the caller's query, and every later use replays the opening
/// reads so each query records them. Only a clean answer keeps the operation:
/// a refusal, a budget stop or a store error reopens it for the next point, so
/// a transient failure is never reused as another query's answer (#8411).
struct PythonDefinitionBatchOperation<'a> {
    python: &'a PythonAnalyzer,
    request: Option<(
        crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest<'a>,
        brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads,
    )>,
}

pub(crate) fn definition_batch_resolver<'a>(
    analyzer: &'a dyn IAnalyzer,
) -> Option<Box<dyn DefinitionBatchResolver<'a> + 'a>> {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
    Some(Box::new(PythonDefinitionBatchOperation {
        python,
        request: None,
    }))
}

impl<'a> DefinitionBatchResolver<'a> for PythonDefinitionBatchOperation<'a> {
    fn release_file_operation(&mut self) {
        self.request = None;
    }

    fn release_before_store_read(&mut self) {
        // A writer-backed reader owns the writer mutex, and the caller's store
        // read would wait for it (#6018); pooled WAL readers may stay.
        if self
            .request
            .as_ref()
            .is_some_and(|(request, _)| request.reader_excludes_store_access())
        {
            self.request = None;
        }
    }

    fn precompute(
        &mut self,
        _analyzer: &dyn IAnalyzer,
        _context: &mut DefinitionBatchContext<'_, '_>,
        _requests: &[DefinitionLookupRequest],
        _cancellation: Option<&CancellationToken>,
    ) {
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch(
        &mut self,
        analyzer: &'a dyn IAnalyzer,
        _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
        _context: &mut DefinitionBatchContext<'a, '_>,
        request: &DefinitionLookupRequest,
        source: &Arc<str>,
        tree: &Option<Tree>,
        site: &ResolvedReferenceSite,
        _operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
        cancellation: Option<&CancellationToken>,
        _go_session: Option<&ResolutionSession>,
    ) -> std::ops::ControlFlow<DefinitionResolution, DefinitionResolution> {
        match &self.request {
            Some((_, reads)) => {
                brokk_bifrost_analysis::analyzer::usages::common::replay_memo_reads(
                    reads, analyzer,
                );
            }
            None => {
                let cancel = cancellation.cloned().unwrap_or_default();
                self.request = Some(
                    brokk_bifrost_analysis::analyzer::usages::common::capture_memo_reads(
                        analyzer,
                        || {
                            crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest::open(
                                self.python,
                                &cancel,
                            )
                        },
                    ),
                );
            }
        }
        let (retained, _) = self.request.as_mut().expect("Python batch request opened");
        let result = retained.resolve_definition_with_call_evidence_bounded(
            brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file: &request.file,
                source,
                tree: tree.as_ref(),
                site,
                budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation,
            },
        );
        // Go's rule: only a stopped answer or a failed operation releases the
        // request; an incomplete or unprojectable answer keeps it.
        let clean = matches!(
            &result,
            BoundedResolution::Complete { value: (outcome, _), .. }
                if !outcome.diagnostics.iter().any(|diagnostic| {
                    brokk_bifrost_analysis::analyzer::usages::common::is_native_operation_failure(
                        &diagnostic.kind,
                    )
                })
        );
        if !clean || retained.reader_excludes_store_access() {
            self.request = None;
        }
        std::ops::ControlFlow::Continue(definition_resolution_from_bounded(
            result,
            Language::Python,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_definition_dispatch<'a>(
    analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    _context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<
        'a,
        '_,
    >,
    request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
    source: &std::sync::Arc<str>,
    tree: &Option<tree_sitter::Tree>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    _operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    _go_session: Option<
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    >,
) -> std::ops::ControlFlow<
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
> {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)
        .expect("Python dispatch hook requires Python analyzer");
    let cancel = cancellation.cloned().unwrap_or_default();
    let mut retained =
        crate::analyzer::python::native_request::definition_lookup::PythonReceiverRequest::open(
            python, &cancel,
        );
    let result = retained.resolve_definition_with_call_evidence_bounded(
        brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
            analyzer,
            file: &request.file,
            source,
            tree: tree.as_ref(),
            site,
            budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation,
        },
    );
    std::ops::ControlFlow::Continue(definition_resolution_from_bounded(result, Language::Python))
}

#[cfg(test)]
mod bounded_tests {
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    use crate::analyzer::usages::get_definition::python::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "c3db46f1308d: retained Python definition request held the writer-only store reader across lookups"
    )]
    fn python_definition_batch_releases_writer_only_reader_between_points() {
        let source = "from service import Service\n\ndef handle(service: Service):\n    service.run()\n    service.stop()\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("service.py", "class Service:\n    def run(self):\n        pass\n    def stop(self):\n        pass\n")
            .file("app.py", source)
            .build();
        let project = fixture.project_dyn();
        let store = brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test(project.as_ref()).expect("writer-only store");
        assert!(store.store.uses_single_connection_reads());
        let python =
            PythonAnalyzer::new_with_config_store_context(project, Default::default(), store, None)
                .expect("Python analyzer");
        let scope = AnalyzerQueryScope::new(&python);
        let mut context = DefinitionBatchContext::new(&python, scope.token());
        let requests = ["run", "stop"]
            .into_iter()
            .map(|name| {
                let start =
                    source.find(&format!("service.{name}()")).expect("call") + "service.".len();
                DefinitionLookupRequest {
                    file: fixture.file("app.py"),
                    line: None,
                    column: None,
                    start_byte: Some(start),
                    end_byte: Some(start + name.len()),
                }
            })
            .collect();
        let outcomes =
            resolve_definition_requests(&python, scope.token(), &mut context, requests, None, None);
        assert_eq!(outcomes.len(), 2);
        for (outcome, expected) in outcomes
            .iter()
            .zip(["service.Service.run", "service.Service.stop"])
        {
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{outcome:?}"
            );
            let [definition] = outcome.definitions.as_slice() else {
                panic!("expected one definition: {outcome:?}");
            };
            assert_eq!(definition.fq_name(), expected);
        }
    }

    #[test]
    #[hardwon("#9575: named Python import reads cannot discard the mutation evidence receipt")]
    fn unindexed_import_identity_keeps_named_reads_and_the_mutation_scope_receipt() {
        let source = "from unavailable.package import ImmutableDict\nvalue = ImmutableDict\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("a.py", source)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let start = source.rfind("ImmutableDict").unwrap();
        let (answer, reads) =
            brokk_bifrost_analysis::analyzer::capture_query_reads(analyzer, || {
                resolve_value_identity_with_source_outcome(
                    analyzer,
                    DefinitionLookupRequest {
                        file: project.file("a.py"),
                        line: None,
                        column: None,
                        start_byte: Some(start),
                        end_byte: Some(start + "ImmutableDict".len()),
                    },
                    project.file("a.py"),
                    Arc::from(source),
                    None,
                )
            });
        assert!(matches!(answer, Ok(None)), "{answer:?}");
        // #9751: completed mutation evidence is certified by the whole Python
        // scope instead of refusing reuse.
        assert!(
            reads
                .keys()
                .contains(&analyzer.workspace_scope_read_key(&[Language::Python])),
            "missing Python mutation scope receipt: {:?}",
            reads.keys()
        );
        assert!(reads.is_bounded(), "{reads:?}");
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(reads.execution_dependences(), 0);
        assert!(
            reads.keys().contains(&ReadKey::index(
                brokk_bifrost_analysis::analyzer::read_ledger::IndexFamily::PackageMembership,
                "unavailable.package",
            )),
            "missing package membership: {:?}",
            reads.keys()
        );
        assert!(
            reads.keys().iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::WorkspaceFact,
                    question: brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::WorkspaceFact {
                        family: brokk_bifrost_analysis::analyzer::read_ledger::WorkspaceFactFamily::PythonModuleSpellings,
                        ..
                    },
                    ..
                }
            )),
            "missing module spelling authority: {:?}",
            reads.keys()
        );
    }

    #[test]
    #[hardwon(
        "#5745: repeated module guards exhausted hierarchy work and memo hits must retain current owner reads"
    )]
    fn module_mutation_operation_memo_preserves_stops_sources_and_owner_reads() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
        let source = "class A: pass\nclass B: pass\nclass C(A, B): pass\n";
        let changed = format!("{source}\ndef writer():\n    global A\n    A = B\n");
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("a.py", source)
            .file("b.py", source)
            .file("changed.py", &changed)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
        let prepared = {
            let scope = AnalyzerQueryScope::new(analyzer);
            py.prepared_syntax(scope.token(), &project.file("a.py"))
                .unwrap()
        };
        let base = prepared
            .tree()
            .root_node()
            .named_child(2)
            .unwrap()
            .child_by_field_name("superclasses")
            .unwrap()
            .named_child(0)
            .unwrap();
        let funded = || ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, None);

        // No outer query: nested owner reads must not replace the provider's memo.
        assert!(
            py.active_query_request_memo::<PythonModuleMutationRequestMemo>()
                .is_none()
        );
        let session = funded();
        let provider = PythonDefinitionProvider::new(py, &session);
        for _ in 0..2 {
            assert_eq!(
                provider.module_binding_unmutated_at_bounded(
                    &project.file("a.py"),
                    &prepared,
                    "A",
                    base
                ),
                Some(true)
            );
            assert_eq!(
                provider.module_export_unmutated_bounded(&project.file("a.py"), &prepared, "B"),
                Some(true)
            );
        }
        assert_eq!(
            provider
                .module_mutations
                .collections
                .load(Ordering::Relaxed),
            1
        );
        let fresh_session = funded();
        let fresh = PythonDefinitionProvider::new(py, &fresh_session);
        assert!(!Arc::ptr_eq(
            &provider.module_mutations,
            &fresh.module_mutations
        ));

        // An active query shares only syntax facts. A warm identical-byte owner
        // must record its own file dependency, never replay the first owner's.
        let scope = AnalyzerQueryScope::new(analyzer);
        let session = funded();
        let active = PythonDefinitionProvider::new(py, &session);
        let sibling = PythonDefinitionProvider::new(py, &session);
        assert!(Arc::ptr_eq(
            &active.module_mutations,
            &sibling.module_mutations
        ));
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("a.py"), &prepared, "A"),
            Some(true)
        );
        let other = py
            .prepared_syntax(scope.token(), &project.file("b.py"))
            .unwrap();
        let (answer, reads) =
            brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads(analyzer, || {
                sibling.module_export_unmutated_bounded(&project.file("b.py"), &other, "A")
            });
        assert_eq!(answer, Some(true));
        let keys = reads.keys();
        assert!(
            keys.iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "b.py")),
            "{keys:?}"
        );
        assert!(
            !keys.iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "a.py")),
            "{keys:?}"
        );
        assert_eq!(
            active.module_mutations.collections.load(Ordering::Relaxed),
            1
        );
        let changed = py
            .prepared_syntax(scope.token(), &project.file("changed.py"))
            .unwrap();
        assert_ne!(prepared.source_sha256(), changed.source_sha256());
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &changed, "A"),
            Some(false)
        );
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &changed, "B"),
            Some(true)
        );
        assert_eq!(
            active.module_mutations.collections.load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            active.module_export_unmutated_bounded(&project.file("changed.py"), &prepared, "A"),
            None,
            "a warm digest cannot substitute for a changed owner's current bytes"
        );

        // Partial collection is not published; a funded caller can fill later.
        let memo = PythonModuleMutationRequestMemo::default();
        let mut tiny = INTERACTIVE_TYPE_LOOKUP_BUDGET;
        tiny.max_scope_nodes = 1;
        let stopped = ResolutionSession::bounded(tiny, None);
        assert!(memo.facts(&prepared, &stopped).is_none());
        assert!(memo.facts.lock().unwrap().is_empty());
        assert!(memo.facts(&prepared, &funded()).is_some());
        assert_eq!(memo.collections.load(Ordering::Relaxed), 2);
        assert!(
            memo.facts(&prepared, &stopped).is_none(),
            "a warm hit cannot repair exhaustion"
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled =
            ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, Some(&cancellation));
        assert!(memo.facts(&prepared, &cancelled).is_none());
        let late = CancellationToken::cancel_after_checks_for_test(2);
        let cancelled = ResolutionSession::bounded(INTERACTIVE_TYPE_LOOKUP_BUDGET, Some(&late));
        assert!(
            memo.facts(&prepared, &cancelled).is_none(),
            "cancellation after hit entry is still terminal"
        );
        assert!(matches!(
            cancelled.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
        assert_eq!(memo.collections.load(Ordering::Relaxed), 2);
    }

    struct ExpandedCallableRangeAnalyzer {
        base: PythonAnalyzer,
        callable: CodeUnit,
        range: Range,
    }

    impl CodeUnitIndex for ExpandedCallableRangeAnalyzer {
        fn project(&self) -> &dyn brokk_bifrost_core::analyzer::project::Project {
            self.base.project()
        }

        fn languages(&self) -> std::collections::BTreeSet<Language> {
            self.base.languages()
        }

        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            self.base.all_declarations()
        }

        fn search_definitions(
            &self,
            pattern: &str,
            auto_quote: bool,
        ) -> std::collections::BTreeSet<CodeUnit> {
            self.base.search_definitions(pattern, auto_quote)
        }

        fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
            self.base.enclosing_code_unit(file, range)
        }

        fn enclosing_code_unit_for_lines(
            &self,
            file: &ProjectFile,
            start_line: usize,
            end_line: usize,
        ) -> Option<CodeUnit> {
            self.base
                .enclosing_code_unit_for_lines(file, start_line, end_line)
        }

        fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
            if code_unit == &self.callable {
                vec![self.range]
            } else {
                self.base.ranges(code_unit)
            }
        }

        fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
            self.base.get_skeleton(code_unit)
        }

        fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
            self.base.get_skeleton_header(code_unit)
        }

        fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
            self.base.get_source(code_unit, include_comments)
        }

        fn get_sources(
            &self,
            code_unit: &CodeUnit,
            include_comments: bool,
        ) -> std::collections::BTreeSet<String> {
            self.base.get_sources(code_unit, include_comments)
        }

        fn signature_metadata(
            &self,
            code_unit: &CodeUnit,
        ) -> Vec<brokk_bifrost_core::analyzer::model::SignatureMetadata> {
            self.base.signature_metadata(code_unit)
        }
    }

    impl IAnalyzer for ExpandedCallableRangeAnalyzer {
        fn update_with_listing(
            &self,
            changed_files: &std::collections::BTreeSet<ProjectFile>,
            listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
        ) -> Self {
            Self {
                base: self.base.update_with_listing(changed_files, listing),
                callable: self.callable.clone(),
                range: self.range,
            }
        }

        fn update_all(&self) -> Self {
            Self {
                base: self.base.update_all(),
                callable: self.callable.clone(),
                range: self.range,
            }
        }

        fn extract_call_receiver(&self, reference: &str) -> Option<String> {
            self.base.extract_call_receiver(reference)
        }

        fn is_access_expression(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
        ) -> bool {
            self.base.is_access_expression(file, start_byte, end_byte)
        }

        fn find_nearest_declaration(
            &self,
            file: &ProjectFile,
            start_byte: usize,
            end_byte: usize,
            ident: &str,
        ) -> Option<brokk_bifrost_core::analyzer::model::DeclarationInfo> {
            self.base
                .find_nearest_declaration(file, start_byte, end_byte, ident)
        }
    }

    #[test]
    #[hardwon("#4271: Python callable return inference selected the last sibling definition")]
    fn callable_return_type_uses_the_first_sibling_function_definition() {
        let source = "class First:\n    pass\n\nclass Second:\n    pass\n\ndef make_first():\n    return First()\n\ndef make_second():\n    return Second()\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Python, &[("app.py", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let file = analyzer
            .analyzed_files()
            .into_iter()
            .next()
            .expect("fixture Python file");
        let callable = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.identifier() == "make_first" && unit.is_function())
            .expect("make_first declaration");
        let scope = AnalyzerQueryScope::new(analyzer);
        let context = request_definition_context(py, analyzer, scope.token(), &file, source);
        let first_start = source.find("def make_first").expect("first sibling");
        let range = Range {
            start_byte: first_start,
            end_byte: source.len(),
            start_line: source[..first_start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: source.bytes().filter(|byte| *byte == b'\n').count(),
        };
        let indexed = ExpandedCallableRangeAnalyzer {
            base: py.clone(),
            callable: callable.clone(),
            range,
        };
        let support = AnalyzerDefinitionLookup::new(analyzer, Language::None);

        let inferred = python_callable_return_type(&indexed, py, &support, &context, &callable)
            .expect("the first sibling returns a known class");

        assert_eq!(inferred.identifier(), "First");
    }

    #[test]
    fn python_shadowing_context_keeps_supplied_source_identities_separate() {
        let original = "def read(local):\n    local.use()\n";
        let changed = "def read(other):\n    local.use()\n";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("app.py", original)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).unwrap();
        let scope = AnalyzerQueryScope::new(analyzer);
        let file = project.file("app.py");
        let equivalent = String::from(original);
        let prepared = py
            .prepared_syntax(scope.token(), &file)
            .expect("prepared source is indexed");
        let original_key = definition_context_key(analyzer, &file, original, Some(&prepared));
        let equivalent_key = definition_context_key(analyzer, &file, &equivalent, Some(&prepared));
        let changed_key = definition_context_key(analyzer, &file, changed, Some(&prepared));
        assert_eq!(original_key, equivalent_key);
        assert_eq!(
            original_key.source,
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::from_array(
                prepared.source_sha256()
            )
        );
        assert_ne!(original_key, changed_key);
        assert_eq!(
            changed_key.source,
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(changed)
        );

        for (source, expected) in [
            (original, true),
            (changed, false),
            (equivalent.as_str(), true),
            (original, true),
        ] {
            let context = request_definition_context(py, analyzer, scope.token(), &file, source);
            let tree = parse_python_tree(source).unwrap();
            let reference = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .child_by_field_name("body")
                .unwrap()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap()
                .child_by_field_name("function")
                .unwrap()
                .child_by_field_name("object")
                .unwrap();
            assert_eq!(
                context.name_shadowed_at("local", reference, source),
                expected
            );
        }
        assert_eq!(
            request_definition_build_counts(py).0,
            2,
            "byte-equivalent supplied source reuses the original context"
        );
    }

    #[test]
    fn python_shadowing_reuses_completed_bindings_across_reparsed_references() {
        let source = "def first(local):\n    local.use()\n    imported.use()\ndef second():\n    local.use()\n";
        let mut scopes = HashMap::default();
        for _ in 0..2 {
            // Each parse owns different nodes; retained facts must use source
            // positions and preserve both local and module binding behavior.
            let tree = parse_python_tree(source).unwrap();
            let mut pending = vec![tree.root_node()];
            let mut answers = Vec::new();
            while let Some(node) = pending.pop() {
                if node.kind() == "attribute" {
                    let reference = node.child_by_field_name("object").unwrap();
                    answers.push((
                        reference.start_byte(),
                        python_name_shadowed_at(
                            python_slice(reference, source),
                            reference,
                            source,
                            &mut scopes,
                        ),
                    ));
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            answers.sort_unstable();
            assert_eq!(
                answers
                    .into_iter()
                    .map(|(_, shadowed)| shadowed)
                    .collect::<Vec<_>>(),
                [true, false, false]
            );
            assert_eq!(scopes.len(), 2, "one completed inventory per callable");
        }
    }

    #[test]
    fn external_decorator_binding_distinguishes_absence_and_lexical_shadowing() {
        for (body, expected) in [
            ("@decorator\nclass Expected: pass\n", true),
            (
                "def outer():\n    from external import decorator\n    @decorator\n    class Expected: pass\n",
                true,
            ),
            (
                "def outer():\n    from external import value\n    @value.decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    import external.value\n    @external.value.decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    @decorator\n    class Expected: pass\n",
                true,
            ),
            (
                "def outer():\n    def decorator(cls): return cls\n    @decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    class decorator: pass\n    @decorator\n    class Expected: pass\n",
                false,
            ),
            (
                "def outer():\n    decorator = replacement\n    def inner():\n        nonlocal decorator\n        @decorator\n        class Expected: pass\n",
                false,
            ),
        ] {
            let source = format!("from external import decorator\n{body}");
            let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("app.py", &source)
                .build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
            let tree = parse_python_tree(&source).unwrap();
            let mut stack = vec![tree.root_node()];
            let expression = loop {
                let node = stack.pop().expect("fixture contains a decorator");
                if node.kind() == "decorator" {
                    break node.named_child(0).unwrap();
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            };
            let scope = AnalyzerQueryScope::new(python);
            let session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                None,
            );
            let support = PythonDefinitionProvider::new(python, &session);
            let actual = python_external_imported_symbol_bounded(
                &support,
                scope.token(),
                &project.file("app.py"),
                &source,
                tree.root_node(),
                expression,
            );
            assert_eq!(
                actual,
                expected.then(|| ("external".to_owned(), "decorator".to_owned())),
                "{source}"
            );
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "6c7b92f9623b: modeled Python wildcard imports were incorrectly left uncertain across same-target reexports"
    )]
    #[test]
    fn external_import_survives_only_same_target_workspace_wildcard_reexports() {
        let interface = concat!(
            "from abc import ABC\n",
            "from registry.models import *\n",
            "\n",
            "class Registry(ABC):\n",
            "    pass\n",
        );
        for (models, expected) in [
            (
                "from abc import ABC\nclass ToDict(ABC):\n    pass\n",
                Some(("abc".to_owned(), "ABC".to_owned())),
            ),
            ("class ABC:\n    pass\n", None),
        ] {
            let project = crate::inline_project::InlineTestProject::with_language(Language::Python)
                .file("registry/__init__.py", "")
                .file("registry/interface.py", interface)
                .file("registry/models.py", models)
                .build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let python = resolve_analyzer::<PythonAnalyzer>(workspace.analyzer()).unwrap();
            let scope = AnalyzerQueryScope::new(python);
            let file = project.file("registry/interface.py");
            let tree = parse_python_tree(interface).unwrap();
            let mut stack = vec![tree.root_node()];
            let base = loop {
                let node = stack.pop().expect("fixture contains Registry(ABC)");
                if node.kind() == "class_definition"
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|name| python_slice(name, interface) == "Registry")
                {
                    break node
                        .child_by_field_name("superclasses")
                        .and_then(|bases| bases.named_child(0))
                        .expect("Registry has one base");
                }
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            };
            let session = ResolutionSession::bounded(
                brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                None,
            );
            let support = PythonDefinitionProvider::new(python, &session);
            let actual = python_external_imported_symbol_bounded(
                &support,
                scope.token(),
                &file,
                interface,
                tree.root_node(),
                base,
            );
            assert_eq!(actual, expected, "models source:\n{models}");
        }
    }

    fn imported_call_selection(source: &str, callee: &str) -> Option<PythonImportedCallSelection> {
        imported_call_selection_with_steps(source, callee, || true)
    }

    fn imported_call_selection_with_steps(
        source: &str,
        callee: &str,
        scope_step: impl FnMut() -> bool,
    ) -> Option<PythonImportedCallSelection> {
        let tree = parse_python_tree(source).expect("Python tree");
        let start_byte = source
            .rfind(callee)
            .unwrap_or_else(|| panic!("missing `{callee}` call in source"));
        let end_byte = start_byte + callee.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: "caller.py".to_string(),
            text: callee.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        let file = ProjectFile::new(std::env::temp_dir(), "caller.py");
        let parsed = brokk_bifrost_python::declarations::parse_python_file(
            &brokk_bifrost_core::analyzer::project::TestProject::new(file.root(), Language::Python),
            &file,
            source,
            &tree,
        );
        exact_python_imported_call_selection(source, &tree, &site, &parsed.imports, scope_step)
    }

    fn imported_call_proof(source: &str, callee: &str) -> Option<ExactExternalCallProof> {
        imported_call_selection(source, callee).map(|selection| selection.proof)
    }

    #[test]
    fn same_statement_from_import_aliases_keep_their_own_callable_identity() {
        let source = "from yaml import unsafe_load as unsafe_load_alias, safe_load as safe_load_alias, load as load_alias\nunsafe_load_alias(data)\nsafe_load_alias(data)\nload_alias(data, Loader=loader)\n";
        for (alias, canonical, member, parameter_count) in [
            ("unsafe_load_alias", "yaml.unsafe_load", "unsafe_load", 1),
            ("safe_load_alias", "yaml.safe_load", "safe_load", 1),
            ("load_alias", "yaml.load", "load", 2),
        ] {
            let selection = imported_call_selection(source, alias)
                .unwrap_or_else(|| panic!("missing exact proof for `{canonical}`"));
            assert_eq!(selection.proof.canonical_callee(), canonical);
            assert_eq!(selection.module, vec!["yaml".to_owned()]);
            assert_eq!(selection.member, member);
            assert_eq!(selection.proof.parameter_count(), parameter_count);
        }
    }

    #[test]
    #[hardwon(
        "#5721: imported-call fallback bypassed competing declarations and captured-cell writes"
    )]
    fn exact_python_import_call_refuses_shadowed_and_rebound_locals() {
        let sources = [
            "import subprocess as sp\nsp = FakeProcess()\nsp.run(command)\n",
            "import requests\nrequests = FakeSession()\nrequests.get(url, verify=False)\n",
            "import subprocess as sp\ndef call(sp):\n    sp.run(command)\n",
            "def call(factory):\n    import subprocess as sp\n    sp = factory()\n    sp.run(command)\n",
            "def call():\n    from subprocess import run\n    def run(): pass\n    run(command)\n",
            "def call():\n    from subprocess import run\n    class run: pass\n    run(command)\n",
            "def call():\n    from subprocess import run\n    def mutate():\n        nonlocal run\n        run = fake\n    mutate()\n    run(command)\n",
            "def call():\n    from subprocess import run\n    class Mutate:\n        nonlocal run\n        run = fake\n    run(command)\n",
            "def call():\n    from subprocess import run\n    def capture(): return run\n    capture.__closure__[0].cell_contents = fake\n    run(command)\n",
        ];
        for source in sources {
            let callee = if source.contains("requests.get") {
                "get"
            } else {
                "run"
            };
            assert!(
                imported_call_proof(source, callee).is_none(),
                "shadowed call unexpectedly proved: {source}"
            );
        }
        let source = "def call():\n    from subprocess import run\n    run(command)\n";
        assert!(imported_call_proof(source, "run").is_some());
        for source in [
            "def call():\n    import pkg.sub\n    pkg.sub.run(command)\n",
            "def call():\n    import pkg.sub as alias\n    alias.run(command)\n",
        ] {
            assert_eq!(
                imported_call_proof(source, "run")
                    .unwrap()
                    .canonical_callee(),
                "pkg.sub.run",
                "{source}",
            );
        }
        for allowance in [0, 1, 8] {
            let session = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_scope_nodes: allowance,
                    ..brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET
                },
                None,
            );
            let selected =
                imported_call_selection_with_steps(source, "run", || session.scope_step());
            assert!(
                selected.is_none(),
                "a stopped selector must not attach import proof"
            );
            assert!(matches!(
                session.finish(selected),
                BoundedResolution::Exceeded { .. }
            ));
        }
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        cancellation.cancel();
        let session = ResolutionSession::bounded(
            brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            Some(&cancellation),
        );
        let selected = imported_call_selection_with_steps(source, "run", || session.scope_step());
        assert!(matches!(
            session.finish(selected),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn exact_python_import_call_refuses_ambiguous_and_unstructured_shapes() {
        let sources = [
            (
                "import subprocess as sp\nimport fake as sp\nsp.run(command)\n",
                "run",
            ),
            (
                "import subprocess\nsubprocess.run.extra(command)\n",
                "extra",
            ),
            ("from subprocess import *\nrun(command)\n", "run"),
            ("run(command)\n", "run"),
            (
                "def call():\n    import pkg.sub\n    pkg.other.run(command)\n",
                "run",
            ),
            ("import pkg.sub\npkg.other.run(command)\n", "run"),
            (
                "import subprocess\nvalue = subprocess\nvalue.run(command)\n",
                "run",
            ),
        ];
        for (source, callee) in sources {
            assert!(
                imported_call_proof(source, callee).is_none(),
                "unstructured call unexpectedly proved: {source}"
            );
        }
    }

    #[test]
    fn exact_python_import_call_refuses_class_and_conditional_scopes() {
        let class_source = "class Commands:\n    import subprocess as sp\n\n    def call(self):\n        sp.run(command)\n";
        assert!(imported_call_proof(class_source, "run").is_none());
        let conditional_source =
            "import subprocess\nif enabled:\n    import fake as sp\nsp.run(command)\n";
        assert!(imported_call_proof(conditional_source, "run").is_none());
        let conditional_function_source = "def invoke(command, enabled):\n    if enabled:\n        from subprocess import run\n    return run(command)\n";
        assert!(imported_call_proof(conditional_function_source, "run").is_none());
    }
}

#[cfg(test)]
mod batch_context_tests {

    use crate::analyzer::usages::get_definition::python::*;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#3164: one-call Python batches repeatedly rebuilt scope facts and parsed prepared source"
    )]
    fn python_call_target_batches_reuse_request_context_and_prepared_syntax() {
        let source = Arc::<str>::from(
            "from service import Service\n\ndef handle(service: Service):\n    service.run()\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("app.py", source.as_ref()),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let member_start = source.rfind("run").expect("receiver member in source");
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(member_start),
            end_byte: Some(member_start + "run".len()),
        };
        let scope = AnalyzerQueryScope::new(analyzer);
        let prepared = py
            .prepared_syntax(scope.token(), &file)
            .expect("prepared Python syntax");
        assert_eq!(prepared.source(), source.as_ref());
        let mut ledgers = Vec::new();

        for _ in 0..2 {
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            let ledger_scope = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
            let outcomes = resolve_call_target_batch_with_source(
                analyzer,
                scope.token(),
                vec![request.clone()],
                file.clone(),
                Arc::clone(&source),
                None,
            );
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome.status, DefinitionLookupStatus::Resolved);
            assert_eq!(
                outcomes[0].outcome.definitions[0].fq_name(),
                "service.Service.run"
            );
            drop(ledger_scope);
            ledgers.push(ledger);
        }

        assert_eq!(py.prepared_syntax_parse_count_for_test(&file), 1);
        assert!(ledgers.iter().all(|ledger| !ledger.is_empty()));
    }

    /// #3496: one call-target batch keeps whatever its resolver proved about
    /// the call, whichever language wrote it.
    ///
    /// The route used to send a hand-kept list of languages through the branch
    /// that retains `exact_external_call` and `external_callee_identity`, and
    /// flattened every other language's evidence to `None` one layer above the
    /// resolver that produced it. Ruby's boundary proof was discarded that way
    /// for as long as Ruby was absent from the list (#3459). These rows read
    /// the languages that publish a proof today back through the production
    /// entry point, beside one that publishes none, so an absent proof stays
    /// the resolver's own answer rather than the route's.

    #[test]
    fn python_batch_context_resolves_explicit_reexports_without_generic_imports() {
        let source =
            "from facade import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("facade.py", "from service import Service\n"),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let start_byte = source.rfind("run").expect("receiver member in source");

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes = resolve_definition_requests(
            analyzer,
            token,
            &mut context,
            vec![DefinitionLookupRequest {
                file,
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + "run".len()),
            }],
            None,
            None,
        );

        assert_eq!(outcomes[0].status, DefinitionLookupStatus::Resolved);
        assert_eq!(outcomes[0].definitions[0].fq_name(), "service.Service.run");
    }

    #[test]
    #[hardwon("#5658: supported lexical Python declarations were marked as unsupported binders")]
    fn python_native_lexical_definitions_present_parameters_and_temporal_writes() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::model::DeclarationKind;

        for (source, needle, identifier, kind, declaration_start) in [
            (
                "def handle(service: Service):\n    service.run()\n",
                "service.run",
                "service",
                DeclarationKind::Parameter,
                11,
            ),
            (
                "def f(x):\n    x = 2\n    x\n",
                "x\n",
                "x",
                DeclarationKind::LocalVariable,
                14,
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Python)
                .file("app.py", source)
                .build();
            let workspace = fixture.workspace_analyzer(Default::default());
            let analyzer = workspace.analyzer();
            let scope = AnalyzerQueryScope::new(analyzer);
            let mut context = DefinitionBatchContext::new(analyzer, scope.token());
            let start = source.rfind(needle).expect("lexical reference in fixture");
            let outcomes = resolve_definition_requests(
                analyzer,
                scope.token(),
                &mut context,
                vec![DefinitionLookupRequest {
                    file: fixture.file("app.py"),
                    line: None,
                    column: None,
                    start_byte: Some(start),
                    end_byte: Some(start + identifier.len()),
                }],
                None,
                None,
            );
            assert_eq!(
                outcomes[0].status,
                DefinitionLookupStatus::Resolved,
                "{outcomes:#?}"
            );
            let lexical = outcomes[0]
                .lexical_definition
                .as_ref()
                .expect("presented lexical declaration");
            assert_eq!(lexical.identifier, identifier);
            assert_eq!(lexical.kind, kind);
            assert_eq!(lexical.name_range.start_byte, declaration_start);
        }
    }

    #[test]
    fn python_batch_context_preserves_reexport_source_order_across_facades() {
        let source = "from facade_import_wins import Service as ImportedWins\nfrom facade_local_wins import Service as LocalWins\n\ndef handle(imported: ImportedWins, local: LocalWins):\n    imported.leaf_only()\n    local.local_only()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "leaf.py",
                    "class Service:\n    def leaf_only(self):\n        pass\n",
                ),
                (
                    "middle_import_wins.py",
                    "class Service:\n    pass\n\nfrom leaf import Service\n",
                ),
                (
                    "middle_local_wins.py",
                    "from leaf import Service\n\nclass Service:\n    def local_only(self):\n        pass\n",
                ),
                (
                    "facade_import_wins.py",
                    "from middle_import_wins import Service\n",
                ),
                (
                    "facade_local_wins.py",
                    "from middle_local_wins import Service\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let requests = ["leaf_only", "local_only"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "leaf.Service.leaf_only"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "middle_local_wins.Service.local_only"
        );
    }

    #[test]
    fn python_batch_context_keeps_receiver_types_isolated_by_file() {
        let source_a =
            "from service_a import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let source_b =
            "from service_b import Service\n\ndef handle(service: Service):\n    service.stop()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service_a.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                (
                    "service_b.py",
                    "class Service:\n    def stop(self):\n        pass\n",
                ),
                ("app_a.py", source_a),
                ("app_b.py", source_b),
            ],
        );
        let file_a = ProjectFile::new(fixture.project_root(), "app_a.py");
        let file_b = ProjectFile::new(fixture.project_root(), "app_b.py");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let requests = [(file_a, source_a, "run"), (file_b, source_b, "stop")]
            .into_iter()
            .map(|(file, source, needle)| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file,
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "service_a.Service.run"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "service_b.Service.stop"
        );
    }
}
