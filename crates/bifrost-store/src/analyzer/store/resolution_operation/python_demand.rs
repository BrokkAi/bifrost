//! Production Python source rules. Environment containers describe imports; they
//! never become lexical parents or merge the globals of namespace portions.
//!
//! Attribute-space reads consider same-name (exact, prefix or unknown) writes
//! only through structural owners: imported module aliases; builtins aliases
//! and __builtins__; class names and assignment/import aliases; vars(C); and
//! receiver parameters recorded for methods of a visited class. The shared MRO
//! walk checks every visited ancestor, including ancestor-method self/cls writes.
//! Arbitrary mutation-method owners do not have resolved MROs in stored facts:
//! base operands are references requiring typed hierarchy tasks. Subclass
//! shadowing outside the already selected MRO is an explicit hole (#7412).
//! Method receiver mutations also remain in the reverse query obligation for
//! that hole, as do instances passed to unrelated functions and mutated there.
//!
//! Deferred module-cell reads consider same-name (exact, prefix or unknown)
//! reflective writes only through an imported module name or its bounded,
//! cycle-safe direct-assignment alias chain. Binding rows select those names;
//! no typed receiver evaluation participates in this test.
//!
//! globals()[N] and bare vars()[N] writes have no member-operation rows. The
//! producer instead publishes a module-root UnknownBinder gap, which keeps the
//! module attribute space open, even when the write occurs inside a function.
//! Registry replacements have an import-only module-object projection. A
//! sys.modules[__name__] receiver still has only an expression slot: member
//! mutations through it are not structural module receivers (#7361). Attribute
//! writes through that expression currently lack this per-module safeguard.
//! A module object passed as a value and mutated through a parameter, attribute,
//! call result or other non-structural receiver is likewise a known hole in the
//! per-read proof. Retained reflective operations of these forms contribute one
//! python_dynamic_receiver_mutation_open reverse query obligation. Forms with
//! no retained mutation operation cannot contribute to that operation count.
//! Forward and reverse answers share selected-environment query obligations.
//! They describe query scope and never demote a selected binding (#7362).
pub(super) mod module_registry;
pub(super) mod super_context;

use super::demand_closure::*;
use super::python_lexical::{self, PythonBindingProfile, PythonBindingProofs, PythonLexical};
use super::*;
use crate::analyzer::resolution::temporal_binding::{SessionBudget, Stop};
use crate::analyzer::resolution::{
    DemandReferenceKey, EndpointSignature, LoweredMemberOwnerProperty,
    MAX_TYPED_FACT_ROWS_PER_PAGE, ResolutionAnswer, SharedNameInterner, TypedFactReadOutcome,
};
use crate::analyzer::store::python_binding_rows::{BindingEvent, PythonBindingRows};
use crate::analyzer::store::selected_read_memo::RequestReadCache;
use brokk_bifrost_core::analyzer::model::DispatchExtensibility;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind;

use crate::analyzer::resolution::query_obligations::{NodeQueryObligations, QueryNode};
use crate::analyzer::resolution::{QueryObligation, QueryObligations};

/// The summary's recorded environment and placement obligations, one extraction
/// for both query directions; labels retain the reverse contract. The
/// dynamic-receiver obligation needs the summary-wide structural mutation
/// inventory, so each direction adds it only where it has that inventory.
pub(super) fn selected_environment_obligations(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
) -> Result<QueryObligations> {
    let mut scope = QueryObligations::empty();
    let mut statement = ready.inventory.connection().prepare_cached(
        "SELECT gap_kind,subject,json(detail) FROM resolution_unit_summary_gaps WHERE summary_id=?1 AND gap_kind IN ('python_environment_open','python_unknown_placement') ORDER BY gap_kind,subject")?;
    for row in statement.query_map([summary], |row| {
        Ok(QueryObligation::new(
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        scope.insert(row?);
    }
    Ok(scope)
}

type SuperContextRows =
    RequestReadCache<(i64, Option<u32>), Option<super_context::SuperContextRow>>;
type MemberRoleRows = RequestReadCache<
    (i64, u32),
    Option<std::rc::Rc<super::python_members::PythonMemberRoleInputs>>,
>;

const PYTHON_HALF_PLACEMENTS: &str = "SELECT providers.container_path
             FROM main.python_unit_summary_providers providers
             JOIN main.resolution_unit_summary_members members
               ON members.summary_id=providers.summary_id
              AND members.member_ordinal=providers.member_ordinal
             JOIN temp.selected_resolution_mounts mounted
               ON mounted.blob_id=members.blob_id AND mounted.persisted_relative_path=members.rel_path
             WHERE providers.summary_id=?1 AND mounted.mount_ordinal=?2
               AND providers.state IN ('selected','alternative')";
const PYTHON_BINDING_SOURCE_FORMAT: &str =
    "SELECT format FROM python_binding_source WHERE blob_id=?1";

/// Survivors receive a cohort only after temporal reduction. Origin and source
/// byte position are deliberately absent from the ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PythonRank {
    pub cohort: u32,
}

type ImportRouteRows = Vec<(Option<String>, String, String)>;
type SummaryImportRows = Vec<(String, String, String, String, String)>;
type PrefixProviderRows = Vec<(String, std::path::PathBuf, String)>;
type ImportRouteCache = RequestReadCache<(i64, String, u32, i64), std::sync::Arc<ImportRouteRows>>;
type DeferredContainerCache = RequestReadCache<(i64, i64), std::sync::Arc<Vec<String>>>;
type MemberOwnerRows = (
    Vec<SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ResolutionCompletion,
);

/// A selected environment's identity is request-owned. The caller validates its
/// snapshot, profile and output digest before constructing the rules.
pub(super) struct PythonRules<'a, 'store, 'input> {
    pub ready: &'a ReadySelectedResolution<'store, 'input>,
    pub typed: &'a dyn SelectedTypedFactSource,
    pub summary: i64,
    selected_query_obligations: QueryObligations,
    pub(super) mutations: &'a super::PythonMutationQuery<'a, 'store>,
    pub profile: PythonBindingProfile,
    /// Declared minimum Python version, not an exact interpreter version. None means undeclared.
    pub python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
    pub cancellation: &'a CancellationToken,
    pub session: &'a ResolutionSession,
    pub observations: &'a RefCell<Vec<String>>,
    /// Only constructor probe names constructed by this operation (at most three).
    pub(super) probe_spellings: RefCell<Vec<(SemanticId, String)>>,
    arena: &'a RefCell<ClosedRelations>,
    // One suspended source close owns these inputs. Remove them at publication;
    // rebuilding its borrowed Half view must perform no context/prefix SQL.
    source_inputs: RefCell<HashMap<CandidatePathIdentity, PythonHalfInputs>>,
    external_imports: &'a RefCell<PythonExternalImports>,
    // One forward operation fixes the store and format; only blob selects rows.
    binding_rows: RefCell<
        RequestReadCache<
            i64,
            brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
        >,
    >,
    // This forward operation fixes the summary, store and format; the placement
    // memo lives for the operation, so its key carries no epoch.
    placement_unit: [u8; 32],
    placements: RefCell<super::placement_access::PlacementMemo<String>>,
    root_prefixes: RefCell<RequestReadCache<i64, Vec<PythonRootPrefix>>>,
    namespace_imports: RefCell<RequestReadCache<SemanticId, PythonNamespaceImportRoute>>,
    module_sites: RefCell<RequestReadCache<i64, Option<ResolutionSiteId>>>,
    // Immutable selected-environment inputs are shared by all source halves
    // in this forward operation and dropped with the request.
    conditional_import_sites: RefCell<RequestReadCache<(i64, String), Vec<u32>>>,
    pub(super) super_context_rows: RefCell<SuperContextRows>,
    pub(super) member_role_rows: RefCell<MemberRoleRows>,
    import_routes: RefCell<ImportRouteCache>,
    summary_imports:
        RefCell<RequestReadCache<(i64, String, u32), std::sync::Arc<SummaryImportRows>>>,
    prefix_providers: RefCell<RequestReadCache<(i64, String, String, String), PrefixProviderRows>>,
    deferred_provider_containers: RefCell<DeferredContainerCache>,
    member_owner_rows: RefCell<RequestReadCache<Vec<SemanticId>, std::sync::Arc<MemberOwnerRows>>>,
    qualified_members: HashMap<
        crate::analyzer::resolution::QualifiedMemberId,
        super::member_access::QualifiedMemberSlot<
            PythonQualifiedInputs,
            super::python_members::PythonMemberRow,
        >,
    >,
    // Attribute inventory and completed mutation proofs live for this forward
    // operation only. They never become a workspace or cross-request index.
    pub(super) attribute_hooks: RefCell<HashMap<SemanticId, ResolutionCompletion>>,
    // Ordinary namespace proofs are retained only for this keyword query.
    ordinary_keyword_namespaces: RefCell<HashSet<SemanticId>>,
    // A qualifier proved to be a one-hop module alias maps to its source
    // reference, for this keyword query only: the namespace route reads the
    // source's answer in place of the alias cell's own assignment target.
    module_aliases: RefCell<HashMap<SemanticId, SemanticId>>,
    pub(super) attribute_mutations:
        RefCell<HashMap<(SemanticId, SemanticId), ResolutionCompletion>>,
    pub(super) attribute_metaclasses:
        RefCell<HashMap<(SemanticId, SemanticId), ResolutionCompletion>>,
    pub(super) attribute_metaclass_fallbacks:
        RefCell<HashMap<(SemanticId, SemanticId), ResolutionCompletion>>,
    dispatch_extensibility: &'a RefCell<HashMap<SemanticId, DispatchExtensibility>>,
    prepared_references: RefCell<HashMap<CandidatePathIdentity, SemanticId>>,
    universe_mutations: RefCell<HashMap<CandidatePathIdentity, UniverseMutationInputs>>,
    module_mutations: RefCell<HashMap<CandidatePathIdentity, UniverseMutationInputs>>,
    deferred_mutations: RefCell<
        HashMap<CandidatePathIdentity, Vec<super::python_members::operations::ModuleMutation>>,
    >,
    module_spaces: RefCell<HashMap<String, PythonModuleAttributeSpace>>,
    wildcard_inventories: RefCell<HashMap<String, (bool, bool)>>,
    reference_inputs: RefCell<HashMap<CandidatePathIdentity, PythonReferenceInputs>>,
    module_import_inputs: HashMap<EndpointSignature, PythonModuleImportInputs>,
    module_registry: module_registry::Registry,
}

/// A Python file module is the nameless Value declaration. Anonymous callables
/// have Callable authority; file paths belong only to selected mounts.
pub(super) fn module_declaration_site(
    connection: &rusqlite::Connection,
    blob: i64,
) -> Result<Option<ResolutionSiteId>> {
    let sites = connection.prepare_cached(
        "SELECT semantic.source_site
         FROM resolution_semantic_sites semantic
         JOIN source_native_declaration_bridges bridge
           ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
         JOIN source_declarations declaration
           ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
         WHERE semantic.blob_id=?1 AND semantic.semantic_role='definition'
           AND semantic.namespace=?2 AND declaration.name_occurrence_id IS NULL"
    )?.query_map(rusqlite::params![blob, ResolutionNamespace::Value.label()], |row| {
        row.get::<_, u32>(0).map(ResolutionSiteId::new)
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    assert!(
        sites.len() <= 1,
        "one nameless Value module declaration per blob: {sites:?}"
    );
    Ok(sites.first().copied())
}

// Runtime module-object attributes need not have authored bindings. __path__
// exists only on packages; keeping it open on plain modules is conservative.
// This predicate is shared by module-attribute and public-name star inventory
// proofs; both keep names without authored bindings open.
const MODULE_OBJECT_ATTRIBUTES: &[&str] = &[
    "__name__",
    "__file__",
    "__doc__",
    "__dict__",
    "__path__",
    "__package__",
    "__spec__",
    "__loader__",
    "__cached__",
];

/// The reference semantic and spelling of one reference site. Both seeks are
/// primary-key or unique-key lookups: `resolution_semantic_sites` is keyed by
/// `(blob_id, source_site)`, and the lookup identity by its semantic key.
pub(crate) const REFERENCE_BY_SOURCE_SITE_SQL: &str =
    "SELECT semantic.semantic_key,name.spelling FROM resolution_semantic_sites semantic
 JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id
   AND lookup.semantic_key=semantic.semantic_key
 JOIN resolution_identities name ON name.id=lookup.identity_id
 WHERE semantic.blob_id=?1 AND semantic.source_site=?2 AND semantic.semantic_role='reference'";

const CURATED_STAR_CHILD_PREFIX_SQL: &str = "SELECT EXISTS(
                               SELECT 1 FROM resolution_unit_summary_members member
                               INDEXED BY resolution_unit_summary_members_blob
                               CROSS JOIN python_unit_summary_imports imports
                                 ON imports.summary_id=member.summary_id AND imports.member_ordinal=member.member_ordinal
                               CROSS JOIN python_unit_summary_providers parent
                                 ON parent.summary_id=imports.summary_id AND parent.container_path=imports.target_container
                               CROSS JOIN python_unit_summary_surfaces surface
                                 ON surface.summary_id=parent.summary_id AND surface.container_path=parent.container_path
                                  AND surface.surface='wildcard' AND surface.policy='curated'
                               CROSS JOIN python_unit_summary_export_names exported
                                 ON exported.summary_id=surface.summary_id AND exported.container_path=surface.container_path
                                  AND exported.surface=surface.surface AND exported.name=?5 AND exported.slot_site IS NULL
                               CROSS JOIN python_unit_summary_providers child INDEXED BY python_unit_summary_providers_module
                                 ON child.summary_id=parent.summary_id AND child.module_name=parent.module_name || '.' || ?5
                                  AND child.root_slot=parent.root_slot AND child.state='selected' AND child.kind IN ('module','package')
                               CROSS JOIN resolution_unit_summary_members child_member
                                 ON child_member.summary_id=child.summary_id AND child_member.member_ordinal=child.member_ordinal
                               CROSS JOIN selected_resolution_mounts mounted
                                 ON mounted.storage_language='python' AND mounted.persisted_relative_path=child_member.rel_path
                                  AND mounted.blob_id=child_member.blob_id
                               WHERE member.blob_id=?3 AND member.summary_id=?1 AND member.rel_path=?2
                                 AND imports.import_site=?4 AND imports.form='star' AND imports.state='activation_open'
                                 AND parent.kind='package' AND parent.state='selected'
                                 AND NOT EXISTS(SELECT 1 FROM python_unit_summary_imports other
                                   WHERE other.summary_id=imports.summary_id AND other.member_ordinal=imports.member_ordinal
                                     AND other.import_site=imports.import_site AND other.target_container<>imports.target_container)
                                 AND NOT EXISTS(SELECT 1 FROM python_unit_summary_providers other
                                   WHERE other.summary_id=child.summary_id AND other.module_name=child.module_name
                                     AND other.state IN ('alternative','open'))
                                 AND NOT EXISTS(SELECT 1 FROM python_unit_summary_export_names hook
                                   WHERE hook.summary_id=parent.summary_id AND hook.container_path=parent.container_path
                                     AND hook.surface='module' AND hook.name='__getattr__'))";

/// These runtime names cannot be disproved by a closed source-binding inventory.
/// A child provider can become a package attribute through module loading without
/// a writer in __init__.py. Module-object dunders likewise need no source writer;
/// star inventories conservatively retain them, and __path__ is open on modules.
/// Module/package candidates always carry blob_id from their placed source;
/// publication maps that blob/path to member_ordinal. Thus selected/alternative
/// children of these kinds are placed without an extra member_ordinal predicate.
pub(super) fn module_name_open_without_binding(
    connection: &rusqlite::Connection,
    summary: i64,
    container: &str,
    name: &str,
) -> Result<bool> {
    if MODULE_OBJECT_ATTRIBUTES.contains(&name) {
        return Ok(true);
    }
    Ok(connection
        .prepare_cached(
            "SELECT EXISTS(
           SELECT 1 FROM python_unit_summary_providers parent
           JOIN python_unit_summary_providers child
             ON child.summary_id=parent.summary_id AND child.root_slot=parent.root_slot
             AND child.module_name=parent.module_name || '.' || ?3
           WHERE parent.summary_id=?1 AND parent.container_path=?2
             AND parent.kind IN ('package','namespace')
             AND parent.state IN ('selected','alternative')
             AND child.kind IN ('module','package')
             AND child.state IN ('selected','alternative'))",
        )?
        .query_row(rusqlite::params![summary, container, name], |row| {
            row.get(0)
        })?)
}

/// PEP 562 consults module `__getattr__` only when normal lookup fails. A name
/// stays in the module dictionary when some binding of it runs on every import
/// (module level, no guard of any kind) and nothing deletes it anywhere. A read
/// that executes during the module's own initialization (`initializing_read`:
/// the importing event and its entry point) sees only the bindings committed
/// before it; a binding event never closes its own lookup.
fn module_name_bound_unconditionally(
    rows: &crate::analyzer::store::python_binding_rows::PythonBindingRows,
    root: u32,
    name: &str,
    initializing_read: Option<(u32, usize)>,
) -> bool {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::*;
    let Some(slot) = rows
        .slots
        .iter()
        .find(|slot| slot.scope == root && slot.name == name)
    else {
        return false;
    };
    let events = || rows.events.iter().filter(|event| event.slot == slot.slot);
    events().all(|event| event.kind != Delete)
        && events().any(|event| {
            matches!(event.kind, Assign | Function | Class | Import)
                && event.execution_scope == root
                && initializing_read
                    .is_none_or(|(read, point)| event.event != read && event.commit_byte <= point)
                && !rows
                    .site_guards
                    .iter()
                    .any(|guard| guard.site.get() == event.target)
        })
}

fn cached_module_site(
    connection: &rusqlite::Connection,
    blob: i64,
    memo: &RefCell<RequestReadCache<i64, Option<ResolutionSiteId>>>,
) -> Result<Option<ResolutionSiteId>> {
    if let Some(site) = memo.borrow().get(&blob).copied() {
        return Ok(site);
    }
    let site = module_declaration_site(connection, blob)?;
    assert!(memo.borrow_mut().insert(blob, site).is_none());
    Ok(site)
}

pub(super) fn is_module_definition(
    selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
    definition: SemanticId,
    memo: &RefCell<RequestReadCache<i64, Option<ResolutionSiteId>>>,
) -> Result<bool> {
    let Some(ordinal) = definition.ordinal() else {
        return Ok(false);
    };
    let mount = selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    if mount.semantic_language != Language::Python {
        return Ok(false);
    }
    let blob = mount.blob_id();
    let site = cached_module_site(selection.connection(), blob, memo)?;
    Ok(site.is_some_and(|site| {
        definition == crate::analyzer::resolution::mounted_site_semantic(mount.fragment_id(), site)
    }))
}

pub(in crate::analyzer::store) fn namespace_definition_provider()
-> Box<dyn super::super::language_support::NamespaceDefinitionClassifier> {
    struct PythonNamespaces {
        module_sites: RefCell<RequestReadCache<i64, Option<ResolutionSiteId>>>,
    }
    impl super::super::language_support::NamespaceDefinitionClassifier for PythonNamespaces {
        fn definitions(
            &self,
            selection: &crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory<'_>,
            definitions: &[SemanticId],
            cancellation: &CancellationToken,
        ) -> Result<Vec<SemanticId>> {
            let mut namespaces = Vec::new();
            for &definition in definitions {
                if cancellation.is_cancelled() {
                    break;
                }
                if is_module_definition(selection, definition, &self.module_sites)? {
                    namespaces.push(definition);
                }
            }
            Ok(namespaces)
        }
    }
    Box::new(PythonNamespaces {
        module_sites: RefCell::new(RequestReadCache::default()),
    })
}

// Each row is one prerequisite for a selected imported module attribute.
// The shared prefix scheduler follows the reference, including further aliases
// and cycles. These rows never implement a route walk or alias resolver.
struct PythonImportAlias {
    container: String,
    name: String,
    import_site: u32,
    reference: SemanticId,
}

#[derive(Clone, Copy)]
struct PythonModuleObservation {
    mount: u32,
    import_site: u32,
}
#[derive(Default)]
struct PythonReferenceInputs {
    aliases: Vec<PythonImportAlias>,
    deferred_module_scope: Option<u32>,
    resolved_aliases: Vec<PythonAliasTargets>,
    registry_roots: Vec<module_registry::ImportRoot>,
}
#[derive(Clone)]
struct PythonAliasTargets {
    container: String,
    name: String,
    import_site: u32,
    targets: Vec<SemanticId>,
    completion: ResolutionCompletion,
    external_imports: Vec<PythonSelectedExternalImport>,
}

struct PythonModuleImportInputs {
    aliases: Vec<(CandidatePathIdentity, PythonImportAlias)>,
    references: super::member_access::QualifiedReferenceInputs,
    ready: bool,
}

/// One source closure's selected mutation candidates. The shared prefix pump
/// supplies every Reference answer; publication drops this inventory.
struct UniverseMutationInputs {
    operations: Vec<super::python_members::operations::OperationRow>,
    completion: ResolutionCompletion,
}

/// Owned data for one suspended typed group. The rules borrow it only while
/// polling; no context borrows its containing provider.
struct PythonQualifiedInputs {
    query_obligations: RefCell<NodeQueryObligations>,
    rows: brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
    blob: i64,
    lookup: ResolutionLookupSemanticRecipe,
    values: Vec<ResolutionSlotValue>,
    prefix: Option<SemanticId>,
    // The qualifier and the source reference of its one-hop alias assignment,
    // demanded in place of `prefix` when the qualifier is not an import cell.
    alias: Option<(SemanticId, SemanticId)>,
    super_context: Option<super_context::SuperContext>,
    references: super::member_access::QualifiedReferenceInputs,
    super_cursor: Option<super_context::SuperCursor>,
    requires_class: bool,
    implicit_protocol: bool,
    none_absence: bool,
    observations: RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    rendered_order: std::cell::Cell<bool>,
}
impl PythonQualifiedInputs {
    fn view<'a, 'store, 'input>(
        &'a self,
        rules: &'a PythonRules<'a, 'store, 'input>,
        reference: DemandReferenceKey,
    ) -> super::python_members::PythonMemberContext<'a, 'store, 'input> {
        self.references.record_query_obligations(
            &mut self
                .query_obligations
                .borrow_mut()
                .node(QueryNode::Reference(reference.reference)),
        );
        super::python_members::PythonMemberContext {
            rules,
            reference: reference.reference,
            query_obligations: &self.query_obligations,
            environment: reference.environment,
            rows: &self.rows,
            blob: self.blob,
            member_values: &self.values,
            super_cursor: self.super_cursor.as_ref(),
            member_observations: &self.observations,
            rendered_order: &self.rendered_order,
        }
    }
}

pub(super) fn model_open(
    rules: &PythonRules<'_, '_, '_>,
    token: SemanticId,
    code: &'static str,
) -> ResolutionCompletion {
    let mut hash = CanonicalHasher::new(code.as_bytes());
    let model = rules
        .ready
        .context_identities
        .model_member_identity(token)
        .expect("model reason has a selected coordinate");
    super::python_models::hash_model_symbol(&mut hash, &model);
    let reason =
        rules
            .ready
            .context_identities
            .named_semantic(hash.finish(), code, &format!("{token:?}"));
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(reason)])
}

impl crate::analyzer::resolution::QualifiedMemberProvider for PythonRules<'_, '_, '_> {
    fn register_query_lookup(&mut self, lookup: SemanticId, spelling: &str) -> bool {
        let mut probes = self.probe_spellings.borrow_mut();
        if let Some((_, existing)) = probes.iter().find(|(id, _)| *id == lookup) {
            assert_eq!(existing, spelling, "query lookup identity collision");
            return true;
        }
        assert!(
            probes.len() < 3,
            "constructor probe spelling registry exceeded"
        );
        probes.push((lookup, spelling.to_owned()));
        true
    }

    fn poll_construction(
        &mut self,
        input: &crate::analyzer::resolution::TypedConstructionInput,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<
        crate::analyzer::resolution::CloseProgress<
            crate::analyzer::resolution::TypedConstructionResult,
        >,
    > {
        use crate::analyzer::resolution::TypedConstructionResult;
        use crate::analyzer::resolution::{
            CloseContinuationId, CloseProgress, CloseResume, HierarchyOrderRequest,
            ResolutionTypeRef, SelectedTypedFactSource, SharedNameInterner, TypedFactRequest,
        };
        let absent = || {
            CloseProgress::Ready(TypedConstructionResult {
                value: None,
                completion: ResolutionCompletion::Complete,
            })
        };
        assert_eq!(input.language, Language::Python);
        crate::profiling::note_with(|| {
            format!(
                "resolution::python_construction reference={:?} targets={:?} complete={}",
                input.reference,
                input.binding.targets(),
                input.binding.completion() == &ResolutionCompletion::Complete
            )
        });
        let [target] = input.binding.targets() else {
            return Ok(absent());
        };
        if input.binding.completion() == &ResolutionCompletion::Complete
            && let Some(result) = self.model_construction(*target)?
        {
            return Ok(CloseProgress::Ready(result));
        }
        let runtime_builtin = super::python_members::builtin_class(self, *target)?;
        let runtime_class = runtime_builtin.is_some();
        if runtime_class {
            // type(x) returns x's type, not an ordinary instance of type.
            if input.binding.completion() != &ResolutionCompletion::Complete
                || super::python_members::builtin(self.ready, "type") == Some(*target)
            {
                return Ok(absent());
            }
        } else if !super::python_members::is_class(self.ready, *target)? {
            return Ok(absent());
        }
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Python,
            ResolutionNamespace::Value,
            "__new__",
        )
        .semantic(&self.ready.shared_names());
        let order = match resume {
            CloseResume::Start if runtime_class => None,
            CloseResume::Start => {
                return Ok(CloseProgress::Members {
                    continuation: CloseContinuationId::issue(provenance),
                    request: crate::analyzer::resolution::DemandMemberSelectionRequest {
                        policy: &super::python_members::PYTHON_HIERARCHY,
                        order: Some(HierarchyOrderRequest {
                            policy: &super::python_members::PYTHON_C3,
                            start_after: None,
                        }),
                        reference: input.reference.reference,
                        values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            *target, 0,
                        ))],
                        lookup,
                        namespace: ResolutionNamespace::Value,
                        language: Language::Python,
                    },
                    completion: input.binding.completion().clone(),
                });
            }
            CloseResume::Reference { .. } => {
                unreachable!("construction requests its shared C3 proof")
            }
            CloseResume::Members {
                continuation,
                selection,
            } => {
                continuation.assert_current(provenance);
                if let Some(order) = selection.order {
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_construction_order target={target:?} complete={} owners={:?}",
                            provenance.order_status(order).complete,
                            selection.owners
                        )
                    });
                }
                selection.order
            }
        };
        let creation = match super::python_members::ordinary_class_creation(
            self, self.typed, *target, provenance, order,
        )? {
            std::ops::ControlFlow::Break(completion) => {
                return Ok(CloseProgress::Cancelled(completion));
            }
            std::ops::ControlFlow::Continue(
                super::python_members::ClassCreation::OpenOrder(_)
                | super::python_members::ClassCreation::Unproven,
            ) => {
                if let Some(order) = order {
                    let status = provenance.order_status(order);
                    if !status.complete {
                        let completion = if *status.completion == ResolutionCompletion::Complete {
                            ResolutionCompletion::incomplete([
                                ResolutionIncompleteReason::UnsupportedSemantic(*target),
                            ])
                        } else {
                            status.completion.clone()
                        };
                        return Ok(CloseProgress::Ready(TypedConstructionResult {
                            value: None,
                            completion,
                        }));
                    }
                }
                return Ok(absent());
            }
            std::ops::ControlFlow::Continue(super::python_members::ClassCreation::Ordinary(
                creation,
            )) => creation,
        };
        let super::python_members::OrdinaryClassCreation {
            allocator,
            completion: construction_completion,
        } = creation;
        if let super::python_members::OrdinaryAllocator::InheritedObject { owners, object } =
            allocator
        {
            let version = self
                .python_version
                .map(|version| (version.major, version.minor));
            let implicit_provider = self
                .mutations
                .implicit_inputs_provider(&self.ready.context_identities, version);
            let typed = self
                .ready
                .typed_source()
                .with_implicit_environment(self.summary, version)
                .with_implicit_input_provider(&implicit_provider);
            let Some(inventory) = typed.intrinsic_member_inventory(object, self.cancellation)?
            else {
                return Ok(absent());
            };
            let digest = self
                .ready
                .shared_names()
                .digest_for_id(lookup.shared_name_id().expect("intrinsic lookup"))
                .expect("selected intrinsic lookup digest");
            if inventory.presence(digest, ResolutionNamespace::Value)
                != crate::analyzer::resolution::universe::IntrinsicMemberPresence::Present
            {
                return Ok(absent());
            }
            let mut custom_allocator = false;
            for owners in
                owners.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH)
            {
                let read = typed.visit_member_owner_pages_for_owners(
                    TypedFactRequest::new(owners),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        for property in page {
                            if !self.session.scope_step() || self.cancellation.is_cancelled() {
                                return Ok(false);
                            }
                            custom_allocator |= property.row().member_name() == "__new__"
                                && property.row().owner_definition() != object;
                        }
                        Ok(true)
                    }),
                )?;
                if read.is_cancelled() || self.cancellation.is_cancelled() {
                    return Ok(CloseProgress::Cancelled(read.evidence().clone()));
                }
                if custom_allocator
                    || !read.is_exhausted()
                    || read.evidence() != &ResolutionCompletion::Complete
                {
                    return Ok(absent());
                }
            }
            if construction_completion == ResolutionCompletion::Complete
                && let (Some(ordinal), Some(key)) =
                    (input.output.ordinal(), input.output.local_key())
            {
                let mount = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                let keyword: bool = self.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_named_argument_labels label JOIN resolution_semantic_sites reference ON reference.blob_id=label.blob_id AND reference.source_site=label.reference_site AND reference.semantic_role='reference' WHERE label.blob_id=?1 AND reference.semantic_key=?2)")?.query_row(
                        rusqlite::params![mount.blob_id(),key], |row| row.get(0),
                    )?;
                if keyword {
                    self.ordinary_keyword_namespaces.borrow_mut().extend(owners);
                }
            }
        }
        let mut value = ResolutionSlotValue::type_object(ResolutionTypeRef::new(*target, 0))
            .constructed_instance();
        if runtime_builtin.is_some_and(|entry| {
            brokk_bifrost_python::intrinsics::builtin(entry.spelling)
                .expect("classified builtin")
                .allocator_may_return_subclass
        }) {
            value = value.with_receiver_subclass_obligation();
        }
        Ok(CloseProgress::Ready(TypedConstructionResult {
            value: Some(value),
            completion: construction_completion,
        }))
    }

    fn prepare_qualified_member(
        &mut self,
        id: crate::analyzer::resolution::QualifiedMemberId,
        input: &crate::analyzer::resolution::QualifiedMemberInput,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<
        crate::analyzer::resolution::CloseProgress<
            crate::analyzer::resolution::DemandMemberSelectionOutcome,
        >,
    > {
        use crate::analyzer::resolution::{
            CloseProgress, CloseResume, DemandMemberSelectionOutcome as Outcome,
        };
        if matches!(resume, CloseResume::Start) {
            assert_eq!(input.registration.language, Language::Python);
            assert!(input.registration.member_access);
            assert!(!self.qualified_members.contains_key(&id));
            let mount = self.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(input.fragment.ordinal()),
            )?;
            let Some(rows) = self.load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))?
            else {
                return Ok(CloseProgress::Cancelled(cancelled_completion()));
            };
            let SelectedLookupRecipeReadOutcome::Ready(recipes) =
                self.ready.lexical_source().lookup_semantic_recipes(
                    &[SelectedLookupRecipeRequest {
                        fragment: input.fragment,
                        semantic: input.source_lookup,
                    }],
                    self.cancellation,
                    None,
                )?
            else {
                return Ok(CloseProgress::Cancelled(cancelled_completion()));
            };
            // Constructor absence probes can name a member that never occurs
            // in source. Their recipe is query-local, so no selected fragment
            // can carry it. Recover exactly those probe recipes by identity.
            let mut lookup = recipes.into_iter().next().flatten().or_else(|| {
                self.probe_spellings.borrow().iter().find_map(|(id, spelling)| {
                    (*id == input.source_lookup).then(|| {
                        ResolutionLookupSemanticRecipe::new(
                            Language::Python,
                            ResolutionNamespace::Value,
                            spelling,
                        )
                    })
                })
            }).ok_or_else(|| {
                StoreError::corrupt(format!("typed Python member lacks its selected lookup recipe: fragment={:?} lookup={:?}", input.fragment, input.source_lookup))
            })?;
            let implicit_protocol = lookup.namespace() == ResolutionNamespace::Callable;
            let requires_class = input.namespace == ResolutionNamespace::Type;
            if matches!(
                input.namespace,
                ResolutionNamespace::Type | ResolutionNamespace::Callable
            ) {
                lookup = ResolutionLookupSemanticRecipe::new(
                    Language::Python,
                    ResolutionNamespace::Value,
                    lookup.spelling(),
                );
            }
            let none_type = SemanticId::shared_name(self.ready.shared_names().intern(
                crate::analyzer::resolution::universe::intrinsic_type_identity_digest(
                    Language::Python,
                    brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind::LanguageBuiltin,
                    "types.NoneType",
                ),
            ));
            // Only the singleton runtime value has None's closed attribute
            // space. A NoneType class object or an obligated type annotation
            // does not prove that the reaching value is the builtin constant.
            let is_none_constant = |value: &ResolutionSlotValue| {
                matches!(
                    value,
                    ResolutionSlotValue::Runtime {
                        obligation: None,
                        ..
                    }
                ) && value.ty().identity() == none_type
            };
            let super_context = super_context::SuperContext::read(self, input.reference.reference)?;
            let (prefix, alias) = if input.values.is_empty()
                || input.values.iter().any(is_none_constant)
            {
                match self.root_prefix(mount.blob_id(), input.reference.reference)? {
                    Some(prefix) => {
                        let take = match self.prefix_has_import(
                            &rows,
                            &prefix,
                            mount.persisted_relative_path(),
                            mount.blob_id(),
                            input.reference.reference.ordinal().expect("mounted member"),
                        )? {
                            Read::Ready { value, .. } => value,
                            Read::Cancelled(completion) => {
                                return Ok(CloseProgress::Cancelled(completion));
                            }
                            Read::Unavailable { .. } => {
                                unreachable!("lexical slot reads are local")
                            }
                        };
                        crate::profiling::note_with(|| {
                            format!(
                                "python namespace prerequisite blob={} member={} prefix={} profile={:?} take={take}",
                                mount.blob_id(),
                                prefix.member,
                                prefix.site,
                                self.profile,
                            )
                        });
                        let qualifier = SemanticId::local(
                            input.reference.reference.ordinal().expect("mounted member"),
                            prefix.prefix,
                        );
                        let alias = if take {
                            None
                        } else {
                            match self.alias_source(&rows, qualifier, &prefix.name)? {
                                Read::Ready { value, .. } => value,
                                Read::Cancelled(completion) => {
                                    return Ok(CloseProgress::Cancelled(completion));
                                }
                                Read::Unavailable { .. } => {
                                    unreachable!("lexical slot reads are local")
                                }
                            }
                        };
                        if take {
                            (Some(qualifier), None)
                        } else {
                            (None, alias.map(|source| (qualifier, source)))
                        }
                    }
                    None => (None, None),
                }
            } else {
                (None, None)
            };
            let references = super::member_access::QualifiedReferenceInputs::new(
                prefix
                    .into_iter()
                    .chain(alias.map(|(_, source)| source))
                    .chain(
                        super_context
                            .iter()
                            .flat_map(|context| context.prerequisites()),
                    )
                    .map(|reference| DemandReferenceKey {
                        reference,
                        environment: input.reference.environment,
                    }),
            );
            let none_absence = brokk_bifrost_python::intrinsics::none_type_member(
                lookup.spelling(),
                self.python_version,
            ) == brokk_bifrost_python::intrinsics::Availability::Absent
                && input.values.iter().any(is_none_constant);
            let values = input
                .values
                .iter()
                .copied()
                .filter(|value| !none_absence || !is_none_constant(value))
                .collect();
            let context = PythonQualifiedInputs {
                query_obligations: RefCell::new(NodeQueryObligations::empty()),
                rows,
                blob: mount.blob_id(),
                lookup,
                values,
                prefix,
                alias,
                super_context,
                requires_class,
                implicit_protocol,
                none_absence,
                references,
                super_cursor: None,
                observations: RefCell::new(Vec::new()),
                rendered_order: std::cell::Cell::new(false),
            };
            // Python selects callable and class-valued members from Value
            // bindings. Normalize only this query-local input; published route
            // identities retain their original namespaces. Type queries still
            // require the selected value to denote a class.
            let mut member_input = input.clone();
            if matches!(
                member_input.namespace,
                ResolutionNamespace::Callable | ResolutionNamespace::Type
            ) {
                assert_eq!(context.lookup.namespace, ResolutionNamespace::Value);
                member_input.namespace = ResolutionNamespace::Value;
                member_input.lookup = context.lookup.semantic(&self.ready.shared_names());
            }
            self.qualified_members.insert(
                id,
                super::member_access::QualifiedMemberSlot::new(context, member_input),
            );
        }
        let mut slot = self
            .qualified_members
            .remove(&id)
            .expect("prepared typed Python slot");
        let progress =
            slot.context
                .references
                .poll(provenance, resume, self.session, self.cancellation)?;
        let completion = slot.context.references.completion.clone();
        let result = match progress {
            CloseProgress::Reference {
                continuation,
                key,
                completion,
            } => CloseProgress::Reference {
                continuation,
                key,
                completion,
            },
            CloseProgress::Cancelled(completion) => CloseProgress::Cancelled(completion),
            CloseProgress::Members { .. } => {
                unreachable!("reference inventory requests no members")
            }
            CloseProgress::Ready(()) => {
                if let Some(prefix) = slot.context.prefix {
                    let binding = slot
                        .context
                        .references
                        .answers()
                        .find(|(key, _)| key.reference == prefix)
                        .expect("the selected prefix prerequisite has settled")
                        .1
                        .binding();
                    let mut external = selected_external_imports(self.external_imports, prefix);
                    for selected in &mut external {
                        selected
                            .remaining_member_path
                            .push(slot.context.lookup.spelling().to_owned());
                        selected.completion = selected.completion.combine(&completion);
                    }
                    // An admitted receiver is consumed by the shared member
                    // reducer, including its descriptor and MRO obligations.
                    // Namespace admission only establishes the initial binding.
                    let model_receiver = slot.context.values.iter().any(|value| {
                        self.ready
                            .context_identities
                            .model_member_identity(value.ty().identity())
                            .is_some()
                    });
                    if !model_receiver
                        && let Some(token) =
                            self.admit_model(input.reference.reference, &external)?
                    {
                        self.qualified_members.insert(id, slot);
                        return Ok(CloseProgress::Ready(Outcome::AdmittedBinding(token)));
                    }
                    if !external.is_empty() {
                        let mut retained = self.external_imports.borrow_mut();
                        let selected = retained
                            .selections
                            .entry(input.reference.reference)
                            .or_default()
                            .entry(PythonExternalSelectionSource::Member(id))
                            .or_default();
                        retain_external_import_observations(selected, external);
                    }
                    // Classification deliberately ignores binding completion:
                    // prefix_selection applies it to the namespace route, so a
                    // conditional import stays incomplete on that route rather
                    // than falling back to the typed member path.
                    let projected =
                        self.module_member_prefix(prefix, binding, &slot.context.lookup)?;
                    let binding = projected.as_ref().unwrap_or(binding);
                    let mut namespace = !binding.targets().is_empty();
                    for &target in binding.targets() {
                        namespace &= is_module_definition(
                            &self.ready.inventory,
                            target,
                            &self.module_sites,
                        )?;
                    }
                    if namespace {
                        self.qualified_members.insert(id, slot);
                        return Ok(CloseProgress::Ready(Outcome::QualifierIsNamespace));
                    }
                    if binding.targets().is_empty()
                        && self.namespace_import_route(prefix)?.is_some()
                    {
                        self.qualified_members.insert(id, slot);
                        return Ok(CloseProgress::Ready(Outcome::QualifierIsNamespace));
                    }
                }
                if let Some((qualifier, source)) = slot.context.alias {
                    // A qualifier assigned from exactly one reference is a
                    // namespace iff that reference's answer is only modules.
                    // The source answer's reads entered this answer through
                    // its prerequisite; its completion joins the namespace
                    // route in `prefix_selection`.
                    let source_binding = slot
                        .context
                        .references
                        .answers()
                        .find(|(key, _)| key.reference == source)
                        .expect("the alias source prerequisite has settled")
                        .1
                        .binding();
                    let mut namespace = !source_binding.targets().is_empty();
                    for &target in source_binding.targets() {
                        namespace &= is_module_definition(
                            &self.ready.inventory,
                            target,
                            &self.module_sites,
                        )?;
                    }
                    if namespace {
                        self.module_aliases.borrow_mut().insert(qualifier, source);
                        self.qualified_members.insert(id, slot);
                        return Ok(CloseProgress::Ready(Outcome::QualifierIsNamespace));
                    }
                }
                if let Some(context) = &slot.context.super_context {
                    slot.context.super_cursor = context
                        .selected(self, &slot.context.references.answers().collect::<Vec<_>>())?;
                    if let Some(cursor) = &slot.context.super_cursor {
                        slot.context.values = vec![cursor.receiver];
                    }
                    // Every call has a retained possible-super context. If its
                    // callee is not proven builtin super, keep the real typed
                    // call-result values rather than treating it as a failed
                    // proxy. Unknown calls still have no invented receiver.
                }
                if slot.context.implicit_protocol
                    && slot.context.values.iter().any(|value| {
                        self.ready
                            .context_identities
                            .model_member_identity(value.ty().identity())
                            .is_none()
                    })
                {
                    // Source special-method lookup also needs its own class-only
                    // dictionary rules. Keep that unsupported surface open rather
                    // than reuse ordinary instance-attribute interception.
                    let mut hash = CanonicalHasher::new(b"python-source-implicit-protocol:v1");
                    hash.field(
                        "reference",
                        &input.reference.reference.to_string().into_bytes(),
                    );
                    let reason = self.ready.context_identities.named_semantic(
                        hash.finish(),
                        "python_source_implicit_protocol_open",
                        "source implicit protocol lookup is not published",
                    );
                    self.qualified_members.insert(id, slot);
                    return Ok(CloseProgress::Ready(Outcome::Unavailable(
                        completion.combine(&ResolutionCompletion::incomplete([
                            ResolutionIncompleteReason::UnsupportedSemantic(reason),
                        ])),
                    )));
                }
                if let Some(owners) = self
                    .own_model_dictionaries(&slot.context.values, slot.context.lookup.spelling())?
                {
                    self.qualified_members.insert(id, slot);
                    return Ok(CloseProgress::Ready(Outcome::OwnDictionary(owners)));
                }
                if slot.context.values.is_empty() && slot.context.none_absence {
                    CloseProgress::Ready(Outcome::Ready {
                        request: Some(slot.context.view(self, input.reference).member_request(
                            input.reference.reference,
                            Vec::new(),
                            slot.access.input.lookup,
                            slot.access.input.namespace,
                        )),
                        completion,
                    })
                } else if slot.context.values.is_empty() {
                    CloseProgress::Ready(Outcome::Unavailable(
                        completion.combine(&open(input.reference.reference)),
                    ))
                } else {
                    CloseProgress::Ready(Outcome::Ready {
                        request: Some(slot.context.view(self, input.reference).member_request(
                            input.reference.reference,
                            slot.context.values.clone(),
                            slot.access.input.lookup,
                            slot.access.input.namespace,
                        )),
                        completion,
                    })
                }
            }
        };
        self.qualified_members.insert(id, slot);
        Ok(result)
    }
    fn poll_qualified_member(
        &mut self,
        id: crate::analyzer::resolution::QualifiedMemberId,
        selection: &crate::analyzer::resolution::DemandMemberSelection,
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<
        crate::analyzer::resolution::CloseProgress<Read<super::member_access::MemberAccessResult>>,
    > {
        let mut slot = self
            .qualified_members
            .remove(&id)
            .expect("prepared typed Python slot");
        let input = slot.access.input.clone();
        let reference = input.reference.reference;
        let context = slot.context.view(self, input.reference);
        let route = super::python_members::PythonMemberRoute {
            lookup: &slot.context.lookup,
            namespace: input.namespace,
            step: input.route_ordinal,
            selection,
            provenance,
        };
        let mut progress = slot.access.poll(
            id,
            selection,
            provenance,
            resume,
            self.session,
            self.cancellation,
            &context,
            |owner| super::python_members::member_rows(&context, &route, owner),
            |row| {
                let mut read = context.member_target(route.lookup, route.namespace, row)?;
                if slot.context.requires_class
                    && let Read::Ready { value, completion } = &mut read
                    && let Some(target) = value
                    && !super::python_members::is_class(self.ready, target.target.token)?
                {
                    *value = None;
                    *completion = completion.combine(&open(reference));
                }
                Ok(read)
            },
            || {
                Ok(Read::ready(std::mem::take(
                    &mut *slot.context.observations.borrow_mut(),
                )))
            },
        )?;
        // An MRO miss retains subclass uncertainty.
        // A proven unchanged current-instance reference is recorded structurally.
        if let crate::analyzer::resolution::CloseProgress::Ready(Read::Ready {
            value,
            completion,
        }) = &mut progress
        {
            value
                .query_obligations
                .union(&slot.context.query_obligations.borrow().published());
            self.dispatch_extensibility.borrow_mut().remove(&reference);
            let mount = self.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(input.fragment.ordinal()),
            )?;
            let nominal_self: bool = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites semantic
                 JOIN resolution_sites site ON site.blob_id=semantic.blob_id
                  AND site.site=semantic.source_site
                 WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                  AND semantic.semantic_role='reference' AND site.receiver_origin=1)",
                )?
                .query_row(
                    rusqlite::params![mount.blob_id(), reference.local_key()],
                    |row| row.get(0),
                )?;
            let nominal_parameter = if !nominal_self
                && slot
                    .context
                    .values
                    .iter()
                    .any(|value| matches!(value, ResolutionSlotValue::Runtime { .. }))
            {
                match self.nominal_parameter_receiver(
                    mount.blob_id(),
                    reference,
                    &slot.context.rows,
                )? {
                    Read::Ready { value, .. } => value,
                    Read::Cancelled(completion) => {
                        self.qualified_members.insert(id, slot);
                        return Ok(crate::analyzer::resolution::CloseProgress::Cancelled(
                            completion,
                        ));
                    }
                    Read::Unavailable { .. } => {
                        unreachable!("nominal parameter classification uses selected local rows")
                    }
                }
            } else {
                false
            };
            if nominal_self || nominal_parameter {
                // Only a unique complete target proves resolved receiver dispatch.
                // Several complete targets remain an ambiguous definition answer.
                if value.targets.len() == 1 && *completion == ResolutionCompletion::Complete {
                    self.dispatch_extensibility
                        .borrow_mut()
                        .insert(reference, DispatchExtensibility::Open);
                }
                if !value.targets.is_empty() {
                    self.qualified_members.insert(id, slot);
                    return Ok(progress);
                }
                let label = format!(
                    "{}:reference={reference:?}:member={}",
                    mount.persisted_relative_path(),
                    slot.context.lookup.spelling()
                );
                let mut hash = CanonicalHasher::new(b"python-receiver-subclass-member-missing:v1");
                hash.field("site", label.as_bytes());
                let reason = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "python_receiver_subclass_member_missing",
                    &label,
                );
                *completion = completion.combine(&open(reason));
                value.completion = value.completion.combine(&open(reason));
            }
        }
        self.qualified_members.insert(id, slot);
        Ok(progress)
    }
    fn cancel_qualified_member(&mut self, id: crate::analyzer::resolution::QualifiedMemberId) {
        self.qualified_members.remove(&id);
    }
}

type PythonStarRoutes = HashMap<u32, Vec<(RouteLocation, ResolutionLookupSemanticRecipe)>>;

#[derive(Clone, Debug)]
struct PythonModuleAttributeSpace {
    completion: ResolutionCompletion,
    /// Module `__getattr__` (PEP 562) is consulted only after normal lookup
    /// fails, so a read of a strictly unconditional binding does not take it.
    hook_completion: ResolutionCompletion,
    star_completion: ResolutionCompletion,
    star_sites: Vec<u32>,
}

#[derive(Debug, Default)]
struct PythonModuleRead {
    locations: Vec<RouteLocation>,
    // The pending lookup is unchanged: the scheduler must not consume it yet.
    lookup_continuations: Vec<RouteLocation>,
    selected_binding: bool,
}

#[derive(Clone)]
struct PythonNamespaceImportRoute {
    containers: Vec<String>,
    completion: ResolutionCompletion,
}
impl PythonModuleRead {
    fn is_empty(&self) -> bool {
        self.locations.is_empty() && self.lookup_continuations.is_empty()
    }
}

pub(super) struct PythonPlacement {
    container: String,
    universe: std::cell::Cell<Option<crate::analyzer::resolution::UniverseEntry>>,
    lexical: RefCell<Option<PythonLexical>>,
    stars: RefCell<PythonStarRoutes>,
}

#[derive(Clone)]
pub(super) struct PythonTarget {
    location: RouteLocation,
    rank: Option<PythonRank>,
    scope: Option<ResolutionScopeId>,
}

pub(super) struct PythonHalf<'a, 'store, 'input> {
    open: Option<OpenHalf>,
    query_obligations: std::rc::Rc<RefCell<NodeQueryObligations>>,
    pub(super) rules: &'a PythonRules<'a, 'store, 'input>,
    pub(super) source: &'a SourceHalf,
    placements: Vec<PythonPlacement>,
    import_site: Option<u32>,
    import_name: Option<String>,
    import_module_operand: Option<(u32, u32)>,
    pub(super) rows: brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
    fragment: BindingFragmentId,
    pub(super) blob: i64,
    reference_site: Option<u32>,
    deferred_module_scope: Option<u32>,
    prefix: Option<std::rc::Rc<ResolutionAnswer>>,
    universe_unmutated: bool,
    import_aliases: std::rc::Rc<[PythonAliasTargets]>,
    module_mutations: std::rc::Rc<[super::python_members::operations::ModuleMutation]>,
    completion: ResolutionCompletion,
    stopped: std::cell::Cell<bool>,
    /// Open module-attribute coverage of module reads that found no binding.
    /// An empty placement carries it: a module `__getattr__` or dynamic writer
    /// can supply the name, so the empty answer is not a complete absence.
    empty_module_read: RefCell<ResolutionCompletion>,
    pub(super) member_observations:
        RefCell<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>,
    pub(super) rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
}

impl<'a, 'store, 'input> PythonHalf<'a, 'store, 'input> {
    fn new(
        rules: &'a PythonRules<'a, 'store, 'input>,
        source: &'a SourceHalf,
        completion: ResolutionCompletion,
        query_obligations: std::rc::Rc<RefCell<NodeQueryObligations>>,
        rows: brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
        blob: i64,
        rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
    ) -> Self {
        Self {
            open: None,
            query_obligations,
            rules,
            source,
            placements: Vec::new(),
            import_site: None,
            import_name: None,
            import_module_operand: None,
            rows,
            fragment: source.identity.fragment(),
            blob,
            reference_site: None,
            deferred_module_scope: None,
            prefix: None,
            universe_unmutated: false,
            import_aliases: Vec::new().into(),
            module_mutations: Vec::new().into(),
            completion,
            stopped: std::cell::Cell::new(false),
            empty_module_read: RefCell::new(ResolutionCompletion::Complete),
            member_observations: RefCell::new(Vec::new()),
            rendered_order,
        }
    }

    fn open(
        rules: &'a PythonRules<'a, 'store, 'input>,
        source: &'a SourceHalf,
        completion: ResolutionCompletion,
        label: &'static str,
        evidence: &str,
    ) -> Self {
        let mut hash = CanonicalHasher::new(b"python-open-source-half:v1");
        hash.field("source", &source.token.get().to_le_bytes());
        hash.field("label", label.as_bytes());
        let reason = rules
            .ready
            .context_identities
            .named_semantic(hash.finish(), label, evidence);
        Self {
            open: Some(OpenHalf::new(ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]))),
            ..Self::new(
                rules,
                source,
                completion,
                std::rc::Rc::new(RefCell::new(NodeQueryObligations::empty())),
                brokk_bifrost_core::retention_budget::BudgetedValue::request_only(
                    PythonBindingRows::default(),
                ),
                0,
                std::rc::Rc::new(std::cell::Cell::new(false)),
            )
        }
    }
}

struct PythonHalfInputs {
    query_obligations: std::rc::Rc<RefCell<NodeQueryObligations>>,
    requesting_path: String,
    conditional_imports: Vec<u32>,
    activation_reasons: Vec<SemanticId>,
    endpoint_completion: ResolutionCompletion,
    containers: Vec<String>,
    import_site: Option<u32>,
    import_name: Option<String>,
    import_module_operand: Option<(u32, u32)>,
    rows: brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
    fragment: BindingFragmentId,
    blob: i64,
    reference_site: Option<u32>,
    deferred_module_scope: Option<u32>,
    prefix: Option<std::rc::Rc<ResolutionAnswer>>,
    universe_unmutated: bool,
    import_aliases: std::rc::Rc<[PythonAliasTargets]>,
    module_mutations: std::rc::Rc<[super::python_members::operations::ModuleMutation]>,
    rendered_order: std::rc::Rc<std::cell::Cell<bool>>,
}
impl PythonHalfInputs {
    fn view<'a, 'store, 'input>(
        &self,
        rules: &'a PythonRules<'a, 'store, 'input>,
        source: &'a SourceHalf,
        completion: ResolutionCompletion,
    ) -> PythonHalf<'a, 'store, 'input> {
        // This is the consuming accessor, reached for both memo hits and misses.
        debug_assert_eq!(self.fragment, source.identity.fragment());
        rules.record_unplaced_scope(source.token, &self.query_obligations, &self.requesting_path);
        PythonHalf {
            placements: self
                .containers
                .iter()
                .map(|container| PythonPlacement {
                    container: container.clone(),
                    lexical: RefCell::new(None),
                    stars: RefCell::new(HashMap::default()),
                    universe: std::cell::Cell::new(None),
                })
                .collect(),
            import_site: self.import_site,
            import_name: self.import_name.clone(),
            import_module_operand: self.import_module_operand,
            rows: self.rows.clone(),
            fragment: self.fragment,
            blob: self.blob,

            reference_site: self.reference_site,
            deferred_module_scope: self.deferred_module_scope,
            prefix: self.prefix.clone(),
            universe_unmutated: self.universe_unmutated,
            import_aliases: std::rc::Rc::clone(&self.import_aliases),
            module_mutations: std::rc::Rc::clone(&self.module_mutations),
            ..PythonHalf::new(
                rules,
                source,
                completion.combine(&self.endpoint_completion),
                std::rc::Rc::clone(&self.query_obligations),
                self.rows.clone(),
                self.blob,
                std::rc::Rc::clone(&self.rendered_order),
            )
        }
    }
}

fn open(semantic: SemanticId) -> ResolutionCompletion {
    ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(semantic)])
}

struct SettledPrefix {
    mount:
        std::sync::Arc<crate::analyzer::store::resolution_selection::SelectedResolutionMountRecord>,
    rows: brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
    site: u32,
    name: String,
    state: PythonLexical,
}

#[derive(Clone)]
struct PythonRootPrefix {
    member: u32,
    prefix: u32,
    site: u32,
    name: String,
}

pub(super) fn conditional_imports(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
    rows: &PythonBindingRows,
    caller: &str,
    blob: i64,
) -> Result<Vec<u32>> {
    let sites = ready.inventory.connection().prepare_cached(
            "SELECT imports.import_site FROM resolution_unit_summary_members member JOIN python_unit_summary_imports imports ON imports.summary_id=member.summary_id AND imports.member_ordinal=member.member_ordinal WHERE member.summary_id=?1 AND member.rel_path=?2 AND member.blob_id=?3 GROUP BY imports.import_site HAVING COUNT(DISTINCT imports.target_container)=1 AND MIN(imports.state='activation_open') AND MIN(EXISTS(SELECT 1 FROM python_unit_summary_providers provider WHERE provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container AND (provider.state='selected' OR (provider.state='alternative' AND EXISTS(SELECT 1 FROM python_unit_summary_roots root WHERE root.summary_id=provider.summary_id AND root.root_slot=provider.root_slot AND root.authority='workspace')))))",
        )?.query_map(rusqlite::params![summary,caller,blob], |row| row.get::<_,u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let sites = sites
        .into_iter()
        .filter(|site| python_lexical::unconditional_import(rows, *site))
        .collect::<Vec<_>>();
    Ok(sites)
}

fn unit_metadata(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
) -> Result<(Vec<u8>, String)> {
    if let Some(metadata) = ready.inventory.python_unit_metadata.borrow().get(&summary) {
        return Ok(metadata.clone());
    }
    let metadata: (Vec<u8>, String) = ready.inventory.connection().prepare_cached("SELECT summary.unit_key,roots.observation FROM resolution_unit_summaries summary JOIN python_unit_summary_roots roots ON roots.summary_id=summary.summary_id WHERE summary.summary_id=?1 LIMIT 1")?.query_row(
        [summary], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    assert!(
        ready
            .inventory
            .python_unit_metadata
            .borrow_mut()
            .insert(summary, metadata.clone())
            .is_none()
    );
    Ok(metadata)
}

/// Selected route evidence is request-local, not an execution observation.
pub(super) fn import_route_obligation(
    ready: &ReadySelectedResolution<'_, '_>,
    summary: i64,
    caller: &str,
    site: u32,
    state: &str,
) -> Result<(ResolutionCompletion, String)> {
    let kind = match state {
        "relative_context_open" => "python_relative_context_open",
        "provider_open" => "python_provider_open",
        _ => unreachable!("only unresolved selected routes have endpoint obligations"),
    };
    let (unit, profile) = unit_metadata(ready, summary)?;
    let label = format!("{kind}:{caller}:site={site}:{state}");
    let mut hash = CanonicalHasher::new(b"python-import-route-obligation:v1");
    hash.field("unit", &unit);
    hash.field("profile", profile.as_bytes());
    hash.field("import", label.as_bytes());
    let reason = ready
        .context_identities
        .named_semantic(hash.finish(), kind, &label);
    Ok((open(reason), label))
}

type PythonModuleBindings = (
    u32,
    i64,
    brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>,
);

impl PythonRules<'_, '_, '_> {
    pub(super) fn visit_member_owners(
        &self,
        owners: &[SemanticId],
        visitor: &mut FactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> Result<TypedFactReadOutcome> {
        let key = owners.to_vec();
        let cached = self.member_owner_rows.borrow().get(&key).cloned();
        let missed = cached.is_none();
        let answer = if let Some(cached) = cached {
            cached
        } else {
            let mut rows = Vec::new();
            let read = self
                .ready
                .typed_source()
                .visit_member_owner_pages_for_owners(
                    TypedFactRequest::new(owners),
                    self.cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
            if read.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(read.evidence().clone()));
            }
            if !read.is_exhausted() {
                return Ok(TypedFactReadOutcome::stopped(read.evidence().clone()));
            }
            std::sync::Arc::new((rows, read.evidence().clone()))
        };
        for page in answer.0.chunks(MAX_TYPED_FACT_ROWS_PER_PAGE) {
            if !visitor.visit_page(page)? {
                return Ok(TypedFactReadOutcome::stopped(answer.1.clone()));
            }
        }
        if self.cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(answer.1.clone()));
        }
        if missed {
            self.member_owner_rows
                .borrow_mut()
                .insert(key, std::sync::Arc::clone(&answer));
        }
        Ok(TypedFactReadOutcome::exhausted(answer.1.clone()))
    }
    pub(super) fn record_query_scope(
        &self,
        reference: SemanticId,
        scope: &RefCell<NodeQueryObligations>,
        kind: &str,
    ) {
        debug_assert_ne!(
            kind, "python_dynamic_receiver_mutation_open",
            "dynamic-receiver scope is recorded lazily by record_dynamic_receiver_scope"
        );
        // The served node is explicit even when its memo was filled by another root.
        for obligation in self
            .selected_query_obligations
            .iter()
            .filter(|obligation| obligation.kind == kind)
        {
            scope
                .borrow_mut()
                .node(QueryNode::Reference(reference))
                .insert(obligation.clone());
        }
    }
    pub(super) fn record_dynamic_receiver_scope(
        &self,
        reference: SemanticId,
        scope: &RefCell<NodeQueryObligations>,
    ) -> Result<()> {
        let obligation = self.mutations.dynamic_receiver_obligation()?;
        // The served node is explicit even when its memo was filled by another root.
        if let Some(obligation) = obligation {
            scope
                .borrow_mut()
                .node(QueryNode::Reference(reference))
                .insert(obligation.clone());
        }
        Ok(())
    }
    pub(super) fn record_unplaced_scope(
        &self,
        reference: SemanticId,
        scope: &RefCell<NodeQueryObligations>,
        path: &str,
    ) {
        for obligation in self.selected_query_obligations.iter().filter(|obligation| {
            obligation.kind == "python_unknown_placement" && obligation.subject == path
        }) {
            scope
                .borrow_mut()
                .node(QueryNode::Reference(reference))
                .insert(obligation.clone());
        }
    }

    fn root_prefix(&self, blob: i64, reference: SemanticId) -> Result<Option<PythonRootPrefix>> {
        let find = |rows: &[PythonRootPrefix]| {
            rows.binary_search_by_key(&reference.local_key().expect("local member"), |row| {
                row.member
            })
            .ok()
            .map(|index| rows[index].clone())
        };
        if let Some(rows) = self.root_prefixes.borrow().get(&blob) {
            return Ok(find(rows));
        }
        // The source root half retains its positioned prefix in the second
        // end-stack symbol, as in resolution_lexical::root_prefix_sites.
        let rows = self.ready.inventory.connection().prepare_cached(
                "SELECT DISTINCT node.semantic_local_key, semantic.semantic_key, semantic.source_site, name.spelling
                 FROM resolution_paths path
                 JOIN resolution_node_catalog node ON node.blob_id=path.blob_id AND node.local_key=path.start_node
                 JOIN resolution_semantic_sites semantic ON semantic.blob_id=path.blob_id
                   AND semantic.semantic_role='reference'
                   AND semantic.semantic_key=CAST(json_extract(path.body,'$[4][1]') AS INTEGER)
                 JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id
                   AND lookup.semantic_key=semantic.semantic_key
                 JOIN resolution_identities name ON name.id=lookup.identity_id
                 WHERE path.blob_id=?1 AND path.end_node=-1 AND path.root_terminal IS NOT NULL
                   AND node.semantic_local_key IS NOT NULL
                   AND json_array_length(path.body,'$[4]')=4
                   AND json_type(path.body,'$[4][1]')='integer'
                   AND CAST(json_extract(path.body,'$[4][1]') AS INTEGER)>=0
                 ORDER BY node.semantic_local_key"
            )?.query_map([blob], |row| Ok(PythonRootPrefix {
                    member: row.get(0)?, prefix: row.get(1)?, site: row.get(2)?, name: row.get(3)?,
                }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let selected = find(&rows);
        assert!(self.root_prefixes.borrow_mut().insert(blob, rows).is_none());
        Ok(selected)
    }

    // A runtime value alone does not prove nominal parameter provenance:
    // constructed locals retain their closed negative member proofs. Reuse
    // lexical selection so captures and rebindings follow the native binder.
    fn nominal_parameter_receiver(
        &self,
        blob: i64,
        reference: SemanticId,
        rows: &PythonBindingRows,
    ) -> Result<Read<bool>> {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ALL_DECLARATION_TYPE_ROLES, DeclarationTypeRole,
        };
        let Some(prefix) = self.root_prefix(blob, reference)? else {
            return Ok(Read::ready(false));
        };
        let Some(mut state) = python_lexical::lexical_selection(
            rows,
            prefix.site,
            &prefix.name,
            self.profile,
            PythonBindingProofs::default(),
        ) else {
            return Ok(Read::ready(false));
        };
        python_lexical::select_lexical(
            &mut state,
            rows,
            &mut SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            },
            self.cancellation,
        )?;
        if state.selection.stopped.is_some() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        for parameter in rows.events.iter().filter(|event| {
            event.kind == ResolutionBindingEventKind::Parameter
                && state
                    .selection
                    .selected
                    .iter()
                    .any(|selected| selected.occurrence == event.event)
        }) {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let authored = parameter.authored.ok_or_else(|| {
                StoreError::corrupt("Python parameter writer lacks its authored declaration")
            })?;
            let annotated: bool = self.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_member_annotations WHERE blob_id=?1 AND owner=?2)")?.query_row( rusqlite::params![blob,authored], |row| row.get(0))?;
            if annotated {
                return Ok(Read::ready(true));
            }
            // The same first-instance proof seeds the parameter's type. This
            // also recognizes an unchanged parameter captured by a nested frame.
            let role = ALL_DECLARATION_TYPE_ROLES
                .iter()
                .position(|role| *role == DeclarationTypeRole::Parameter)
                .expect("parameter role is registered") as i64;
            let slots = self.ready.inventory.connection().prepare_cached(
                "SELECT declaration.slot FROM resolution_declaration_types declaration
                 JOIN resolution_semantic_sites semantic ON semantic.blob_id=declaration.blob_id
                  AND semantic.semantic_key=declaration.definition AND semantic.semantic_role='definition'
                 WHERE declaration.blob_id=?1 AND semantic.source_site=?2 AND declaration.role=?3")?
                .query_map(rusqlite::params![blob,authored,role], |row| row.get::<_,u32>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for slot in slots {
                let seed = super::super::python_member_rows::receiver_seed(
                    &self.ready.inventory,
                    SemanticId::local(reference.ordinal().expect("mounted Python receiver"), slot),
                    self.cancellation,
                )?;
                if seed.is_some_and(|seed| {
                    seed.value.obligation().is_none() && seed.prerequisites.is_empty()
                }) {
                    return Ok(Read::ready(true));
                }
            }
        }
        Ok(Read::ready(false))
    }

    fn none_definition(&self, definition: SemanticId) -> Result<bool> {
        let Some(ordinal) = definition.ordinal() else {
            return Ok(false);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let value_role = brokk_bifrost_core::analyzer::resolution_facts::ALL_DECLARATION_TYPE_ROLES
            .iter()
            .position(|role| {
                *role == brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole::Value
            })
            .expect("value role is registered") as i64;
        Ok(self
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM resolution_declaration_types property
             JOIN resolution_type_transfers transfer ON transfer.blob_id=property.blob_id
               AND transfer.target_slot=property.slot
             JOIN resolution_intrinsic_seeds seed ON seed.blob_id=transfer.blob_id
               AND seed.slot=transfer.source_slot
             WHERE property.blob_id=?1 AND property.definition=?2 AND property.role=?3
               AND seed.spelling='types.NoneType' AND seed.completion IS NULL
               AND transfer.completion IS NULL AND transfer.value_transform=0
               AND NOT EXISTS(SELECT 1 FROM resolution_type_transfers other
                 WHERE other.blob_id=transfer.blob_id AND other.target_slot=transfer.target_slot
                   AND other.source_slot<>transfer.source_slot))",
            )?
            .query_row(
                rusqlite::params![mount.blob_id(), definition.local_key(), value_role],
                |row| row.get(0),
            )?)
    }

    fn lexical_selection_obligation(
        &self,
        reference: SemanticId,
        name: &str,
        state: &PythonLexical,
    ) -> SemanticId {
        let detail = format!(
            "reference={reference:?}:name={name}:open={}:residual={:?}:unbound={:?}",
            state.selection.open, state.selection.residual, state.selection.unbound,
        );
        let mut hash = CanonicalHasher::new(b"python-lexical-selection-open:v1");
        hash.field("selection", detail.as_bytes());
        self.ready.context_identities.named_semantic(
            hash.finish(),
            "python_lexical_selection_open",
            &detail,
        )
    }

    /// The lexical selection of one prefix reference, settled with no unbound
    /// path, no stopped walk and no star import in its file. This is the one
    /// writer rule for a Python qualifier: the None projection and the one-hop
    /// module alias both read it, so a global or other-scope writer is judged by
    /// `select_lexical`'s identity proofs for both.
    fn settled_prefix(&self, prefix: SemanticId) -> Result<Option<SettledPrefix>> {
        let ordinal = prefix.ordinal().expect("mounted Python prefix");
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let Some(rows) = self.load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))? else {
            return Ok(None);
        };
        let prefix_row: Option<(u32,String)> = self.ready.inventory.connection().prepare_cached("SELECT semantic.source_site,name.spelling FROM resolution_semantic_sites semantic
             JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id
               AND lookup.semantic_key=semantic.semantic_key
             JOIN resolution_identities name ON name.id=lookup.identity_id
             WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='reference'")?.query_row(
            rusqlite::params![mount.blob_id(),prefix.local_key()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let Some((site, name)) = prefix_row else {
            return Ok(None);
        };
        let Some(mut state) = python_lexical::lexical_selection(
            &rows,
            site,
            &name,
            self.profile,
            PythonBindingProofs::default(),
        ) else {
            return Ok(None);
        };
        python_lexical::select_lexical(
            &mut state,
            &rows,
            &mut SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            },
            self.cancellation,
        )?;
        if state.selection.stopped.is_some()
            || state.selection.selected.is_empty()
            || !state.selection.unbound.is_empty()
            || rows.imports.iter().any(|import| {
                import.form
                    == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
            })
        {
            return Ok(None);
        }
        Ok(Some(SettledPrefix {
            mount,
            rows,
            site,
            name,
            state,
        }))
    }

    /// The source reference of a prefix that is exactly one direct assignment
    /// `prefix = <reference>` and whose source is an import cell, or None. The
    /// producer records the source only for a direct single-target assignment,
    /// so a destructuring, an augmented assignment, a call or an attribute value
    /// has none. One hop: the result is itself only demanded, never followed, so
    /// `b = a; a = sub` leaves `b` to the answer for `a`, which is an
    /// assignment and not a module.
    ///
    /// The source is requested under the same positive condition as a direct
    /// qualifier (`prefix_has_import`): a reference prerequisite that closes a
    /// typed cycle drops the cycle reason, and a source with no reaching import
    /// can sit in one (`x = y; y = x.member` in a loop).
    fn alias_source(
        &self,
        rows: &PythonBindingRows,
        prefix: SemanticId,
        prefix_name: &str,
    ) -> Result<Read<Option<SemanticId>>> {
        // Cheap rejection from loaded rows before the lexical walk: the
        // qualifier's name must be written somewhere by a direct assignment
        // from a reference. Slots are ordered by slot.
        if !rows.events.iter().any(|event| {
            event.kind == ResolutionBindingEventKind::Assign
                && event.source_reference.is_some()
                && rows
                    .slots
                    .binary_search_by_key(&event.slot, |slot| slot.slot)
                    .is_ok_and(|slot| rows.slots[slot].name == prefix_name)
        }) {
            return Ok(Read::ready(None));
        }
        let Some(settled) = self.settled_prefix(prefix)? else {
            return Ok(Read::ready(None));
        };
        let [selected] = settled.state.selection.selected.as_slice() else {
            return Ok(Read::ready(None));
        };
        let Some(event) = settled
            .rows
            .events
            .iter()
            .find(|event| event.event == selected.occurrence)
        else {
            return Ok(Read::ready(None));
        };
        let (ResolutionBindingEventKind::Assign, Some(source_site)) =
            (event.kind, event.source_reference)
        else {
            return Ok(Read::ready(None));
        };
        let ordinal = prefix.ordinal().expect("mounted Python prefix");
        let blob = settled.mount.blob_id();
        let Some((key, name)) = self
            .ready
            .inventory
            .connection()
            .prepare_cached(REFERENCE_BY_SOURCE_SITE_SQL)?
            .query_row(rusqlite::params![blob, source_site], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?))
            })
            .optional()?
        else {
            return Ok(Read::ready(None));
        };
        let has_import = match self.prefix_has_import(
            &settled.rows,
            &PythonRootPrefix {
                member: key,
                prefix: key,
                site: source_site,
                name,
            },
            settled.mount.persisted_relative_path(),
            blob,
            ordinal,
        )? {
            Read::Ready { value, .. } => value,
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { .. } => unreachable!("lexical slot reads are local"),
        };
        Ok(Read::ready(
            has_import.then(|| SemanticId::local(ordinal, key)),
        ))
    }

    /// Project the prefix for this member access, independently of its ordinary
    /// value read. None is still a reaching value, but its missing member raises
    /// AttributeError and contributes no declaration to the successful access.
    fn module_member_prefix(
        &self,
        prefix: SemanticId,
        binding: &ResolutionAnswer,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Option<ResolutionAnswer>> {
        if brokk_bifrost_python::intrinsics::none_type_member(
            lookup.spelling(),
            self.python_version,
        ) != brokk_bifrost_python::intrinsics::Availability::Absent
        {
            return Ok(None);
        }
        let mut targets = Vec::new();
        let mut removed_targets = Vec::new();
        for &target in binding.targets() {
            if is_module_definition(&self.ready.inventory, target, &self.module_sites)? {
                targets.push(target);
            } else if self.none_definition(target)? {
                removed_targets.push(target);
            } else {
                return Ok(None);
            }
        }
        if removed_targets.is_empty() {
            return Ok(None);
        }
        let Some(SettledPrefix {
            mount,
            rows,
            site,
            name,
            mut state,
        }) = self.settled_prefix(prefix)?
        else {
            return Ok(None);
        };
        let ordinal = prefix.ordinal().expect("mounted Python prefix");
        let token_identity =
            crate::analyzer::resolution::fact_lowering::root_reference_token_identity(
                ResolutionSiteId::new(site),
                lookup.namespace(),
            );
        let token: Option<u32> = self.ready.inventory.connection().prepare_cached("SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND identity_digest=?2")?.query_row(
            rusqlite::params![mount.blob_id(), token_identity.fragment_local_digest().as_slice()],
            |row| row.get(0),
        ).optional()?;
        let Some(token) = token else {
            return Ok(None);
        };
        let mut discharged = std::collections::BTreeSet::from([
            ResolutionIncompleteReason::UnsupportedSemantic(prefix),
            ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(ordinal, token)),
        ]);
        let lexical_obligation =
            self.lexical_selection_obligation(SemanticId::local(ordinal, token), &name, &state);
        let mut removed_writers = Vec::new();
        let mut imports = Vec::new();
        for selected in &state.selection.selected {
            let Some(event) = rows
                .events
                .iter()
                .find(|event| event.event == selected.occurrence)
            else {
                return Ok(None);
            };
            if event.kind == ResolutionBindingEventKind::Import {
                let import = rows
                    .imports
                    .iter()
                    .find(|import| import.binding_event == Some(event.event))
                    .expect("import event metadata");
                // Provider identity is conditional on import success; execution
                // uncertainty is irrelevant only to this successful member read.
                let unique: bool = self.ready.inventory.connection().prepare_cached("SELECT COUNT(DISTINCT imports.target_container)=1 AND MIN(imports.state='activation_open')
                     AND MIN(EXISTS(SELECT 1 FROM python_unit_summary_providers provider
                       WHERE provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container
                         AND provider.state='selected'))
                     FROM python_unit_summary_imports imports
                     JOIN resolution_unit_summary_members member ON member.summary_id=imports.summary_id
                       AND member.member_ordinal=imports.member_ordinal
                     WHERE imports.summary_id=?1 AND member.blob_id=?2 AND imports.import_site=?3 AND member.rel_path=?4")?.query_row(
                    rusqlite::params![self.summary,mount.blob_id(),import.import_site.get(),mount.persisted_relative_path()], |row| row.get::<_,Option<bool>>(0),
                )?.unwrap_or(false);
                if !unique {
                    return Ok(None);
                }
                imports.push(import.import_site.get());
                discharged.extend(
                    self.import_activation_reasons(
                        mount.blob_id(),
                        ordinal,
                        import.import_site.get(),
                    )?
                    .into_iter()
                    .map(ResolutionIncompleteReason::UnsupportedSemantic),
                );
            } else if !event.authored.is_some_and(|site| {
                binding.targets().iter().any(|target| {
                    *target
                        == crate::analyzer::resolution::mounted_site_semantic(
                            mount.fragment_id(),
                            ResolutionSiteId::new(site),
                        )
                })
            }) {
                return Ok(None);
            }
            if event.authored.is_some_and(|site| {
                removed_targets.contains(&crate::analyzer::resolution::mounted_site_semantic(
                    mount.fragment_id(),
                    ResolutionSiteId::new(site),
                ))
            }) {
                removed_writers.push(event.event);
            }
        }
        if targets.len() == 1 {
            let mut budget = SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            };
            match python_lexical::project_alternatives(
                &mut state,
                &rows,
                removed_writers,
                imports,
                &mut budget,
            ) {
                Ok(true) => {
                    python_lexical::select_lexical(
                        &mut state,
                        &rows,
                        &mut budget,
                        self.cancellation,
                    )?;
                    if state.selection.stopped.is_none()
                        && !state.selection.open
                        && state.selection.residual.is_empty()
                        && state.selection.unbound.is_empty()
                        && state.selection.completion == ResolutionCompletion::Complete
                    {
                        discharged.insert(ResolutionIncompleteReason::UnsupportedSemantic(
                            lexical_obligation,
                        ));
                    }
                }
                Ok(false) => {}
                Err(Stop::Budget | Stop::Cancelled) => return Ok(None),
            }
        }
        let completion = binding
            .completion()
            .without_reasons_with_poll(&discharged.into_iter().collect::<Vec<_>>(), &mut || {
                self.cancellation.is_cancelled()
            })
            .unwrap_or_else(cancelled_completion);
        Ok(Some(ResolutionAnswer::new(targets, Vec::new(), completion)))
    }

    fn prefix_has_import(
        &self,
        rows: &PythonBindingRows,
        prefix: &PythonRootPrefix,
        caller: &str,
        blob: i64,
        ordinal: u32,
    ) -> Result<Read<bool>> {
        let mut rooted_prefix = prefix.clone();
        let mut visited = HashSet::default();
        while let Some(parent) =
            self.root_prefix(blob, SemanticId::local(ordinal, rooted_prefix.prefix))?
        {
            if self.cancellation.is_cancelled() || !self.session.scope_step() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            if !visited.insert(parent.member) {
                return Err(StoreError::corrupt("Python source qualifier prefix cycle"));
            }
            rooted_prefix = parent;
        }
        let prefix = &rooted_prefix;
        let Some(state) = python_lexical::lexical_selection(
            rows,
            prefix.site,
            &prefix.name,
            self.profile,
            PythonBindingProofs::default(),
        ) else {
            return Ok(Read::ready(false));
        };
        let start = ResolutionScopeId::new(state.start_scope);
        let point = rows
            .observations
            .iter()
            .find(|observation| observation.reference.get() == prefix.site)
            .expect("selected prefix has a binding observation")
            .point_byte;
        let state = RefCell::new(state);
        let imports = std::cell::Cell::new(false);
        let selected = select_lexical_route_starts::<u32, (), _>(
            start,
            |scope| {
                Ok(
                    python_lexical::lexical_parent(&state.borrow(), rows, scope.get())
                        .map(ResolutionScopeId::new),
                )
            },
            |scope, _| {
                let mut state = state.borrow_mut();
                let slot = python_lexical::lexical_slot(&state, rows, scope.get())
                    .map(|slot| (slot.slot, slot.whole_scope));
                let before = state.selection.selected.len();
                python_lexical::lexical_tier(
                    &mut state,
                    rows,
                    scope.get(),
                    &mut SessionBudget {
                        session: self.session,
                        cancellation: self.cancellation,
                    },
                );
                if state.selection.stopped.is_some() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                // An ordered class cell can have only future writes here;
                // its hole continues to an outer slot. Whole-scope locals
                // still own an early unbound read, including a later import.
                if let Some((slot, whole_scope)) = slot
                    && (whole_scope || state.selection.selected.len() > before)
                {
                    imports.set(
                        imports.get()
                            || rows.events.iter().any(|event| {
                                event.slot == slot
                                    && event.kind == ResolutionBindingEventKind::Import
                            }),
                    );
                } else if state.selection.selected.len() == before
                    && !MODULE_OBJECT_ATTRIBUTES.contains(&prefix.name.as_str())
                {
                    // A star has no named binding event. Request the prefix
                    // only for a placed curated child, so an unrelated star
                    // cannot create a prerequisite cycle for local values.
                    for (site, owner, commit) in &rows.import_positions {
                        if *owner != scope.get()
                            || *commit > point
                            || !python_lexical::unconditional_import(rows, *site)
                            || !rows.imports.iter().any(|import| {
                                import.import_site.get() == *site
                                    && import.form
                                        == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
                            })
                        {
                            continue;
                        }
                        let child: bool = self
                            .ready
                            .inventory
                            .connection()
                            .prepare_cached(CURATED_STAR_CHILD_PREFIX_SQL)?
                            .query_row(
                                rusqlite::params![self.summary, caller, blob, site, prefix.name],
                                |row| row.get(0),
                            )?;
                        if child {
                            imports.set(true);
                            break;
                        }
                    }
                }
                Ok(Read::ready(vec![Ok(RankedLexicalTier {
                    rank: 0,
                    tier: RouteEdgeTier {
                        blocks_fallback: true,
                        ..Default::default()
                    },
                    providers: Vec::new(),
                })]))
            },
            |_, _| python_lexical::outer_can_compete(&state.borrow()),
            |_, _| false,
            &mut ResolutionCompletion::Complete,
            self.cancellation,
        )?;
        Ok(match selected {
            Read::Ready { .. } => Read::ready(imports.get()),
            Read::Cancelled(completion) => Read::Cancelled(completion),
            Read::Unavailable { .. } => unreachable!("lexical slot reads are local"),
        })
    }

    fn import_route_completion(
        &self,
        caller: &str,
        blob: i64,
        import: &brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportFact,
    ) -> Result<ResolutionCompletion> {
        if self.external_imports.borrow().requested_reference.is_some() {
            self.external_imports
                .borrow_mut()
                .observed_imports
                .insert((caller.to_owned(), import.import_site.get()));
        }
        let states = self.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT imports.state FROM resolution_unit_summary_members member INDEXED BY resolution_unit_summary_members_blob CROSS JOIN python_unit_summary_imports imports ON imports.summary_id=member.summary_id AND imports.member_ordinal=member.member_ordinal WHERE member.blob_id=?4 AND member.summary_id=?1 AND member.rel_path=?2 AND imports.import_site=?3",
        )?.query_map(rusqlite::params![self.summary,caller,import.import_site.get(),blob], |row| row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut completion = ResolutionCompletion::Complete;
        for state in states {
            if matches!(state.as_str(), "relative_context_open" | "provider_open") {
                completion = completion.combine(
                    &import_route_obligation(
                        self.ready,
                        self.summary,
                        caller,
                        import.import_site.get(),
                        &state,
                    )?
                    .0,
                );
            }
        }
        Ok(completion)
    }

    /// Provider selection fixes a writer's identity conditional on import success.
    /// It is neither an execution proof nor authority to close guarded writers.
    fn conditional_imports(
        &self,
        rows: &PythonBindingRows,
        caller: &str,
        blob: i64,
    ) -> Result<Vec<u32>> {
        let key = (blob, caller.to_owned());
        if let Some(sites) = self.conditional_import_sites.borrow().get(&key) {
            return Ok(sites.clone());
        }
        let sites = conditional_imports(self.ready, self.summary, rows, caller, blob)?;
        assert!(
            self.conditional_import_sites
                .borrow_mut()
                .insert(key, sites.clone())
                .is_none()
        );
        Ok(sites)
    }

    fn import_activation_reasons(
        &self,
        blob: i64,
        ordinal: u32,
        site: u32,
    ) -> Result<Vec<SemanticId>> {
        let origin = crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::Extracted(brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnprovenActivation));
        Ok(self.ready.inventory.connection().prepare_cached(
            "SELECT reason FROM resolution_gap_reasons WHERE blob_id=?1 AND origin=?3 AND (site=?2 OR site IN (SELECT target_reference FROM resolution_root_import_demands WHERE blob_id=?1 AND import_site=?2 AND target_reference IS NOT NULL))",
        )?.query_map(rusqlite::params![blob,site,origin], |row| Ok(SemanticId::local(ordinal,row.get(0)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// An alias prerequisite can copy its import's provisional reasons into
    /// this caller. Carry the same exact selected writer proof to that caller;
    /// never treat the prerequisite's other incomplete reasons as discharged.
    fn alias_import_activation_reasons(&self, reference: SemanticId) -> Result<Vec<SemanticId>> {
        let Some(ordinal) = reference.ordinal() else {
            return Ok(Vec::new());
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let blob = mount.blob_id();
        let site: Option<u32> = self.ready.inventory.connection().prepare_cached("SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'")?.query_row(
            rusqlite::params![blob,reference.local_key()], |row|row.get(0)).optional()?;
        let Some(site) = site else {
            return Ok(Vec::new());
        };
        let sites = self.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT import_site FROM resolution_root_import_demands WHERE blob_id=?1 AND target_reference=?2",
        )?.query_map(rusqlite::params![blob,site], |row|row.get::<_,u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if sites.is_empty() {
            return Ok(Vec::new());
        }
        let Some(rows) = self.load_binding_rows(blob, Some(mount.blob_oid()))? else {
            return Ok(Vec::new());
        };
        let fixed = self.conditional_imports(&rows, mount.persisted_relative_path(), blob)?;
        let mut reasons = Vec::new();
        for site in sites.into_iter().filter(|site| fixed.contains(site)) {
            reasons.extend(self.import_activation_reasons(blob, ordinal, site)?);
        }
        Ok(reasons)
    }

    fn source_import_site(
        &self,
        blob: i64,
        identity: CandidatePathIdentity,
        token: SemanticId,
    ) -> Result<Option<u32>> {
        self.ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT import_site FROM main.resolution_root_import_demands
             WHERE blob_id=?1 AND target_reference=(
               SELECT reference_source_site FROM main.resolution_root_route_segments
               WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL)
             UNION
             SELECT import_source_site FROM main.resolution_semantic_catalog
             WHERE blob_id=?1 AND local_key=?3 AND import_source_site IS NOT NULL",
            )?
            .query_row(
                rusqlite::params![blob, identity.path().local_key(), token.local_key()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn load_binding_rows(
        &self,
        blob: i64,
        oid: Option<git2::Oid>,
    ) -> Result<Option<brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>>>
    {
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(rows) = self.binding_rows.borrow().get(&blob) {
            return Ok(Some(rows.clone()));
        }
        let Some(rows) = PythonBindingRows::load(
            self.ready.inventory.connection(),
            &self.ready.store.cache_budget,
            blob,
            oid,
            self.cancellation,
        )?
        else {
            return Ok(None);
        };
        if self.cancellation.is_cancelled() {
            return Ok(None);
        }
        // Suspended halves and qualified inputs retain rows after the memo borrow ends.
        assert!(
            self.binding_rows
                .borrow_mut()
                .insert(blob, rows.clone())
                .is_none()
        );
        Ok(Some(rows))
    }

    fn module_bindings(&self, container: &str) -> Result<Read<Option<PythonModuleBindings>>> {
        let selected = self.ready.inventory.connection().prepare_cached(
            "SELECT mounted.mount_ordinal,mounted.blob_id FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             JOIN selected_resolution_mounts mounted ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
             WHERE provider.summary_id=?1 AND provider.container_path=?2 AND provider.state IN ('selected','alternative')",
        )?.query_row(
            rusqlite::params![self.summary,container],|row|Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?)),
        ).optional()?;
        let Some((mount, blob)) = selected else {
            return Ok(Read::ready(None));
        };
        let rows = self.load_binding_rows(blob, None)?;
        Ok(Read::ready(rows.map(|rows| (mount, blob, rows))))
    }

    fn read_reference_inputs(&self, reference: SemanticId) -> Result<Read<PythonReferenceInputs>> {
        let ordinal = reference
            .ordinal()
            .expect("authored Python reference mount");
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let blob = mount.blob_id();
        let lookup = format!(
            "{} AND NOT EXISTS(SELECT 1 FROM resolution_qualified_routes qualified WHERE qualified.blob_id=?1 AND qualified.reference=?2)",
            crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL
        );
        let Some((name, site)) = self
            .ready
            .inventory
            .connection()
            .query_row(
                &lookup,
                rusqlite::params![blob, reference.local_key()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
        else {
            return Ok(Read::ready(PythonReferenceInputs::default()));
        };
        let Some(rows) = self.load_binding_rows(blob, Some(mount.blob_oid()))? else {
            return Ok(if self.cancellation.is_cancelled() {
                Read::Cancelled(cancelled_completion())
            } else {
                Read::Unavailable { reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance, completion: open(reference) }
            });
        };
        let mut import_sites = self.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT import_site FROM resolution_root_import_demands WHERE blob_id=?1 AND target_reference=?2",
        )?.query_map(rusqlite::params![blob,site],|row|row.get::<_,u32>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut deferred_module_scope = None;
        if let Some(mut state) = python_lexical::lexical_selection(
            &rows,
            site,
            &name,
            self.profile,
            PythonBindingProofs::default(),
        ) {
            python_lexical::select_lexical(
                &mut state,
                &rows,
                &mut SessionBudget {
                    session: self.session,
                    cancellation: self.cancellation,
                },
                self.cancellation,
            )?;
            if state.selection.stopped.is_some() {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            deferred_module_scope = state.deferred_module_scope;
            if import_sites.is_empty() {
                import_sites.extend(
                    rows.imports
                        .iter()
                        .filter(|import| {
                            import.binding_event.is_some_and(|event| {
                                state
                                    .selection
                                    .selected
                                    .iter()
                                    .any(|selected| selected.occurrence == event)
                            })
                        })
                        .map(|import| import.import_site.get()),
                );
            }
        }
        let mut aliases = Vec::new();
        let mut registry_roots = Vec::new();
        for site in import_sites {
            let roots = self.registry_import_roots(ordinal, site)?;
            for root in &roots {
                let Some(name) = &root.member else {
                    continue;
                };
                if self.module_has_registry(&root.container)? {
                    continue;
                }
                match self.module_import_aliases(
                    &root.container,
                    name,
                    Some(PythonModuleObservation {
                        mount: ordinal,
                        import_site: site,
                    }),
                )? {
                    Read::Ready { value, .. } => aliases.extend(value),
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                }
            }
            registry_roots.extend(roots);
        }
        aliases.sort_by(|a, b| {
            (&a.container, &a.name, a.reference).cmp(&(&b.container, &b.name, b.reference))
        });
        aliases.dedup_by(|a, b| {
            a.container == b.container && a.name == b.name && a.reference == b.reference
        });
        Ok(Read::ready(PythonReferenceInputs {
            aliases,
            deferred_module_scope,
            resolved_aliases: Vec::new(),
            registry_roots,
        }))
    }

    /// Invert module_owner for a selected prefix, preserving the selected mount.
    /// Bare names never pass through this continuation boundary.
    fn module_container(&self, location: &RouteLocation) -> Result<Option<RouteLocation>> {
        let RouteLocation::Owner { definition, .. } = location else {
            return Ok(None);
        };
        let Some(ordinal) = definition.ordinal() else {
            return Ok(None);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        if !is_module_definition(&self.ready.inventory, *definition, &self.module_sites)? {
            return Ok(None);
        }
        let containers = self.ready.inventory.connection().prepare_cached(
            "SELECT provider.container_path
             FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member
               ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             WHERE provider.summary_id=?1 AND member.blob_id=?2 AND member.rel_path=?3
               AND provider.state IN ('selected','alternative') AND provider.kind IN ('module','package') LIMIT 2",
        )?.query_map(
            rusqlite::params![self.summary, mount.blob_id(), mount.persisted_relative_path()],
            |row| row.get::<_, String>(0),
        )?.collect::<rusqlite::Result<Vec<_>>>()?;
        // Summary production emits one provider per candidate file. The selected
        // mount fixes both blob and path, so its inverse must be unique.
        assert!(
            containers.len() <= 1,
            "one provider per candidate file: {containers:?}"
        );
        let container = containers.into_iter().next();
        Ok(container.map(|container| RouteLocation::Container {
            unit: self.summary,
            container,
        }))
    }

    // A namespace portion has no authored module declaration. Retain its
    // selected import binding as a query-local route to the package container.
    fn namespace_import_route(
        &self,
        prefix: SemanticId,
    ) -> Result<Option<PythonNamespaceImportRoute>> {
        let stopped = |stop| PythonNamespaceImportRoute {
            containers: Vec::new(),
            completion: match stop {
                Stop::Cancelled => cancelled_completion(),
                Stop::Budget => ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::TimeBudgetExceeded(prefix),
                ]),
            },
        };
        if self.cancellation.is_cancelled() {
            return Ok(Some(stopped(Stop::Cancelled)));
        }
        if let Some(route) = self.namespace_imports.borrow().get(&prefix) {
            return Ok(Some(route.clone()));
        }
        let Some(ordinal) = prefix.ordinal() else {
            return Ok(None);
        };
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let Some(rows) = self.load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))? else {
            return Ok(None);
        };
        let reference: Option<(u32, String)> = self.ready.inventory.connection().prepare_cached(
            "SELECT semantic.source_site,name.spelling FROM resolution_semantic_sites semantic
             JOIN resolution_reference_lookup_identities lookup ON lookup.blob_id=semantic.blob_id
               AND lookup.semantic_key=semantic.semantic_key
             JOIN resolution_identities name ON name.id=lookup.identity_id
             WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='reference'",
        )?.query_row(rusqlite::params![mount.blob_id(), prefix.local_key()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        }).optional()?;
        let Some((site, name)) = reference else {
            return Ok(None);
        };
        let Some(mut state) = python_lexical::lexical_selection(
            &rows,
            site,
            &name,
            self.profile,
            PythonBindingProofs::default(),
        ) else {
            return Ok(None);
        };
        python_lexical::select_lexical(
            &mut state,
            &rows,
            &mut SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            },
            self.cancellation,
        )?;
        if let Some(stop) = state.selection.stopped {
            return Ok(Some(stopped(stop)));
        }
        if state.selection.selected.is_empty() || !state.selection.unbound.is_empty() {
            return Ok(None);
        }
        let mut containers = Vec::new();
        let mut completion = ResolutionCompletion::Complete;
        let mut boundaries_unique = true;
        for selected in &state.selection.selected {
            let Some(event) = rows
                .events
                .iter()
                .find(|event| event.event == selected.occurrence)
                .filter(|event| event.kind == ResolutionBindingEventKind::Import)
            else {
                return Ok(None);
            };
            let Some(import) = rows.imports.iter().find(|import| import.binding_event == Some(event.event))
                .filter(|import| import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Module)
            else {
                return Ok(None);
            };
            let boundary =
                state.selected_import_boundary_is_unique(&rows, event.execution_scope, event.event);
            let dominates = python_lexical::import_dominates(
                &rows,
                import.import_site.get(),
                site,
                self.profile,
                &mut SessionBudget {
                    session: self.session,
                    cancellation: self.cancellation,
                },
            );
            if let Err(stop) = dominates {
                return Ok(Some(stopped(stop)));
            }
            if !matches!(dominates, Ok(true)) {
                return Ok(None);
            }
            boundaries_unique &= boundary;
            completion = completion.combine(&self.import_route_completion(
                mount.persisted_relative_path(),
                mount.blob_id(),
                import,
            )?);
            let roots = self.registry_import_roots(ordinal, import.import_site.get())?;
            if roots.is_empty() {
                return Ok(None);
            }
            for root in roots {
                let selected_namespace: bool = self.ready.inventory.connection().prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_providers provider
                     WHERE provider.summary_id=?1 AND provider.container_path=?2
                       AND provider.module_name=?6
                       AND provider.kind='namespace' AND provider.state IN ('selected','alternative')
                       AND EXISTS(SELECT 1 FROM python_unit_summary_imports imported
                         JOIN resolution_unit_summary_members source
                           ON source.summary_id=imported.summary_id
                            AND source.member_ordinal=imported.member_ordinal
                         JOIN python_unit_summary_providers target
                           ON target.summary_id=imported.summary_id
                            AND target.container_path=imported.target_container
                         WHERE imported.summary_id=?1 AND source.blob_id=?3
                           AND source.rel_path=?4 AND imported.import_site=?5
                           AND imported.state='activation_open'
                           AND target.root_slot=provider.root_slot
                           AND target.state IN ('selected','alternative')))",
                )?.query_row(rusqlite::params![self.summary, root.container, mount.blob_id(), mount.persisted_relative_path(), import.import_site.get(), name], |row| row.get(0))?;
                if !selected_namespace {
                    return Ok(None);
                }
                containers.push(root.container);
            }
        }
        // Selected module imports of the same top-level package are equivalent
        // writers: each retains a portion of the package's search path.
        if state.selection.selected.len() == 1 && !boundaries_unique {
            return Ok(None);
        }
        containers.sort();
        containers.dedup();
        let route = PythonNamespaceImportRoute {
            containers,
            completion,
        };
        self.namespace_imports
            .borrow_mut()
            .insert(prefix, route.clone());
        Ok(Some(route))
    }

    /// Select the target module's reaching import writers and hand their source
    /// references to the shared scheduler. This also serves bare from-imports.
    fn module_import_aliases(
        &self,
        container: &str,
        name: &str,
        observation: Option<PythonModuleObservation>,
    ) -> Result<Read<Vec<PythonImportAlias>>> {
        let mut aliases = Vec::new();
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        let (target_mount, target_blob, target_rows) = match self.module_bindings(container)? {
            Read::Ready {
                value: Some(value), ..
            } => value,
            Read::Ready { value: None, .. } => return Ok(Read::ready(Vec::new())),
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable { reason, completion });
            }
        };
        let root = target_rows
            .scopes
            .iter()
            .find(|scope| scope.parent.is_none())
            .expect("module inventory has a root");
        let mut state = if let Some(site) = self.initializing_package_import(
            container,
            observation.filter(|observation| observation.mount == target_mount),
        )? {
            python_lexical::initializing_module_selection(
                &target_rows,
                site,
                name,
                self.profile,
                PythonBindingProofs::default(),
            )
            .expect("initializing import belongs to this package's root execution")
        } else {
            python_lexical::module_selection(
                &target_rows,
                root.scope,
                name,
                self.profile,
                PythonBindingProofs::default(),
            )
        };
        python_lexical::lexical_tier(
            &mut state,
            &target_rows,
            root.scope,
            &mut SessionBudget {
                session: self.session,
                cancellation: self.cancellation,
            },
        );
        if state.selection.stopped.is_some() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        for import in target_rows.imports.iter().filter(|import| {
            import.binding_event.is_some_and(|event| {
                state
                    .selection
                    .selected
                    .iter()
                    .any(|selected| selected.occurrence == event)
            })
        }) {
            for key in self.ready.inventory.connection().prepare_cached(
                "SELECT DISTINCT semantic.semantic_key FROM resolution_root_import_demands demand
                 JOIN resolution_semantic_sites semantic ON semantic.blob_id=demand.blob_id AND semantic.source_site=demand.target_reference AND semantic.semantic_role='reference'
                 WHERE demand.blob_id=?1 AND demand.import_site=?2",
            )?.query_map(rusqlite::params![target_blob,import.import_site.get()],|row|row.get::<_,u32>(0))? {
                aliases.push(PythonImportAlias {container:container.to_owned(),name:name.to_owned(),import_site:import.import_site.get(),reference:SemanticId::local(target_mount,key?)});
            }
        }

        Ok(Read::ready(aliases))
    }

    /// Only a from-import executed by this selected package reads the package
    /// before initialization completes. Equal blobs at other paths do not count.
    fn initializing_package_import(
        &self,
        container: &str,
        observation: Option<PythonModuleObservation>,
    ) -> Result<Option<u32>> {
        let Some(observation) = observation else {
            return Ok(None);
        };
        let same_package: bool = self.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member
               ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             JOIN selected_resolution_mounts mounted
               ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
             WHERE provider.summary_id=?1 AND provider.container_path=?2
               AND provider.kind='package' AND provider.state IN ('selected','alternative')
               AND mounted.mount_ordinal=?3)")?.query_row(
            rusqlite::params![self.summary, container, observation.mount],
            |row| row.get(0),
        )?;
        if !same_package {
            return Ok(None);
        }
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(observation.mount))?;
        let Some(rows) = self.load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))? else {
            return Ok(None);
        };
        Ok(
            python_lexical::module_initialization_event(&rows, observation.import_site)
                .map(|_| observation.import_site),
        )
    }
}

impl<'a, 'store, 'input> DemandRules for PythonRules<'a, 'store, 'input> {
    fn prepare_module_imports(
        &mut self,
        frame: &RootFrame,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        provenance: crate::analyzer::resolution::HierarchyProvenanceView<'_>,
        mut resume: crate::analyzer::resolution::CloseResume<'_>,
    ) -> Result<crate::analyzer::resolution::CloseProgress<Read<()>>> {
        use crate::analyzer::resolution::{CloseProgress, CloseResume};
        if !self.module_import_inputs.contains_key(&frame.endpoint) {
            if !self.module_registries_started(&frame.endpoint) {
                assert!(matches!(resume, CloseResume::Start));
                let mut requests = Vec::new();
                for half in &frame.halves {
                    let SelectedRootPathHalf::Reference { identity, .. } = half else {
                        continue;
                    };
                    if let Some(prepared) = self.reference_inputs.borrow().get(identity) {
                        requests.extend(
                            prepared
                                .registry_roots
                                .iter()
                                .cloned()
                                .map(|root| (*identity, root)),
                        );
                    }
                    let SelectedRootPathHalf::Reference {
                        prefix_reference: Some(prefix),
                        ..
                    } = half
                    else {
                        continue;
                    };
                    let answer = inputs
                        .iter()
                        .find(|(key, _)| key.reference == *prefix)
                        .expect("the shared scheduler supplies the selected qualifier")
                        .1;
                    let reference = self.prepared_references.borrow()[identity];
                    let mount = self.ready.inventory.mount_record_by_ordinal(
                        SelectedResolutionMountOrdinal::new(
                            reference.ordinal().expect("source reference mount"),
                        ),
                    )?;
                    const MODULE_MEMBER_NAME_SQL: &str = "SELECT name.spelling
                    FROM resolution_semantic_sites site
                    JOIN resolution_reference_lookup_identities lookup
                      ON lookup.blob_id=site.blob_id AND lookup.semantic_key=site.semantic_key
                    JOIN resolution_identities name ON name.id=lookup.identity_id
                    WHERE site.blob_id=?1 AND site.semantic_key=?2 AND site.semantic_role='reference'";
                    let name: String = self
                        .ready
                        .inventory
                        .connection()
                        .prepare_cached(MODULE_MEMBER_NAME_SQL)?
                        .query_row(
                            rusqlite::params![mount.blob_id(), reference.local_key()],
                            |row| row.get(0),
                        )?;
                    for &definition in answer.binding().targets() {
                        let Some(RouteLocation::Container { container, .. }) = self
                            .module_container(&RouteLocation::Owner {
                                definition,
                                scope: None,
                            })?
                        else {
                            continue;
                        };
                        let import_site = if definition.ordinal() == reference.ordinal() {
                            self.source_import_site(mount.blob_id(), *identity, reference)?
                        } else {
                            None
                        };
                        requests.push((
                            *identity,
                            module_registry::ImportRoot {
                                container,
                                member: Some(name.clone()),
                                observation: import_site.map(|import_site| {
                                    PythonModuleObservation {
                                        mount: reference.ordinal().expect("source reference mount"),
                                        import_site,
                                    }
                                }),
                            },
                        ));
                    }
                }
                self.begin_module_registries(&frame.endpoint, requests);
            }
            let requests = match self.poll_module_registries(&frame.endpoint, provenance, resume)? {
                CloseProgress::Ready(requests) => requests,
                CloseProgress::Reference {
                    continuation,
                    key,
                    completion,
                } => {
                    return Ok(CloseProgress::Reference {
                        continuation,
                        key,
                        completion,
                    });
                }
                CloseProgress::Cancelled(completion) => {
                    return Ok(CloseProgress::Cancelled(completion));
                }
                CloseProgress::Members { .. } => {
                    unreachable!("module registries request reference answers")
                }
            };
            let mut aliases = Vec::new();
            for (identity, request) in requests {
                let Some(name) = request.member else {
                    continue;
                };
                let (container, completion) = self.imported_module_view(&request.container)?;
                if completion != ResolutionCompletion::Complete {
                    continue;
                }
                let aliases_prepared = container == request.container
                    && !self.module_has_registry(&container)?
                    && self
                        .reference_inputs
                        .borrow()
                        .get(&identity)
                        .is_some_and(|prepared| {
                            prepared.registry_roots.iter().any(|root| {
                                root.container == container
                                    && root.member.as_deref() == Some(name.as_str())
                            })
                        });
                if aliases_prepared {
                    continue;
                }
                match self.module_import_aliases(&container, &name, request.observation)? {
                    Read::Ready { value, .. } => {
                        aliases.extend(value.into_iter().map(|alias| (identity, alias)))
                    }
                    Read::Cancelled(completion) => {
                        return Ok(CloseProgress::Cancelled(completion));
                    }
                    Read::Unavailable { reason, completion } => {
                        return Ok(CloseProgress::Ready(Read::Unavailable {
                            reason,
                            completion,
                        }));
                    }
                }
            }
            let references = super::member_access::QualifiedReferenceInputs::new(
                aliases.iter().map(|(_, alias)| DemandReferenceKey {
                    reference: alias.reference,
                    environment: CALLER_ENVIRONMENT,
                }),
            );
            self.module_import_inputs.insert(
                frame.endpoint.clone(),
                PythonModuleImportInputs {
                    aliases,
                    references,
                    ready: false,
                },
            );
            resume = CloseResume::Start;
        }
        let mut prepared = self
            .module_import_inputs
            .remove(&frame.endpoint)
            .expect("prepared module imports");
        let progress = if prepared.ready {
            CloseProgress::Ready(())
        } else {
            prepared
                .references
                .poll(provenance, resume, self.session, self.cancellation)?
        };
        if matches!(progress, CloseProgress::Ready(())) && !prepared.ready {
            for (identity, alias) in &prepared.aliases {
                let answer = prepared
                    .references
                    .answers()
                    .find(|(key, _)| key.reference == alias.reference)
                    .expect("selected import prerequisite settled")
                    .1
                    .binding();
                self.reference_inputs
                    .borrow_mut()
                    .get_mut(identity)
                    .expect("prepared reference inputs")
                    .resolved_aliases
                    .push(PythonAliasTargets {
                        container: alias.container.clone(),
                        name: alias.name.clone(),
                        import_site: alias.import_site,
                        external_imports: selected_external_imports(
                            self.external_imports,
                            alias.reference,
                        ),
                        targets: answer.targets().to_vec(),
                        completion: answer.completion().clone(),
                    });
            }
            prepared.ready = true;
        }
        self.module_import_inputs
            .insert(frame.endpoint.clone(), prepared);
        Ok(progress.map(|()| Read::ready(())))
    }

    fn qualified_members(&mut self) -> Option<QualifiedMembers<'_>> {
        Some(QualifiedMembers(self))
    }

    type Placement = PythonPlacement;
    type Target = PythonTarget;
    type Member = ();
    type Provider = ();
    type MemberRow = super::python_members::PythonMemberRow;
    type PlacementObservations = CollectedPlacementObservations;
    type Rank = PythonRank;
    type Half<'b>
        = PythonHalf<'b, 'store, 'input>
    where
        Self: 'b;
    type PreparationKey = ();
    type Certificate = ();

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        retained_completion: Option<&ResolutionCompletion>,
    ) -> Result<Read<EndpointAdmission>> {
        if let Some(completion) = retained_completion {
            return Ok(Read::ready(EndpointAdmission::Ready(completion.clone())));
        }
        if endpoint.node() != BindingNodeId::universal_root()
            && endpoint.symbols().fixed().is_empty()
        {
            return Ok(Read::ready(EndpointAdmission::Ready(
                ResolutionCompletion::Complete,
            )));
        }
        if endpoint.node() != BindingNodeId::universal_root() {
            let completion = endpoint
                .symbols()
                .fixed()
                .first()
                .map_or(ResolutionCompletion::Complete, |symbol| {
                    open(symbol.symbol())
                });
            return Ok(Read::ready(EndpointAdmission::Context(
                Admission::BaseOwned {
                    completion,
                    base: BaseEligibility::Exclude,
                },
            )));
        }
        let selected = self
            .arena
            .borrow()
            .selected_universe_continuation_completion(endpoint);
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        if let Some(completion) = selected {
            return Ok(Read::ready(EndpointAdmission::Context(
                Admission::BaseOwned {
                    completion,
                    base: BaseEligibility::Exclude,
                },
            )));
        }
        Ok(Read::ready(EndpointAdmission::Discover))
    }
    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        source: Option<super::source_demand::SourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        completion: ResolutionCompletion,
    ) -> Result<Read<Admission>> {
        let Some(source) = source else {
            return Ok(Read::Unavailable {
                reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance,
                completion,
            });
        };
        let mut frame = RootFrame::positioned(endpoint, source, halves);
        let requesting =
            self.ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(
                    source.fragment.ordinal(),
                ))?;
        for obligation in self.selected_query_obligations.iter().filter(|obligation| {
            obligation.kind == "python_unknown_placement"
                && obligation.subject == requesting.persisted_relative_path()
        }) {
            frame.query_obligations.insert(obligation.clone());
        }
        frame.context = Some(ContextId(0));
        frame.completion = completion;
        Ok(Read::ready(Admission::SourceOwned(frame)))
    }
    fn derive_context(
        &mut self,
        key: ContextId,
        _: &RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        assert_eq!(key, ContextId(0));
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(Read::Cancelled(cancelled_completion()));
        }
        Ok(Read::ready(None))
    }
    fn resolve_prefix_operands(
        &mut self,
        frame: &mut RootFrame,
        _: Option<&SelectedResolutionContextSet>,
    ) -> Result<Read<Vec<ResolvedPrefixOperand>>> {
        for half in &frame.halves {
            let SelectedRootPathHalf::Reference {
                identity,
                source_reference,
                ..
            } = half
            else {
                continue;
            };
            let cached = self.prepared_references.borrow().get(identity).copied();
            let reference = if let Some(reference) = cached {
                reference
            } else {
                if self.cancellation.is_cancelled() || !self.session.scope_step() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                // The route token names a root continuation. Its source node
                // supplies the canonical reference used by typed input rows.
                let classified = self
                    .ready
                    .lexical_source()
                    .classify_endpoint_nodes(&[*source_reference], self.cancellation)?;
                if self.cancellation.is_cancelled() {
                    return Ok(Read::Cancelled(cancelled_completion()));
                }
                let [classification] = classified.as_slice() else {
                    panic!("one selected source node has one classification: {classified:?}");
                };
                assert_eq!(classification.node(), *source_reference);
                let reference = classification
                    .reference()
                    .expect("a source-reference half starts at a reference node");
                assert!(
                    self.prepared_references
                        .borrow_mut()
                        .insert(*identity, reference)
                        .is_none()
                );
                reference
            };
            let mount = self.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(
                    reference.ordinal().expect("source reference mount"),
                ),
            )?;
            for obligation in self.selected_query_obligations.iter().filter(|obligation| {
                obligation.kind == "python_unknown_placement"
                    && obligation.subject == mount.persisted_relative_path()
            }) {
                frame.query_obligations.insert(obligation.clone());
            }
            if !self.universe_mutations.borrow().contains_key(identity) {
                let ordinal = reference.ordinal().expect("source reference mount");
                let mount = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                let spelling: Option<(String, u32)> = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
                    )?
                    .query_row(
                        rusqlite::params![mount.blob_id(), reference.local_key()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let read = if let Some((spelling, site)) = spelling.filter(|(spelling, _)| {
                    brokk_bifrost_python::intrinsics::builtin(spelling).is_some()
                }) {
                    let Some(rows) =
                        self.load_binding_rows(mount.blob_id(), Some(mount.blob_oid()))?
                    else {
                        return Ok(if self.cancellation.is_cancelled() {
                            Read::Cancelled(cancelled_completion())
                        } else {
                            Read::Unavailable {
                                reason: crate::analyzer::resolution::DemandRootUnavailableReason::MissingSourceProvenance,
                                completion: open(reference),
                            }
                        });
                    };
                    // Builtins-module effects cannot replace a lexical binding.
                    // Use the existing shared lexical selector before installing
                    // universe-only waits: an unanswered receiver must never
                    // prevent that binding from being selected at all (#6384).
                    let mut lexical = python_lexical::lexical_selection(
                        &rows,
                        site,
                        &spelling,
                        self.profile,
                        PythonBindingProofs::default(),
                    );
                    if let Some(state) = &mut lexical {
                        python_lexical::select_lexical(
                            state,
                            &rows,
                            &mut SessionBudget {
                                session: self.session,
                                cancellation: self.cancellation,
                            },
                            self.cancellation,
                        )?;
                    }
                    if lexical
                        .as_ref()
                        .is_some_and(|state| !state.selection.selected.is_empty())
                    {
                        self.observations.borrow_mut().push(format!(
                            "universe lexical-hit name={spelling:?} retained=true"
                        ));
                        Read::ready(Vec::new())
                    } else {
                        super::python_members::operations::universe_rows(
                            self, reference, &spelling,
                        )?
                    }
                } else {
                    Read::ready(Vec::new())
                };
                match read {
                    Read::Ready { value, completion } => {
                        self.universe_mutations.borrow_mut().insert(
                            *identity,
                            UniverseMutationInputs {
                                operations: value,
                                completion,
                            },
                        );
                    }
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                }
            }
            if !self.reference_inputs.borrow().contains_key(identity) {
                let reference_inputs = match self.read_reference_inputs(reference)? {
                    Read::Ready { value, .. } => value,
                    Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                    Read::Unavailable { reason, completion } => {
                        return Ok(Read::Unavailable { reason, completion });
                    }
                };
                self.reference_inputs
                    .borrow_mut()
                    .insert(*identity, reference_inputs);
            }
        }
        for half in &frame.halves {
            let (identity, token) = match half {
                SelectedRootPathHalf::Reference {
                    identity, token, ..
                }
                | SelectedRootPathHalf::Import {
                    identity, token, ..
                } => (*identity, *token),
                SelectedRootPathHalf::Export { .. } => continue,
            };
            if self.module_mutations.borrow().contains_key(&identity) {
                continue;
            }
            let mount = SelectedMountTable::new(&self.ready.inventory)
                .mount_for_fragment(identity.fragment())?
                .expect("a source half belongs to its selected mount");
            let blob = self
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())?
                .blob_id();
            let needs_attributes = match half {
                SelectedRootPathHalf::Import { .. } => {
                    if let Some(site) = self.source_import_site(blob, identity, token)? {
                        self.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports
                             WHERE summary_id=?1 AND import_site=?2 AND form IN ('from','star')
                             AND member_ordinal IN (SELECT member_ordinal FROM resolution_unit_summary_members
                              WHERE summary_id=?1 AND blob_id=?3))")?.query_row(
                            rusqlite::params![self.summary, site, blob], |row| row.get(0),
                        )?
                    } else {
                        false
                    }
                }
                SelectedRootPathHalf::Reference { .. } => {
                    let reference = *self
                        .prepared_references
                        .borrow()
                        .get(&identity)
                        .expect("reference preparation precedes attribute prerequisites");
                    self.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM resolution_qualified_routes
                         WHERE blob_id=?1 AND reference=(SELECT source_site FROM resolution_semantic_sites
                          WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'))")?.query_row(
                        rusqlite::params![blob, reference.local_key()], |row| row.get::<_, bool>(0),
                    )? || self.reference_inputs.borrow().get(&identity)
                        .is_some_and(|inputs| inputs.deferred_module_scope.is_some())
                }
                SelectedRootPathHalf::Export { .. } => unreachable!(),
            };
            let deferred = self
                .reference_inputs
                .borrow()
                .get(&identity)
                .is_some_and(|inputs| inputs.deferred_module_scope.is_some());
            let read = if deferred {
                let scan_cpu = crate::profiling::enabled().then(crate::profiling::thread_cpu_time);
                let scan_sql = brokk_bifrost_core::cache_db::sql_profile::totals_with_rows();
                let reference = self.prepared_references.borrow()[&identity];
                let name: String = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        crate::analyzer::store::python_member_rows::UNIVERSE_REFERENCE_NAME_SQL,
                    )?
                    .query_row(rusqlite::params![blob, reference.local_key()], |row| {
                        row.get(0)
                    })?;
                let key = (self.summary, blob);
                let containers = if let Some(rows) = self
                    .deferred_provider_containers
                    .borrow()
                    .get(&key)
                    .cloned()
                {
                    rows
                } else {
                    let rows = self.ready.inventory.connection().prepare_cached(
                    "SELECT provider.container_path FROM python_unit_summary_providers provider
                     JOIN resolution_unit_summary_members member ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
                     WHERE provider.summary_id=?1 AND member.blob_id=?2 AND provider.state IN ('selected','alternative')"
                )?.query_map(rusqlite::params![self.summary,blob], |row| row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    let rows = std::sync::Arc::new(rows);
                    if !self.cancellation.is_cancelled() {
                        self.deferred_provider_containers
                            .borrow_mut()
                            .insert(key, std::sync::Arc::clone(&rows));
                    }
                    rows
                };
                let (candidates, selected) =
                    self.mutations.module_mutation_counts(&containers, &name)?;
                self.observations.borrow_mut().push(format!("deferred module mutation scan name={name:?} candidates={candidates} structural={selected}"));
                if let Some(start) = scan_cpu {
                    let sql = scan_sql
                        .zip(brokk_bifrost_core::cache_db::sql_profile::totals_with_rows())
                        .map(|(before, after)| after.0 - before.0);
                    crate::profiling::note_with(|| {
                        format!(
                            "resolution::python_deferred_module_mutation_scan reference={reference:?} name={name:?} cpu_ns={} sql={sql:?} candidates={candidates} structural={selected}",
                            (crate::profiling::thread_cpu_time() - start).as_nanos(),
                        )
                    });
                }
                self.deferred_mutations.borrow_mut().insert(identity, (0..selected).map(|_| super::python_members::operations::ModuleMutation::structurally_selected()).collect());
                Read::ready(Vec::new())
            } else if needs_attributes {
                if let Some(site) = self.source_import_site(blob, identity, token)? {
                    super::python_members::operations::import_rows(self, blob, site)?
                } else {
                    // Qualified receivers are closed at their selected member
                    // space; no environment-wide receiver tasks belong here.
                    Read::ready(Vec::new())
                }
            } else {
                Read::ready(Vec::new())
            };
            match read {
                Read::Ready { value, completion } => {
                    if needs_attributes {
                        self.observations.borrow_mut().push(format!(
                            "module mutation prerequisites half={} operations={}",
                            if matches!(half, SelectedRootPathHalf::Import { .. }) {
                                "import"
                            } else {
                                "reference"
                            },
                            value.len(),
                        ));
                    }
                    self.module_mutations.borrow_mut().insert(
                        identity,
                        UniverseMutationInputs {
                            operations: value,
                            completion,
                        },
                    );
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            }
        }
        Ok(Read::ready(Vec::new()))
    }
    fn prefix_operands(&self, frame: &RootFrame, caller: EnvironmentId) -> Vec<PrefixOperand> {
        let mut operands = default_prefix_operands(frame, caller);
        for (index, half) in frame.halves.iter().enumerate() {
            let identity = match half {
                SelectedRootPathHalf::Reference { identity, .. }
                | SelectedRootPathHalf::Import { identity, .. } => identity,
                SelectedRootPathHalf::Export { .. } => continue,
            };
            if let Some(mutations) = self.module_mutations.borrow().get(identity) {
                operands.extend(
                    mutations
                        .operations
                        .iter()
                        .flat_map(|operation| operation.universe_prerequisites())
                        .map(|reference| PrefixOperand {
                            key: DemandReferenceKey {
                                reference,
                                environment: caller,
                            },
                            source_halves: Box::new([HalfId(index)]),
                        }),
                );
            }
            let SelectedRootPathHalf::Reference {
                identity,
                prefix_reference,
                ..
            } = half
            else {
                continue;
            };
            if let Some(source) = prefix_reference
                .and_then(|reference| self.module_aliases.borrow().get(&reference).copied())
            {
                operands.push(PrefixOperand {
                    key: DemandReferenceKey {
                        reference: source,
                        environment: caller,
                    },
                    source_halves: Box::new([HalfId(index)]),
                });
            }
            if let Some(inputs) = self.reference_inputs.borrow().get(identity) {
                operands.extend(inputs.aliases.iter().map(|alias| PrefixOperand {
                    key: DemandReferenceKey {
                        reference: alias.reference,
                        environment: caller,
                    },
                    source_halves: Box::new([HalfId(index)]),
                }));
            }
            if let Some(mutations) = self.universe_mutations.borrow().get(identity) {
                operands.extend(
                    mutations
                        .operations
                        .iter()
                        .flat_map(|operation| operation.universe_prerequisites())
                        .map(|reference| PrefixOperand {
                            key: DemandReferenceKey {
                                reference,
                                environment: caller,
                            },
                            source_halves: Box::new([HalfId(index)]),
                        }),
                );
            }
        }
        operands
    }
    fn admit_candidate(
        &self,
        frame: &RootFrame,
        cursor: &RouteCursor,
        _: &ExportCandidate,
    ) -> CandidateDecision {
        self.activation(frame, cursor.half)
    }
    fn half_rows<'b>(
        &'b self,
        source: &'b SourceHalf,
        frame: &'b RootFrame,
        _: &'b crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        _: &'b dyn HalfSource,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<HalfRowsOutcome<Self::Half<'b>>> {
        if self.cancellation.is_cancelled() {
            return Ok(HalfRowsOutcome::Stopped);
        }
        if let Some(inputs) = self.source_inputs.borrow().get(&source.identity) {
            return Ok(HalfRowsOutcome::Rows(inputs.view(
                self,
                source,
                frame.completion.clone(),
            )));
        }
        // A rebuilt source half replaces its prior selection. Other halves of
        // the same reference keep their alternatives until they are rebuilt.
        if let Some(imports) = self
            .external_imports
            .borrow_mut()
            .selections
            .get_mut(&self.reference_for_source(source))
        {
            imports.remove(&PythonExternalSelectionSource::Root(source.identity));
        }
        let Some(mount) = SelectedMountTable::new(&self.ready.inventory)
            .mount_for_fragment(source.identity.fragment())?
        else {
            // #7314: planned halves come from selected mount and stage rows;
            // the rebaser accepts every selected ordinal. A missing mount
            // therefore violates the selected store contract.
            return Err(StoreError::corrupt(format!(
                "planned Python half fragment {:?} has no selected mount",
                source.identity.fragment()
            )));
        };
        let mount_record = self
            .ready
            .inventory
            .mount_record_by_ordinal(mount.ordinal())?;
        debug_assert_eq!(mount_record.storage_language(), "python");
        let blob = mount_record.blob_id();
        let placement_key = super::placement_access::PlacementKey {
            language: Language::Python,
            unit_digest: self.placement_unit,
            // UNIQUE(storage_language, persisted_relative_path) on
            // temp.selected_resolution_mounts gives each Python path one ordinal.
            subject: super::placement_access::PlacementSubject {
                blob: Some(blob),
                path: Some(mount.ordinal().get() as usize),
                file_version: None,
            },
            declaration: None,
        };
        let placements: Vec<PythonPlacement> = super::placement_access::read_placements(
            &self.ready.inventory,
            &placement_key,
            super::placement_access::PlacementRead {
                sql: PYTHON_HALF_PLACEMENTS,
                bind: |key: &super::placement_access::PlacementKey| {
                    let ordinal = key
                        .subject
                        .path
                        .expect("Python placement key has a mount ordinal");
                    vec![
                        self.summary.into(),
                        i64::try_from(ordinal)
                            .expect("Python mount ordinal fits SQLite integer")
                            .into(),
                    ]
                },
                decode: |row: &rusqlite::Row<'_>| Ok(row.get::<_, String>(0)?),
            },
            Some(&mut self.placements.borrow_mut()),
        )?
        .into_iter()
        .map(|container| PythonPlacement {
            container,
            universe: std::cell::Cell::new(None),
            lexical: RefCell::new(None),
            stars: RefCell::new(HashMap::default()),
        })
        .collect();
        let reference_site = self.ready.inventory.connection().prepare_cached("SELECT reference_source_site FROM resolution_root_route_segments WHERE blob_id=?1 AND path_key=?2 AND reference_source_site IS NOT NULL
             UNION SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?3 AND semantic_role='reference'")?.query_row(
            rusqlite::params![blob, source.identity.path().local_key(), source.token.local_key()], |row| row.get(0),
        ).optional()?;
        // Module operands resolve their recorded module prefix, never the
        // imported member selector. The PK read lives only in this request.
        let operand = if source.is_import {
            None
        } else if let Some(reference_site) = reference_site {
            self.ready
                .inventory
                .connection()
                .prepare_cached(
                    crate::analyzer::store::python_binding_rows::IMPORT_MODULE_OPERAND_SQL,
                )?
                .query_row(rusqlite::params![blob, reference_site], |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                })
                .optional()?
        } else {
            None
        };
        if let Some((_, prefix_len, module_segments)) = operand
            && (prefix_len == 0 || prefix_len > module_segments)
        {
            return Err(StoreError::corrupt(format!(
                "invalid Python import module operand: {operand:?}"
            )));
        }
        let import_site = match operand {
            Some((site, _, _)) => Some(site),
            None => self.source_import_site(blob, source.identity, source.token)?,
        };
        let import_module_operand =
            operand.map(|(_, prefix_len, module_segments)| (module_segments, prefix_len));
        let import_name = match import_site.filter(|_| import_module_operand.is_none()) {
            Some(site) => self.ready.inventory.connection().prepare_cached("SELECT source_name FROM main.resolution_import_selectors WHERE blob_id=?1 AND site=?2")?.query_row(
                rusqlite::params![blob, site],
                |row| row.get::<_, Option<String>>(0),
            ).optional()?.flatten(),
            None => None,
        };
        if let Some(site) = import_site.filter(|_| import_module_operand.is_none())
            && let Some(boundary) =
                self.external_import_boundary(source.identity.fragment(), site)?
        {
            self.retain_external_imports(
                source,
                vec![PythonSelectedExternalImport {
                    consumed_prefix: boundary.bound_name.iter().cloned().collect(),
                    remaining_member_path: Vec::new(),
                    completion: boundary.completion.clone(),
                    identity_is_unique: true,
                    boundary_is_unique: true,
                    selection: Vec::new(),
                    boundary,
                }],
            );
        }
        if let Some(prefix) = source.prefix {
            let inherited = selected_external_imports(self.external_imports, prefix);
            let inherited = inherited
                .into_iter()
                .map(|mut selected| {
                    selected.remaining_member_path.extend(
                        source
                            .route
                            .iter()
                            .chain(std::iter::once(&source.demand))
                            .map(|part| part.spelling().to_owned()),
                    );
                    selected
                })
                .collect();
            self.retain_external_imports(source, inherited);
        }
        let Some(rows) = self.load_binding_rows(blob, Some(mount_record.blob_oid()))? else {
            if self.cancellation.is_cancelled() {
                return Ok(HalfRowsOutcome::Stopped);
            }
            let format = self
                .ready
                .inventory
                .connection()
                .prepare_cached(PYTHON_BINDING_SOURCE_FORMAT)?
                .query_row([blob], |row| row.get::<_, i64>(0))
                .optional()?;
            let (label, evidence) = match format {
                Some(format)
                    if format
                        != crate::analyzer::store::python_binding_rows::NATIVE_SOURCE_FORMAT =>
                {
                    (
                        "python_binding_format_stale",
                        format!("native binding source format {format} is stale"),
                    )
                }
                _ => (
                    "python_binding_rows_missing",
                    format!("native binding rows are unavailable for blob {blob}"),
                ),
            };
            return Ok(HalfRowsOutcome::Rows(PythonHalf::open(
                self,
                source,
                frame.completion.clone(),
                label,
                &evidence,
            )));
        };
        let prefix = source.prefix.map(|prefix| {
            let answer = inputs
                .iter()
                .find(|(key, _)| key.reference == prefix)
                .expect("the shared prefix scheduler supplies the selected operand")
                .1;
            let Some(alias) = self.module_aliases.borrow().get(&prefix).copied() else {
                return std::rc::Rc::new(answer.binding().clone());
            };
            // A one-hop module alias routes through the modules its source
            // names. The alias cell's own answer still limits completeness.
            let module = inputs
                .iter()
                .find(|(key, _)| key.reference == alias)
                .expect("the shared prefix scheduler supplies the alias source")
                .1
                .binding();
            std::rc::Rc::new(ResolutionAnswer::new(
                module.targets().to_vec(),
                Vec::new(),
                answer.binding().completion().combine(module.completion()),
            ))
        });
        let mut universe_unmutated = false;
        if let Some(mutations) = self.universe_mutations.borrow().get(&source.identity) {
            universe_unmutated = mutations.completion == ResolutionCompletion::Complete;
            for operation in &mutations.operations {
                match super::python_members::operations::prove(self, operation, inputs)? {
                    super::python_members::operations::OperationProof::NoEffect => {}
                    super::python_members::operations::OperationProof::Reference(_)
                    | super::python_members::operations::OperationProof::Instance(_)
                    | super::python_members::operations::OperationProof::Possible { .. } => {
                        universe_unmutated = false;
                        super::python_members::operations::receipt(self, operation, false)?;
                    }
                }
            }
            self.observations.borrow_mut().push(format!(
                "universe inventory unmutated={universe_unmutated} operations={}",
                mutations.operations.len()
            ));
        }
        if universe_unmutated
            && brokk_bifrost_python::intrinsics::builtin(source.demand.spelling()).is_some()
        {
            let origin=crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedRoute));
            universe_unmutated = if let Some(site) = reference_site {
                let owner: Option<u32> = self.ready.inventory.connection().prepare_cached("SELECT definition.semantic_key FROM python_member_sites site
                     JOIN resolution_node_catalog node ON node.blob_id=site.blob_id AND node.source_scope=site.scope
                     JOIN resolution_member_scope_properties scope ON scope.blob_id=node.blob_id AND scope.scope_head_node_key=node.local_key AND scope.scope_kind='type_body'
                     JOIN resolution_semantic_sites definition ON definition.blob_id=scope.blob_id AND definition.semantic_key=scope.definition_semantic_key AND definition.semantic_role='definition'
                     WHERE site.blob_id=?1 AND site.site=?2 LIMIT 1")?.query_row(
                    rusqlite::params![blob,site], |row| row.get(0),
                ).optional()?;
                let ordinary_owner = owner.filter(|owner| {
                    self.ordinary_keyword_namespaces
                        .borrow()
                        .contains(&SemanticId::local(
                            source.identity.fragment().ordinal(),
                            *owner,
                        ))
                });
                self.ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        crate::analyzer::store::python_member_rows::BUILTIN_NAMESPACE_CLOSED_SQL,
                    )?
                    .query_row(
                        rusqlite::params![blob, site, origin, ordinary_owner],
                        |row| row.get(0),
                    )?
            } else {
                false
            };
            self.observations.borrow_mut().push(format!(
                "universe lexical-namespace closed={universe_unmutated} statements=1"
            ));
        }
        let mut activation_reasons = Vec::new();
        let import_aliases: std::rc::Rc<[PythonAliasTargets]> = self
            .reference_inputs
            .borrow()
            .get(&source.identity)
            .into_iter()
            .flat_map(|inputs| inputs.aliases.iter())
            .map(|alias| {
                let answer = inputs
                    .iter()
                    .find(|(key, _)| key.reference == alias.reference)
                    .map(|(_, answer)| *answer);
                if answer.is_some_and(|answer| answer.binding().targets().len() == 1) {
                    activation_reasons
                        .extend(self.alias_import_activation_reasons(alias.reference)?);
                }
                Ok(PythonAliasTargets {
                    container: alias.container.clone(),
                    name: alias.name.clone(),
                    import_site: alias.import_site,
                    external_imports: selected_external_imports(
                        self.external_imports,
                        alias.reference,
                    ),
                    targets: answer
                        .map_or_else(Vec::new, |answer| answer.binding().targets().to_vec()),
                    completion: answer.map_or_else(
                        || open(alias.reference),
                        |answer| answer.binding().completion().clone(),
                    ),
                })
            })
            .collect::<Result<Vec<_>>>()?
            .into();
        let import_aliases: std::rc::Rc<[PythonAliasTargets]> = import_aliases
            .iter()
            .cloned()
            .chain(
                self.reference_inputs
                    .borrow()
                    .get(&source.identity)
                    .into_iter()
                    .flat_map(|inputs| inputs.resolved_aliases.iter().cloned()),
            )
            .collect::<Vec<_>>()
            .into();
        let mut module_mutations = self
            .module_mutations
            .borrow()
            .get(&source.identity)
            .into_iter()
            .flat_map(|mutations| mutations.operations.iter())
            .filter_map(|operation| operation.module_receiver(self, inputs).transpose())
            .collect::<Result<Vec<_>>>()?;
        if let Some(mutations) = self
            .deferred_mutations
            .borrow_mut()
            .remove(&source.identity)
        {
            module_mutations.extend(mutations);
        }
        let endpoint_completion = match import_site {
            Some(site) => self.import_route_completion(
                mount_record.persisted_relative_path(),
                blob,
                rows.imports
                    .iter()
                    .find(|import| import.import_site.get() == site)
                    .expect("selected import has retained source metadata"),
            )?,
            None => ResolutionCompletion::Complete,
        };
        let conditional_imports =
            self.conditional_imports(&rows, mount_record.persisted_relative_path(), blob)?;
        if let Some(site) = import_site.filter(|site| conditional_imports.contains(site)) {
            activation_reasons.extend(self.import_activation_reasons(
                blob,
                mount.ordinal().get(),
                site,
            )?);
        }
        let prepared = PythonHalfInputs {
            requesting_path: mount.persisted_relative_path().to_owned(),
            query_obligations: std::rc::Rc::new(RefCell::new(NodeQueryObligations::empty())),
            conditional_imports,
            activation_reasons,
            endpoint_completion,
            containers: placements
                .into_iter()
                .map(|placement| placement.container)
                .collect(),
            import_site,
            import_name,
            import_module_operand,
            rows,
            fragment: mount.fragment(),
            blob,
            reference_site,
            deferred_module_scope: self
                .reference_inputs
                .borrow()
                .get(&source.identity)
                .and_then(|inputs| inputs.deferred_module_scope),
            prefix,
            universe_unmutated,
            import_aliases,
            module_mutations: module_mutations.into(),
            rendered_order: std::rc::Rc::new(std::cell::Cell::new(false)),
        };
        let view = prepared.view(self, source, frame.completion.clone());
        assert!(
            self.source_inputs
                .borrow_mut()
                .insert(source.identity, prepared)
                .is_none()
        );
        Ok(HalfRowsOutcome::Rows(view))
    }
    fn activation(&self, frame: &RootFrame, half: HalfId) -> CandidateDecision {
        match &frame.halves[half.0] {
            SelectedRootPathHalf::Import {
                identity, token, ..
            } => {
                let inputs = self.source_inputs.borrow();
                let prepared = inputs
                    .get(identity)
                    .expect("source rows precede candidate admission");
                if prepared
                    .import_site
                    .is_some_and(|site| prepared.conditional_imports.contains(&site))
                {
                    CandidateDecision::Open(prepared.endpoint_completion.clone())
                } else {
                    CandidateDecision::Open(prepared.endpoint_completion.combine(&open(*token)))
                }
            }
            SelectedRootPathHalf::Reference { .. } => {
                CandidateDecision::Open(frame.completion.clone())
            }
            _ => unreachable!("source admission contains source halves"),
        }
    }
    fn closure_policy(
        &self,
        frame: &RootFrame,
        facts: &ClosureFacts<'_>,
    ) -> Result<Read<ClosurePolicy>> {
        let mut activation_reasons = Vec::new();
        let mut query_obligations = frame.query_obligations.clone();
        if let Some(module) = self.module_import_inputs.get(&frame.endpoint) {
            module
                .references
                .record_query_obligations(&mut query_obligations);
        }
        // Binding rows survive publication: selection changes cannot alter a blob's facts.
        for half in &frame.halves {
            match half {
                SelectedRootPathHalf::Reference { identity, .. }
                | SelectedRootPathHalf::Import { identity, .. } => {
                    if let Some(prepared) = self.source_inputs.borrow_mut().remove(identity) {
                        query_obligations.union(&prepared.query_obligations.borrow().published());
                        activation_reasons.extend(prepared.activation_reasons);
                    }
                    self.prepared_references.borrow_mut().remove(identity);
                    self.universe_mutations.borrow_mut().remove(identity);
                    self.module_mutations.borrow_mut().remove(identity);
                    self.reference_inputs.borrow_mut().remove(identity);
                }
                SelectedRootPathHalf::Export { .. } => unreachable!("source frame"),
            }
        }
        Ok(Read::ready(
            ClosurePolicy::new(
                ResolutionCompletion::Complete,
                BaseEligibility::Exclude,
                DemandClosureDischarges::exact(activation_reasons),
                facts
                    .generated
                    .iter()
                    .map(|(candidate, source)| GeneratedContinuation {
                        candidate: *candidate,
                        source: *source,
                        base: BaseEligibility::Exclude,
                    })
                    .collect(),
            )
            .with_query_scope(crate::analyzer::resolution::ClosedQueryScope {
                query_obligations,
                ..Default::default()
            }),
        ))
    }
}

impl PythonHalf<'_, '_, '_> {
    fn record_environment(&self, reference: SemanticId) {
        self.rules.record_query_scope(
            reference,
            &self.query_obligations,
            "python_environment_open",
        );
    }
    fn record_mutation(&self, reference: SemanticId) -> Result<()> {
        self.rules
            .record_dynamic_receiver_scope(reference, &self.query_obligations)
    }
    fn import_route_completion(&self, site: u32) -> Result<ResolutionCompletion> {
        self.record_environment(self.source.token);
        self.import_route_completion_for(self.fragment.ordinal(), self.blob, &self.rows, site)
    }

    fn import_route_completion_for(
        &self,
        ordinal: u32,
        blob: i64,
        rows: &PythonBindingRows,
        site: u32,
    ) -> Result<ResolutionCompletion> {
        let mount = self
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let completion = self.rules.import_route_completion(
            mount.persisted_relative_path(),
            blob,
            rows.imports
                .iter()
                .find(|import| import.import_site.get() == site)
                .expect("selected import has retained source metadata"),
        )?;
        // Empty routes have no candidate witness to retain their evidence.
        // Keep this selected route's provider/placement evidence until publication.
        let mut inputs = self.rules.source_inputs.borrow_mut();
        let prepared = inputs
            .get_mut(&self.source.identity)
            .expect("prepared Python source half");
        prepared.endpoint_completion = prepared.endpoint_completion.combine(&completion);
        Ok(completion)
    }

    fn authored(&self, fragment: BindingFragmentId, event: &BindingEvent) -> Option<RouteLocation> {
        // Imports select their routed target, never the authored local alias as
        // a substitute for the imported definition. Activation remains open.
        if event.kind
            == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Import
        {
            return None;
        }
        event.authored.map(|site| RouteLocation::Owner {
            definition: crate::analyzer::resolution::mounted_site_semantic(
                fragment,
                ResolutionSiteId::new(site),
            ),
            scope: None,
        })
    }
    fn import_starts(
        &self,
        container: &str,
        blob: i64,
        site: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Vec<(RouteLocation, Option<ResolutionLookupSemanticRecipe>)>> {
        let key = (self.rules.summary, container.to_owned(), site, blob);
        let destinations = if let Some(rows) =
            { self.rules.import_routes.borrow().get(&key).cloned() }
        {
            rows
        } else {
            let rows = self.rules.ready.inventory.connection().prepare_cached(
            "WITH routes AS (
               SELECT imports.*,NOT EXISTS(SELECT 1 FROM resolution_root_import_segments prefix WHERE prefix.blob_id=?4 AND prefix.import_site=imports.import_site) AS binds_head
               FROM python_unit_summary_imports imports
               WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3
             ) SELECT CASE WHEN routes.form='module' AND routes.binds_head THEN binding.container_path WHEN routes.form='module' THEN loaded.container_path ELSE routes.target_container END,routes.form,routes.requested_name
             FROM routes
             LEFT JOIN resolution_import_selectors selector ON selector.blob_id=?4 AND selector.site=routes.import_site
             LEFT JOIN python_unit_summary_providers loaded ON loaded.summary_id=routes.summary_id AND loaded.container_path=routes.target_container
             LEFT JOIN python_unit_summary_providers binding ON routes.form='module' AND routes.binds_head
               AND binding.summary_id=routes.summary_id AND (binding.module_name=selector.source_name OR (
                 NOT EXISTS(SELECT 1 FROM python_unit_summary_providers exact WHERE exact.summary_id=routes.summary_id AND exact.module_name=selector.source_name AND exact.root_slot=loaded.root_slot AND exact.state IN ('selected','alternative'))
                 AND EXISTS(SELECT 1 FROM python_unit_summary_spellings head JOIN python_unit_summary_spellings full_spelling ON full_spelling.summary_id=head.summary_id AND full_spelling.source_root=head.source_root
                   WHERE head.summary_id=routes.summary_id AND head.module_name=selector.source_name AND head.target_container=binding.container_path AND head.admitted
                     AND full_spelling.module_name=routes.module_name AND full_spelling.target_container=routes.target_container AND full_spelling.admitted)))
               AND binding.root_slot=loaded.root_slot AND binding.state IN ('selected','alternative')",
        )?.query_map(rusqlite::params![self.rules.summary,container,site,blob], |row| Ok((row.get::<_,Option<String>>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let rows = std::sync::Arc::new(rows);
            if !self.rules.cancellation.is_cancelled() {
                self.rules
                    .import_routes
                    .borrow_mut()
                    .insert(key, std::sync::Arc::clone(&rows));
            }
            rows
        };
        Ok(destinations
            .iter()
            .filter_map(|(container, form, name)| {
                // An external module has no selected provider. Preserve its
                // route obligation, without inventing an empty module container.
                let container = container
                    .as_deref()
                    .filter(|container| !container.is_empty())?;
                let head = (form != "module").then(|| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        lookup.namespace(),
                        if form == "star" {
                            lookup.spelling()
                        } else {
                            name
                        },
                    )
                });
                Some((
                    RouteLocation::Container {
                        unit: self.rules.summary,
                        container: container.to_owned(),
                    },
                    head,
                ))
            })
            .collect())
    }
    fn binding_proofs(
        &self,
        placement: &PythonPlacement,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<PythonBindingProofs> {
        let (mut proofs, stars) = self.import_binding_proofs(
            self.fragment.ordinal(),
            self.blob,
            &self.rows,
            &placement.container,
            lookup,
        )?;
        *placement.stars.borrow_mut() = stars;
        proofs.source_completion = Some(self.completion.clone());
        // Only a deferred lookup that reaches the module cell needs module
        // namespace closure. Local/cell bindings must not wait on these inputs.
        if let Some(module) = self.deferred_module_scope {
            if self.module_attribute_space(&placement.container)? != ResolutionCompletion::Complete
            {
                proofs.open_scopes.push(module);
            } else if self.completion == ResolutionCompletion::Complete
                && let Some(site) = self.reference_site
            {
                match self
                    .rules
                    .function_initialization_start(self.blob, site, &self.rows)?
                {
                    None => proofs.completed_scopes.push(module),
                    Some(point) => {
                        proofs.initialization_start = Some(point);
                        let later = self.rules.initialization_has_later(
                            self.blob,
                            module,
                            lookup.spelling(),
                            point,
                        );
                        if !later {
                            proofs.completed_scopes.push(module);
                        }
                    }
                }
            }
        }
        // An empty module cell has no initialization order to prove. Admit
        // that fact only for this builtin name and current mutation-free source.
        if brokk_bifrost_python::intrinsics::builtin(lookup.spelling()).is_some_and(|entry|
            entry.versions.availability(self.rules.python_version)
                == brokk_bifrost_python::intrinsics::Availability::Present)
            && let Some(module) = self.rows.scopes.iter().find(|scope| scope.parent.is_none())
            && !self.rows.slots.iter().any(|slot| slot.scope == module.scope && slot.name == lookup.spelling())
            && !self.rows.import_positions.iter().any(|(site,scope,_)|
                *scope == module.scope && self.rows.imports.iter().any(|import|
                    import.import_site.get() == *site && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star))
            && self.builtin_inventory_closed()
        {
            proofs.absent_scopes.push(module.scope);
        }
        Ok(proofs)
    }

    fn import_binding_proofs(
        &self,
        ordinal: u32,
        blob: i64,
        rows: &PythonBindingRows,
        container: &str,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<(PythonBindingProofs, PythonStarRoutes)> {
        let mount = self
            .rules
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let mut proofs = PythonBindingProofs {
            conditional_imports: self.rules.conditional_imports(
                rows,
                mount.persisted_relative_path(),
                blob,
            )?,
            ..Default::default()
        };
        let mut stars = PythonStarRoutes::default();
        let mut occurrence = rows
            .events
            .iter()
            .map(|event| event.event)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .expect("event occurrence capacity");
        for import in &rows.imports {
            if import.form
                != brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
            {
                continue;
            }
            let site = import.import_site.get();
            let mut starts = Vec::new();
            let mut absent = proofs.conditional_imports.contains(&site);
            let mut inventory_closed = proofs.conditional_imports.contains(&site);
            for (location, head) in self.import_starts(container, blob, site, lookup)? {
                let RouteLocation::Container { ref container, .. } = location else {
                    unreachable!()
                };
                let present: bool = self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)")?.query_row(
                    rusqlite::params![self.rules.summary,container,lookup.spelling()], |row|row.get(0),
                )?;
                let closed = self.wildcard_inventory_closed(container, lookup.spelling())?;
                absent &= closed && !present;
                inventory_closed &= closed;
                if present {
                    starts.push((location, head.expect("star attribute head")));
                }
            }
            if absent {
                proofs
                    .absent_star_members
                    .push((site, lookup.spelling().to_owned()));
            }
            if !starts.is_empty() {
                proofs
                    .route_bindings
                    .push(python_lexical::PythonRouteBinding {
                        occurrence,
                        import_site: site,
                        name: lookup.spelling().to_owned(),
                        certain: inventory_closed,
                        completion: if inventory_closed {
                            self.import_route_completion_for(ordinal, blob, rows, site)?
                        } else {
                            self.import_route_completion_for(ordinal, blob, rows, site)?
                                .combine(&open(self.source.token))
                        },
                    });
                stars.insert(occurrence, starts);
                occurrence = occurrence.checked_add(1).expect("star occurrence capacity");
            }
        }
        Ok((proofs, stars))
    }
    // Regular packages/modules have one selected provider. Namespace portions
    // are closed only when every retained portion belongs to analysis roots.
    fn provider_completion(&self, container: &str) -> Result<ResolutionCompletion> {
        self.record_environment(self.source.token);
        if container.is_empty() {
            return Ok(ResolutionCompletion::Complete);
        }
        let mut statement = self.rules.ready.inventory.connection().prepare_cached(
            "SELECT p.kind,p.state,p.rel_path,root.root_path,
               EXISTS(SELECT 1 FROM resolution_unit_summary_members member
                JOIN selected_resolution_mounts mounted ON mounted.blob_id=member.blob_id
                 AND mounted.persisted_relative_path=member.rel_path
                WHERE member.summary_id=p.summary_id AND member.member_ordinal=p.member_ordinal)
             FROM python_unit_summary_providers p
             JOIN python_unit_summary_roots root ON root.summary_id=p.summary_id AND root.root_slot=p.root_slot
             WHERE p.summary_id=?1 AND p.module_name=(SELECT module_name
              FROM python_unit_summary_providers WHERE summary_id=?1 AND container_path=?2)
              AND p.state IN ('selected','alternative','open')",
        )?;
        let mut closed = true;
        let mut found = false;
        for row in statement.query_map(rusqlite::params![self.rules.summary, container], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, bool>(4)?,
            ))
        })? {
            if self.rules.cancellation.is_cancelled() {
                return Ok(cancelled_completion());
            }
            if !self.rules.session.scope_step() {
                return Ok(ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::TimeBudgetExceeded(self.source.token),
                ]));
            }
            let (kind, state, path, root, mounted) = row?;
            self.rules
                .record_unplaced_scope(self.source.token, &self.query_obligations, &path);
            found = true;
            closed &= state != "open"
                && match kind.as_str() {
                    "namespace" => {
                        std::path::Path::new(&path).starts_with(std::path::Path::new(&root))
                    }
                    "package" | "module" => mounted,
                    _ => false,
                };
        }
        Ok(if found && closed {
            ResolutionCompletion::Complete
        } else {
            open(self.source.token)
        })
    }

    fn wildcard_inventory_closed(&self, container: &str, name: &str) -> Result<bool> {
        let cached = self
            .rules
            .wildcard_inventories
            .borrow()
            .get(container)
            .copied();
        self.record_environment(self.source.token);
        let (policy_closed, public_names) = if let Some(cached) = cached {
            cached
        } else {
            let inventory = self
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT policy IN ('curated','public_names'), policy='public_names'
                 FROM python_unit_summary_surfaces
                 WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard'",
                )?
                .query_row(rusqlite::params![self.rules.summary, container], |row| {
                    Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?))
                })
                .optional()?
                .unwrap_or((false, false));
            self.rules
                .wildcard_inventories
                .borrow_mut()
                .insert(container.to_owned(), inventory);
            inventory
        };
        if !policy_closed
            || self.module_attribute_space(container)? != ResolutionCompletion::Complete
        {
            return Ok(false);
        }
        Ok(!public_names
            || !module_name_open_without_binding(
                self.rules.ready.inventory.connection(),
                self.rules.summary,
                container,
                name,
            )?)
    }

    fn module_attribute_space(&self, container: &str) -> Result<ResolutionCompletion> {
        let space = self.module_attribute_space_inputs(container)?;
        Ok(space
            .completion
            .combine(&space.hook_completion)
            .combine(&space.star_completion))
    }

    fn module_attribute_space_for_read(
        &self,
        name: &str,
        proofs: &PythonBindingProofs,
        space: &PythonModuleAttributeSpace,
        completion: ResolutionCompletion,
    ) -> Result<ResolutionCompletion> {
        // The producer's unknown star binder is an inventory obligation. A
        // complete per-name route (or absence proof) discharges only this read.
        let stars_closed = space.star_sites.iter().all(|site| {
            proofs
                .absent_star_members
                .iter()
                .any(|(import, member)| import == site && member == name)
                || proofs.route_bindings.iter().any(|route| {
                    route.import_site == *site
                        && route.name == name
                        && route.certain
                        && route.completion == ResolutionCompletion::Complete
                })
        });
        Ok(if stars_closed {
            completion
        } else {
            completion.combine(&space.star_completion)
        })
    }

    fn module_attribute_space_inputs(&self, container: &str) -> Result<PythonModuleAttributeSpace> {
        let cached = self.rules.module_spaces.borrow().get(container).cloned();
        self.record_environment(self.source.token);
        self.record_mutation(self.source.token)?;
        let mut space = if let Some(cached) = cached {
            cached
        } else {
            let mut completion = self.provider_completion(container)?;
            let mut star_sites = Vec::new();
            let mut star_completion = ResolutionCompletion::Complete;
            let mut hook_completion = ResolutionCompletion::Complete;
            let module = match self.rules.module_bindings(container)? {
                Read::Ready {
                    value,
                    completion: evidence,
                } => {
                    completion = completion.combine(&evidence);
                    value
                }
                Read::Cancelled(evidence)
                | Read::Unavailable {
                    completion: evidence,
                    ..
                } => {
                    return Ok(PythonModuleAttributeSpace {
                        completion: completion
                            .combine(&evidence)
                            .combine(&open(self.source.token)),
                        hook_completion: ResolutionCompletion::Complete,
                        star_completion,
                        star_sites,
                    });
                }
            };
            if let Some((_, blob, rows)) = module {
                let root = rows
                    .scopes
                    .iter()
                    .find(|scope| scope.parent.is_none())
                    .expect("module root");
                let hook = rows
                    .slots
                    .iter()
                    .any(|slot| slot.scope == root.scope && slot.name == "__getattr__");
                let origin=crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                    crate::analyzer::resolution::LoweringGapOrigin::Extracted(brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedRoute));
                let dynamic_sites = self.rules.ready.inventory.connection().prepare_cached(
                    "SELECT DISTINCT reason.site FROM resolution_gaps gap JOIN resolution_gap_reasons reason ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason WHERE gap.blob_id=?1 AND gap.covers IN (2,5) AND gap.lookup=0 AND reason.origin=?2",
                )?.query_map(rusqlite::params![blob,origin], |row| row.get::<_,u32>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut dynamic = false;
                for site in dynamic_sites {
                    if rows.imports.iter().any(|import| import.import_site.get() == site
                        && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star) {
                        star_sites.push(site);
                    } else {
                        dynamic = true;
                    }
                }
                if !star_sites.is_empty() {
                    let owner = match self.module_owner(container)? {
                        Some(RouteLocation::Owner { definition, .. }) => definition,
                        _ => self.source.token,
                    };
                    star_completion = open(owner);
                }
                let unresolved_star: bool = self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports imports WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.form='star' AND (imports.state<>'activation_open' OR NOT EXISTS(SELECT 1 FROM python_unit_summary_providers provider WHERE provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container AND provider.state IN ('selected','alternative') AND provider.member_ordinal IS NOT NULL)))")?.query_row(
                    rusqlite::params![self.rules.summary,container], |row|row.get(0))?;
                self.rules.observations.borrow_mut().push(format!(
                    "module attribute-space hook={hook} dynamic={dynamic} unresolved-star={unresolved_star}"
                ));
                if hook || dynamic || unresolved_star {
                    let owner = match self.module_owner(container)? {
                        Some(RouteLocation::Owner { definition, .. }) => definition,
                        _ => self.source.token,
                    };
                    if dynamic || unresolved_star {
                        completion = completion.combine(&open(owner));
                    } else {
                        hook_completion = open(owner);
                    }
                }
            }
            let space = PythonModuleAttributeSpace {
                completion,
                hook_completion,
                star_completion,
                star_sites,
            };
            self.rules
                .module_spaces
                .borrow_mut()
                .insert(container.to_owned(), space.clone());
            space
        };
        let mut completion =
            crate::analyzer::resolution::model::ExactCompletionAccumulator::default();
        let mut cancelled = || self.rules.cancellation.is_cancelled();
        if completion
            .include(&space.completion, &mut cancelled)
            .is_none()
        {
            return Ok(PythonModuleAttributeSpace {
                completion: cancelled_completion(),
                ..space
            });
        }
        let owner = self.module_owner(container)?;
        for mutation in self.module_mutations.iter() {
            let incoming = if let Some(RouteLocation::Owner { definition, .. }) = owner {
                mutation.completion(definition, self.rules)?
            } else {
                // A namespace portion has no authored module declaration.
                mutation.namespace_completion(self.source.token, self.rules)?
            };
            if completion.include(&incoming, &mut cancelled).is_none() {
                return Ok(PythonModuleAttributeSpace {
                    completion: cancelled_completion(),
                    ..space
                });
            }
        }
        space.completion = completion
            .finish(&mut cancelled)
            .unwrap_or_else(cancelled_completion);
        Ok(space)
    }

    /// Namespace packages have no authored module declaration.
    fn module_owner(&self, container: &str) -> Result<Option<RouteLocation>> {
        let selected = self.rules.ready.inventory.connection().prepare_cached("SELECT mounted.mount_ordinal, member.blob_id
             FROM python_unit_summary_providers provider
             JOIN resolution_unit_summary_members member
               ON member.summary_id=provider.summary_id AND member.member_ordinal=provider.member_ordinal
             JOIN selected_resolution_mounts mounted
               ON mounted.blob_id=member.blob_id AND mounted.persisted_relative_path=member.rel_path
             WHERE provider.summary_id=?1 AND provider.container_path=?2
               AND provider.state IN ('selected','alternative') AND provider.kind IN ('module','package')")?.query_row(
            rusqlite::params![self.rules.summary, container],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
        ).optional()?;
        let Some((ordinal, blob)) = selected else {
            return Ok(None);
        };
        let Some(site) = cached_module_site(
            self.rules.ready.inventory.connection(),
            blob,
            &self.rules.module_sites,
        )?
        else {
            return Ok(None);
        };
        let mount = SelectedMountTable::new(&self.rules.ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        Ok(Some(RouteLocation::Owner {
            definition: crate::analyzer::resolution::mounted_site_semantic(mount.fragment(), site),
            scope: None,
        }))
    }

    fn imported_child_is_attached(&self, child: &str) -> Result<bool> {
        let source_reference = self.rules.reference_for_source(self.source);
        let reference: Option<u32> = self.rules.ready.inventory.connection().prepare_cached("SELECT source_site FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?2 AND semantic_role='reference'")?.query_row(
            rusqlite::params![self.blob, source_reference.local_key()], |row| row.get(0),
        ).optional()?;
        let Some(reference) = reference else {
            return Ok(false);
        };
        // Container names are selected module identities, not source text.
        // A deeper loaded module attaches every preceding package child.
        let mount = self.rules.ready.inventory.mount_record_by_ordinal(
            SelectedResolutionMountOrdinal::new(self.fragment.ordinal()),
        )?;
        let imports = self.rules.ready.inventory.connection().prepare_cached(
            "SELECT DISTINCT imports.import_site
             FROM python_unit_summary_imports imports
             JOIN resolution_unit_summary_members caller
               ON caller.summary_id=imports.summary_id AND caller.member_ordinal=imports.member_ordinal
             JOIN python_unit_summary_providers loaded
               ON loaded.summary_id=imports.summary_id AND loaded.container_path=imports.target_container
             JOIN python_unit_summary_providers child
               ON child.summary_id=loaded.summary_id AND child.root_slot=loaded.root_slot
             WHERE imports.summary_id=?1 AND caller.blob_id=?2
               AND imports.form='module' AND imports.state='activation_open' AND child.container_path=?3
               AND caller.rel_path=?4
               AND loaded.state='selected' AND child.state='selected'
               AND (loaded.module_name=child.module_name OR
                 substr(loaded.module_name,1,length(child.module_name)+1)=child.module_name || '.')"
        )?.query_map(rusqlite::params![self.rules.summary,self.blob,child,mount.persisted_relative_path()], |row| row.get::<_,u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for import in imports {
            match python_lexical::import_dominates(
                &self.rows,
                import,
                reference,
                self.rules.profile,
                &mut SessionBudget {
                    session: self.rules.session,
                    cancellation: self.rules.cancellation,
                },
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(Stop::Cancelled | Stop::Budget) => return Ok(false),
            }
        }
        Ok(false)
    }

    fn module_locations(
        &self,
        container: &str,
        name: &str,
        remaining: &[String],
    ) -> Result<Read<PythonModuleRead>> {
        self.record_environment(self.source.token);
        let mut read = self.module_binding_selection(container, name, remaining)?;
        if let Read::Ready { value, completion } = &mut read
            && value.is_empty()
            && *completion == ResolutionCompletion::Complete
            && module_name_open_without_binding(
                self.rules.ready.inventory.connection(),
                self.rules.summary,
                &self.rules.imported_module_view(container)?.0,
                name,
            )?
        {
            *completion = completion.combine(&open(self.source.token));
        }
        Ok(read)
    }

    fn module_binding_selection(
        &self,
        container: &str,
        name: &str,
        remaining: &[String],
    ) -> Result<Read<PythonModuleRead>> {
        let (view, registry_completion) = self.rules.imported_module_view(container)?;
        let container = view.as_str();
        let (ordinal, blob, rows) = match self.rules.module_bindings(container)? {
            Read::Ready {
                value: Some(value), ..
            } => value,
            Read::Ready { value: None, .. } => {
                return Ok(Read::Ready {
                    value: PythonModuleRead::default(),
                    completion: self
                        .provider_completion(container)?
                        .combine(&registry_completion),
                });
            }
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { reason, completion } => {
                return Ok(Read::Unavailable { reason, completion });
            }
        };
        let Some(root) = rows.scopes.iter().find(|scope| scope.parent.is_none()) else {
            return Ok(Read::Ready {
                value: PythonModuleRead::default(),
                completion: open(self.source.token),
            });
        };
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Python,
            self.source.demand.namespace(),
            name,
        );
        let (proofs, stars) =
            self.import_binding_proofs(ordinal, blob, &rows, container, &lookup)?;
        let initializing = self.rules.initializing_package_import(
            container,
            self.import_site
                .filter(|_| ordinal == self.fragment.ordinal())
                .map(|import_site| PythonModuleObservation {
                    mount: self.fragment.ordinal(),
                    import_site,
                }),
        )?;
        let initializing_read = initializing.map(|site| {
            let event = python_lexical::module_initialization_event(&rows, site)
                .expect("initializing import belongs to this package's root execution");
            (event.event, event.entry_byte)
        });
        let space = self.module_attribute_space_inputs(container)?;
        let completion =
            if module_name_bound_unconditionally(&rows, root.scope, name, initializing_read) {
                space.completion.clone()
            } else {
                space.completion.combine(&space.hook_completion)
            };
        let namespace_completion =
            self.module_attribute_space_for_read(name, &proofs, &space, completion)?;
        let mut state = if let Some(site) = initializing {
            python_lexical::initializing_module_selection(
                &rows,
                site,
                name,
                self.rules.profile,
                proofs,
            )
            .expect("initializing import belongs to this package's root execution")
        } else {
            python_lexical::module_selection(&rows, root.scope, name, self.rules.profile, proofs)
        };
        python_lexical::lexical_tier(
            &mut state,
            &rows,
            root.scope,
            &mut SessionBudget {
                session: self.rules.session,
                cancellation: self.rules.cancellation,
            },
        );
        // A complete module cell inventory with no writer proves dictionary
        // absence. Dynamic hooks/writes and unresolved stars are accounted for
        // by module_attribute_space below, independently of initialization.
        let absent = if initializing.is_some() {
            state.selection.selected.is_empty() && !state.selection.open
        } else {
            !rows.slots.iter().any(|slot| slot.scope == root.scope && slot.name == name)
                && !rows.imports.iter().any(|import| {
                    import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::Star
                })
        };
        if absent && state.selection.stopped.is_none() {
            debug_assert!(state.selection.selected.is_empty());
            state.selection.open = false;
            state.selection.residual.clear();
            if initializing.is_some() {
                state.selection.unbound.clear();
            }
        }
        let mut completion = match self.selection_completion(&state) {
            Read::Ready { completion, .. } => completion,
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { .. } => unreachable!("lexical selection cannot be unavailable"),
        };
        let mount = SelectedMountTable::new(&self.rules.ready.inventory)
            .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        let mut value = PythonModuleRead::default();
        if state.selection.stopped.is_none() {
            for selected in &state.selection.selected {
                if let Some(starts) = stars.get(&selected.occurrence) {
                    for (location, head) in starts {
                        debug_assert_eq!(head, &lookup);
                        value.lookup_continuations.push(location.clone());
                    }
                    continue;
                }
                let event = rows
                    .events
                    .iter()
                    .find(|event| event.event == selected.occurrence)
                    .expect("selected event belongs to the module inventory");
                if let Some(authored) = self.authored(mount.fragment(), event) {
                    value.locations.push(authored);
                } else if event.kind == brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Import {
                    for alias in self.import_aliases.iter().filter(|alias| alias.container == container && alias.name == name) {
                        completion = completion.combine(&alias.completion);
                        if !alias.external_imports.is_empty() && rows.imports.iter().any(|import| import.binding_event == Some(event.event) && import.import_site.get() == alias.import_site) {
                        let selection_state = PythonExternalSelectionState::new(mount.fragment(), blob, &state.selection, selected);
                        let namespace_closed = self.module_attribute_space(container)? == ResolutionCompletion::Complete;
                        let external_imports = alias.external_imports.iter().cloned().map(|mut selected| {
                            selected.remaining_member_path.extend_from_slice(remaining);
                            selected.completion = selected.completion.combine(&selection_state.completion).combine(&alias.completion);
                            selected.selection.push(selection_state.clone());
                            selected.identity_is_unique &= state.selected_import_identity_is_unique(&rows, root.scope, event.event) && namespace_closed;
                            selected.boundary_is_unique &= state.selected_import_boundary_is_unique(&rows, root.scope, event.event) && namespace_closed;
                            selected
                        }).collect();
                        self.rules.retain_external_imports(self.source, external_imports);
                        }
                        value.locations.extend(alias.targets.iter().map(|definition| RouteLocation::Owner { definition: *definition, scope: None }));
                    }
                }
            }
        }
        completion = completion
            .combine(&namespace_completion)
            .combine(&registry_completion);
        value.selected_binding = !state.selection.selected.is_empty();
        value.locations.sort();
        value.locations.dedup();
        value.lookup_continuations.sort();
        value.lookup_continuations.dedup();
        Ok(Read::Ready { value, completion })
    }
    /// Mutation authority is the retained operation inventory, confirmed only
    /// through the shared prefix prerequisites. Lexical source events remain
    /// the authority for local/module shadowing; no source is reparsed here.
    fn builtin_inventory_closed(&self) -> bool {
        let Some(site) = self.reference_site else {
            return false;
        };
        self.universe_unmutated && self.import_site.is_none()
            && !self.rules.cancellation.is_cancelled()
            && !self.rows.events.iter().any(|event|event.target==site && event.kind!=brokk_bifrost_core::analyzer::resolution_facts::ResolutionBindingEventKind::Augment)
    }

    fn selection_completion(&self, state: &PythonLexical) -> Read<()> {
        if state.selection.stopped == Some(Stop::Cancelled) {
            self.rules
                .observations
                .borrow_mut()
                .push("lexical-selection-cancelled".into());
        }
        let mut completion = state.selection.completion.clone();
        if state.selection.open
            || !state.selection.residual.is_empty()
            || !state.selection.unbound.is_empty()
        {
            let reason = self.rules.lexical_selection_obligation(
                self.source.token,
                self.source.demand.spelling(),
                state,
            );
            completion = completion.combine(&open(reason));
        }
        match state.selection.stopped {
            Some(Stop::Cancelled) => Read::Cancelled(completion.combine(&cancelled_completion())),
            Some(Stop::Budget) => Read::Ready {
                value: (),
                completion: completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::TimeBudgetExceeded(self.source.token),
                ])),
            },
            None => Read::Ready {
                value: (),
                completion,
            },
        }
    }
}

impl PythonHalf<'_, '_, '_> {
    pub(super) fn member_context(&self) -> super::python_members::PythonMemberContext<'_, '_, '_> {
        super::python_members::PythonMemberContext {
            rules: self.rules,
            reference: self.source.token,
            query_obligations: &self.query_obligations,
            environment: crate::analyzer::resolution::CALLER_ENVIRONMENT,
            rows: &self.rows,
            blob: self.blob,
            member_values: &[],
            super_cursor: None,
            member_observations: &self.member_observations,
            rendered_order: &self.rendered_order,
        }
    }

    fn member_request(
        &self,
        reference: SemanticId,
        values: Vec<ResolutionSlotValue>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> crate::analyzer::resolution::DemandMemberSelectionRequest {
        self.member_context().member_request(
            reference,
            values,
            lookup.semantic(&self.rules.ready.shared_names()),
            ResolutionNamespace::Value,
        )
    }
    fn owner_request(
        &self,
        location: &RouteLocation,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>> {
        let RouteLocation::Owner { definition, .. } = location else {
            return Ok(None);
        };
        if !super::python_members::is_class(self.rules.ready, *definition)? {
            return Ok(None);
        }
        Ok(Some(self.member_request(
            self.source.token,
            vec![ResolutionSlotValue::type_object(
                crate::analyzer::resolution::ResolutionTypeRef::new(*definition, 0),
            )],
            lookup,
        )))
    }
}

impl HalfRules for PythonHalf<'_, '_, '_> {
    fn source_endpoint_completion(
        &self,
        source: &SourceHalf,
        _: &EndpointSignature,
        _: &ReadySelectedResolution<'_, '_>,
    ) -> Option<ResolutionCompletion> {
        if self.open.is_some() {
            return None;
        }
        let inputs = self.rules.source_inputs.borrow();
        let completion = &inputs
            .get(&source.identity)
            .expect("prepared Python source half")
            .endpoint_completion;
        (completion != &ResolutionCompletion::Complete).then(|| completion.clone())
    }
    fn member_access(
        &self,
    ) -> Option<&dyn super::member_access::MemberAccessRules<Self::MemberRow>> {
        Some(self)
    }
    fn provider_observations(
        &self,
    ) -> Result<Read<Vec<crate::analyzer::resolution::HierarchyProviderObservation>>> {
        Ok(Read::ready(std::mem::take(
            &mut *self.member_observations.borrow_mut(),
        )))
    }
    fn terminal_member_request(
        &self,
        _: &PythonPlacement,
        target: &SourceTargetContext<'_, PythonRank>,
    ) -> Result<Read<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>>> {
        // With no qualifier the lexical tier already selected the declaration
        // named by the terminal lookup. A class binding is then a value, not
        // a second lookup of that same name inside the selected class.
        if self.source.route.is_empty() {
            return Ok(Read::ready(None));
        }
        Ok(Read::ready(
            self.owner_request(&target.cursor.location, target.lookup)?,
        ))
    }
    fn member_rows(
        &self,
        _: &PythonPlacement,
        route: &MemberRouteContext<'_, PythonRank>,
        owner: SemanticId,
    ) -> Result<Read<Vec<Self::MemberRow>>> {
        let RouteLocation::Owner { definition, .. } = &route.cursor.location else {
            unreachable!("Python source member requests start at a class owner");
        };
        let values = [ResolutionSlotValue::type_object(
            crate::analyzer::resolution::ResolutionTypeRef::new(*definition, 0),
        )];
        let context = super::python_members::PythonMemberContext {
            member_values: &values,
            ..self.member_context()
        };
        super::python_members::member_rows(
            &context,
            &super::python_members::PythonMemberRoute {
                lookup: route.lookup,
                namespace: route.namespace,
                step: route.cursor.consumed_prefix_segments,
                selection: route.selection,
                provenance: route.provenance,
            },
            owner,
        )
    }
    fn member_target(
        &self,
        _: &PythonPlacement,
        route: &MemberRouteContext<'_, PythonRank>,
        row: &Self::MemberRow,
    ) -> Result<Read<Option<SelectedMemberRouteTarget>>> {
        self.member_context()
            .member_target(route.lookup, route.namespace, row)
    }
    type Placement = PythonPlacement;
    type Target = PythonTarget;
    type Member = ();
    type Provider = ();
    type MemberRow = super::python_members::PythonMemberRow;
    type Rank = PythonRank;
    type LexicalTiers = Vec<LexicalStartTier<PythonRank, ()>>;
    fn selected_universe(
        &self,
        placement: &PythonPlacement,
    ) -> Option<(
        SemanticId,
        Option<crate::analyzer::resolution::UniverseEntry>,
    )> {
        self.reference_site.map(|site| {
            (
                crate::analyzer::resolution::mounted_site_semantic(
                    self.fragment,
                    ResolutionSiteId::new(site),
                ),
                placement.universe.get(),
            )
        })
    }
    fn language(&self) -> Language {
        Language::Python
    }
    fn placements(&mut self) -> Vec<PythonPlacement> {
        std::mem::take(&mut self.placements)
    }
    fn initial_completion(&self) -> ResolutionCompletion {
        self.open.as_ref().map_or_else(
            || self.completion.clone(),
            |open| self.completion.combine(open.completion()),
        )
    }
    fn placement(
        &self,
        _: &PythonPlacement,
        tag: ClosureTag,
    ) -> Option<PlacementFacts<PythonTarget>> {
        Some(PlacementFacts {
            tag,
            completion: self.completion.clone(),
            targets: Vec::new(),
            members: Vec::new(),
        })
    }
    fn root_starts(
        &mut self,
        _: &PythonPlacement,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Vec<PlacementStart<(), PythonRank>>> {
        // Lexical selection owns the source scope, including its uncovered
        // regions. A parallel environment-root route would reopen closed cells.
        if self.source.anchor == ResolutionRootImportAnchor::Lexical
            && !self.source.is_import
            && self.import_site.is_none()
        {
            return Ok(Vec::new());
        }
        let mut cursor = WalkCursor::container(facts.tag, self.rules.summary, String::new(), 0);
        cursor.namespace = self.source.demand.namespace();
        Ok(vec![PlacementStart::Route {
            cursor,
            anchor: self.source.anchor,
            rank: Some(PythonRank { cohort: 0 }),
            scope: None,
        }])
    }
    fn route_rules<'a>(
        &'a self,
        placement: &'a PythonPlacement,
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl RouteRules<ClosureTag> + 'a {
        PythonRoute {
            half: self,
            placement,
        }
    }
    fn prefix_selection(
        &mut self,
        _: &PythonPlacement,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Option<StartSelection<PythonRank, ()>>> {
        let Some(prefix) = &self.prefix else {
            return Ok(None);
        };
        let projected = self.rules.module_member_prefix(
            self.source.prefix.expect("prepared member prefix"),
            prefix,
            &self.source.demand,
        )?;
        if let Some(projected) = &projected
            && let ResolutionCompletion::Incomplete(reasons) = prefix.completion()
        {
            // This member's successful-read proof is local to its endpoint.
            // Do not use for_prefix: the ordinary prefix value remains open.
            let closed = reasons
                .iter()
                .filter_map(|reason| match *reason {
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic)
                    | ResolutionIncompleteReason::ReceiverSubclassObligation(semantic)
                        if !projected.completion().contains_reason(*reason) =>
                    {
                        Some(semantic)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            self.rules
                .source_inputs
                .borrow_mut()
                .get_mut(&self.source.identity)
                .expect("prepared member source half")
                .activation_reasons
                .extend(closed);
        }
        let prefix = projected.as_ref().unwrap_or(prefix);
        facts.completion = facts.completion.combine(prefix.completion());
        let mut locations = Vec::new();
        for &definition in prefix.targets() {
            if let Some(location) = self.rules.module_container(&RouteLocation::Owner {
                definition,
                scope: None,
            })? {
                locations.push(RankedStart {
                    location,
                    rank: Some(PythonRank { cohort: 0 }),
                    scope: None,
                });
            }
        }
        if locations.is_empty()
            && prefix.targets().is_empty()
            && let Some(route) = self
                .rules
                .namespace_import_route(self.source.prefix.expect("prepared member prefix"))?
        {
            facts.completion = facts.completion.combine(&route.completion);
            for container in route.containers {
                locations.push(RankedStart {
                    location: RouteLocation::Container {
                        unit: self.rules.summary,
                        container,
                    },
                    rank: Some(PythonRank { cohort: 0 }),
                    scope: None,
                });
            }
        }
        Ok(Some(StartSelection {
            lexical: None,
            locations,
            scopes: Vec::new(),
            blocks_fallback: true,
            head: None,
            providers: Vec::new(),
        }))
    }
    fn prefix_starts(
        &mut self,
        _: &PythonPlacement,
        selection: StartSelection<PythonRank, ()>,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Vec<PlacementStart<(), PythonRank>>> {
        Ok(selection
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: 0,
                    start_step: 0,
                    namespace: self.source.demand.namespace(),
                },
                anchor: self.source.anchor,
                rank: start.rank,
                scope: start.scope,
            })
            .collect())
    }
    fn lexical_selection(
        &self,
        placement: &PythonPlacement,
        facts: &mut PlacementFacts<PythonTarget>,
    ) -> Result<Option<StartSelection<PythonRank, ()>>> {
        // An import's source reference names the provider route, not an
        // importer-local cell (notably `from .model import target as public`).
        // A qualified read resumes through its prepared prefix prerequisite.
        if self.source.anchor != ResolutionRootImportAnchor::Lexical
            || self.import_site.is_some()
            || self.source.is_import
            || self.source.prefix.is_some()
        {
            return Ok(None);
        }
        let lookup = self
            .source
            .route
            .first()
            .unwrap_or(&self.source.demand)
            .clone();
        let proofs = self.binding_proofs(placement, &lookup)?;
        let state = self.reference_site.and_then(|site| {
            python_lexical::lexical_selection(
                &self.rows,
                site,
                lookup.spelling(),
                self.rules.profile,
                proofs,
            )
        });
        let request = state.as_ref().map(|state| LexicalStartRequest {
            scope: ResolutionScopeId::new(state.start_scope),
            lookup,
        });
        if state.is_none() {
            facts.completion = facts.completion.combine(&open(self.source.token));
        }
        // Each borrowed view is reconstructed from the current J3 proof inputs;
        // an earlier survivor set is never promoted after prerequisite refinement.
        *placement.lexical.borrow_mut() = state;
        Ok(Some(StartSelection {
            lexical: request,
            locations: Vec::new(),
            scopes: Vec::new(),
            blocks_fallback: true,
            head: None,
            providers: Vec::new(),
        }))
    }
    fn lexical_parent(
        &self,
        placement: &PythonPlacement,
        scope: ResolutionScopeId,
    ) -> Result<Option<ResolutionScopeId>> {
        let state = placement.lexical.borrow();
        Ok(python_lexical::lexical_parent(
            state.as_ref().expect("selected lexical state"),
            &self.rows,
            scope.get(),
        )
        .map(ResolutionScopeId::new))
    }
    fn lexical_tier(
        &self,
        placement: &PythonPlacement,
        scope: ResolutionScopeId,
        _: u32,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Self::LexicalTiers>> {
        let mut state = placement.lexical.borrow_mut();
        let state = state.as_mut().expect("selected lexical state");
        let module_tier = self
            .rows
            .scopes
            .iter()
            .any(|row| row.scope == scope.get() && row.parent.is_none());
        if module_tier {
            self.record_mutation(self.source.token)?;
        }
        let before = state.selection.selected.len();
        python_lexical::lexical_tier(
            state,
            &self.rows,
            scope.get(),
            &mut SessionBudget {
                session: self.rules.session,
                cancellation: self.rules.cancellation,
            },
        );
        if module_tier
            && state.selection.selected.is_empty()
            && !state.selection.residual.is_empty()
        {
            self.record_environment(self.source.token);
        }
        if state.builtin_fallback {
            self.record_environment(self.source.token);
            self.record_mutation(self.source.token)?;
            let detail = format!(
                "builtins.{} may be selected before the sole module-cell writer runs",
                lookup.spelling()
            );
            let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"python-builtin-fallback-before-writer:v1",
            );
            hash.field("name", lookup.spelling().as_bytes());
            let reason = self.rules.ready.context_identities.named_semantic(
                hash.finish(),
                "python_builtin_fallback_before_writer",
                &detail,
            );
            let completion = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]);
            state.selection.completion = state.selection.completion.combine(&completion);
            let mut inputs = self.rules.source_inputs.borrow_mut();
            let prepared = inputs
                .get_mut(&self.source.identity)
                .expect("prepared Python source half");
            prepared.endpoint_completion = prepared.endpoint_completion.combine(&completion);
        }
        if self.source.route.len() <= 1
            && lookup.spelling() == self.source.demand.spelling()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_none()
            && !state.selection.open
            && state.selection.stopped.is_none()
            && state.selection.unbound.is_empty()
            && state.selection.selected.is_empty()
            && !state.selection.residual.is_empty()
            && state.selection.completion == ResolutionCompletion::Complete
            && let Some(builtin) = brokk_bifrost_python::intrinsics::builtin(lookup.spelling())
            && builtin.versions.availability(self.rules.python_version)
                == brokk_bifrost_python::intrinsics::Availability::Present
            && self.builtin_inventory_closed()
        {
            self.record_environment(self.source.token);
            self.record_mutation(self.source.token)?;
            let entry = crate::analyzer::resolution::universe_lookup(
                Language::Python,
                ResolutionNamespace::Value,
                builtin.name,
            )
            .expect("Python builtin table is registered in the universe");
            placement.universe.set(Some(entry));
            state.selection.residual.clear();
            self.rules.observations.borrow_mut().push(format!(
                "universe={} identity={} predeclared=true version={:?}",
                builtin.qualified_name,
                brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
                    &crate::analyzer::resolution::universe::identity_digest(entry)
                ),
                self.rules.python_version,
            ));
        }
        // Closed source and wildcard inventories can prove a missing name.
        // Residual at the final scope is then absence, not an unknown writer.
        // A slot introduced only by later writes is also absent at this read:
        // lexical_tier has already applied chronology and mutation openness.
        // LOAD_GLOBAL does not invoke module __getattr__; retain source completion
        // (including opaque namespace writes) independently of this residual.
        if !state.selection.open
            && state.selection.unbound.is_empty()
            && state.selection.selected.is_empty()
            && state.selection.stopped.is_none()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_none()
            && brokk_bifrost_python::intrinsics::builtin(lookup.spelling()).is_none()
            && self.builtin_inventory_closed()
        {
            self.record_environment(self.source.token);
            self.record_mutation(self.source.token)?;
            state.selection.residual.clear();
        }
        self.stopped.set(state.selection.stopped.is_some());
        let mut coverage = match self.selection_completion(state) {
            Read::Ready { completion, .. } => completion,
            Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
            Read::Unavailable { .. } => unreachable!("lexical selection cannot be unavailable"),
        };
        // A residual carried to a known semantic parent is not missing evidence.
        // Only an uncovered region at the end of traversal stays open.
        if !state.selection.open
            && state.selection.unbound.is_empty()
            && state.selection.stopped.is_none()
            && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_some()
        {
            coverage = state.selection.completion.clone();
        }
        let mut tiers = Vec::new();
        if state.selection.stopped.is_none() {
            let selected_writers = state.selection.selected[before..].to_vec();
            for selected in &selected_writers {
                if let Some(starts) = placement.stars.borrow().get(&selected.occurrence) {
                    for (location, head) in starts {
                        tiers.push(LexicalStartTier {
                            ranked: RankedLexicalTier {
                                rank: PythonRank { cohort: 0 },
                                tier: RouteEdgeTier {
                                    coverage: coverage.clone(),
                                    blocks_fallback: true,
                                    ..Default::default()
                                },
                                providers: Vec::new(),
                            },
                            head: Some((location.clone(), head.clone())),
                        });
                    }
                } else if let Some(event) = self
                    .rows
                    .events
                    .iter()
                    .find(|event| event.event == selected.occurrence)
                {
                    if let Some(import) = self
                        .rows
                        .imports
                        .iter()
                        .find(|import| import.binding_event == Some(event.event))
                    {
                        if let Some(boundary) = self
                            .rules
                            .external_import_boundary(self.fragment, import.import_site.get())?
                        {
                            let remaining = self
                                .source
                                .route
                                .iter()
                                .chain(std::iter::once(&self.source.demand))
                                .skip(1)
                                .map(|part| part.spelling().to_owned())
                                .collect();
                            self.rules.retain_external_imports(
                                self.source,
                                vec![PythonSelectedExternalImport {
                                    consumed_prefix: vec![lookup.spelling().to_owned()],
                                    remaining_member_path: remaining,
                                    completion: state
                                        .selection
                                        .completion
                                        .clone()
                                        .combine(&boundary.completion),
                                    identity_is_unique: state.selected_import_identity_is_unique(
                                        &self.rows,
                                        scope.get(),
                                        event.event,
                                    ),
                                    boundary_is_unique: state.selected_import_boundary_is_unique(
                                        &self.rows,
                                        scope.get(),
                                        event.event,
                                    ),
                                    selection: vec![PythonExternalSelectionState::new(
                                        self.fragment,
                                        self.blob,
                                        &state.selection,
                                        selected,
                                    )],
                                    boundary,
                                }],
                            );
                        }
                        let imports = selected_external_imports(
                            self.rules.external_imports,
                            self.rules.reference_for_source(self.source),
                        );
                        if let Some(token) = self
                            .rules
                            .admit_model(self.rules.reference_for_source(self.source), &imports)?
                        {
                            python_lexical::admit_import(
                                state,
                                &self.rows,
                                import.import_site.get(),
                                &mut SessionBudget {
                                    session: self.rules.session,
                                    cancellation: self.rules.cancellation,
                                },
                                self.rules.cancellation,
                            )?;
                            coverage = match self.selection_completion(state) {
                                Read::Ready { completion, .. } => completion,
                                Read::Cancelled(completion) => {
                                    return Ok(Read::Cancelled(completion));
                                }
                                Read::Unavailable { .. } => {
                                    unreachable!("lexical selection cannot be unavailable")
                                }
                            };
                            // Admission supplies this selected import's binding
                            // identity, conditional on the successful import.
                            // Discharge only its persisted activation obligation;
                            // lexical mutation and uncovered regions remain open.
                            let reasons = self.rules.import_activation_reasons(
                                self.blob,
                                self.fragment.ordinal(),
                                import.import_site.get(),
                            )?;
                            self.rules
                                .source_inputs
                                .borrow_mut()
                                .get_mut(&self.source.identity)
                                .expect("prepared Python source half")
                                .activation_reasons
                                .extend(reasons);
                            tiers.push(LexicalStartTier {
                                ranked: RankedLexicalTier {
                                    rank: PythonRank { cohort: 0 },
                                    tier: RouteEdgeTier {
                                        edges: vec![RouteLocation::Owner {
                                            definition: token,
                                            scope: None,
                                        }],
                                        coverage: coverage.clone(),
                                        blocks_fallback: true,
                                        ..Default::default()
                                    },
                                    providers: Vec::new(),
                                },
                                head: None,
                            });
                            continue;
                        }
                        // A missing destination still has route-local placement
                        // evidence; retain it on the final blocker-only tier.
                        coverage = coverage
                            .combine(&self.import_route_completion(import.import_site.get())?);
                        if state.conditional_import_identity(import.import_site.get()) {
                            let reasons = self.rules.import_activation_reasons(
                                self.blob,
                                self.fragment.ordinal(),
                                import.import_site.get(),
                            )?;
                            self.rules
                                .source_inputs
                                .borrow_mut()
                                .get_mut(&self.source.identity)
                                .expect("prepared Python source half")
                                .activation_reasons
                                .extend(reasons);
                        }
                        for (location, head) in self.import_starts(
                            &placement.container,
                            self.blob,
                            import.import_site.get(),
                            lookup,
                        )? {
                            let mut tier = RouteEdgeTier {
                                coverage: if state
                                    .conditional_import_identity(import.import_site.get())
                                {
                                    coverage.clone()
                                } else {
                                    coverage.combine(&open(self.source.token))
                                },
                                blocks_fallback: true,
                                ..Default::default()
                            };
                            let head = if let Some(head) = head {
                                Some((location, head))
                            } else {
                                tier.edges.push(location);
                                None
                            };
                            tiers.push(LexicalStartTier {
                                ranked: RankedLexicalTier {
                                    rank: PythonRank { cohort: 0 },
                                    tier,
                                    providers: Vec::new(),
                                },
                                head,
                            });
                        }
                    } else if let Some(location) = self.authored(self.fragment, event) {
                        tiers.push(LexicalStartTier {
                            ranked: RankedLexicalTier {
                                rank: PythonRank { cohort: 0 },
                                tier: RouteEdgeTier {
                                    edges: vec![location],
                                    coverage: coverage.clone(),
                                    blocks_fallback: true,
                                    ..Default::default()
                                },
                                providers: Vec::new(),
                            },
                            head: None,
                        });
                    }
                }
            }
        }
        self.rules.observations.borrow_mut().push(format!(
            "lexical scope={} selected={:?} residual={:?} unbound={:?} open={} stopped={:?}",
            scope.get(),
            state.selection.selected,
            state.selection.residual,
            state.selection.unbound,
            state.selection.open,
            state.selection.stopped
        ));
        {
            let mut inputs = self.rules.source_inputs.borrow_mut();
            let prepared = inputs
                .get_mut(&self.source.identity)
                .expect("prepared Python source half");
            // Source-row completion still carries its own persisted gaps and
            // exact discharges. Publish only the temporal endpoint obligation
            // here; copying that completion would reintroduce discharged gaps.
            if state.selection.open
                || !state.selection.unbound.is_empty()
                || state.selection.stopped.is_some()
                || (!state.selection.residual.is_empty()
                    && python_lexical::lexical_parent(state, &self.rows, scope.get()).is_none())
            {
                prepared.endpoint_completion = prepared
                    .endpoint_completion
                    .combine(&open(self.source.token));
            }
        }
        // Retain blockers even when no selected write can produce a target.
        tiers.push(LexicalStartTier {
            ranked: RankedLexicalTier {
                rank: PythonRank { cohort: 0 },
                tier: RouteEdgeTier {
                    coverage,
                    blocks_fallback: true,
                    ..Default::default()
                },
                providers: Vec::new(),
            },
            head: None,
        });
        Ok(Read::ready(tiers))
    }

    fn outer_can_compete(
        &self,
        placement: &PythonPlacement,
        _: Option<&PythonRank>,
        _: u32,
    ) -> bool {
        python_lexical::outer_can_compete(
            placement
                .lexical
                .borrow()
                .as_ref()
                .expect("selected lexical state"),
        )
    }
    fn lexical_starts(
        &self,
        selection: StartSelection<PythonRank, ()>,
        facts: &PlacementFacts<PythonTarget>,
    ) -> Vec<PlacementStart<(), PythonRank>> {
        if self.stopped.get() {
            return Vec::new();
        }
        let consumed = usize::from(!self.source.route.is_empty());
        selection
            .locations
            .into_iter()
            .map(|start| PlacementStart::Route {
                cursor: WalkCursor {
                    tag: facts.tag,
                    location: start.location,
                    consumed_prefix_segments: consumed,
                    start_step: consumed,
                    namespace: self.source.demand.namespace(),
                },
                anchor: ResolutionRootImportAnchor::Lexical,
                rank: start.rank,
                scope: start.scope,
            })
            .collect()
    }
    fn route_target(
        &self,
        location: RouteLocation,
        rank: Option<&PythonRank>,
        scope: Option<ResolutionScopeId>,
    ) -> PythonTarget {
        PythonTarget {
            location,
            rank: rank.copied(),
            scope,
        }
    }
    fn target_location(&self, target: &PythonTarget) -> RouteLocation {
        target.location.clone()
    }
    fn exports(
        &self,
        placement: &PythonPlacement,
        target: PythonTarget,
        completion: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        let target = target.location;
        if let RouteLocation::Container {
            unit,
            ref container,
        } = target
        {
            // Import endpoints bind a local alias. The selected source name
            // remains the module attribute (or terminal module segment).
            let lookup = self.import_name.as_ref().map_or_else(
                || self.source.demand.clone(),
                |name| {
                    ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        self.source.demand.namespace(),
                        name.as_str(),
                    )
                },
            );
            let star = match self.import_site {
                Some(site) if self.source.is_import => self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND import_site=?2 AND importer_container=?3 AND form='star')")?.query_row(
                    rusqlite::params![unit, site, placement.container], |row| row.get::<_, bool>(0),
                )?,
                _ => false,
            };
            let surface = if star { "wildcard" } else { "module" };
            let membership: Option<Option<u32>> = self
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT slot_site FROM python_unit_summary_export_names
                 WHERE summary_id=?1 AND container_path=?2 AND surface=?3 AND name=?4",
                )?
                .query_row(
                    rusqlite::params![unit, container, surface, lookup.spelling()],
                    |row| row.get(0),
                )
                .optional()?;
            let policy: Option<String> = self.rules.ready.inventory.connection().prepare_cached("SELECT policy FROM python_unit_summary_surfaces WHERE summary_id=?1 AND container_path=?2 AND surface=?3")?.query_row(
                rusqlite::params![unit,container,surface], |row| row.get(0),
            ).optional()?;
            self.rules.observations.borrow_mut().push(format!(
                "surface={surface} policy={policy:?} name={} member={}",
                lookup.spelling(),
                membership.is_some()
            ));
        }
        // Canonical export slots describe inventory only. Authored reaching
        // definitions require M4-3a's retained event reader, never hydration of
        // the slot as an ordinary root export.
        Ok(Some(ExportHydration {
            exports: Vec::new(),
            blockers: Vec::new(),
            unstaged: if matches!(target, RouteLocation::Owner { .. }) {
                completion.clone()
            } else {
                let RouteLocation::Container { ref container, .. } = target else {
                    unreachable!()
                };
                completion.combine(&self.module_attribute_space(container)?)
            },
            coverage: ExportCoverage::default(),
        }))
    }
    fn proven_targets(
        &self,
        placement: &PythonPlacement,
        target: &PythonTarget,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        self.rules.observations.borrow_mut().push(format!(
            "target cohort={:?} declaring-scope={:?}",
            target.rank, target.scope
        ));
        let (locations, mut evidence) = match &target.location {
            RouteLocation::Owner { .. } => (vec![target.location.clone()], completion.clone()),
            RouteLocation::Container { container, .. } => {
                let name = self
                    .import_name
                    .as_deref()
                    .unwrap_or(self.source.demand.spelling());
                let star = match self.import_site {
                    Some(site) if self.source.is_import => self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND importer_container=?2 AND import_site=?3 AND form='star')")?.query_row(
                        rusqlite::params![self.rules.summary,placement.container,site],|row|row.get::<_,bool>(0),
                    )?,
                    _ => false,
                };
                if star && !self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_export_names WHERE summary_id=?1 AND container_path=?2 AND surface='wildcard' AND name=?3)")?.query_row(
                    rusqlite::params![self.rules.summary,container,name], |row|row.get::<_,bool>(0),
                )? {
                    let closed = self.wildcard_inventory_closed(container, name)?;
                    return Ok(Read::Ready { value:Vec::new(), completion: if closed { completion.clone() } else { completion.combine(&open(self.source.token)) } });
                }
                let module_import = match self.import_site {
                    Some(site) if self.source.is_import => self.rules.ready.inventory.connection().prepare_cached("SELECT EXISTS(SELECT 1 FROM python_unit_summary_imports WHERE summary_id=?1 AND importer_container=?2 AND import_site=?3 AND form='module')")?.query_row(
                        rusqlite::params![self.rules.summary, placement.container, site], |row| row.get::<_, bool>(0),
                    )?,
                    _ => false,
                };
                if self.import_module_operand.is_some()
                    || module_import
                    || (!self.source.is_import
                        && self.import_site.is_none()
                        && self.source.route.is_empty()
                        && self.source.prefix.is_none())
                {
                    let (view, registry) = self.rules.imported_module_view(container)?;
                    (
                        self.module_owner(&view)?.into_iter().collect(),
                        completion.combine(&registry),
                    )
                } else {
                    let lookup = ResolutionLookupSemanticRecipe::new(
                        Language::Python,
                        self.source.demand.namespace(),
                        name,
                    );
                    let route = self
                        .source
                        .route
                        .iter()
                        .cloned()
                        .chain(std::iter::once(lookup))
                        .collect::<Vec<_>>();
                    let cursor = WalkCursor {
                        tag: (),
                        location: target.location.clone(),
                        consumed_prefix_segments: self.source.route.len(),
                        start_step: 0,
                        namespace: self.source.demand.namespace(),
                    };
                    let mut coverage = completion.clone();
                    let reached = match walk_lookup_route(
                        &PythonRoute {
                            half: self,
                            placement,
                        },
                        cursor,
                        &route,
                        &mut coverage,
                        self.rules.cancellation,
                    )? {
                        Read::Ready {
                            value,
                            completion: read,
                        } => {
                            coverage = coverage.combine(&read);
                            value
                        }
                        Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                        Read::Unavailable { reason, completion } => {
                            return Ok(Read::Unavailable { reason, completion });
                        }
                    };
                    let mut locations = Vec::new();
                    for cursor in reached {
                        let location = cursor.location;
                        match location {
                            RouteLocation::Container { container, .. } => {
                                let (view, registry) =
                                    self.rules.imported_module_view(&container)?;
                                coverage = coverage.combine(&registry);
                                if let Some(owner) = self.module_owner(&view)? {
                                    locations.push(owner);
                                }
                            }
                            RouteLocation::Owner { .. } => locations.push(location),
                        }
                    }
                    (locations, coverage)
                }
            }
        };
        let mut targets = Vec::new();
        for location in locations {
            let RouteLocation::Owner { definition, .. } = location else {
                unreachable!("module attribute projection emits authored definitions")
            };
            match self.proven_owner(definition, &evidence)? {
                Read::Ready { value, completion } => {
                    evidence = evidence.combine(&completion);
                    targets.extend(value);
                }
                Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
                Read::Unavailable { reason, completion } => {
                    return Ok(Read::Unavailable { reason, completion });
                }
            }
        }
        Ok(Read::Ready {
            value: targets,
            completion: evidence,
        })
    }
    fn empty_placement(
        &mut self,
        _: &PlacementFacts<PythonTarget>,
        observation: &mut HalfObservation,
    ) -> Result<()> {
        observation.completion = observation
            .completion
            .combine(&self.empty_module_read.borrow());
        Ok(())
    }
    fn empty_target(
        &self,
        _: &PythonPlacement,
        target: &PythonTarget,
    ) -> Result<ResolutionCompletion> {
        match &target.location {
            RouteLocation::Owner { .. } => Ok(ResolutionCompletion::Complete),
            RouteLocation::Container { container, .. } => self.provider_completion(container),
        }
    }
}

impl PythonHalf<'_, '_, '_> {
    fn proven_owner(
        &self,
        definition: SemanticId,
        completion: &ResolutionCompletion,
    ) -> Result<Read<Vec<ProvenTarget>>> {
        // Namespace qualifiers are values even in a type path. Only the
        // terminal qualified type must denote a class, including the
        // QualifierIsNamespace route which bypasses typed member selection.
        if self.source.demand.namespace() == ResolutionNamespace::Type
            && !self.source.is_import
            && (self.source.prefix.is_some() || !self.source.route.is_empty())
            && !super::python_members::is_class(self.rules.ready, definition)?
        {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: completion.combine(&open(self.source.token)),
            });
        }
        if self
            .rules
            .ready
            .context_identities
            .model_member_identity(definition)
            .is_some()
        {
            return Ok(Read::ready(vec![ProvenTarget {
                target: self
                    .rules
                    .model_target(definition, &self.source.demand, self.fragment),
                material: BridgeMaterial::same_language(Language::Python),
            }]));
        }
        let paths = self.rules.ready.lexical_source();
        let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) =
            paths.semantic_provenance(definition, self.rules.cancellation)?
        else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(definition),
            });
        };
        let Some(node) = paths.lookup_definition_node(definition, self.rules.cancellation)? else {
            return Ok(Read::Ready {
                value: Vec::new(),
                completion: open(definition),
            });
        };
        Ok(Read::ready(vec![ProvenTarget {
            target: SelectedMemberTarget {
                fragment: provenance.mount().fragment(),
                token: definition,
                definition: node,
                lookup: self.source.demand.clone(),
                completion: completion.clone(),
            },
            material: BridgeMaterial::same_language(Language::Python),
        }]))
    }
}

struct PythonRoute<'a, 'store, 'input> {
    half: &'a PythonHalf<'a, 'store, 'input>,
    placement: &'a PythonPlacement,
}
impl<T: Clone + Eq + std::hash::Hash> RouteRules<T> for PythonRoute<'_, '_, '_> {
    fn member_request(
        &self,
        cursor: &WalkCursor<T>,
        lookup: &ResolutionLookupSemanticRecipe,
    ) -> Result<Read<Option<crate::analyzer::resolution::DemandMemberSelectionRequest>>> {
        Ok(Read::ready(
            self.half.owner_request(&cursor.location, lookup)?,
        ))
    }
    fn root_starts(
        &self,
        start: &WalkCursor<T>,
        completion: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
        if let RouteLocation::Container { container, .. } = &start.location {
            *completion = completion.combine(&self.half.provider_completion(container)?);
        }
        if let Some(site) = self.half.import_site {
            *completion = completion.combine(&self.half.import_route_completion(site)?);
            let key = (
                self.half.rules.summary,
                self.placement.container.clone(),
                site,
            );
            let destinations = if let Some(rows) =
                self.half.rules.summary_imports.borrow().get(&key).cloned()
            {
                rows
            } else {
                let rows = self
                .half
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT imports.target_container,imports.form,imports.module_name,coalesce(provider.rel_path,''),imports.state
                 FROM main.python_unit_summary_imports imports
                 LEFT JOIN main.python_unit_summary_providers provider
                   ON provider.summary_id=imports.summary_id AND provider.container_path=imports.target_container
                 WHERE imports.summary_id=?1 AND imports.importer_container=?2 AND imports.import_site=?3",
                )?
                .query_map(
                    rusqlite::params![self.half.rules.summary, self.placement.container, site],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
                let rows = std::sync::Arc::new(rows);
                if !self.half.rules.cancellation.is_cancelled() {
                    self.half
                        .rules
                        .summary_imports
                        .borrow_mut()
                        .insert(key, std::sync::Arc::clone(&rows));
                }
                rows
            };
            self.half.rules.observations.borrow_mut().push(format!(
                "import-site={site} destinations={:?}",
                destinations
                    .iter()
                    .map(|(_, form, module, path, _)| (form, module, path))
                    .collect::<Vec<_>>()
            ));
            if let Some((module_segments, prefix_len)) = self.half.import_module_operand {
                let mut locations = Vec::new();
                for (destination, _, module, _, state) in destinations.iter() {
                    if state == "relative_context_open" {
                        continue;
                    }
                    // Summary names already carry the importer's relative
                    // package context. Select this exact module prefix.
                    let components = module.split('.').collect::<Vec<_>>();
                    let Some(context_len) = components.len().checked_sub(module_segments as usize)
                    else {
                        continue;
                    };
                    let prefix_end = context_len + prefix_len as usize;
                    let Some(prefix) = components.get(..prefix_end) else {
                        continue;
                    };
                    let prefix_name = prefix.join(".");
                    let key = (
                        self.half.rules.summary,
                        prefix_name.clone(),
                        destination.clone(),
                        module.clone(),
                    );
                    let mut candidates = if let Some(rows) =
                        self.half.rules.prefix_providers.borrow().get(&key).cloned()
                    {
                        rows
                    } else {
                        let mut statement = self.half.rules.ready.inventory.connection().prepare_cached(
                        "SELECT provider.container_path,root.root_path,root.authority
                         FROM main.python_unit_summary_providers provider
                         JOIN main.python_unit_summary_roots root ON root.summary_id=provider.summary_id AND root.root_slot=provider.root_slot
                         WHERE provider.summary_id=?1 AND (provider.module_name=?2 OR (
                           NOT EXISTS(SELECT 1 FROM python_unit_summary_providers exact WHERE exact.summary_id=?1 AND exact.module_name=?2 AND exact.state IN ('selected','alternative'))
                           AND EXISTS(SELECT 1 FROM python_unit_summary_spellings prefix JOIN python_unit_summary_spellings full_spelling ON full_spelling.summary_id=prefix.summary_id AND full_spelling.source_root=prefix.source_root
                             WHERE prefix.summary_id=?1 AND prefix.module_name=?2 AND prefix.target_container=provider.container_path AND prefix.admitted
                               AND full_spelling.module_name=?4 AND full_spelling.target_container=?3 AND full_spelling.admitted))) AND provider.state IN ('selected','alternative')
                           AND (root.authority<>'workspace' OR ?3=''
                            OR provider.root_slot=(SELECT root_slot FROM main.python_unit_summary_providers WHERE summary_id=?1 AND container_path=?3))",
                    )?;
                        let rows = statement
                            .query_map(
                                rusqlite::params![
                                    self.half.rules.summary,
                                    prefix_name,
                                    destination,
                                    module
                                ],
                                |row| {
                                    Ok((
                                        row.get::<_, String>(0)?,
                                        std::path::PathBuf::from(row.get::<_, String>(1)?),
                                        row.get::<_, String>(2)?,
                                    ))
                                },
                            )?
                            .collect::<rusqlite::Result<Vec<_>>>()?;
                        if !self.half.rules.cancellation.is_cancelled() {
                            self.half
                                .rules
                                .prefix_providers
                                .borrow_mut()
                                .insert(key, rows.clone());
                        }
                        rows
                    };
                    if candidates
                        .first()
                        .is_some_and(|candidate| candidate.2 == "workspace")
                    {
                        // Even an absent terminal module can have a real prefix.
                        // Its providers obey the same importing-root rule.
                        let mount = self.half.rules.ready.inventory.mount_record_by_ordinal(
                            SelectedResolutionMountOrdinal::new(self.half.fragment.ordinal()),
                        )?;
                        brokk_bifrost_python::graph_support::retain_nearest_owning_root(
                            std::path::Path::new(mount.persisted_relative_path()),
                            &mut candidates,
                            |candidate| candidate.1.clone(),
                        );
                    }
                    for (container, _, _) in candidates {
                        let location = RouteLocation::Container {
                            unit: self.half.rules.summary,
                            container,
                        };
                        if !locations.contains(&location) {
                            locations.push(location);
                        }
                    }
                }
                return Ok(RouteStarts {
                    locations,
                    consumed: self.half.source.route.len(),
                });
            }
            if destinations
                .iter()
                .any(|(_, form, _, _, _)| form != "module")
            {
                let mut locations = Vec::new();
                for (container, ..) in destinations.iter() {
                    if container.is_empty() {
                        continue;
                    }
                    let (container, registry) = self.half.rules.imported_module_view(container)?;
                    *completion = completion.combine(&registry);
                    locations.push(RouteLocation::Container {
                        unit: self.half.rules.summary,
                        container,
                    });
                }
                return Ok(RouteStarts {
                    locations,
                    consumed: self.half.source.route.len(),
                });
            }
        }
        if self.half.source.anchor == ResolutionRootImportAnchor::Lexical {
            return Ok(RouteStarts {
                locations: vec![start.location.clone()],
                consumed: 0,
            });
        }
        Ok(RouteStarts {
            locations: vec![start.location.clone()],
            consumed: 0,
        })
    }
    fn route_tier(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
        tier: usize,
    ) -> Result<Option<RouteEdgeTier>> {
        if tier != 0 {
            return Ok(None);
        }
        let RouteLocation::Container { unit, container } = &cursor.location else {
            return Ok(Some(RouteEdgeTier {
                // A class has the member provider above. Other owner values
                // have no container/member provider proved by this route.
                blockers: match &cursor.location {
                    RouteLocation::Owner { definition, .. }
                        if super::python_members::is_class(self.half.rules.ready, *definition)? =>
                    {
                        ResolutionCompletion::Complete
                    }
                    _ => open(self.half.source.token),
                },
                blocks_fallback: true,
                ..Default::default()
            }));
        };
        assert_eq!(*unit, self.half.rules.summary);
        let mut providers = self
            .half
            .rules
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT child.container_path,child.module_name,child.root_slot,child.kind,child.rel_path,child.state FROM main.python_unit_summary_providers child
             WHERE child.summary_id=?1 AND child.state IN ('selected','alternative')
               AND child.module_name=CASE WHEN ?2='' THEN ?3 ELSE
                   (SELECT parent.module_name FROM main.python_unit_summary_providers parent
                    WHERE parent.summary_id=?1 AND parent.container_path=?2) || '.' || ?3 END
               AND (?2='' OR EXISTS(
                   SELECT 1 FROM main.python_unit_summary_providers parent
                   WHERE parent.summary_id=?1 AND parent.container_path=?2
                     AND parent.kind IN ('package','namespace')
                     AND parent.root_slot=child.root_slot))",
            )?
            .query_map(
                rusqlite::params![unit, container, segment.spelling()],
                |row| {
                    Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, i64>(2)?,row.get::<_, String>(3)?,row.get::<_, String>(4)?,row.get::<_, String>(5)?))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
        if providers.is_empty() && !container.is_empty() {
            let conn = self.half.rules.ready.inventory.connection();
            let module = conn.prepare_cached("SELECT module_name || '.' || ?3 FROM python_unit_summary_providers WHERE summary_id=?1 AND container_path=?2 AND kind IN ('package','namespace')")?.query_row(rusqlite::params![unit,container,segment.spelling()], |row|row.get::<_,String>(0)).optional()?;
            if let Some(module) = module {
                let mount = self.half.rules.ready.inventory.mount_record_by_ordinal(
                    SelectedResolutionMountOrdinal::new(self.half.fragment.ordinal()),
                )?;
                let mut candidates = conn.prepare_cached("SELECT target_container,source_root,admitted FROM python_unit_summary_spellings WHERE summary_id=?1 AND module_name=?2")?.query_map(rusqlite::params![unit,module], |row| Ok((row.get::<_,String>(0)?,std::path::PathBuf::from(row.get::<_,String>(1)?),row.get::<_,bool>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                brokk_bifrost_python::graph_support::retain_nearest_owning_root(
                    std::path::Path::new(mount.persisted_relative_path()),
                    &mut candidates,
                    |candidate| candidate.1.clone(),
                );
                candidates.retain(|candidate| candidate.2);
                if let [candidate] = candidates.as_slice() {
                    providers.push(conn.prepare_cached("SELECT container_path,module_name,root_slot,kind,rel_path,state FROM python_unit_summary_providers WHERE summary_id=?1 AND container_path=?2")?.query_row(rusqlite::params![unit,candidate.0], |row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))?);
                }
            }
        }
        self.half.rules.observations.borrow_mut().push(format!(
            "segment={} providers={:?}",
            segment.spelling(),
            providers
                .iter()
                .map(|(_, module, root, kind, path, state)| (module, root, kind, path, state))
                .collect::<Vec<_>>()
        ));
        // Python reference 7.11: from-import reads the attribute, then imports a missing package child.
        let from_import = self.half.import_module_operand.is_none() && self.half.import_site.map_or_else(
            || cursor.consumed_prefix_segments == 0
                && self.placement.lexical.borrow().as_ref().is_some_and(|state| {
                !state.selection.selected.is_empty()
                    && state.selection.selected.iter().all(|selected| self.half.rows.imports.iter().any(|import|
                        import.binding_event == Some(selected.occurrence)
                            && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::From))
            }),
            |site| self.half.import_name.as_deref() == Some(segment.spelling())
                && self.half.rows.imports.iter().any(|import| import.import_site.get() == site
                    && import.form == brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm::From),
        );
        let from_import_child = from_import
            && !MODULE_OBJECT_ATTRIBUTES.contains(&segment.spelling())
            && providers
                .iter()
                .any(|(_, _, _, kind, _, _)| matches!(kind.as_str(), "module" | "package"));
        let mut attached_child =
            !from_import && !providers.is_empty() && self.half.import_module_operand.is_none();
        if attached_child {
            for (child, ..) in &providers {
                if !self.half.imported_child_is_attached(child)? {
                    attached_child = false;
                    break;
                }
            }
        }
        let namespace_without_child = providers.is_empty()
            && self
                .half
                .rules
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM python_unit_summary_providers
                 WHERE summary_id=?1 AND container_path=?2 AND kind='namespace'
                   AND state IN ('selected','alternative'))",
                )?
                .query_row(rusqlite::params![unit, container], |row| {
                    row.get::<_, bool>(0)
                })?;
        // A curated star import reads the package attribute first and imports
        // a missing name as a child. Identify this particular lexical route;
        // ordinary module reads and public-name stars retain their open proof.
        let curated_star = cursor.consumed_prefix_segments == 0
            && self
                .placement
                .lexical
                .borrow()
                .as_ref()
                .is_some_and(|state| {
                    state.selection.selected.len() == 1
                        && self
                            .placement
                            .stars
                            .borrow()
                            .get(&state.selection.selected[0].occurrence)
                            .is_some_and(|starts| {
                                starts.iter().any(|(location, head)| {
                                    location == &cursor.location
                                        && head.spelling() == segment.spelling()
                                })
                            })
                })
            && self
                .half
                .rules
                .wildcard_inventories
                .borrow()
                .get(container)
                .is_some_and(|(closed, public_names)| *closed && !*public_names);
        let star_child_owner = if curated_star
            && !MODULE_OBJECT_ATTRIBUTES.contains(&segment.spelling())
            && providers.len() == 1
            && matches!(providers[0].3.as_str(), "module" | "package")
            && providers[0].5 == "selected"
            && self.half.provider_completion(&providers[0].0)? == ResolutionCompletion::Complete
        {
            self.half.module_owner(&providers[0].0)?
        } else {
            None
        };
        let mut edges: Vec<_> = providers
            .into_iter()
            .map(|(container, ..)| RouteLocation::Container {
                unit: *unit,
                container,
            })
            .collect();
        let mut lookup_continuations = Vec::new();
        let mut coverage = self.half.provider_completion(container)?;
        if namespace_without_child {
            // Another namespace portion or an unacquired environment provider
            // may supply this child. An empty selected portion proves no absence.
            coverage = coverage.combine(&open(self.half.source.token));
        }
        if !container.is_empty() && self.half.import_module_operand.is_none() {
            let remaining = self
                .half
                .source
                .route
                .iter()
                .chain(std::iter::once(&self.half.source.demand))
                .skip(cursor.consumed_prefix_segments + 1)
                .map(|part| part.spelling().to_owned())
                .collect::<Vec<_>>();
            let locations = if let Some(child_owner) = star_child_owner {
                match self.half.module_binding_selection(
                    container,
                    segment.spelling(),
                    &remaining,
                )? {
                    Read::Ready { value, completion }
                        if completion == ResolutionCompletion::Complete
                            && !value.selected_binding =>
                    {
                        debug_assert!(value.is_empty());
                        edges.clear();
                        edges.push(child_owner);
                        Read::Ready {
                            value: PythonModuleRead::default(),
                            completion,
                        }
                    }
                    Read::Ready { value, completion }
                        if completion == ResolutionCompletion::Complete
                            && !value.locations.is_empty() =>
                    {
                        debug_assert!(value.selected_binding);
                        edges.clear();
                        Read::Ready { value, completion }
                    }
                    Read::Ready { .. } => {
                        self.half
                            .module_locations(container, segment.spelling(), &remaining)?
                    }
                    Read::Cancelled(completion) => Read::Cancelled(completion),
                    Read::Unavailable { reason, completion } => {
                        Read::Unavailable { reason, completion }
                    }
                }
            } else if attached_child {
                // Loading P.N sets P.N after P/__init__ has executed.
                Read::Ready {
                    value: PythonModuleRead::default(),
                    completion: self.half.module_attribute_space(container)?,
                }
            } else if from_import_child {
                self.half
                    .module_binding_selection(container, segment.spelling(), &remaining)?
            } else {
                self.half
                    .module_locations(container, segment.spelling(), &remaining)?
            };
            match locations {
                Read::Ready { value, completion } => {
                    if value.is_empty() {
                        let mut gap = self.half.empty_module_read.borrow_mut();
                        *gap = gap.combine(&completion);
                    }
                    // Completed-module reads retain the attribute/child union.
                    // During this package's initialization a reaching attribute
                    // wins; only an absent attribute permits the child import.
                    if from_import_child
                        && !value.is_empty()
                        && completion == ResolutionCompletion::Complete
                        && self.placement.container == *container
                        && self
                            .half
                            .rules
                            .initializing_package_import(
                                container,
                                self.half
                                    .import_site
                                    .map(|import_site| PythonModuleObservation {
                                        mount: self.half.fragment.ordinal(),
                                        import_site,
                                    }),
                            )?
                            .is_some()
                    {
                        edges.clear();
                    }
                    edges.extend(value.locations);
                    lookup_continuations.extend(value.lookup_continuations);
                    coverage = coverage.combine(&completion);
                }
                Read::Cancelled(completion) | Read::Unavailable { completion, .. } => {
                    coverage = coverage.combine(&completion);
                }
            }
        }
        Ok(Some(RouteEdgeTier {
            edges,
            lookup_continuations,
            coverage,
            independent: true,
            ..Default::default()
        }))
    }
    fn dead_end(
        &self,
        cursor: &WalkCursor<T>,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        match &cursor.location {
            RouteLocation::Container { container, .. } => self.half.provider_completion(container),
            RouteLocation::Owner { .. } => Ok(ResolutionCompletion::Complete),
        }
    }
}

/// One selected, external import route in a caller file. Source spelling is
/// retained as structured segments; summary module text is never an identity.
/// Relative routes can support a boundary claim only, never runtime/model admission.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PythonSelectedImportBoundary {
    pub fragment: BindingFragmentId,
    pub blob: i64,
    pub import_site: ResolutionSiteId,
    pub form: brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm,
    pub relative_level: u32,
    pub module_segment_count: u32,
    pub binding_event: Option<u32>,
    pub route: Vec<String>,
    pub bound_name: Option<String>,
    /// Prefix retained by the root binder. Unaliased dotted module imports
    /// bind their head; explicit aliases bind the complete module route.
    pub binding_segment_count: u32,
    pub completion: ResolutionCompletion,
}

/// The temporal proof accompanying one selected import along its native route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PythonExternalSelectionState {
    pub fragment: BindingFragmentId,
    pub blob: i64,
    pub binding_event: u32,
    pub selected_region: Vec<(u64, bool)>,
    pub residual_regions: Vec<Vec<(u64, bool)>>,
    pub unbound_regions: Vec<Vec<(u64, bool)>>,
    pub open: bool,
    pub completion: ResolutionCompletion,
}

impl PythonExternalSelectionState {
    fn new(
        fragment: BindingFragmentId,
        blob: i64,
        state: &crate::analyzer::resolution::temporal_binding::TemporalSelection,
        selected: &crate::analyzer::resolution::temporal_binding::SelectedOccurrence,
    ) -> Self {
        Self {
            fragment,
            blob,
            binding_event: selected.occurrence,
            selected_region: selected.region.0.clone(),
            residual_regions: state
                .residual
                .iter()
                .map(|region| region.0.clone())
                .collect(),
            unbound_regions: state
                .unbound
                .iter()
                .map(|region| region.0.clone())
                .collect(),
            open: state.open,
            completion: state.completion.clone(),
        }
    }
}

/// Request-local evidence from native reaching-import selection.
#[derive(Clone, Debug)]
pub struct PythonSelectedExternalImport {
    pub boundary: PythonSelectedImportBoundary,
    pub consumed_prefix: Vec<String>,
    pub remaining_member_path: Vec<String>,
    pub completion: ResolutionCompletion,
    pub identity_is_unique: bool,
    /// The import is unique at this read. This supports only a boundary claim;
    /// runtime/model identity still requires identity_is_unique.
    pub boundary_is_unique: bool,
    pub selection: Vec<PythonExternalSelectionState>,
}

impl PythonSelectedExternalImport {
    // Multiple paths can reach one retained route. No earlier observation can
    // hide a later open boundary or a conflicting temporal selection.
    fn merge_observation(&mut self, other: Self) {
        let same_selection = self.consumed_prefix == other.consumed_prefix
            && self.completion == other.completion
            && self.boundary.completion == other.boundary.completion
            && self.selection == other.selection;
        self.identity_is_unique &= other.identity_is_unique && same_selection;
        self.boundary_is_unique &= other.boundary_is_unique && same_selection;
        self.boundary.completion = self.boundary.completion.combine(&other.boundary.completion);
        self.completion = self.completion.combine(&other.completion);
        for state in other.selection {
            if !self.selection.contains(&state) {
                self.selection.push(state);
            }
        }
    }
}

fn retain_external_import_observations(
    selected: &mut Vec<PythonSelectedExternalImport>,
    imports: Vec<PythonSelectedExternalImport>,
) {
    for import in imports {
        if let Some(old) = selected.iter_mut().find(|old| {
            old.boundary.fragment == import.boundary.fragment
                && old.boundary.blob == import.boundary.blob
                && old.boundary.import_site == import.boundary.import_site
                && old.remaining_member_path == import.remaining_member_path
        }) {
            old.merge_observation(import);
        } else {
            selected.push(import);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PythonExternalSelectionSource {
    Root(CandidatePathIdentity),
    Member(crate::analyzer::resolution::QualifiedMemberId),
}

#[derive(Default)]
pub(super) struct PythonExternalImports {
    pub(super) requested_reference: Option<SemanticId>,
    observed_imports: HashSet<(String, u32)>,
    selections: HashMap<
        SemanticId,
        HashMap<PythonExternalSelectionSource, Vec<PythonSelectedExternalImport>>,
    >,
}

pub(super) fn selected_external_imports(
    imports: &RefCell<PythonExternalImports>,
    reference: SemanticId,
) -> Vec<PythonSelectedExternalImport> {
    let mut imports = imports
        .borrow()
        .selections
        .get(&reference)
        .into_iter()
        .flat_map(|halves| halves.values())
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    imports.sort_by(|a, b| {
        (
            a.boundary.fragment,
            a.boundary.blob,
            a.boundary.import_site.get(),
            &a.remaining_member_path,
        )
            .cmp(&(
                b.boundary.fragment,
                b.boundary.blob,
                b.boundary.import_site.get(),
                &b.remaining_member_path,
            ))
    });
    let mut selected: Vec<PythonSelectedExternalImport> = Vec::new();
    for import in imports {
        if let Some(previous) = selected.last_mut().filter(|previous| {
            previous.boundary.fragment == import.boundary.fragment
                && previous.boundary.blob == import.boundary.blob
                && previous.boundary.import_site == import.boundary.import_site
                && previous.remaining_member_path == import.remaining_member_path
        }) {
            previous.merge_observation(import);
        } else {
            selected.push(import);
        }
    }
    selected
}

// A source-root miss names every raw candidate, including structurally rejected
// roots. This evidence belongs to the selected import, not the whole environment.
fn source_root_gap(
    conn: &rusqlite::Connection,
    summary: i64,
    imports: &HashSet<(String, u32)>,
) -> Result<Option<(String, Vec<String>)>> {
    let mut imports = imports.iter().collect::<Vec<_>>();
    imports.sort();
    for (path, site) in imports {
        let mut modules = conn.prepare_cached("SELECT DISTINCT imported.module_name FROM python_unit_summary_imports imported JOIN resolution_unit_summary_members member ON member.summary_id=imported.summary_id AND member.member_ordinal=imported.member_ordinal WHERE imported.summary_id=?1 AND member.rel_path=?2 AND imported.import_site=?3 AND imported.relative_level=0 AND instr(imported.module_name,'.')>0")?;
        let modules = modules
            .query_map(rusqlite::params![summary, path, site], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for module in modules {
            let mut names = conn.prepare_cached("SELECT DISTINCT provider.module_name,provider.rel_path FROM python_unit_summary_spellings spelling JOIN python_unit_summary_providers provider ON provider.summary_id=spelling.summary_id AND provider.container_path=spelling.target_container WHERE spelling.summary_id=?1 AND spelling.module_name=?2 ORDER BY provider.module_name,provider.rel_path")?.query_map(rusqlite::params![summary,module], |row|Ok(format!("{} ({})",row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            names.sort();
            names.dedup();
            if !names.is_empty() {
                return Ok(Some((module, names)));
            }
        }
    }
    Ok(None)
}

/// Python admission inputs accompany the ordinary shared definition projection.
pub struct PythonDefinitionAnswer {
    pub modeled_definitions: Vec<(
        SemanticId,
        crate::analyzer::semantic_model::ModelSymbolRef,
        crate::analyzer::semantic_model::SemanticModelSymbol,
    )>,
    pub dispatch_extensibility: Option<DispatchExtensibility>,
    pub reference: super::native_units::SelectedNativeReferenceUnits,
    pub selected_external_imports: Vec<PythonSelectedExternalImport>,
    pub source_root_gap: Option<(String, Vec<String>)>,
}

impl PythonRules<'_, '_, '_> {
    fn reference_for_source(&self, source: &SourceHalf) -> SemanticId {
        if source.is_import {
            source.token
        } else {
            *self
                .prepared_references
                .borrow()
                .get(&source.identity)
                .expect("native source reference classification precedes selection")
        }
    }

    fn retain_external_imports(
        &self,
        source: &SourceHalf,
        imports: Vec<PythonSelectedExternalImport>,
    ) {
        if imports.is_empty() {
            return;
        }
        let mut retained = self.external_imports.borrow_mut();
        if retained.requested_reference.is_none() {
            return;
        }
        let selected = retained
            .selections
            .entry(self.reference_for_source(source))
            .or_default()
            .entry(PythonExternalSelectionSource::Root(source.identity))
            .or_default();
        retain_external_import_observations(selected, imports);
    }

    fn external_import_boundary(
        &self,
        fragment: BindingFragmentId,
        site: u32,
    ) -> Result<Option<PythonSelectedImportBoundary>> {
        if self.external_imports.borrow().requested_reference.is_none() {
            return Ok(None);
        }
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(None);
        }
        let mount = self
            .ready
            .inventory
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(fragment.ordinal()))?;
        let blob = mount.blob_id();
        let connection = self.ready.inventory.connection();
        let row = connection.prepare_cached("SELECT authored.form,authored.relative_level,authored.module_segments,authored.binding_event,json(authored.route),slot.name,
                CASE WHEN authored.form=0 AND NOT EXISTS(SELECT 1 FROM resolution_root_import_segments prefix WHERE prefix.blob_id=authored.blob_id AND prefix.import_site=authored.import_site) THEN 1 ELSE json_array_length(authored.route) END,member.rel_path
             FROM python_binding_imports authored
             JOIN resolution_unit_summary_members member ON member.summary_id=?3 AND member.blob_id=authored.blob_id AND member.rel_path=?4
             LEFT JOIN resolution_binding_events event ON event.blob_id=authored.blob_id AND event.event=authored.binding_event
             LEFT JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id AND slot.slot=event.slot
             WHERE authored.blob_id=?1 AND authored.import_site=?2
               AND EXISTS(SELECT 1 FROM python_unit_summary_imports route WHERE route.summary_id=?3 AND route.member_ordinal=member.member_ordinal AND route.import_site=authored.import_site AND route.state='provider_open')
               AND NOT EXISTS(SELECT 1 FROM python_unit_summary_imports route WHERE route.summary_id=?3 AND route.member_ordinal=member.member_ordinal AND route.import_site=authored.import_site AND route.target_container!='')
               AND (authored.relative_level=0 OR ((SELECT count(DISTINCT route.module_name) FROM python_unit_summary_imports route WHERE route.summary_id=?3 AND route.member_ordinal=member.member_ordinal AND route.import_site=authored.import_site)=1
                 AND NOT EXISTS(SELECT 1 FROM python_unit_summary_imports route WHERE route.summary_id=?3 AND route.member_ordinal=member.member_ordinal AND route.import_site=authored.import_site AND route.state!='provider_open')))")?.query_row(
            rusqlite::params![blob, site, self.summary, mount.persisted_relative_path()], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,u32>(1)?,row.get::<_,u32>(2)?,row.get::<_,Option<u32>>(3)?,row.get::<_,String>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,u32>(6)?,row.get::<_,String>(7)?))
        ).optional()?;
        let Some((
            form,
            relative_level,
            module_segment_count,
            binding_event,
            route,
            bound_name,
            binding_segment_count,
            path,
        )) = row
        else {
            return Ok(None);
        };
        use brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm;
        let form = match form {
            0 => PythonNativeImportForm::Module,
            1 => PythonNativeImportForm::From,
            2 => PythonNativeImportForm::Star,
            _ => return Err(StoreError::corrupt("invalid retained Python import form")),
        };
        let route = serde_json::from_str(&route).map_err(|error| {
            StoreError::corrupt(format!("invalid Python import route: {error}"))
        })?;
        Ok(Some(PythonSelectedImportBoundary {
            fragment,
            blob,
            import_site: ResolutionSiteId::new(site),
            form,
            relative_level,
            module_segment_count,
            binding_event,
            route,
            bound_name,
            binding_segment_count,
            completion: import_route_obligation(
                self.ready,
                self.summary,
                &path,
                site,
                "provider_open",
            )?
            .0,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn project_python_named_argument<
    P: crate::analyzer::resolution::DemandRootProvider + ?Sized,
>(
    ready: &ReadySelectedResolution<'_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    provider: &mut P,
    reference: SemanticId,
    summary: i64,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
    mutations: &super::PythonMutationQuery<'_, '_>,
) -> Result<(
    Option<super::native_units::SelectedNativeNamedArgument>,
    Vec<SemanticId>,
    bool,
)> {
    struct PythonNamedArguments<'a, P: ?Sized> {
        ready: &'a ReadySelectedResolution<'a, 'a>,
        provider: &'a mut P,
        cancellation: &'a CancellationToken,
        session: &'a ResolutionSession,
        reference: SemanticId,
        callee: Option<SemanticId>,
        summary: i64,
        open_reason: Option<&'static str>,
        possible_classes: Vec<SemanticId>,
        callee_complete: bool,
        class_constructor: Option<SemanticId>,
        class_owners: Vec<SemanticId>,
        mutations: &'a super::PythonMutationQuery<'a, 'a>,
    }
    impl<P: crate::analyzer::resolution::DemandRootProvider + ?Sized> PythonNamedArguments<'_, P> {
        fn load_binding_rows(
            &self,
            blob: i64,
            oid: Option<git2::Oid>,
        ) -> Result<Option<brokk_bifrost_core::retention_budget::BudgetedValue<PythonBindingRows>>>
        {
            PythonBindingRows::load(
                self.ready.inventory.connection(),
                &self.ready.store.cache_budget,
                blob,
                oid,
                self.cancellation,
            )
        }
        fn class_member_absent(
            &mut self,
            operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            owner: SemanticId,
            name: &str,
        ) -> Result<bool> {
            use crate::analyzer::resolution::{
                DemandReferenceKey, HierarchyPolicy, QualifiedMemberInput,
                QualifiedMemberRegistration, ResolutionTypeRef,
            };
            let mount = self.ready.inventory.mount_record_by_ordinal(
                SelectedResolutionMountOrdinal::new(
                    self.reference.ordinal().expect("positioned label"),
                ),
            )?;
            let lookup = ResolutionLookupSemanticRecipe::new(
                Language::Python,
                ResolutionNamespace::Value,
                name,
            )
            .semantic(&self.ready.shared_names());
            let registered = self
                .provider
                .qualified_members()
                .is_some_and(|members| members.register_query_lookup(lookup, name));
            assert!(
                registered,
                "Python constructor probe requires a Python member provider"
            );
            let Some(selected) = operation.resolve_member_by_demand(
                QualifiedMemberInput {
                    reference: DemandReferenceKey::caller(self.reference),
                    route_ordinal: 0,
                    precedence: 0,
                    fragment: mount.fragment_id(),
                    source_lookup: lookup,
                    lookup,
                    namespace: ResolutionNamespace::Value,
                    values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        owner, 0,
                    ))],
                    completion: ResolutionCompletion::Complete,
                    registration: QualifiedMemberRegistration {
                        language: Language::Python,
                        hierarchy_identity: super::python_members::PYTHON_HIERARCHY.identity().0,
                        member_access: true,
                    },
                },
                self.provider,
            )?
            else {
                return Ok(false);
            };
            if !selected.access.targets.is_empty() {
                return Ok(false);
            }
            if !selected
                .order
                .is_some_and(|order| operation.member_order_complete(order))
            {
                return Ok(false);
            }
            // Only the shared reducer's certified empty member inventory proves
            // absence. object.__init__ and object.__new__ have separate
            // intrinsic applicability receipts: neither adds keyword parameters.
            if let ResolutionCompletion::Incomplete(reasons) = &selected.access.completion {
                let mut reasons = reasons.iter();
                let intrinsic = match reasons.next() {
                    Some(ResolutionIncompleteReason::UnsupportedSemantic(reason))
                        if matches!(name, "__init__" | "__new__") =>
                    {
                        let object = super::python_members::builtin(self.ready, "object");
                        operation
                            .service_reason_details(*reason)
                            .is_some_and(|(kind, fields)| {
                                kind == "intrinsic-member-applicability-open"
                                    && matches!(fields.as_slice(), [owner, intrinsic_name]
                                    if Some(*owner) == object && *intrinsic_name == lookup)
                            })
                    }
                    _ => false,
                };
                if !intrinsic || reasons.next().is_some() {
                    return Ok(false);
                }
            } else if !selected.access.missing_member {
                return Ok(false);
            }
            for owner in &self.class_owners {
                let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
                    return Ok(false);
                };
                let owner_mount = self
                    .ready
                    .inventory
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                let authored: bool = self.ready.inventory.connection().prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites semantic
                       JOIN python_member_classes class ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site
                       JOIN python_member_member_roles member ON member.blob_id=class.blob_id AND member.owner=class.class
                       JOIN resolution_binding_events event ON event.blob_id=member.blob_id AND event.authored=member.member
                       JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id AND slot.slot=event.slot
                     WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2 AND semantic.semantic_role='definition'
                       AND slot.name=?3)",
                )?.query_row(rusqlite::params![owner_mount.blob_id(), key, name], |row| row.get(0))?;
                if authored {
                    return Ok(false);
                }
            }
            let open = self
                .mutations
                .class_member_may_be_mutated(&self.class_owners, name)?;
            Ok(!open)
        }
    }
    impl<P: crate::analyzer::resolution::DemandRootProvider + ?Sized>
        super::native_units::NamedArgumentRules for PythonNamedArguments<'_, P>
    {
        fn resolve_callee(
            &mut self,
            operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            reference: SemanticId,
        ) -> Result<Option<FactResolutionAnswer>> {
            self.callee = Some(reference);
            Ok(
                match operation.resolve_reference_by_demand(reference, self.provider)? {
                    FactDemandResolution::Ready(answer) => {
                        self.callee_complete =
                            answer.binding().completion() == &ResolutionCompletion::Complete;
                        for &target in answer.binding().targets() {
                            if super::python_members::is_class(self.ready, target)? {
                                self.possible_classes.push(target);
                            }
                        }
                        Some(*answer)
                    }
                    FactDemandResolution::Cancelled(_) => None,
                },
            )
        }

        fn callable_completion<'a>(
            &self,
            answer: &'a FactResolutionAnswer,
        ) -> &'a ResolutionCompletion {
            // Parameter identity does not require argument applicability
            // or a return annotation on the selected Python callable.
            answer.binding().completion()
        }

        fn dispatch_is_proven(
            &self,
            answer: &FactResolutionAnswer,
            target: SemanticId,
        ) -> Result<bool> {
            // Python binding resolution selects the declaration. Receiver
            // transfer evidence governs invocation, not parameter identity.
            debug_assert_eq!(answer.binding().targets(), &[target]);
            Ok(answer.binding().completion() == &ResolutionCompletion::Complete)
        }

        fn parameter(
            &mut self,
            operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            mut callable: SemanticId,
            label: &str,
        ) -> Result<super::native_units::NamedParameter> {
            use super::native_units::NamedParameter;
            if super::python_members::is_class(self.ready, callable)? {
                self.class_constructor = Some(callable);
                use crate::analyzer::resolution::{
                    DemandReferenceKey, HierarchyPolicy, QualifiedMemberInput,
                    QualifiedMemberRegistration, ResolutionTypeRef,
                };
                let FactDemandResolution::Ready(answer) = operation.resolve_reference_by_demand(
                    self.callee.expect("resolved callee"),
                    self.provider,
                )?
                else {
                    return Ok(NamedParameter::Open);
                };
                let (constructed, proof) = operation.prove_construction_by_demand(
                    &crate::analyzer::resolution::TypedConstructionInput {
                        reference: DemandReferenceKey::caller(
                            self.callee.expect("resolved callee"),
                        ),
                        output: self.reference,
                        language: Language::Python,
                        binding: answer.binding().clone(),
                    },
                    self.provider,
                )?;
                if constructed.is_none() || proof != ResolutionCompletion::Complete {
                    return Ok(NamedParameter::Open);
                }
                let mount = self.ready.inventory.mount_record_by_ordinal(
                    SelectedResolutionMountOrdinal::new(
                        self.reference.ordinal().expect("positioned label"),
                    ),
                )?;
                use super::super::python_member_rows::{self, DataclassKeywordInitializer};
                let class_rows_mount = self.ready.inventory.mount_record_by_ordinal(
                    SelectedResolutionMountOrdinal::new(callable.ordinal().expect("source class")),
                )?;
                let decorator_count: u32 = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        "SELECT count(*) FROM resolution_semantic_sites semantic
                       JOIN python_member_decorators decorator ON decorator.blob_id=semantic.blob_id
                         AND decorator.declaration=semantic.source_site
                     WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                       AND semantic.semantic_role='definition'",
                    )?
                    .query_row(
                        rusqlite::params![
                            class_rows_mount.blob_id(),
                            callable.local_key().expect("source class")
                        ],
                        |row| row.get(0),
                    )?;
                let explicit_init: bool = self.ready.inventory.connection().prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM resolution_member_owner_properties
                     WHERE blob_id=?1 AND owner_definition_semantic_key=?2 AND member_name='__init__')",
                )?.query_row(rusqlite::params![class_rows_mount.blob_id(), callable.local_key().expect("source class")], |row| row.get(0))?;
                let class_rows = if decorator_count > 0 && (!explicit_init || decorator_count == 1)
                {
                    let Some(rows) = self.load_binding_rows(
                        class_rows_mount.blob_id(),
                        Some(class_rows_mount.blob_oid()),
                    )?
                    else {
                        return Ok(NamedParameter::Open);
                    };
                    Some(rows)
                } else {
                    None
                };
                let field_navigation = if !explicit_init && let Some(rows) = class_rows.as_deref() {
                    match python_member_rows::dataclass_keyword_initializer(
                        &self.ready.inventory,
                        self.summary,
                        callable,
                        rows,
                        self.cancellation,
                        self.mutations,
                    )? {
                        DataclassKeywordInitializer::Fields => true,
                        DataclassKeywordInitializer::Ordinary => false,
                        DataclassKeywordInitializer::Open => {
                            self.open_reason = Some("python_dataclass_init_option_open");
                            return Ok(NamedParameter::Open);
                        }
                    }
                } else {
                    false
                };
                let explicit_dataclass_init = !field_navigation
                    && decorator_count == 1
                    && python_member_rows::admitted_dataclass_expression(
                        &self.ready.inventory,
                        self.summary,
                        callable,
                        class_rows
                            .as_deref()
                            .expect("one decorated class has binding rows"),
                        self.cancellation,
                        self.mutations,
                    )?
                    .is_some();
                if decorator_count > u32::from(field_navigation || explicit_dataclass_init) {
                    return Ok(NamedParameter::Open);
                }
                let constructor_safe: bool = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        "SELECT class.bases_complete=1 AND class.metaclass IS NULL
                       AND NOT EXISTS(SELECT 1 FROM python_member_member_roles member
                         JOIN resolution_binding_events event ON event.blob_id=member.blob_id
                           AND event.authored=member.member
                         JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id
                           AND slot.slot=event.slot
                         WHERE member.blob_id=class.blob_id AND member.owner=class.class
                           AND slot.name='__new__')
                     FROM resolution_semantic_sites semantic JOIN python_member_classes class
                       ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site
                     WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                       AND semantic.semantic_role='definition'",
                    )?
                    .query_row(
                        rusqlite::params![
                            class_rows_mount.blob_id(),
                            callable.local_key().expect("source class")
                        ],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !constructor_safe {
                    return Ok(NamedParameter::Open);
                }
                // A generated dataclass initializer can include fields from
                // dataclass bases. Certify every authored base before using
                // that inherited signature; a missing edge stays open.
                let mut pending = vec![callable];
                let mut visited = HashSet::default();
                while let Some(owner) = pending.pop() {
                    if !visited.insert(owner) {
                        return Ok(NamedParameter::Open);
                    }
                    self.class_owners.push(owner);
                    let (Some(ordinal), Some(key)) = (owner.ordinal(), owner.local_key()) else {
                        return Ok(NamedParameter::Open);
                    };
                    let owner_mount = self
                        .ready
                        .inventory
                        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                    let conn = self.ready.inventory.connection();
                    let base_sites = conn.prepare_cached(
                        "SELECT base.kind,semantic.semantic_key FROM resolution_semantic_sites owner
                         JOIN python_member_base_operands base ON base.blob_id=owner.blob_id
                           AND base.class=owner.source_site
                         LEFT JOIN resolution_semantic_sites semantic ON semantic.blob_id=base.blob_id
                           AND semantic.source_site=base.expression_site AND semantic.semantic_role='reference'
                         WHERE owner.blob_id=?1 AND owner.semantic_key=?2
                           AND owner.semantic_role='definition' ORDER BY base.ordinal"
                    )?.query_map(rusqlite::params![owner_mount.blob_id(), key], |row| {
                        Ok((row.get::<_,u32>(0)?, row.get::<_,Option<u32>>(1)?))
                    })?.collect::<rusqlite::Result<Vec<_>>>()?;
                    if owner != callable {
                        let safe: bool = conn.prepare_cached(
                            "SELECT class.bases_complete=1 AND class.metaclass IS NULL
                              AND NOT EXISTS(SELECT 1 FROM python_member_member_roles member
                                JOIN resolution_binding_events event ON event.blob_id=member.blob_id
                                  AND event.authored=member.member
                                JOIN resolution_binding_slots slot ON slot.blob_id=event.blob_id
                                  AND slot.slot=event.slot
                                WHERE member.blob_id=class.blob_id AND member.owner=class.class
                                  AND slot.name='__new__')
                             FROM resolution_semantic_sites semantic JOIN python_member_classes class
                               ON class.blob_id=semantic.blob_id AND class.class=semantic.source_site
                             WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                               AND semantic.semantic_role='definition'"
                        )?.query_row(rusqlite::params![owner_mount.blob_id(), key], |row| row.get(0)).optional()?.unwrap_or(false);
                        if !safe {
                            return Ok(NamedParameter::Open);
                        }
                        let decorators: u32 = conn.prepare_cached(
                            "SELECT count(*) FROM resolution_semantic_sites semantic
                             JOIN python_member_decorators decorator ON decorator.blob_id=semantic.blob_id
                               AND decorator.declaration=semantic.source_site
                             WHERE semantic.blob_id=?1 AND semantic.semantic_key=?2
                               AND semantic.semantic_role='definition'"
                        )?.query_row(rusqlite::params![owner_mount.blob_id(), key], |row| row.get(0))?;
                        if decorators > 0 {
                            if decorators != 1 {
                                return Ok(NamedParameter::Open);
                            }
                            let Some(owner_rows) = self.load_binding_rows(
                                owner_mount.blob_id(),
                                Some(owner_mount.blob_oid()),
                            )?
                            else {
                                return Ok(NamedParameter::Open);
                            };
                            if python_member_rows::admitted_dataclass_expression(
                                &self.ready.inventory,
                                self.summary,
                                owner,
                                &owner_rows,
                                self.cancellation,
                                self.mutations,
                            )?
                            .is_none()
                            {
                                return Ok(NamedParameter::Open);
                            }
                        }
                    }
                    for (kind, reference) in base_sites {
                        let Some(reference) = reference.filter(|_| kind == 0) else {
                            return Ok(NamedParameter::Open);
                        };
                        let FactDemandResolution::Ready(base) = operation
                            .resolve_reference_by_demand(
                                SemanticId::local(ordinal, reference),
                                self.provider,
                            )?
                        else {
                            return Ok(NamedParameter::Open);
                        };
                        let [base_owner] = base.binding().targets() else {
                            return Ok(NamedParameter::Open);
                        };
                        if base.binding().completion() != &ResolutionCompletion::Complete
                            || !super::python_members::is_class(self.ready, *base_owner)?
                        {
                            return Ok(NamedParameter::Open);
                        }
                        pending.push(*base_owner);
                    }
                }
                let lookup = ResolutionLookupSemanticRecipe::new(
                    Language::Python,
                    ResolutionNamespace::Value,
                    if field_navigation { label } else { "__init__" },
                )
                .semantic(&self.ready.shared_names());
                if !field_navigation {
                    let registered = self
                        .provider
                        .qualified_members()
                        .is_some_and(|members| members.register_query_lookup(lookup, "__init__"));
                    assert!(
                        registered,
                        "Python constructor requires a Python member provider"
                    );
                }
                let Some(selected) = operation.resolve_member_by_demand(
                    QualifiedMemberInput {
                        reference: DemandReferenceKey::caller(self.reference),
                        route_ordinal: 0,
                        precedence: 0,
                        fragment: mount.fragment_id(),
                        source_lookup: lookup,
                        lookup,
                        namespace: ResolutionNamespace::Value,
                        values: vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                            callable, 0,
                        ))],
                        completion: ResolutionCompletion::Complete,
                        registration: QualifiedMemberRegistration {
                            language: Language::Python,
                            hierarchy_identity: super::python_members::PYTHON_HIERARCHY
                                .identity()
                                .0,
                            member_access: true,
                        },
                    },
                    self.provider,
                )?
                else {
                    // A missing member is not a complete negative lookup when
                    // the hierarchy or constructor may be dynamic.
                    return Ok(NamedParameter::Open);
                };
                // An empty __init__ selection needs the certified absence
                // proof below; its object intrinsic receipt is incomplete here.
                if (field_navigation || !selected.access.targets.is_empty())
                    && super::native_units::ordered_member_binding_completion(
                        self.ready,
                        operation,
                        &selected.access,
                        selected.order,
                        callable,
                        lookup,
                        self.cancellation,
                    )? != ResolutionCompletion::Complete
                {
                    return Ok(NamedParameter::Open);
                }
                if selected.access.targets.is_empty() {
                    if field_navigation
                        || !self.class_member_absent(operation, callable, "__init__")?
                    {
                        return Ok(NamedParameter::Open);
                    }
                    // An absent initializer is only a negative constructor
                    // proof when the other class call surfaces are closed too.
                    // Member access visits the resolved C3 owners and their
                    // structural attribute-space mutations for each spelling.
                    for name in ["__new__", "__signature__"] {
                        if !self.class_member_absent(operation, callable, name)? {
                            return Ok(NamedParameter::Open);
                        }
                    }
                    return Ok(NamedParameter::Absent);
                }
                let [target] = selected.access.targets.as_slice() else {
                    return Ok(NamedParameter::Open);
                };
                let constructor = callable;
                callable = target.target.token;
                if field_navigation {
                    let field_mount = self.ready.inventory.mount_record_by_ordinal(
                        SelectedResolutionMountOrdinal::new(
                            callable.ordinal().expect("source field"),
                        ),
                    )?;
                    let Some(field_rows) = self
                        .load_binding_rows(field_mount.blob_id(), Some(field_mount.blob_oid()))?
                    else {
                        return Ok(NamedParameter::Open);
                    };
                    return Ok(
                        match python_member_rows::dataclass_keyword_field(
                            &self.ready.inventory,
                            self.summary,
                            callable,
                            constructor,
                            &field_rows,
                            self.cancellation,
                            &mut |reference| {
                                use python_member_rows::DataclassAnnotationIdentity as Identity;
                                let FactDemandResolution::Ready(answer) = operation
                                    .resolve_reference_by_demand(reference, self.provider)?
                                else {
                                    return Ok(Identity::Unknown);
                                };
                                let [target] = answer.binding().targets() else {
                                    return Ok(Identity::Unknown);
                                };
                                if answer.binding().completion() != &ResolutionCompletion::Complete
                                {
                                    return Ok(Identity::Unknown);
                                }
                                Ok(
                                    if crate::analyzer::resolution::universe_entry_for_identity(
                                        &self.ready.lexical_source(),
                                        *target,
                                        self.cancellation,
                                    )?
                                    .is_some_and(|entry| entry.language == Language::Python)
                                    {
                                        Identity::Builtin
                                    } else if super::python_members::is_class(self.ready, *target)?
                                    {
                                        Identity::SourceClass
                                    } else {
                                        Identity::Unknown
                                    },
                                )
                            },
                            self.mutations,
                        )? {
                            Some(true) => NamedParameter::Found(callable),
                            Some(false)
                                if self.class_member_absent(
                                    operation,
                                    constructor,
                                    "__new__",
                                )? && self.class_member_absent(
                                    operation,
                                    constructor,
                                    "__signature__",
                                )? =>
                            {
                                NamedParameter::Absent
                            }
                            Some(false) => NamedParameter::Open,
                            None => {
                                self.open_reason = Some("python_dataclass_keyword_shape_open");
                                NamedParameter::Open
                            }
                        },
                    );
                }
            }
            let (Some(ordinal), Some(key)) = (callable.ordinal(), callable.local_key()) else {
                return Ok(NamedParameter::Open);
            };
            if self.cancellation.is_cancelled() {
                return Ok(NamedParameter::Open);
            }
            let mount = self
                .ready
                .inventory
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
            let decorators = self.ready.inventory.connection().prepare_cached(
                "SELECT reference.semantic_key FROM resolution_semantic_sites callable
                   JOIN python_member_decorators decorator ON decorator.blob_id=callable.blob_id
                     AND decorator.declaration=callable.source_site
                   LEFT JOIN resolution_semantic_sites reference ON reference.blob_id=decorator.blob_id
                     AND reference.source_site=decorator.expression_site AND reference.semantic_role='reference'
                   WHERE callable.blob_id=?1 AND callable.semantic_key=?2
                     AND callable.semantic_role='definition' ORDER BY decorator.ordinal"
            )?.query_map(rusqlite::params![mount.blob_id(), key], |row| row.get::<_,Option<u32>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let decorator_safe = match decorators.as_slice() {
                [] => true,
                [Some(reference)] => {
                    let FactDemandResolution::Ready(answer) = operation
                        .resolve_reference_by_demand(
                            SemanticId::local(ordinal, *reference),
                            self.provider,
                        )?
                    else {
                        return Ok(NamedParameter::Open);
                    };
                    answer.binding().completion() == &ResolutionCompletion::Complete
                        && answer.binding().targets()
                            == super::python_members::builtin(self.ready, "staticmethod").as_slice()
                }
                _ => false,
            };
            if !decorator_safe {
                return Ok(NamedParameter::Open);
            }
            let signature_safe: bool = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites callable
                   JOIN python_member_parameters parameter ON parameter.blob_id=callable.blob_id
                     AND parameter.callable=callable.source_site
                   WHERE callable.blob_id=?1 AND callable.semantic_key=?2
                     AND callable.semantic_role='definition')
                 AND NOT EXISTS(SELECT 1 FROM resolution_identities name
                   JOIN resolution_reference_lookup_identities lookup ON lookup.identity_id=name.id
                   JOIN resolution_semantic_sites target ON target.blob_id=lookup.blob_id
                     AND target.semantic_key=lookup.semantic_key AND target.semantic_role='reference'
                   JOIN python_member_receiver_writes writes ON writes.blob_id=target.blob_id
                     AND writes.site=target.source_site
                   JOIN temp.selected_resolution_mounts mounted ON mounted.blob_id=writes.blob_id
                   WHERE name.spelling='__signature__' AND mounted.storage_language='python')",
                )?
                .query_row(rusqlite::params![mount.blob_id(), key], |row| row.get(0))?;
            if !signature_safe {
                return Ok(NamedParameter::Open);
            }
            // Properties and unknown descriptors do not expose their
            // getter's parameter list as the signature of a call.
            let parameters = self
                .ready
                .inventory
                .connection()
                .prepare_cached(
                    "SELECT parameter.parameter
             FROM resolution_semantic_sites callable
             JOIN python_member_parameters parameter
               ON parameter.blob_id=callable.blob_id
              AND parameter.callable=callable.source_site
             JOIN source_native_declaration_bridges bridge
               ON bridge.blob_id=parameter.blob_id
              AND bridge.source_site=parameter.parameter
             JOIN source_declarations declaration
               ON declaration.blob_id=bridge.blob_id
              AND declaration.declaration_id=bridge.declaration_id
             WHERE callable.blob_id=?1 AND callable.semantic_key=?2
               AND callable.semantic_role='definition'
               AND parameter.kind IN (1,2)
               AND declaration.lexical_identifier=?3
               AND NOT EXISTS(
                 SELECT 1 FROM python_member_member_roles member
                 WHERE member.blob_id=callable.blob_id
                   AND member.member=callable.source_site
                   AND member.kind NOT IN (0,1,2))
             LIMIT 2",
                )?
                .query_map(rusqlite::params![mount.blob_id(), key, label], |row| {
                    row.get::<_, u32>(0)
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if parameters.is_empty() {
                let has_kwargs: bool = self
                    .ready
                    .inventory
                    .connection()
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM resolution_semantic_sites callable
                     JOIN python_member_parameters parameter
                       ON parameter.blob_id=callable.blob_id
                      AND parameter.callable=callable.source_site
                     WHERE callable.blob_id=?1 AND callable.semantic_key=?2
                       AND callable.semantic_role='definition' AND parameter.kind=4)",
                    )?
                    .query_row(rusqlite::params![mount.blob_id(), key], |row| row.get(0))?;
                if !has_kwargs {
                    if let Some(owner) = self.class_constructor {
                        for name in ["__new__", "__signature__"] {
                            if !self.class_member_absent(operation, owner, name)? {
                                return Ok(NamedParameter::Open);
                            }
                        }
                    }
                    return Ok(NamedParameter::Absent);
                }
            }
            Ok(match parameters.as_slice() {
                [parameter] => {
                    NamedParameter::Found(crate::analyzer::resolution::mounted_site_semantic(
                        mount.fragment_id(),
                        ResolutionSiteId::new(*parameter),
                    ))
                }
                _ => NamedParameter::Open,
            })
        }
    }
    let mut argument_rules = PythonNamedArguments {
        ready,
        provider,
        cancellation,
        session,
        reference,
        callee: None,
        summary,
        open_reason: None,
        possible_classes: Vec::new(),
        callee_complete: false,
        class_constructor: None,
        class_owners: Vec::new(),
        mutations,
    };
    let named_argument = super::native_units::resolve_named_argument_parameter_with_rules(
        ready,
        operation,
        reference,
        cancellation,
        session,
        &mut argument_rules,
    )?;
    let projected = match (argument_rules.open_reason, named_argument) {
        (
            Some(reason),
            Some(super::native_units::SelectedNativeNamedArgument::Incomplete(message)),
        ) => Some(
            super::native_units::SelectedNativeNamedArgument::Incomplete(format!(
                "{reason}: {message}"
            )),
        ),
        (_, answer) => answer,
    };
    Ok((
        projected,
        argument_rules.possible_classes,
        argument_rules.callee_complete,
    ))
}

impl SelectedResolutionOperation<'_, '_> {
    /// Read every provider-open route for one selected caller file. Relative
    /// imports and routes with workspace providers retain native authority.
    /// None means the caller is outside the selected Python mounts; a mounted
    /// file with no external imports returns Some with an empty vector.
    #[doc(hidden)]
    pub fn python_selected_external_imports(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        caller_path: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<PythonSelectedImportBoundary>>> {
        const CANCELLED: &str = "Python external import boundary read cancelled";
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled(CANCELLED));
        }
        let Some(source) = self.mount_table().mount_for_path("python", caller_path)? else {
            return Ok(None);
        };
        let record = self
            .ready
            .inventory
            .mount_record_by_ordinal(source.ordinal())?;
        let blob = record.blob_id();
        let context = empty_contexts_for(
            self.mount_table(),
            &ResolutionCompletion::Complete,
            &selected_mount_lookup(self.mount_table()),
            self.ready.context_identities.clone(),
        )?;
        let Some(blueprint) = self.prepare_prefix_blueprint(context, cancellation)? else {
            return Err(StoreError::cancelled(CANCELLED));
        };
        let boundaries = self.with_python_forward_operation(
            summary, python_version, &blueprint, &ResolutionSession::unbounded(), cancellation,
            |_, _, _, _, _, _, _, _| {
                let connection = self.ready.inventory.connection();
                let mut statement = connection.prepare_cached(
                    "SELECT authored.import_site,authored.form,authored.relative_level,
                            authored.module_segments,authored.binding_event,json(authored.route),slot.name,
                            CASE WHEN authored.form=0 AND NOT EXISTS(
                              SELECT 1 FROM resolution_root_import_segments prefix
                              WHERE prefix.blob_id=authored.blob_id AND prefix.import_site=authored.import_site)
                              THEN 1 ELSE json_array_length(authored.route) END
                     FROM python_binding_imports authored
                     LEFT JOIN resolution_binding_events event
                       ON event.blob_id=authored.blob_id AND event.event=authored.binding_event
                     LEFT JOIN resolution_binding_slots slot
                       ON slot.blob_id=event.blob_id AND slot.slot=event.slot
                     WHERE authored.blob_id=?1 AND authored.relative_level=0
                       AND EXISTS(
                         SELECT 1 FROM resolution_unit_summary_members member
                         JOIN python_unit_summary_imports route
                           ON route.summary_id=member.summary_id AND route.member_ordinal=member.member_ordinal
                         WHERE member.summary_id=?2 AND member.blob_id=authored.blob_id
                           AND member.rel_path=?3 AND route.import_site=authored.import_site
                           AND route.state='provider_open')
                       AND NOT EXISTS(
                         SELECT 1 FROM resolution_unit_summary_members member
                         JOIN python_unit_summary_imports route
                           ON route.summary_id=member.summary_id AND route.member_ordinal=member.member_ordinal
                         WHERE member.summary_id=?2 AND member.blob_id=authored.blob_id
                           AND member.rel_path=?3 AND route.import_site=authored.import_site
                           AND route.target_container!='')
                     ORDER BY authored.import_site",
                )?;
                let mut rows = statement.query(rusqlite::params![blob,summary,caller_path])?;
                let mut boundaries = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Err(StoreError::cancelled(CANCELLED));
                    }
                    use brokk_bifrost_core::analyzer::resolution_facts::PythonNativeImportForm;
                    let form = match row.get::<_, u32>(1)? {
                        0 => PythonNativeImportForm::Module,
                        1 => PythonNativeImportForm::From,
                        2 => PythonNativeImportForm::Star,
                        _ => return Err(StoreError::corrupt("invalid retained Python import form")),
                    };
                    let site = row.get::<_, u32>(0)?;
                    let route = serde_json::from_str(&row.get::<_, String>(5)?)
                        .map_err(|error| StoreError::corrupt(format!("invalid Python import route: {error}")))?;
                    boundaries.push(PythonSelectedImportBoundary {
                        fragment: source.fragment(),
                        blob,
                        import_site: ResolutionSiteId::new(site),
                        form,
                        relative_level: row.get(2)?,
                        module_segment_count: row.get(3)?,
                        binding_event: row.get(4)?,
                        route,
                        bound_name: row.get(6)?,
                        binding_segment_count: row.get(7)?,
                        completion: import_route_obligation(&self.ready, summary, caller_path, site, "provider_open")?.0,
                    });
                }
                Ok(boundaries)
            },
        )?;
        if cancellation.is_cancelled() {
            return Err(StoreError::cancelled(CANCELLED));
        }
        Ok(Some(boundaries))
    }

    /// Read the real selected hierarchy inputs and intrinsic inventory through
    /// their ordinary hooks; class-route evaluation remains a separate bridge.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn python_native_builtin_hierarchy_probe(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        use crate::analyzer::resolution::{SelectedTypedFactSource, SharedNameInterner, universe};
        use std::fmt::Write;
        let (_, observation) = unit_metadata(&self.ready, summary)?;
        let profile = match observation.as_str() {
            "runtime" => PythonBindingProfile::Runtime,
            "typing" => PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python observation profile")),
        };
        let session = ResolutionSession::unbounded();
        let mutations =
            super::PythonMutationQuery::new(&self.ready, summary, profile, &session, cancellation)?;
        let implicit_provider = mutations.implicit_inputs_provider(
            &self.ready.context_identities,
            python_version.map(|version| (version.major, version.minor)),
        );
        let typed = self
            .ready
            .typed_source()
            .with_implicit_environment(
                summary,
                python_version.map(|version| (version.major, version.minor)),
            )
            .with_implicit_input_provider(&implicit_provider);
        let typed = crate::analyzer::resolution::seam_profile::SeamProfiled::observing(&typed);
        let classes = self.ready.inventory.connection().prepare_cached(
            "SELECT mounted.mount_ordinal,mounted.persisted_relative_path,semantic.semantic_key,class.class
             FROM temp.selected_resolution_mounts mounted
             JOIN python_member_classes class ON class.blob_id=mounted.blob_id
             JOIN resolution_semantic_sites semantic ON semantic.blob_id=class.blob_id
              AND semantic.source_site=class.class AND semantic.semantic_role='definition'
             WHERE mounted.semantic_language='python'
             ORDER BY mounted.persisted_relative_path,class.class",
        )?.query_map([], |row| Ok((row.get::<_,u32>(0)?,row.get::<_,String>(1)?,row.get::<_,u32>(2)?,row.get::<_,u32>(3)?)))?
         .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut output = String::new();
        for (ordinal, path, key, site) in classes {
            let owner = SemanticId::local(ordinal, key);
            let inputs = typed
                .implicit_base_inputs(owner, cancellation)?
                .expect("selected class inputs");
            let root = inputs.root_object.as_ref().map(|root| {
                assert!(matches!(root.authority,crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic { descriptor } if descriptor==root.identity));
                let id=root.identity.shared_name_id().expect("intrinsic root identity");
                universe::entry_for_digest(self.ready.shared_names().digest_for_id(id).expect("selected root digest"))
                    .expect("selected intrinsic root").identity_spelling
            });
            writeln!(output,"hierarchy {path}:site={site} creation={:?} written={} inventory={} implicit={root:?} complete={}",
                inputs.creation,inputs.written_base_count,inputs.written_inventory_complete,inputs.completion==ResolutionCompletion::Complete).expect("String write");
        }
        if let Some(root) = brokk_bifrost_python::intrinsics::implicit_base(python_version) {
            let entry = universe::lookup(
                Language::Python,
                ResolutionNamespace::TypeOrValue,
                root.name,
            )
            .expect("root universe entry");
            let owner = SemanticId::shared_name(
                self.ready
                    .shared_names()
                    .intern(universe::identity_digest(entry)),
            );
            let inputs = typed
                .implicit_base_inputs(owner, cancellation)?
                .expect("intrinsic root inputs");
            assert!(
                matches!(inputs.authority,crate::analyzer::resolution::ImplicitBaseAuthority::Intrinsic { descriptor } if descriptor==owner)
            );
            writeln!(
                output,
                "intrinsic-root {} self-base={} complete={}",
                root.qualified_name,
                inputs.root_object.is_some(),
                inputs.completion == ResolutionCompletion::Complete
            )
            .expect("String write");
            for name in ["__repr__", "__getstate__", "not_an_object_member"] {
                let lookup = super::ResolutionLookupSemanticRecipe::new(
                    Language::Python,
                    ResolutionNamespace::Value,
                    name,
                )
                .semantic(&self.ready.shared_names());
                let present =
                    typed
                        .intrinsic_member_inventory(owner, cancellation)?
                        .map(|inventory| {
                            inventory.presence(
                                self.ready
                                    .shared_names()
                                    .digest_for_id(
                                        lookup.shared_name_id().expect("lookup shared name"),
                                    )
                                    .expect("lookup digest"),
                                ResolutionNamespace::Value,
                            ) != universe::IntrinsicMemberPresence::Absent
                        });
                writeln!(output, "intrinsic-inventory {name} may-contain={present:?}")
                    .expect("String write");
            }
        }
        Ok(output)
    }

    /// One operation and demand cache for a selected Python environment.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_python_forward_operation<T>(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        blueprint: &SelectedFactOperationBlueprint,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        run: impl FnOnce(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &mut DemandProvider<SharedDemand<'_, '_, '_, PythonRules<'_, '_, '_>>>,
            &SelectedResolutionLexicalSource<'_, '_>,
            &RefCell<ClosedRelations>,
            &RefCell<Vec<String>>,
            &RefCell<PythonExternalImports>,
            &RefCell<HashMap<SemanticId, DispatchExtensibility>>,
            &super::PythonMutationQuery<'_, '_>,
        ) -> Result<T>,
    ) -> Result<T> {
        self.with_python_forward_operation_using_artifacts(
            summary,
            python_version,
            blueprint,
            session,
            cancellation,
            &mut crate::analyzer::resolution::ForwardCandidateArtifactCache::default(),
            run,
        )
    }

    /// As `with_python_forward_operation`, for a caller that owns a
    /// query-local candidate cache: demanded answers carry over to the next
    /// operation of the same query, as Go's entry does.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_python_forward_operation_using_artifacts<T>(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        blueprint: &SelectedFactOperationBlueprint,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        artifacts: &mut crate::analyzer::resolution::ForwardCandidateArtifactCache,
        run: impl FnOnce(
            &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
            &mut DemandProvider<SharedDemand<'_, '_, '_, PythonRules<'_, '_, '_>>>,
            &SelectedResolutionLexicalSource<'_, '_>,
            &RefCell<ClosedRelations>,
            &RefCell<Vec<String>>,
            &RefCell<PythonExternalImports>,
            &RefCell<HashMap<SemanticId, DispatchExtensibility>>,
            &super::PythonMutationQuery<'_, '_>,
        ) -> Result<T>,
    ) -> Result<T> {
        let paths = self.ready.lexical_source();
        self.with_python_forward_inputs(
            summary,
            python_version,
            blueprint,
            &paths,
            session,
            cancellation,
            |mut provider,
             source,
             typed,
             arena,
             observations,
             external_imports,
             dispatch_extensibility,
             mutations| {
                let operation_run =
                    |operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>| {
                        run(
                            operation,
                            &mut provider,
                            &paths,
                            arena,
                            observations,
                            external_imports,
                            dispatch_extensibility,
                            mutations,
                        )
                    };
                let finalizer =
                    &crate::analyzer::resolution::fact_resolution::NOOP_LEXICAL_ANSWER_FINALIZER;
                blueprint.with_forward_operation_in_session_using_artifacts(
                    source,
                    &paths,
                    typed,
                    finalizer,
                    crate::analyzer::resolution::ForwardOperationArtifactContext {
                        cancellation,
                        session,
                        artifacts,
                    },
                    operation_run,
                )
            },
        )
    }

    /// Dormant bulk entry: one provider and forward operation for every admitted
    /// fragment. Only seed enumeration is restricted; dependencies remain visible.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn stage_python_reference_batches(
        &self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        blueprint: &SelectedFactOperationBlueprint,
        fragments: &HashSet<BindingFragmentId>,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        let paths = self
            .ready
            .lexical_source()
            .with_forward_reference_fragments(fragments);
        self.with_python_forward_inputs(
            environment.summary,
            environment.python_version,
            blueprint,
            &paths,
            session,
            cancellation,
            |provider, source, typed, _, _, _, dispatch_extensibility, mutations| {
                blueprint.with_demand_operation(
                    source,
                    &paths,
                    &paths,
                    typed,
            &crate::analyzer::resolution::fact_resolution::NOOP_LEXICAL_ANSWER_FINALIZER,
                    provider,
                    cancellation,
                    session,
                    |operation| {
                        let mut project_label = |operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
                            provider: &mut dyn crate::analyzer::resolution::DemandRootProvider,
                            reference: SemanticId,
                            answer: FactResolutionAnswer| -> Result<(FactResolutionAnswer, Option<Vec<SemanticId>>)> {
                            let (named, classes, callee_complete) = project_python_named_argument(
                                &self.ready, operation, provider, reference, environment.summary,
                                cancellation, session, mutations,
                            )?;
                            let Some(named) = named else { return Ok((answer, None)); };
                            let metadata = answer.site_metadata()
                                .ok_or_else(|| StoreError::corrupt("keyword label has no reference metadata"))?;
                            let (targets, completion, scoped) = match named {
                                super::native_units::SelectedNativeNamedArgument::Resolved(target, _) =>
                                    (vec![target], ResolutionCompletion::Complete, None),
                                super::native_units::SelectedNativeNamedArgument::Absent(_) =>
                                    (Vec::new(), ResolutionCompletion::Complete, None),
                                super::native_units::SelectedNativeNamedArgument::Incomplete(message) => {
                                    let label = match operation.named_argument_label_for_reference(reference)? {
                                        crate::analyzer::resolution::NamedArgumentLabelRead::Found(label) => label,
                                        _ => return Err(StoreError::corrupt("projected keyword label disappeared")),
                                    };
                                    let candidates = if callee_complete {
                                        super::python_members::class_attribute_candidates(
                                            &self.ready, operation, provider, reference,
                                            &classes, &label.spelling, cancellation,
                                        )?
                                    } else {
                                        None
                                    };
                                    let mut hash = CanonicalHasher::new(b"python-graph-named-argument-open:v1");
                                    hash.field("reference", format!("{reference:?}").as_bytes());
                                    hash.field("reason", message.as_bytes());
                                    let reason = self.ready.context_identities.named_semantic(
                                        hash.finish(), "python_named_argument_open", &message,
                                    );
                                    (Vec::new(), ResolutionCompletion::incomplete([
                                        ResolutionIncompleteReason::UnsupportedSemantic(reason),
                                    ]), candidates)
                                }
                            };
                            let mut projected = FactResolutionAnswer::from_selected_summary_binding(
                                metadata, targets, completion,
                            );
                            projected.query_obligations = answer.query_obligations;
                            Ok((projected, scoped))
                        };
                        operation.stage_all_reference_batches_with_projection(
                            maximum_batch_size, &mut project_label, &mut |batch| {
                                let dispatch = dispatch_extensibility.borrow();
                                let batch = batch.clone().with_dispatch_extensibility(|reference| {
                                    dispatch.get(&reference).copied()
                                });
                                sink(&batch)
                            },
                        )
                    },
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_python_forward_inputs<T>(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        blueprint: &SelectedFactOperationBlueprint,
        paths: &SelectedResolutionLexicalSource<'_, '_>,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        run: impl FnOnce(
            DemandProvider<SharedDemand<'_, '_, '_, PythonRules<'_, '_, '_>>>,
            &dyn BatchResolutionFragmentSource,
            &dyn SelectedTypedFactSource,
            &RefCell<ClosedRelations>,
            &RefCell<Vec<String>>,
            &RefCell<PythonExternalImports>,
            &RefCell<HashMap<SemanticId, DispatchExtensibility>>,
            &super::PythonMutationQuery<'_, '_>,
        ) -> Result<T>,
    ) -> Result<T> {
        let (_, observation) = unit_metadata(&self.ready, summary)?;
        let profile = match observation.as_str() {
            "runtime" => PythonBindingProfile::Runtime,
            "typing" => PythonBindingProfile::Typing,
            _ => return Err(StoreError::corrupt("invalid Python observation profile")),
        };
        let selected_query_obligations = selected_environment_obligations(&self.ready, summary)?;
        let mutations =
            super::PythonMutationQuery::new(&self.ready, summary, profile, session, cancellation)?;
        let implicit_provider = mutations.implicit_inputs_provider(
            &self.ready.context_identities,
            python_version.map(|version| (version.major, version.minor)),
        );
        let typed = self
            .ready
            .typed_source()
            .with_implicit_environment(
                summary,
                python_version.map(|version| (version.major, version.minor)),
            )
            .with_implicit_input_provider(&implicit_provider);
        let base = blueprint.path_fragment_source(paths, paths, Some(session));
        let arena = RefCell::new(ClosedRelations::default());
        let observations = RefCell::new(Vec::new());
        let source = ClosedForwardSource::new(&base, paths, &arena, session, CALLER_ENVIRONMENT);
        let external_imports = RefCell::new(PythonExternalImports::default());
        let dispatch_extensibility = RefCell::new(HashMap::default());
        self.with_shared_forward_provider(
            PythonRules {
                ready: &self.ready,
                typed: &typed,
                summary,
                selected_query_obligations,
                mutations: &mutations,
                placement_unit: brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes(
                    b"bifrost-python-placement-unit-v1",
                    &summary.to_le_bytes(),
                ),
                profile,
                python_version,
                cancellation,
                session,
                observations: &observations,
                probe_spellings: RefCell::new(Vec::new()),
                arena: &arena,
                source_inputs: RefCell::new(HashMap::default()),
                external_imports: &external_imports,
                dispatch_extensibility: &dispatch_extensibility,
                binding_rows: RefCell::new(RequestReadCache::default()),
                placements: RefCell::new(super::placement_access::PlacementMemo::default()),
                root_prefixes: RefCell::new(RequestReadCache::default()),
                namespace_imports: RefCell::new(RequestReadCache::default()),
                module_sites: RefCell::new(RequestReadCache::default()),
                conditional_import_sites: RefCell::new(RequestReadCache::default()),
                super_context_rows: RefCell::new(RequestReadCache::default()),
                member_role_rows: RefCell::new(RequestReadCache::default()),
                import_routes: RefCell::new(RequestReadCache::default()),
                summary_imports: RefCell::new(RequestReadCache::default()),
                prefix_providers: RefCell::new(RequestReadCache::default()),
                deferred_provider_containers: RefCell::new(RequestReadCache::default()),
                member_owner_rows: RefCell::new(RequestReadCache::default()),
                qualified_members: HashMap::default(),
                attribute_hooks: RefCell::new(HashMap::default()),
                ordinary_keyword_namespaces: RefCell::new(HashSet::default()),
                module_aliases: RefCell::new(HashMap::default()),
                attribute_mutations: RefCell::new(HashMap::default()),
                attribute_metaclasses: RefCell::new(HashMap::default()),
                attribute_metaclass_fallbacks: RefCell::new(HashMap::default()),
                prepared_references: RefCell::new(HashMap::default()),
                universe_mutations: RefCell::new(HashMap::default()),
                module_mutations: RefCell::new(HashMap::default()),
                deferred_mutations: RefCell::new(HashMap::default()),
                module_spaces: RefCell::new(HashMap::default()),
                wildcard_inventories: RefCell::new(HashMap::default()),
                reference_inputs: RefCell::new(HashMap::default()),
                module_import_inputs: HashMap::default(),
                module_registry: module_registry::Registry::default(),
            },
            &arena,
            paths,
            paths,
            None,
            cancellation,
            session,
            |provider| {
                run(
                    provider,
                    &source,
                    &typed,
                    &arena,
                    &observations,
                    &external_imports,
                    &dispatch_extensibility,
                    &mutations,
                )
            },
        )
    }

    pub(super) fn python_definition_reference(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<LocatedSemantic> {
        let sites = match self.ready.lexical_source().lookup_semantic_sites(
            locator,
            cancellation,
            session,
        )? {
            SelectedSemanticLookupOutcome::Found(sites) => sites,
            SelectedSemanticLookupOutcome::Missing => return Ok(LocatedSemantic::Missing),
            SelectedSemanticLookupOutcome::Cancelled => return Ok(LocatedSemantic::Cancelled),
        };
        // The synthetic callee-value read retains qualifier, service and context
        // reasons the call reference may lack. It is an operation-internal fact,
        // not a user-addressable reference; keep it for resolution, not locations.
        let mut internal = self.ready.inventory.connection().prepare_cached(
            "SELECT 1 FROM temp.selected_resolution_mounts mount
             JOIN resolution_semantic_sites reference
               ON reference.blob_id=mount.blob_id AND reference.semantic_key=?2
              AND reference.semantic_role='reference'
             JOIN python_member_operations operation
               ON operation.blob_id=reference.blob_id
              AND operation.callee_reference=reference.source_site
             WHERE mount.mount_ordinal=?1",
        )?;
        let mut references = Vec::new();
        for site in sites {
            let semantic = site.semantic();
            let (Some(mount), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
                return Err(StoreError::corrupt(
                    "a selected Python reference has no mounted source identity",
                ));
            };
            let Some(is_internal) =
                session.query(|| internal.exists(rusqlite::params![mount, key]))
            else {
                return Ok(LocatedSemantic::Cancelled);
            };
            if !is_internal? {
                references.push(semantic);
            }
        }
        match references.as_slice() {
            [] => Ok(LocatedSemantic::Missing),
            [reference] => Ok(LocatedSemantic::Found(*reference)),
            _ => Err(StoreError::new(format!(
                "singular Python definition lookup requires one user-addressable source site: {locator:?}, alternatives {references:?}"
            ))),
        }
    }

    /// Resolve exactly one selected source reference in the caller's environment.
    /// Declaration inventory lookup is a separate product path, not a binding query.
    pub fn python_definition_at(
        &mut self,
        environment: &super::super::python_unit_summaries::PythonSelectedEnvironment,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
        session: &ResolutionSession,
    ) -> Result<
        BoundedResolution<
            SelectedResolutionOperationOutcome<SelectedResolutionLocated<PythonDefinitionAnswer>>,
        >,
    > {
        use super::native_units::{SelectedNativeReferenceUnits, project_native_definition_units};
        let cancellation = session.cancellation().cloned().unwrap_or_default();
        let mut run = || -> Result<_> {
            let locator = SelectedSemanticLocator::for_reference_range(
                "python",
                super::super::python_unit_summaries::portable(file.rel_path()),
                range.start,
                range.end,
            );
            let reference =
                match self.python_definition_reference(&locator, &cancellation, session)? {
                    LocatedSemantic::Found(reference) => reference,
                    LocatedSemantic::Missing => {
                        return self.finish_native(
                            SelectedResolutionLocated::Missing,
                            &ResolutionCompletion::Complete,
                            &cancellation,
                        );
                    }
                    LocatedSemantic::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                };
            let context = self.empty_contexts(&ResolutionCompletion::Complete)?;
            let Some(blueprint) = self.prepare_prefix_blueprint(context, &cancellation)? else {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            };
            let projected = self.with_python_forward_operation(
                environment.summary,
                environment.python_version,
                &blueprint,
                session,
                &cancellation,
                |operation, provider, _, _, _, external_imports, dispatch_extensibility, mutations| {
                    external_imports.borrow_mut().requested_reference = Some(reference);
                    let named_argument = project_python_named_argument(
                        &self.ready, operation, provider, reference, environment.summary,
                        &cancellation, session, mutations,
                    )?.0;
                    let answer = if named_argument.is_some() {
                        // Labels have no lexical binding. Retain only their structured
                        // source metadata; the shared parameter projection supplies
                        // their definition or explicit open answer.
                        let seed = self.ready.lexical_source().reference_seed(
                            crate::analyzer::resolution::ResolutionQuery::new(reference),
                            &cancellation,
                        )?.ok_or_else(|| StoreError::corrupt("keyword label has no reference seed"))?;
                        FactResolutionAnswer::from_selected_summary_binding(
                            seed.site_metadata().expect("positioned keyword label metadata"),
                            Vec::new(), ResolutionCompletion::Complete,
                        )
                    } else {
                        match operation.resolve_reference_by_demand(reference, provider)? {
                            FactDemandResolution::Ready(answer) => *answer,
                            FactDemandResolution::Cancelled(completion) => return Ok(Err(completion)),
                        }
                    };
                    let answer = if answer.binding().completion() != &ResolutionCompletion::Complete
                        && let Some(field) = self.python_module_field(
                        answer.binding().targets(), &cancellation,
                    )?
                        && field.path != locator.relative_path()
                    {
                        let (_, observation) = unit_metadata(&self.ready, environment.summary)?;
                        let profile = match observation.as_str() {
                            "runtime" => PythonBindingProfile::Runtime,
                            "typing" => PythonBindingProfile::Typing,
                            _ => return Err(StoreError::corrupt("invalid Python observation profile")),
                        };
                        let identity = super::python_reverse::PythonFieldIdentity {
                            operation: self, summary: environment.summary, profile,
                            cancellation: &cancellation, session,
                        };
                        if identity.matches(&locator, &answer, &field)? == Some(true) {
                            // This is the definition-only reply. The demand operation
                            // retains the original open values and all their alternatives.
                            // The query's scope obligations are independent of this
                            // certainty and stay on the reply.
                            let mut reply = FactResolutionAnswer::from_selected_summary_binding(
                                answer.site_metadata().expect("selected Python reference metadata"),
                                answer.binding().targets().to_vec(), ResolutionCompletion::Complete,
                            );
                            reply.query_obligations = answer.query_obligations;
                            reply
                        } else { answer }
                    } else { answer };
                    // A nested class reached through its owner is open only because its
                    // ordinary creation is unproven: unresolved bases leave its metaclass
                    // unknown. Whether a metaclass defines __get__ is a question about the
                    // value, not about which declaration the name selects, so this
                    // definition-only reply reports the class as the bare name does.
                    let mut answer = answer;
                    if let ResolutionCompletion::Incomplete(_) = answer.binding().completion()
                        && let [target] = answer.binding().targets()
                        && let Some(ResolutionCompletion::Incomplete(creation)) = answer
                            .member_owners()
                            .iter()
                            .find(|owner| owner.target() == *target)
                            .and_then(|owner| owner.unproven_class_creation())
                    {
                        // The creation reasons leave the binding's and the answer's
                        // completion; the member owners, rejections and obligations
                        // stay and still feed the resolution trace.
                        let creation = creation.iter().copied().collect::<Vec<_>>();
                        if answer
                            .discharge_binding_reasons(&creation, &mut || cancellation.is_cancelled())
                            .is_none()
                        {
                            return Ok(Err(cancelled_completion()));
                        }
                    }
                    // Binding identity is independent of invocation/application completion.
                    let mut named_reasons =
                        named_reason_details(&self.ready, answer.binding().completion())?;
                    if let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion()
                    {
                        for reason in reasons.iter() {
                            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) | ResolutionIncompleteReason::ReceiverSubclassObligation(semantic) =
                                reason
                                && let Some((name, detail)) =
                                    operation.service_reason_details(*semantic)
                            {
                                named_reasons.push((
                                    "python_service_obligation",
                                    format!("{name}: {detail:?}"),
                                ));
                            }
                        }
                    }
                    let mut modeled_definitions = Vec::new();
                    let mut source_targets = Vec::new();
                    for &target in answer.binding().targets() {
                        if let Some(model_key) = self.ready.context_identities.model_member_identity(target) {
                            let model = if let Some(analyzer) = self.ready.analyzer
                                && let (Some(authority), Some(active)) = (analyzer.model_authority(), analyzer.active_models()) {
                                super::python_models::declaration(&*authority, &active, &model_key, &cancellation)?
                            } else { None };
                            let model = model.ok_or_else(|| StoreError::new(format!("selected Python model declaration unavailable: {model_key}")))?;
                            if model.owner != model_key || super::python_models::symbol_ref(&model.declaration) != model_key {
                                return Err(StoreError::corrupt("selected Python model declaration identity mismatch"));
                            }
                            modeled_definitions.push((target, model_key, model.declaration));
                        }
                        else { source_targets.push(target); }
                    }
                    let mut definitions = project_native_definition_units(
                        &self.ready,
                        &source_targets,
                        &cancellation,
                        session,
                    )?;
                    let absent_member_owners = super::native_units::project_absent_member_owners(
                        &self.ready,
                        answer.absent_member_owners(),
                        &cancellation,
                        session,
                    )?;
                    let member_contexts = super::native_units::project_native_member_contexts(
                        &self.ready,
                        &answer,
                        &cancellation,
                    )?;
                    let predeclared_symbol = super::native_units::project_predeclared_symbol(
                        &self.ready,
                        "python",
                        &answer,
                        &mut definitions,
                        &cancellation,
                    )?;
                                        let source_root_gap = if matches!(&definitions, SelectedNativeDefinitions::Ready(units) if units.is_empty()) {
                        source_root_gap(self.ready.inventory.connection(), environment.summary, &external_imports.borrow().observed_imports)?
                    } else { None };
                    let selected_external_imports = if source_root_gap.is_some() { Vec::new() } else {
                        selected_external_imports(external_imports, reference)
                    };
                    let dispatch = match &definitions {
                        SelectedNativeDefinitions::Ready(definitions)
                            if !definitions.is_empty()
                                && answer.binding().completion() == &ResolutionCompletion::Complete
                                && definitions.iter().all(|(_, definition)| matches!(definition, super::native_units::SelectedNativeDefinition::Unit(unit) if unit.is_function())) =>
                        {
                            dispatch_extensibility.borrow().get(&reference).copied()
                        }
                        _ => None,
                    };
                    Ok(Ok(PythonDefinitionAnswer {
                        modeled_definitions,
                        dispatch_extensibility: dispatch,
                        selected_external_imports,
                        source_root_gap,
                        reference: SelectedNativeReferenceUnits {
                            argument_binding: None,
                            argument_reason_digests: Vec::new(),
                            call_binding_reason_digests: Vec::new(),
                            constructor_hierarchy_reason_digests: Vec::new(),
                            static_type_qualifier_reason_digests: Vec::new(),
                            model_member_selection: None,
                            query_obligations: answer.query_obligations.clone(),
                            answer,
                            definitions,
                            named_reasons,
                            external_members: Vec::new(),
                            direct_target: None,
                            named_argument,
                            predeclared_symbol,
                            callable_applicability_candidates: Vec::new(),
                            member_contexts,
                            trace_provenance: Default::default(),
                            declared_visibilities: Vec::new(),
                            absent_member_owners,
                            diagnostic_identities: Vec::new(),
                            explicit_import_boundary: None,
                        },
                    }))
                },
            )?;
            match projected {
                Ok(answer) => {
                    let completion = answer.reference.answer.binding().completion().clone();
                    self.finish_native(
                        SelectedResolutionLocated::Found(answer),
                        &completion,
                        &cancellation,
                    )
                }
                Err(completion) => Ok(SelectedResolutionOperationOutcome::Cancelled(completion)),
            }
        };
        Ok(match session.finish(run()) {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: value?,
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Unavailable { reason, work } => {
                BoundedResolution::Unavailable { reason, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        })
    }

    /// Explicit dormant validation assembly. No production query calls this.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn python_native_route_probe(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        self.python_native_route_probe_in_session(
            summary,
            python_version,
            &ResolutionSession::unbounded(),
            cancellation,
        )
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn python_native_route_probe_in_session(
        &self,
        summary: i64,
        python_version: Option<brokk_bifrost_python::intrinsics::PythonVersion>,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<String> {
        let cancellation = session.cancellation().unwrap_or(cancellation);
        let context = empty_contexts_for(
            self.mount_table(),
            &ResolutionCompletion::Complete,
            &selected_mount_lookup(self.mount_table()),
            self.ready.context_identities.clone(),
        )?;
        let Some(blueprint) = self.prepare_prefix_blueprint(context, cancellation)? else {
            return Err(StoreError::new("cancelled preparing Python route probe"));
        };
        self.with_python_forward_operation(
            summary, python_version, &blueprint, session, cancellation,
            |operation, provider, paths, arena, observations, _, _, _mutations| {
                let mut roots = Vec::new();
                let outcome = visit_selected_root_import_half_pages(
                    &self.ready.context_identities,
                    paths,
                    paths,
                    None,
                    cancellation,
                    &mut FactPageVisitor::new(&mut |halves| {
                        roots.extend(halves.iter().filter_map(|half| match half {
                            SelectedRootPathHalf::Import {
                                identity, token, ..
                            } => Some((*identity, *token)),
                            SelectedRootPathHalf::Reference { .. } => None,
                            SelectedRootPathHalf::Export { .. } => unreachable!("root import inventory"),
                        }));
                        Ok(true)
                    }),
                )?;
                if outcome.is_cancelled() {
                    return Err(StoreError::new("cancelled reading Python route roots"));
                }
                let root_paths = paths.hydrate_candidate_paths(
                    &roots.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                    cancellation,
                )?;
                let references = self.ready.inventory.connection().prepare_cached(
                    "SELECT mounted.mount_ordinal, mounted.persisted_relative_path, sites.source_site,
                            reference.start_byte,reference.end_byte
                     FROM temp.selected_resolution_mounts mounted
                     JOIN resolution_semantic_sites sites ON sites.blob_id=mounted.blob_id AND sites.semantic_role='reference'
                     JOIN resolution_sites reference ON reference.blob_id=sites.blob_id AND reference.site=sites.source_site
                     WHERE mounted.semantic_language='python'
                     ORDER BY mounted.persisted_relative_path,reference.start_byte,sites.source_site",
                )?.query_map([], |row| Ok((
                    row.get::<_, u32>(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?,
                    row.get::<_, usize>(3)?, row.get::<_, usize>(4)?,
                )))?.collect::<rusqlite::Result<Vec<_>>>()?;
                let mut output = String::new();
                for (identity, path) in root_paths {
                    let token = roots
                        .iter()
                        .find(|(id, _)| *id == identity)
                        .expect("root source token")
                        .1;
                    let completion =
                        operation.prepare_relation_for_test(path.end(), token, &mut *provider)?;
                    use std::fmt::Write;
                    let mount = self
                        .mount_table()
                        .mount_for_fragment(identity.fragment())?
                        .expect("root source mount");
                    writeln!(
                        output,
                        "import-root {} complete={} reasons={:?}",
                        mount.persisted_relative_path(),
                        completion == ResolutionCompletion::Complete,
                        named_reason_details(&self.ready, &completion)?,
                    )
                    .expect("String write");
                    for observation in observations.borrow_mut().drain(..) {
                        writeln!(output, "  {observation}").expect("String write");
                    }
                }
                for (ordinal, path, site, start, end) in references {
                    let mount = self
                        .mount_table()
                        .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                    let reference = crate::analyzer::resolution::mounted_site_semantic(
                        mount.fragment(),
                        ResolutionSiteId::new(site),
                    );
                    // Exercise standalone lexical prerequisites without any
                    // requested-root finalization. Invoking references also
                    // depend on argument/runtime inputs outside this proof.
                    let standalone = paths.reference_seed(ResolutionQuery::new(reference), cancellation)?
                        .and_then(|seed| seed.site_metadata())
                        .is_some_and(|metadata| !metadata.is_callable_reference());
                    if standalone {
                        let prerequisite = operation.resolve_prerequisite_for_test(reference, &mut *provider)?;
                        if let Some((_, _, Some(entry))) = arena.borrow().selected_universe.get(&reference) {
                            assert!(prerequisite.as_ref().is_some_and(|answer|
                                answer.binding().completion() == &ResolutionCompletion::Complete
                                    && !answer.binding().targets().is_empty()),
                                "selected universe prerequisite must reach Ready: {path}:{start}..{end} {reference:?}; answer={:?}; certificate={:?}", prerequisite.as_ref().map(|answer| answer.binding()), arena.borrow().selected_universe.get(&reference));
                            use std::fmt::Write;
                            writeln!(output, "prerequisite-ready {} {path}:{start}..{end}", entry.identity_spelling).expect("String write");
                        }
                    }
                    let answer =
                        match operation.resolve_reference_by_demand(reference, &mut *provider)? {
                            FactDemandResolution::Ready(answer) => answer,
                            FactDemandResolution::Cancelled(completion) => {
                                return Err(StoreError::new(format!(
                                    "Python reference probe cancelled at {path}:{start}..{end} ({reference:?}): {completion:?}; observations={:?}", observations.borrow()
                                )));
                            }
                        };
                    if let Some((owner, _, Some(entry))) = arena.borrow().selected_universe.get(&reference) {
                        use std::fmt::Write;
                        writeln!(output, "universe-certificate {} published={}",
                            entry.identity_spelling,
                            arena.borrow().endpoints.contains_key(owner)).expect("String write");
                    }
                    let mut selected = Vec::new();
                    for target in answer.binding().targets() {
                        if let Some(entry) = crate::analyzer::resolution::universe_entry_for_identity(paths, *target, cancellation)? {
                            selected.push(format!("predeclared:{}", entry.identity_spelling));
                            continue;
                        }
                        let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) = paths.semantic_provenance(*target, cancellation)? else {
                            return Err(StoreError::corrupt("Python target has no authored provenance"));
                        };
                        let target_mount = self.mount_table().mount_for_fragment(provenance.mount().fragment())?.expect("selected target mount");
                        let node = paths.lookup_definition_node(*target, cancellation)?.expect("selected target definition");
                        let site = paths.definition_source_site(target_mount.ordinal(), node, cancellation)?.flatten().expect("authored target site");
                        // Nameless declarations, including file modules, use
                        // their authored occurrence as the diagnostic anchor.
                        let (begin, finish): (usize,usize) = self.ready.inventory.connection().prepare_cached("SELECT COALESCE(declaration.name_start_byte,declaration.start_byte),
                                    COALESCE(declaration.name_end_byte,declaration.end_byte)
                             FROM source_native_declaration_bridges bridge
                             JOIN source_declarations declaration ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
                             WHERE bridge.blob_id=?1 AND bridge.source_site=?2")?.query_row(
                            rusqlite::params![self.ready.inventory.mount_record_by_ordinal(target_mount.ordinal())?.blob_id(),site.get()], |row| Ok((row.get(0)?,row.get(1)?)),
                        )?;
                        selected.push(format!("{}:{begin}..{finish}",target_mount.persisted_relative_path()));
                    }
                    selected.sort();
                    selected.dedup();
                    // Render the operation's actual reason labels, not a
                    // policy-derived guess. Service reasons have no persisted
                    // source gap row for named_reason_details to read.
                    let mut service_reasons = Vec::new();
                    if let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() {
                        for reason in reasons.iter() {
                            if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) | ResolutionIncompleteReason::ReceiverSubclassObligation(semantic) = reason
                                && let Some((name, _)) = operation.service_reason_details(*semantic)
                            {
                                service_reasons.push(name);
                            }
                        }
                    }
                    service_reasons.sort_unstable();
                    service_reasons.dedup();
                    let service_reasons = if service_reasons.is_empty() {
                        String::new()
                    } else {
                        format!(" service-reasons={service_reasons:?}")
                    };
                    use std::fmt::Write;
                    writeln!(
                        output,
                        "{path}:{start}..{end} targets={} complete={} reasons={:?}{service_reasons} selected={selected:?}",
                        answer.binding().targets().len(),
                        answer.binding().completion() == &ResolutionCompletion::Complete,
                        named_reason_details(&self.ready, answer.binding().completion())?,
                    )
                    .expect("String write");
                    if !answer.query_obligations.is_empty() {
                        writeln!(output, "  query-obligations={:?}", answer.query_obligations.iter().map(ToString::to_string).collect::<Vec<_>>()).expect("String write");
                    }
                    for observation in observations.borrow_mut().drain(..) {
                        writeln!(output, "  {observation}").expect("String write");
                    }
                }
                Ok(output)
            },
        )
    }
}

#[cfg(test)]
mod curated_star_prefix_plan_tests {
    use super::CURATED_STAR_CHILD_PREFIX_SQL;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::params;

    #[test]
    fn curated_star_prefix_seeks_populated_relations() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.conn.execute_fixture(|conn| {
            prepare_pin_context(conn);
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            for index in 1..=80_i64 {
                let importer = index * 3;
                let parent = importer + 1;
                let child = importer + 2;
                let package = format!("pkg{index}");
                let caller = format!("caller-{index}.py");
                let parent_path = format!("{package}/__init__.py");
                let child_path = format!("{package}/child.py");
                for (ordinal, path) in [
                    (importer, &caller),
                    (parent, &parent_path),
                    (child, &child_path),
                ] {
                    conn.execute(
                        "INSERT INTO resolution_unit_summary_members VALUES(1,?1,?1,?2,'source')",
                        params![ordinal, path],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO temp.selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) VALUES(?1,?1,'python',?2)",
                        params![ordinal, path],
                    )
                    .unwrap();
                }
                let parent_container = format!("parent-{index}");
                let child_container = format!("child-{index}");
                for (container, module, parent_module, kind, path, ordinal) in [
                    (&parent_container, package.clone(), String::new(), "package", &parent_path, parent),
                    (&child_container, format!("{package}.child"), package.clone(), "module", &child_path, child),
                ] {
                    conn.execute(
                        "INSERT INTO python_unit_summary_providers VALUES(1,?1,?2,?3,0,?4,'selected',?5,?6,zeroblob(32))",
                        params![container, module, parent_module, kind, path, ordinal],
                    )
                    .unwrap();
                }
                conn.execute(
                    "INSERT INTO python_unit_summary_imports VALUES(1,?1,0,?2,?3,?4,0,'','','star','activation_open')",
                    params![importer, format!("importer-{index}"), parent_container, package],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO python_unit_summary_surfaces VALUES(1,?1,'wildcard','curated')",
                    [&parent_container],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO python_unit_summary_export_names VALUES(1,?1,'wildcard','child',NULL)",
                    [&parent_container],
                )
                .unwrap();
            }
            for state in PlannerStatisticsState::BOTH {
                state.install(conn);
                let bindings = params![1, "caller-1.py", 3, 0, "child"];
                let selected: bool = conn
                    .query_row(CURATED_STAR_CHILD_PREFIX_SQL, bindings, |row| row.get(0))
                    .unwrap();
                assert!(selected, "{state}: the placed child must be selected");
                let mut statement = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {CURATED_STAR_CHILD_PREFIX_SQL}"))
                    .unwrap();
                let plan = statement
                    .query_map(params![1, "caller-1.py", 3, 0, "child"], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                for table in [
                    "member", "imports", "parent", "surface", "exported", "child",
                    "child_member", "mounted",
                ] {
                    assert!(
                        plan.iter().any(|step| step.starts_with(&format!("SEARCH {table} "))),
                        "{state}: {table} must be sought: {plan:?}"
                    );
                }
                assert!(
                    plan.iter().all(|step| !step.contains("AUTOMATIC")),
                    "{state}: no automatic indexes: {plan:?}"
                );
            }
        });
    }
}

#[cfg(test)]
mod capped_constructor_tests {
    use super::*;
    use crate::analyzer::resolution::RootClosure;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct ReadReuseRecorder(AtomicUsize);

    impl brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal for ReadReuseRecorder {
        fn refuse_read_reuse(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct ConstructorProvider<'a, 'store, 'input>(PythonRules<'a, 'store, 'input>);
    impl crate::analyzer::resolution::DemandRootProvider for ConstructorProvider<'_, '_, '_> {
        fn qualified_members(
            &mut self,
        ) -> Option<&mut dyn crate::analyzer::resolution::QualifiedMemberProvider> {
            Some(&mut self.0)
        }

        fn discover(
            &mut self,
            _: &crate::analyzer::resolution::DemandRelationKey,
        ) -> Result<crate::analyzer::resolution::DemandRootDiscovery> {
            Ok(
                crate::analyzer::resolution::DemandRootDiscovery::AlreadyReady {
                    completion: ResolutionCompletion::Complete,
                },
            )
        }

        fn close(
            &mut self,
            _: &crate::analyzer::resolution::DemandRelationKey,
            _: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<RootClosure> {
            Ok(RootClosure::Published(ResolutionCompletion::Complete))
        }
    }

    #[test]
    #[hardwon("#8704: a capped C3 order became a complete empty Python constructor result")]
    fn capped_python_c3_constructor_stays_incomplete() {
        use crate::analyzer::resolution::{
            FactResolutionOperation, PreloadedFactResolutionService,
        };
        let (store, workspace, snapshots) =
            crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture();
        let root = tempfile::tempdir().unwrap();
        let project = crate::analyzer::project::TestProject::new(root.path(), Language::Go);
        let cancellation = CancellationToken::new();
        let read_reuse = ReadReuseRecorder::default();
        let languages = [
            crate::analyzer::store::resolution_selection::SelectedResolutionLanguage::new(
                "go",
                Language::Go,
            ),
        ];
        let SelectedResolutionOperationOpenOutcome::Ready(selected) = store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &project,
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                )
                .with_read_reuse(&read_reuse),
                &cancellation,
            )
            .unwrap()
        else {
            panic!("selected fixture opens");
        };
        let target = SemanticId::for_test("8704-constructor-class");
        let reference = SemanticId::for_test("8704-constructor-reference");
        let session = ResolutionSession::unbounded();
        let observations = RefCell::new(Vec::new());
        let arena = RefCell::new(ClosedRelations::default());
        let external_imports = RefCell::new(PythonExternalImports::default());
        let dispatch_extensibility = RefCell::new(HashMap::default());
        let mutations = super::PythonMutationQuery::new(
            &selected.ready,
            0,
            PythonBindingProfile::Runtime,
            &session,
            &cancellation,
        )
        .unwrap();
        let implicit_provider =
            mutations.implicit_inputs_provider(&selected.ready.context_identities, None);
        let typed = selected
            .ready
            .typed_source()
            .with_implicit_environment(0, None)
            .with_implicit_input_provider(&implicit_provider);
        let rules = PythonRules {
            ready: &selected.ready,
            typed: &typed,
            summary: 0,
            selected_query_obligations: QueryObligations::empty(),
            mutations: &mutations,
            profile: PythonBindingProfile::Runtime,
            python_version: None,
            cancellation: &cancellation,
            session: &session,
            observations: &observations,
            probe_spellings: RefCell::new(Vec::new()),
            arena: &arena,
            source_inputs: RefCell::new(HashMap::default()),
            external_imports: &external_imports,
            binding_rows: RefCell::new(RequestReadCache::default()),
            placement_unit: [0; 32],
            placements: RefCell::new(Default::default()),
            root_prefixes: RefCell::new(RequestReadCache::default()),
            namespace_imports: RefCell::new(RequestReadCache::default()),
            module_sites: RefCell::new(RequestReadCache::default()),
            conditional_import_sites: RefCell::new(RequestReadCache::default()),
            super_context_rows: RefCell::new(RequestReadCache::default()),
            member_role_rows: RefCell::new(RequestReadCache::default()),
            import_routes: RefCell::new(RequestReadCache::default()),
            summary_imports: RefCell::new(RequestReadCache::default()),
            prefix_providers: RefCell::new(RequestReadCache::default()),
            deferred_provider_containers: RefCell::new(RequestReadCache::default()),
            member_owner_rows: RefCell::new(RequestReadCache::default()),
            qualified_members: HashMap::default(),
            attribute_hooks: RefCell::new(HashMap::default()),
            ordinary_keyword_namespaces: RefCell::new(HashSet::default()),
            module_aliases: RefCell::new(HashMap::default()),
            attribute_mutations: RefCell::new(HashMap::default()),
            attribute_metaclasses: RefCell::new(HashMap::default()),
            attribute_metaclass_fallbacks: RefCell::new(HashMap::default()),
            dispatch_extensibility: &dispatch_extensibility,
            prepared_references: RefCell::new(HashMap::default()),
            universe_mutations: RefCell::new(HashMap::default()),
            module_mutations: RefCell::new(HashMap::default()),
            deferred_mutations: RefCell::new(HashMap::default()),
            module_spaces: RefCell::new(HashMap::default()),
            wildcard_inventories: RefCell::new(HashMap::default()),
            reference_inputs: RefCell::new(HashMap::default()),
            module_import_inputs: HashMap::default(),
            module_registry: module_registry::Registry::default(),
        };
        let source = PreloadedFactResolutionService::from_lowered_fragments([], []);
        let mut operation = FactResolutionOperation::new(&source, &source, &cancellation);
        let input = crate::analyzer::resolution::TypedConstructionInput {
            reference: DemandReferenceKey::caller(reference),
            output: reference,
            language: Language::Python,
            binding: ResolutionAnswer::new(
                vec![target],
                Vec::new(),
                ResolutionCompletion::Complete,
            ),
        };
        crate::analyzer::resolution::fact_resolution::demand_scheduler::with_python_constructor_order_test(target, || {
            let (value, completion) = operation
                .prove_construction_by_demand(&input, &mut ConstructorProvider(rules))
                .unwrap();
            assert!(value.is_none());
            assert_eq!(
                completion,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::ReceiverBudgetExhausted(target),
                ]),
            );
            // The C3 cap stops before mutation evidence is consumed. Supplying
            // its required recorder must not cause an unrelated mutation scan.
            assert_eq!(read_reuse.0.load(Ordering::Relaxed), 0);
        });
    }
}
